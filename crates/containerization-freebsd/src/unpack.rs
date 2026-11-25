//! Unpacks images into ZFS in the guest. Each layer is applied to a clone of
//! the snapshot beneath it, then snapshotted. Datasets are named by chain ID,
//! so a layer stack shared by several images is unpacked once. The top
//! layer's snapshot is what a container's root is cloned from.

use crate::agent::{self, Spawn};
use crate::{error, images, oci, zfs};
use containerization_freebsd_protocol::message;
use std::time::Duration;

/// The guest agent's binary, where the guest bundle installs it. Its
/// `unpack` subcommand unpacks a layer.
const AGENT: &str = "/usr/local/sbin/containerization-freebsd-agent";
/// Extracting a userland-sized layer takes about a minute.
const UNPACKING: Duration = Duration::from_secs(600);
/// The snapshot taken of each layer's dataset once the layer is applied.
const UNPACKED: &str = "unpacked";

pub struct Unpacker<'a> {
  agent: &'a agent::Agent,
  zfs: zfs::Zfs<'a>,
  store: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unpacked {
  /// The top layer's snapshot.
  pub snapshot: String,
  /// Layers this call unpacked, and layers already unpacked.
  pub unpacked: usize,
  pub cached: usize,
}

impl<'a> Unpacker<'a> {
  /// Unpacks into datasets under `store`, such as `images/layers`. `unpack`
  /// creates and mounts `store` if needed.
  pub fn new(agent: &'a agent::Agent, store: &str) -> Self {
    Self {
      agent,
      zfs: zfs::Zfs::new(agent),
      store: store.to_string(),
    }
  }

  /// Unpacks `image`'s layers for `platform`, streaming each through the
  /// agent and skipping those already unpacked. The guest verifies each
  /// decompressed layer against its diff ID, so a snapshot always holds the
  /// content its chain ID names. Unpacks into one store must not run
  /// concurrently.
  pub fn unpack(&self, image: &images::Image, platform: &oci::Platform) -> error::Result<Unpacked> {
    let (_, manifest) = image.manifest(platform)?;
    let config = image.config(platform)?;
    let diff_ids = &config.rootfs.diff_ids;
    if manifest.layers.is_empty() || manifest.layers.len() != diff_ids.len() {
      return Err(error::Error::Invalid(format!(
        "{} has {} layers, and its config {} digests for them",
        image.reference,
        manifest.layers.len(),
        diff_ids.len()
      )));
    }

    let layers = zfs::SnapshotChain::open(&self.zfs, &self.store, UNPACKED)?;
    let mut unpacked = Unpacked {
      snapshot: String::new(),
      unpacked: 0,
      cached: 0,
    };
    let mut below: Option<String> = None;

    for (index, (layer, chain_id)) in manifest.layers.iter().zip(config.chain_ids()).enumerate() {
      let hex = chain_id.require_sha256()?;
      let staging = format!("{}/.{hex}.tar", layers.mountpoint());
      let (snapshot, cache) = layers
        .link(below.as_deref(), hex, |_, root| {
          let diff_id = diff_ids[index].require_sha256()?;
          self.layer(image, layer, diff_id, root, &staging)
        })
        .map_err(|error| {
          error.context(format!(
            "{} layer {} of {}",
            image.reference,
            index + 1,
            manifest.layers.len()
          ))
        })?;
      match cache {
        zfs::Cache::Hit => unpacked.cached += 1,
        zfs::Cache::Miss => unpacked.unpacked += 1,
      }
      below = Some(snapshot);
    }

    unpacked.snapshot = below.unwrap_or_default();
    Ok(unpacked)
  }

  /// Streams `layer`'s blob to the agent's `unpack`, which decompresses it to
  /// `staging`, checks it against `diff_id`, and applies it to the dataset
  /// mounted at `root`. The agent removes `staging` as it exits, or this does
  /// if the agent was killed first.
  fn layer(
    &self,
    image: &images::Image,
    layer: &oci::Descriptor,
    diff_id: &str,
    root: &str,
    staging: &str,
  ) -> error::Result<()> {
    let compression = compression(&layer.media_type)?;
    let path = image.content().path(&layer.digest)?;
    let name = path.display().to_string();
    let mut blob = std::fs::File::open(&path).map_err(error::Error::io(format!("reading {name}")))?;
    let process = self.agent.spawn(message::Exec::new([
      AGENT,
      "unpack",
      compression,
      root,
      staging,
      diff_id,
    ]))?;

    let result = process.feed(&mut blob, &name, "unpacking", Some(UNPACKING));
    if result.is_err() {
      let _ = self.agent.run(&["rm", "-f", staging], agent::QUICK);
    }
    result
  }
}

/// A layer media type's compression, as the agent's `unpack` names it.
fn compression(media_type: &str) -> error::Result<&'static str> {
  match media_type {
    oci::media_type::LAYER | oci::media_type::DOCKER_LAYER => Ok("none"),
    oci::media_type::LAYER_GZIP | oci::media_type::DOCKER_LAYER_GZIP => Ok("gzip"),
    oci::media_type::LAYER_ZSTD => Ok("zstd"),
    other => Err(error::Error::Invalid(format!(
      "layers of type {other} aren't supported"
    ))),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn decompresses_the_layer_types_it_knows() {
    assert_eq!(compression(oci::media_type::LAYER_GZIP).unwrap(), "gzip");
    assert_eq!(compression(oci::media_type::DOCKER_LAYER_GZIP).unwrap(), "gzip");
    assert_eq!(compression(oci::media_type::LAYER_ZSTD).unwrap(), "zstd");
    assert_eq!(compression(oci::media_type::LAYER).unwrap(), "none");
    assert_eq!(compression(oci::media_type::DOCKER_LAYER).unwrap(), "none");
    assert!(compression("application/vnd.oci.image.layer.nondistributable.v1.tar+gzip").is_err());
  }
}
