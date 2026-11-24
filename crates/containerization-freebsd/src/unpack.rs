//! Unpacks images into ZFS in the guest. Each layer is applied to a clone of
//! the snapshot beneath it, then snapshotted. Datasets are named by chain ID,
//! so a layer stack shared by several images is unpacked once. The top
//! layer's snapshot is what a container's root is cloned from.

use crate::agent::{Agent, Exec, QUICK, Spawn};
use crate::error::{Error, Result};
use crate::images::Image;
use crate::oci::{Descriptor, Platform, media_type};
use crate::scripts;
use crate::zfs::{Cache, SnapshotChain, Zfs};
use std::time::Duration;

/// Extracting a userland-sized layer takes about a minute.
const UNPACKING: Duration = Duration::from_secs(600);
/// The snapshot taken of each layer's dataset once the layer is applied.
const UNPACKED: &str = "unpacked";

pub struct Unpacker<'a> {
  agent: &'a Agent,
  zfs: Zfs<'a>,
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
  pub fn new(agent: &'a Agent, store: &str) -> Self {
    Self {
      agent,
      zfs: Zfs::new(agent),
      store: store.to_string(),
    }
  }

  /// Unpacks `image`'s layers for `platform`, streaming each through the
  /// agent and skipping those already unpacked. The guest verifies each
  /// decompressed layer against its diff ID, so a snapshot always holds the
  /// content its chain ID names. Unpacks into one store must not run
  /// concurrently.
  pub fn unpack(&self, image: &Image, platform: &Platform) -> Result<Unpacked> {
    let (_, manifest) = image.manifest(platform)?;
    let config = image.config(platform)?;
    let diff_ids = &config.rootfs.diff_ids;
    if manifest.layers.is_empty() || manifest.layers.len() != diff_ids.len() {
      return Err(Error::Invalid(format!(
        "{} has {} layers, and its config {} digests for them",
        image.reference,
        manifest.layers.len(),
        diff_ids.len()
      )));
    }

    self.zfs.create_mounted(&self.store)?;
    let directory = self.zfs.mountpoint(&self.store)?;
    let layers = SnapshotChain::new(&self.zfs, &self.store, UNPACKED);
    let mut unpacked = Unpacked {
      snapshot: String::new(),
      unpacked: 0,
      cached: 0,
    };
    let mut below: Option<String> = None;

    for (index, (layer, chain_id)) in manifest.layers.iter().zip(config.chain_ids()).enumerate() {
      let hex = chain_id.require_sha256()?;
      let (snapshot, cache) = layers
        .link(below.as_deref(), hex, |dataset| {
          let diff_id = diff_ids[index].require_sha256()?;
          self.layer(image, layer, diff_id, dataset, &format!("{directory}/.{hex}.tar"))
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
        Cache::Hit => unpacked.cached += 1,
        Cache::Miss => unpacked.unpacked += 1,
      }
      below = Some(snapshot);
    }

    unpacked.snapshot = below.unwrap_or_default();
    Ok(unpacked)
  }

  /// Applies `layer` to `dataset` via the decompressed tarball at `staging`.
  /// The tarball, and the sha256 and whiteout list beside it, are always
  /// removed.
  fn layer(&self, image: &Image, layer: &Descriptor, diff_id: &str, dataset: &str, staging: &str) -> Result<()> {
    let result = self.receive(image, layer, staging).and_then(|()| {
      let root = self.zfs.mountpoint(dataset)?;
      self
        .agent
        .check(&scripts::APPLY.argv(&[&root, staging, diff_id]), UNPACKING)
        .map(|_| ())
    });
    let (sha256, whiteouts) = (format!("{staging}.sha256"), format!("{staging}.whiteouts"));
    let _ = self
      .agent
      .run(&["rm", "-f", staging, &sha256, &whiteouts], QUICK);
    result
  }

  /// Streams `layer`'s blob to the guest, which decompresses it to
  /// `staging`, hashing it and listing its whiteouts as it goes.
  fn receive(&self, image: &Image, layer: &Descriptor, staging: &str) -> Result<()> {
    let compression = compression(&layer.media_type)?;
    let path = image.content().path(&layer.digest)?;
    let name = path.display().to_string();
    let mut blob = std::fs::File::open(&path).map_err(Error::io(format!("reading {name}")))?;
    let process = self
      .agent
      .spawn(Exec::new(scripts::DECOMPRESS.argv(&[compression, staging])))?;

    process.feed(&mut blob, &name, "decompressing", Some(UNPACKING))
  }
}

/// A layer media type's compression, as `scripts::DECOMPRESS` names it.
fn compression(media_type: &str) -> Result<&'static str> {
  match media_type {
    media_type::LAYER | media_type::DOCKER_LAYER => Ok("none"),
    media_type::LAYER_GZIP | media_type::DOCKER_LAYER_GZIP => Ok("gzip"),
    media_type::LAYER_ZSTD => Ok("zstd"),
    other => Err(Error::Invalid(format!("layers of type {other} aren't supported"))),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn decompresses_the_layer_types_it_knows() {
    assert_eq!(compression(media_type::LAYER_GZIP).unwrap(), "gzip");
    assert_eq!(compression(media_type::DOCKER_LAYER_GZIP).unwrap(), "gzip");
    assert_eq!(compression(media_type::LAYER_ZSTD).unwrap(), "zstd");
    assert_eq!(compression(media_type::LAYER).unwrap(), "none");
    assert_eq!(compression(media_type::DOCKER_LAYER).unwrap(), "none");
    assert!(compression("application/vnd.oci.image.layer.nondistributable.v1.tar+gzip").is_err());
  }
}
