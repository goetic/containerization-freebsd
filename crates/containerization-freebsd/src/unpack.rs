//! Unpacks images into ZFS in the guest. Each layer is applied to a clone of
//! the snapshot beneath it, then snapshotted. Datasets are named by chain ID,
//! so a layer stack shared by several images is unpacked once. The top
//! layer's snapshot is what a container's root is cloned from.

use crate::agent::{Agent, Exec};
use crate::error::{Error, Result};
use crate::images::Image;
use crate::oci::{Descriptor, Platform, media_type, sha256_hex};
use crate::scripts;
use crate::zfs::Zfs;
use std::io::Read;
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);
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
    let mut unpacked = Unpacked {
      snapshot: String::new(),
      unpacked: 0,
      cached: 0,
    };
    let mut below: Option<String> = None;

    for (index, (layer, chain_id)) in manifest.layers.iter().zip(config.chain_ids()).enumerate() {
      let hex = sha256_hex(&chain_id).ok_or_else(|| Error::Invalid(format!("{chain_id:?} is not a sha256 digest")))?;
      let dataset = format!("{}/{hex}", self.store);
      let snapshot = format!("{dataset}@{UNPACKED}");

      if self.zfs.exists(&snapshot)? {
        unpacked.cached += 1;
      } else {
        let diff_id = sha256_hex(&diff_ids[index])
          .ok_or_else(|| Error::Invalid(format!("{:?} is not a sha256 digest", diff_ids[index])))?;
        let staging = format!("{directory}/.{hex}.tar");
        self
          .layer(image, layer, diff_id, below.as_deref(), &dataset, &staging)
          .map_err(|error| {
            Error::Guest(format!(
              "{} layer {} of {}: {error}",
              image.reference,
              index + 1,
              manifest.layers.len()
            ))
          })?;
        self.zfs.snapshot(&snapshot)?;
        unpacked.unpacked += 1;
      }
      below = Some(snapshot);
    }

    unpacked.snapshot = below.unwrap_or_default();
    Ok(unpacked)
  }

  /// Applies `layer` to a new `dataset`, a clone of the snapshot `below` or
  /// empty if there is none, via the decompressed tarball at `staging`. The
  /// tarball is always removed, and the dataset is destroyed on failure.
  fn layer(
    &self,
    image: &Image,
    layer: &Descriptor,
    diff_id: &str,
    below: Option<&str>,
    dataset: &str,
    staging: &str,
  ) -> Result<()> {
    // An earlier unpack that failed without cleaning up, such as when the
    // guest stopped, can leave the dataset behind.
    if self.zfs.exists(dataset)? {
      self.zfs.destroy(dataset)?;
    }
    match below {
      Some(below) => self.zfs.clone(below, dataset)?,
      None => self.zfs.create(dataset)?,
    }

    let result = self.receive(image, layer, staging).and_then(|()| {
      let root = self.zfs.mountpoint(dataset)?;
      self
        .agent
        .check(&scripts::APPLY.argv(&[&root, staging, diff_id]), UNPACKING)
        .map(|_| ())
    });
    let _ = self.agent.run(&["rm", "-f", staging], QUICK);
    if result.is_err() {
      let _ = self.zfs.destroy(dataset);
    }
    result
  }

  /// Streams `layer`'s blob to the guest, which decompresses it to
  /// `staging`.
  fn receive(&self, image: &Image, layer: &Descriptor, staging: &str) -> Result<()> {
    let compression = compression(&layer.media_type)?;
    let path = image.content().path(&layer.digest)?;
    let reading = || format!("reading {}", path.display());
    let mut blob = std::fs::File::open(&path).map_err(Error::io(reading()))?;
    let process = self.agent.spawn(Exec {
      argv: scripts::DECOMPRESS
        .argv(&[compression, staging])
        .into_iter()
        .map(String::from)
        .collect(),
      ..Exec::default()
    })?;

    let written = (|| {
      let mut buffer = vec![0; 1 << 20];
      loop {
        let read = blob.read(&mut buffer).map_err(Error::io(reading()))?;
        if read == 0 {
          break;
        }
        process.write(&buffer[..read])?;
      }
      process.close_input()
    })();

    match written {
      Ok(()) => process.finish("decompressing", UNPACKING),
      // A failed write usually means the decompressor exited early, and its
      // error says why.
      Err(error) => match process.finish("decompressing", QUICK) {
        Err(failed @ Error::Guest(_)) => Err(failed),
        _ => Err(error),
      },
    }
  }
}

/// A layer media type's compression, as `scripts::DECOMPRESS` names it.
fn compression(media_type: &str) -> Result<&'static str> {
  match media_type {
    media_type::LAYER | "application/vnd.docker.image.rootfs.diff.tar" => Ok("none"),
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
    assert!(compression("application/vnd.oci.image.layer.nondistributable.v1.tar+gzip").is_err());
  }
}
