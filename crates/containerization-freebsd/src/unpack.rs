//! Images unpacked into ZFS in the guest. Each layer becomes a snapshot of
//! a clone of the layer beneath it, named by its chain id, so a layer images
//! share is unpacked once. The top layer's snapshot is a root to clone, as
//! for a container.

use crate::agent::{Agent, Exec, Exit, Output, Process};
use crate::error::{Error, Result};
use crate::images::Image;
use crate::oci::{Descriptor, Platform, media_type, sha256_hex};
use crate::zfs::Zfs;
use std::io::Read;
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);
/// Extracting a layer the size of a userland takes a minute or so.
const UNPACKING: Duration = Duration::from_secs(600);
/// The name of the snapshot each layer's dataset ends as.
const UNPACKED: &str = "unpacked";

/// Writes stdin, decompressed as `$1` says, to the file `$2`.
const DECOMPRESS: &str = r#"set -e
case "$1" in
  gzip) gzip -dc ;;
  zstd) zstd -dcq ;;
  none) cat ;;
esac > "$2""#;

/// Applies the layer tarball `$2`, whose sha256 must be `$3`, to the root
/// `$1`. Whiteouts hide what the layers beneath made, so they go first, each
/// only within the root; then the layer's own files.
const APPLY: &str = r#"set -e
root=$(realpath -- "$1")
layer=$2
actual=$(sha256 -q -- "$layer")
if [ "$actual" != "$3" ]; then
  echo "its sha256 is $actual, not the config's $3" >&2
  exit 1
fi
tar -tf "$layer" | grep -E '(^|/)\.wh\.[^/]+$' | while IFS= read -r entry; do
  case "$entry" in
    */*) directory=${entry%/*} ;;
    *) directory=. ;;
  esac
  name=${entry##*/}
  parent=$(realpath -q -- "$root/$directory") || continue
  case "$parent/" in
    "$root"/*) ;;
    *) echo "whiteout $entry is outside the root" >&2; exit 1 ;;
  esac
  if [ "$name" = .wh..wh..opq ]; then
    find "$parent" -mindepth 1 -maxdepth 1 -exec chflags -R -P 0 {} + 2>/dev/null || :
    find "$parent" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  else
    hidden=${name#.wh.}
    case "$hidden" in
      '' | . | ..) echo "whiteout $entry hides nothing" >&2; exit 1 ;;
    esac
    if [ -e "$parent/$hidden" ] || [ -L "$parent/$hidden" ]; then
      chflags -R -P 0 "$parent/$hidden" 2>/dev/null || :
      rm -rf -- "$parent/$hidden"
    fi
  fi
done
tar -xpf "$layer" -C "$root" --numeric-owner --exclude '.wh.*'"#;

pub struct Unpacker<'a> {
  agent: &'a Agent,
  zfs: Zfs<'a>,
  store: String,
}

/// What an unpack made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unpacked {
  /// The top layer's snapshot.
  pub snapshot: String,
  /// How many layers were unpacked, and how many were already.
  pub unpacked: usize,
  pub cached: usize,
}

impl<'a> Unpacker<'a> {
  /// Unpacks into datasets under `store`, such as `images/layers`, which it
  /// creates, mounted, if need be.
  pub fn new(agent: &'a Agent, store: &str) -> Self {
    Self {
      agent,
      zfs: Zfs::new(agent),
      store: store.to_string(),
    }
  }

  /// Unpacks `image`'s layers for `platform`, streaming each through the
  /// agent, and skips those unpacked before. The guest checks each against
  /// the digest the image's config gives it uncompressed, so a layer's
  /// snapshot holds what its chain id says. Unpacks into the same store must
  /// not run at once.
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

  /// Unpacks `layer` into a fresh `dataset` on `below`, by way of the
  /// decompressed tarball at `staging`; leaves neither behind if it fails.
  fn layer(
    &self,
    image: &Image,
    layer: &Descriptor,
    diff_id: &str,
    below: Option<&str>,
    dataset: &str,
    staging: &str,
  ) -> Result<()> {
    // Left by an unpack that failed without cleaning up, such as when the
    // guest stopped.
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
        .check(&["sh", "-c", APPLY, "sh", &root, staging, diff_id], UNPACKING)
        .map(|_| ())
    });
    let _ = self.agent.run(&["rm", "-f", staging], QUICK);
    if result.is_err() {
      let _ = self.zfs.destroy(dataset);
    }
    result
  }

  /// Streams `layer`'s blob through the agent into `staging`, decompressed.
  fn receive(&self, image: &Image, layer: &Descriptor, staging: &str) -> Result<()> {
    let compression = compression(&layer.media_type)?;
    let path = image.content().path(&layer.digest)?;
    let reading = || format!("reading {}", path.display());
    let mut blob = std::fs::File::open(&path).map_err(Error::io(reading()))?;
    let process = self.agent.spawn(Exec {
      argv: vec![
        "sh".into(),
        "-c".into(),
        DECOMPRESS.into(),
        "sh".into(),
        compression.into(),
        staging.into(),
      ],
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
      Ok(()) => finish(&process, UNPACKING),
      // A decompressor that fails stops reading: its error says why.
      Err(error) => match finish(&process, QUICK) {
        Err(failed @ Error::Guest(_)) => Err(failed),
        _ => Err(error),
      },
    }
  }
}

/// How a layer of `media_type` is compressed.
fn compression(media_type: &str) -> Result<&'static str> {
  match media_type {
    media_type::LAYER | "application/vnd.docker.image.rootfs.diff.tar" => Ok("none"),
    media_type::LAYER_GZIP | media_type::DOCKER_LAYER_GZIP => Ok("gzip"),
    media_type::LAYER_ZSTD => Ok("zstd"),
    other => Err(Error::Invalid(format!("layers of type {other} aren't supported"))),
  }
}

/// Waits up to `timeout` for `process` to exit, failing unless it exits 0.
fn finish(process: &Process, timeout: Duration) -> Result<()> {
  let mut stderr = Vec::new();

  loop {
    match process.recv_timeout(timeout)? {
      Some(Output::Exited(Exit::Code(0))) => return Ok(()),
      Some(Output::Exited(exit)) => {
        return Err(Error::Guest(format!(
          "decompressing exited {exit:?}: {}",
          String::from_utf8_lossy(&stderr).trim()
        )));
      }
      Some(Output::Stderr(bytes)) => stderr.extend(bytes),
      Some(Output::Stdout(_)) => {}
      None => {
        return Err(Error::Timeout(format!(
          "decompressing did not finish within {}s",
          timeout.as_secs()
        )));
      }
    }
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
