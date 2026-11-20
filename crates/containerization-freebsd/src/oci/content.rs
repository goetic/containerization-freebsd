use super::{Descriptor, sha256_digest, sha256_file, sha256_hex};
use crate::error::{Error, Result};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Blobs stored by digest at `blobs/sha256/<hex>` under the root, as in an OCI
/// image layout. A blob is written under `ingest/` first and moved into place
/// only after its digest is verified.
#[derive(Clone, Debug)]
pub struct ContentStore {
  root: PathBuf,
}

impl ContentStore {
  pub fn new(root: &Path) -> Result<Self> {
    for directory in [root.join("blobs/sha256"), root.join("ingest")] {
      std::fs::create_dir_all(&directory).map_err(Error::io(format!("making {}", directory.display())))?;
    }
    Ok(Self {
      root: root.to_path_buf(),
    })
  }

  /// The path of the blob `digest`, whether or not the store holds it.
  pub fn path(&self, digest: &str) -> Result<PathBuf> {
    let hex = sha256_hex(digest).ok_or_else(|| Error::Invalid(format!("{digest:?} is not a sha256 digest")))?;

    Ok(self.root.join("blobs/sha256").join(hex))
  }

  pub fn has(&self, digest: &str) -> bool {
    self.path(digest).is_ok_and(|path| path.exists())
  }

  pub fn read(&self, digest: &str) -> Result<Vec<u8>> {
    let path = self.path(digest)?;

    std::fs::read(&path).map_err(Error::io(format!("reading blob {digest}")))
  }

  /// Stores `bytes` as a blob and returns its digest.
  pub fn ingest(&self, bytes: &[u8]) -> Result<String> {
    let digest = sha256_digest(bytes);
    let partial = self.partial();

    std::fs::write(&partial, bytes).map_err(Error::io(format!("writing {}", partial.display())))?;
    self.commit(&partial, &digest)?;
    Ok(digest)
  }

  /// Moves the file at `partial`, a path from `partial()`, into the store as
  /// `descriptor`'s blob. If the file's digest or size differs from the
  /// descriptor's, the file is deleted instead.
  pub(crate) fn ingest_file(&self, partial: &Path, descriptor: &Descriptor) -> Result<()> {
    let (digest, size) = sha256_file(partial)?;

    if digest != descriptor.digest || size != descriptor.size {
      let _ = std::fs::remove_file(partial);
      return Err(Error::Checksum {
        path: partial.to_path_buf(),
        actual: format!("{digest} ({size} bytes)"),
        expected: format!("{} ({} bytes)", descriptor.digest, descriptor.size),
      });
    }
    self.commit(partial, &digest)
  }

  /// Stores the contents of `reader` as the blob `digest`, failing if the
  /// contents have a different digest.
  pub(crate) fn ingest_from(&self, reader: &mut impl Read, digest: &str) -> Result<()> {
    let partial = self.partial();
    let written = File::create(&partial).and_then(|mut file| io::copy(reader, &mut file));
    let checked = written
      .map_err(Error::io(format!("writing {}", partial.display())))
      .and_then(|_| sha256_file(&partial));

    match checked {
      Ok((actual, _)) if actual == digest => self.commit(&partial, digest),
      Ok((actual, _)) => {
        let _ = std::fs::remove_file(&partial);
        Err(Error::Checksum {
          path: partial,
          actual,
          expected: digest.to_string(),
        })
      }
      Err(error) => {
        let _ = std::fs::remove_file(&partial);
        Err(error)
      }
    }
  }

  /// A unique path under `ingest/` to write a blob to before it is verified.
  pub(crate) fn partial(&self) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);

    self.root.join("ingest").join(format!(
      "{}-{}",
      std::process::id(),
      NEXT.fetch_add(1, Ordering::Relaxed)
    ))
  }

  pub fn delete(&self, digest: &str) -> Result<()> {
    let path = self.path(digest)?;

    match std::fs::remove_file(&path) {
      Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
        Err(Error::io(format!("deleting blob {digest}"))(error))
      }
      _ => Ok(()),
    }
  }

  /// The digests of all blobs in the store.
  pub fn digests(&self) -> Result<Vec<String>> {
    let directory = self.root.join("blobs/sha256");
    let listing = || format!("listing {}", directory.display());

    std::fs::read_dir(&directory)
      .map_err(Error::io(listing()))?
      .map(|entry| {
        entry
          .map(|entry| format!("sha256:{}", entry.file_name().to_string_lossy()))
          .map_err(Error::io(listing()))
      })
      .collect()
  }

  fn commit(&self, partial: &Path, digest: &str) -> Result<()> {
    let path = self.path(digest)?;

    std::fs::rename(partial, &path).map_err(Error::io(format!("moving blob {digest} into place")))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn keeps_blobs_by_their_digest() {
    let root = tempfile::tempdir().unwrap();
    let store = ContentStore::new(root.path()).unwrap();

    let digest = store.ingest(b"blob").unwrap();

    assert_eq!(digest, sha256_digest(b"blob"));
    assert!(store.has(&digest));
    assert_eq!(store.read(&digest).unwrap(), b"blob");
    assert_eq!(store.digests().unwrap(), std::slice::from_ref(&digest));
    store.delete(&digest).unwrap();
    assert!(!store.has(&digest));
  }

  #[test]
  fn refuses_a_file_that_is_not_its_descriptors_blob() {
    let root = tempfile::tempdir().unwrap();
    let store = ContentStore::new(root.path()).unwrap();
    let partial = store.partial();
    std::fs::write(&partial, b"other").unwrap();
    let descriptor = Descriptor {
      media_type: super::super::media_type::LAYER.into(),
      digest: sha256_digest(b"blob"),
      size: 4,
      platform: None,
      annotations: Default::default(),
    };

    let error = store.ingest_file(&partial, &descriptor).unwrap_err();

    assert!(matches!(error, Error::Checksum { .. }), "{error}");
    assert!(!partial.exists());
    assert!(!store.has(&descriptor.digest));
  }
}
