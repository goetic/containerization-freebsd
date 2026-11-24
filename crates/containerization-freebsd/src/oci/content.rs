use super::{Descriptor, Document, ImageConfig, Manifest, parse};
use crate::digest::{Digest, Hashing};
use crate::error::{Error, Result};
use crate::scratch::Scratch;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Where an OCI image layout keeps its blobs, relative to its root.
pub(crate) const BLOBS: &str = "blobs/sha256";

/// The path of the blob `digest` in the OCI image layout at `root`, whether
/// or not the layout holds it. Fails unless `digest` is sha256.
pub(crate) fn blob_path(root: &Path, digest: &Digest) -> Result<PathBuf> {
  Ok(root.join(BLOBS).join(digest.require_sha256()?))
}

/// Blobs at `blobs/sha256/<hex>` under the root, as in an OCI image layout.
/// Each is written under `ingest/` and renamed into place only once its
/// digest is verified.
#[derive(Clone, Debug)]
pub struct ContentStore {
  root: PathBuf,
}

impl ContentStore {
  pub fn new(root: &Path) -> Result<Self> {
    for directory in [root.join(BLOBS), root.join("ingest")] {
      std::fs::create_dir_all(&directory).map_err(Error::io(format!("making {}", directory.display())))?;
    }
    Ok(Self {
      root: root.to_path_buf(),
    })
  }

  /// The path of the blob `digest`, whether or not the store holds it. Fails
  /// unless `digest` is sha256.
  pub fn path(&self, digest: &Digest) -> Result<PathBuf> {
    blob_path(&self.root, digest)
  }

  pub fn has(&self, digest: &Digest) -> bool {
    self.path(digest).is_ok_and(|path| path.exists())
  }

  pub fn read(&self, digest: &Digest) -> Result<Vec<u8>> {
    let path = self.path(digest)?;

    std::fs::read(&path).map_err(Error::io(format!("reading blob {digest}")))
  }

  pub(crate) fn document(&self, descriptor: &Descriptor) -> Result<Document> {
    if descriptor.is_index() {
      let bytes = self.read(&descriptor.digest)?;
      parse(&bytes, &format!("index {}", descriptor.digest)).map(Document::Index)
    } else {
      self.manifest(descriptor).map(Document::Manifest)
    }
  }

  pub(crate) fn manifest(&self, descriptor: &Descriptor) -> Result<Manifest> {
    parse(
      &self.read(&descriptor.digest)?,
      &format!("manifest {}", descriptor.digest),
    )
  }

  pub(crate) fn config(&self, manifest: &Manifest) -> Result<ImageConfig> {
    parse(
      &self.read(&manifest.config.digest)?,
      &format!("config {}", manifest.config.digest),
    )
  }

  /// Stores `bytes` as a blob and returns its digest.
  pub fn ingest(&self, bytes: &[u8]) -> Result<Digest> {
    let digest = Digest::of(bytes);
    let partial = self.partial();

    std::fs::write(partial.path(), bytes).map_err(Error::io(format!("writing {}", partial.path().display())))?;
    self.commit(partial, &digest)?;
    Ok(digest)
  }

  /// Moves `partial`, from `partial()`, into the store as `descriptor`'s
  /// blob, given the sha256 and size found as it was written. If either
  /// differs from the descriptor's, `partial` is dropped, removing the file.
  pub(crate) fn ingest_hashed(&self, partial: Scratch, descriptor: &Descriptor, sha256: &str, size: u64) -> Result<()> {
    let digest = Digest::from_sha256(sha256);

    if digest != descriptor.digest || size != descriptor.size {
      return Err(Error::Checksum {
        path: partial.path().to_path_buf(),
        actual: format!("{digest} ({size} bytes)"),
        expected: format!("{} ({} bytes)", descriptor.digest, descriptor.size),
      });
    }
    self.commit(partial, &digest)
  }

  /// Stores `reader`'s contents as the blob `digest`, hashing them as they
  /// are written, and fails on a digest mismatch.
  pub(crate) fn ingest_from(&self, reader: &mut impl Read, digest: &Digest) -> Result<()> {
    let partial = self.partial();
    let actual = File::create(partial.path())
      .and_then(|file| {
        let mut hashing = Hashing::new(file);
        io::copy(reader, &mut hashing)?;
        Ok(Digest::from_sha256(&hashing.finish()))
      })
      .map_err(Error::io(format!("writing {}", partial.path().display())))?;

    if actual != *digest {
      return Err(Error::Checksum {
        path: partial.path().to_path_buf(),
        actual: actual.to_string(),
        expected: digest.to_string(),
      });
    }
    self.commit(partial, digest)
  }

  /// A scratch path under `ingest/`, on the store's file system so that a
  /// verified blob can be renamed into place.
  pub(crate) fn partial(&self) -> Scratch {
    Scratch::new_in(&self.root.join("ingest"), "")
  }

  pub fn delete(&self, digest: &Digest) -> Result<()> {
    let path = self.path(digest)?;

    match std::fs::remove_file(&path) {
      Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
        Err(Error::io(format!("deleting blob {digest}"))(error))
      }
      _ => Ok(()),
    }
  }

  /// The digests of the blobs the store holds. Files not named for a sha256
  /// are left out.
  pub fn digests(&self) -> Result<Vec<Digest>> {
    let directory = self.root.join(BLOBS);
    let listing = || format!("listing {}", directory.display());
    let mut digests = Vec::new();

    for entry in std::fs::read_dir(&directory).map_err(Error::io(listing()))? {
      let name = entry.map_err(Error::io(listing()))?.file_name();
      if let Ok(digest) = format!("sha256:{}", name.to_string_lossy()).parse() {
        digests.push(digest);
      }
    }
    Ok(digests)
  }

  /// Moves `partial`, from `partial()`, into the store as the blob `digest`,
  /// which the caller has verified.
  pub(crate) fn commit(&self, partial: Scratch, digest: &Digest) -> Result<()> {
    let path = self.path(digest)?;

    std::fs::rename(partial.path(), &path).map_err(Error::io(format!("moving blob {digest} into place")))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::digest::sha256_file;

  #[test]
  fn keeps_blobs_by_their_digest() {
    let root = tempfile::tempdir().unwrap();
    let store = ContentStore::new(root.path()).unwrap();
    std::fs::write(root.path().join(BLOBS).join("stray"), b"").unwrap();

    let digest = store.ingest(b"blob").unwrap();

    assert_eq!(digest, Digest::of(b"blob"));
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
    let path = partial.path().to_path_buf();
    std::fs::write(&path, b"other").unwrap();
    let (sha256, size) = sha256_file(&path).unwrap();
    let descriptor = Descriptor::new(super::super::media_type::LAYER, Digest::of(b"blob"), 4);

    let error = store
      .ingest_hashed(partial, &descriptor, &sha256, size)
      .unwrap_err();

    assert!(matches!(error, Error::Checksum { .. }), "{error}");
    assert!(!path.exists());
    assert!(!store.has(&descriptor.digest));
  }
}
