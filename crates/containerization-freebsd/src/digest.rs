//! SHA-256 hashes, as lowercase hex and as OCI `sha256:<hex>` digests.

use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// The lowercase hex sha256 of `bytes`.
pub(crate) fn sha256(bytes: &[u8]) -> String {
  format!("{:x}", Sha256::digest(bytes))
}

/// The `sha256:<hex>` digest of `bytes`.
pub fn sha256_digest(bytes: &[u8]) -> String {
  format!("sha256:{}", sha256(bytes))
}

/// The lowercase hex sha256 of the file at `path`, and the file's length.
pub(crate) fn sha256_file(path: &Path) -> Result<(String, u64)> {
  let reading = || format!("reading {}", path.display());
  let mut file = File::open(path).map_err(Error::io(reading()))?;
  let mut hasher = Sha256::new();
  let length = io::copy(&mut file, &mut hasher).map_err(Error::io(reading()))?;

  Ok((format!("{:x}", hasher.finalize()), length))
}

/// The hex part of `digest`, or `None` unless it is `sha256:` and 64
/// lowercase hex digits.
pub fn sha256_hex(digest: &str) -> Option<&str> {
  digest.strip_prefix("sha256:").filter(|hex| {
    hex.len() == 64
      && hex
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
  })
}

/// Writes through to `inner`, hashing what it writes, so that a copy is
/// hashed without reading it back.
pub(crate) struct Hashing<W> {
  inner: W,
  hasher: Sha256,
}

impl<W: Write> Hashing<W> {
  pub(crate) fn new(inner: W) -> Self {
    Self {
      inner,
      hasher: Sha256::new(),
    }
  }

  /// The lowercase hex sha256 of everything written.
  pub(crate) fn finish(self) -> String {
    format!("{:x}", self.hasher.finalize())
  }
}

impl<W: Write> Write for Hashing<W> {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    let written = self.inner.write(bytes)?;
    self.hasher.update(&bytes[..written]);
    Ok(written)
  }

  fn flush(&mut self) -> io::Result<()> {
    self.inner.flush()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  #[test]
  fn knows_a_sha256_digest() {
    let digest = sha256_digest(b"");

    assert_eq!(sha256_hex(&digest), Some(EMPTY));
    assert_eq!(sha256_hex("sha256:E3B0"), None);
    assert_eq!(sha256_hex("sha512:00"), None);
  }

  #[test]
  fn hashes_a_file_and_a_copy_alike() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file");
    let bytes = vec![7u8; 3 << 20];
    std::fs::write(&path, &bytes).unwrap();

    let mut copy = Hashing::new(Vec::new());
    io::copy(&mut bytes.as_slice(), &mut copy).unwrap();

    assert_eq!(sha256_file(&path).unwrap(), (sha256(&bytes), bytes.len() as u64));
    assert_eq!(copy.inner, bytes);
    assert_eq!(copy.finish(), sha256(&bytes));
    assert_eq!(sha256_file(&directory.path().join("missing")).ok(), None);
    std::fs::write(&path, b"").unwrap();
    assert_eq!(sha256_file(&path).unwrap(), (EMPTY.to_string(), 0));
  }
}
