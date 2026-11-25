//! SHA-256 hashes as lowercase hex, and OCI content digests.

use crate::error;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::str::FromStr;

/// A content digest, `<algorithm>:<encoded>`, as OCI descriptors and
/// references carry it. Any well-formed digest parses, so an index entry
/// with an algorithm this crate can't use doesn't make the whole index
/// unreadable; only sha256 digests name blobs in a store.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(String);

impl Digest {
  /// The sha256 digest of `bytes`.
  pub fn of(bytes: &[u8]) -> Self {
    Self::from_sha256(&sha256(bytes))
  }

  /// The sha256 digest whose hex part is `hex`, as `sha256` and `sha256_file`
  /// return it.
  pub(crate) fn from_sha256(hex: &str) -> Self {
    Self(format!("sha256:{hex}"))
  }

  /// The hex part of a sha256 digest, or `None` for another algorithm.
  pub fn sha256_hex(&self) -> Option<&str> {
    self.0.strip_prefix("sha256:")
  }

  /// Like `sha256_hex`, but fails unless this is a sha256 digest, which
  /// naming a blob needs.
  pub(crate) fn require_sha256(&self) -> error::Result<&str> {
    self
      .sha256_hex()
      .ok_or_else(|| error::Error::Invalid(format!("{self} is not a sha256 digest")))
  }

  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl FromStr for Digest {
  type Err = error::Error;

  /// Accepts the image spec's digest grammar. A sha256 digest must also be 64
  /// lowercase hex digits.
  fn from_str(text: &str) -> error::Result<Self> {
    let lowercase_word = |part: &str| {
      !part.is_empty()
        && part
          .bytes()
          .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    };
    let valid = text.split_once(':').is_some_and(|(algorithm, encoded)| {
      algorithm.split(['+', '.', '_', '-']).all(lowercase_word)
        && !encoded.is_empty()
        && encoded
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || b"=_-".contains(&byte))
        && (algorithm != "sha256"
          || encoded.len() == 64
            && encoded
              .bytes()
              .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
    });

    if valid {
      Ok(Self(text.to_string()))
    } else {
      Err(error::Error::Invalid(format!("{text:?} is not a digest")))
    }
  }
}

impl TryFrom<String> for Digest {
  type Error = error::Error;

  fn try_from(text: String) -> error::Result<Self> {
    text.parse()
  }
}

impl From<Digest> for String {
  fn from(digest: Digest) -> Self {
    digest.0
  }
}

impl fmt::Display for Digest {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.0)
  }
}

/// The lowercase hex sha256 of `bytes`.
pub(crate) fn sha256(bytes: &[u8]) -> String {
  hex(&Sha256::digest(bytes))
}

/// The lowercase hex sha256 of the file at `path`, and the file's length.
pub(crate) fn sha256_file(path: &Path) -> error::Result<(String, u64)> {
  let reading = || format!("reading {}", path.display());
  let mut file = File::open(path).map_err(error::Error::io(reading()))?;
  let mut hashing = Hashing::new(io::sink());
  let length = io::copy(&mut file, &mut hashing).map_err(error::Error::io(reading()))?;

  Ok((hashing.finish(), length))
}

/// `bytes` as lowercase hex.
fn hex(bytes: &[u8]) -> String {
  use std::fmt::Write as _;

  bytes
    .iter()
    .fold(String::with_capacity(bytes.len() * 2), |mut hex, byte| {
      let _ = write!(hex, "{byte:02x}");
      hex
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
    hex(&self.hasher.finalize())
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
    let digest = Digest::of(b"");

    assert_eq!(digest.sha256_hex(), Some(EMPTY));
    assert_eq!(format!("sha256:{EMPTY}").parse::<Digest>().unwrap(), digest);
    assert_eq!(digest.require_sha256().unwrap(), EMPTY);
  }

  #[test]
  fn parses_other_algorithms_but_names_blobs_only_by_sha256() {
    let sha512: Digest = "sha512:00ff".parse().unwrap();
    let multihash: Digest = "multihash+base58:QmRZxt2b1FVZPNqd8hsiykDL3TdBDeTSPX9Kv46HmX4Gx8"
      .parse()
      .unwrap();

    assert_eq!((sha512.sha256_hex(), multihash.sha256_hex()), (None, None));
    assert!(matches!(sha512.require_sha256(), Err(error::Error::Invalid(_))));
    for text in [
      "",
      "sha256",
      "sha256:",
      "sha256:E3B0",
      "sha256:00",
      "SHA512:00",
      ":00",
      "sha512:0 0",
    ] {
      assert!(text.parse::<Digest>().is_err(), "{text:?}");
    }
  }

  #[test]
  fn checks_digests_in_documents() {
    let parsed: Vec<Digest> = serde_json::from_str(&format!(r#"["sha256:{EMPTY}", "sha512:00"]"#)).unwrap();

    assert_eq!(serde_json::to_string(&parsed[1]).unwrap(), r#""sha512:00""#);
    assert!(serde_json::from_str::<Digest>(r#""sha256:E3B0""#).is_err());
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
