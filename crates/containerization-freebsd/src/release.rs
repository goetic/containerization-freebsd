//! The pinned FreeBSD release: downloads of its VM image, userland, and the
//! guest bundle built for it, each verified against a published or pinned
//! sha256.

use crate::digest::sha256_file;
use crate::error::{Error, Result};
use crate::http::{self, Method, Request};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use url::Url;

pub const RELEASE: &str = "15.1-RELEASE";
pub const IMAGE: &str = "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-zfs.raw.xz";
/// The decompressed `IMAGE`'s file name in the `base_disk` cache.
pub const BASE_DISK: &str = "base.raw";
/// The guest bundle for `RELEASE`, holding the agent and the virtiofs
/// modules, as this repository's CI publishes it.
pub const BUNDLE: &str = "freebsd-15.1-arm64-guest-r4.tar.xz";
const BUNDLE_URL: &str = "https://github.com/goetic/containerization-freebsd/releases/download/guest-15.1-r4/freebsd-15.1-arm64-guest-r4.tar.xz";
const BUNDLE_SHA256: &str = "eddf74f52ad2d18dfcea136dfa98d41809f7324085682b27d1568003f47947ca";
/// `RELEASE`'s base system, the jails' userland, as named in the `userland`
/// cache.
pub const USERLAND: &str = "FreeBSD-15.1-RELEASE-arm64-base.txz";
const USERLAND_URL: &str = "https://download.freebsd.org/releases/arm64/aarch64/15.1-RELEASE/base.txz";
const USERLAND_SHA256: &str = "5b7a46a0abfbe23a1d4454b5600e2efcfce16b705bc7e9c851c37470c035ef98";

/// Downloads `url` to `destination` unless it is there already, and checks
/// its sha256 against `expected`, if given. A download is hashed as it is
/// written, and a file already there is read to hash it. A file whose
/// sha256 differs is removed.
fn fetch(url: &str, destination: &Path, expected: Option<&str>) -> Result<()> {
  let actual = if destination.exists() {
    match expected {
      Some(_) => sha256_file(destination)?.0,
      None => return Ok(()),
    }
  } else {
    let partial = destination.with_extension("partial");
    let agent = http::agent();
    let parsed = Url::parse(url).map_err(|error| Error::Invalid(format!("{url:?} is not a URL: {error}")))?;
    let mut get = Request::new(Method::Get, parsed);
    let what = get.to_string();
    let downloaded = http::download(&partial, None, &what, |from| {
      get.from = from;
      http::send(&agent, &get, None)?.content(&get)
    })?;
    std::fs::rename(&partial, destination)
      .map_err(Error::io(format!("moving {} into place", destination.display())))?;
    downloaded.sha256
  };

  match expected {
    Some(expected) if actual != expected => {
      let _ = std::fs::remove_file(destination);
      Err(Error::Checksum {
        path: destination.to_path_buf(),
        actual,
        expected: expected.to_string(),
      })
    }
    _ => Ok(()),
  }
}

/// The decompressed base disk in `cache`, downloaded, verified and
/// decompressed if the cache lacks it.
pub fn base_disk(cache: &Path) -> Result<PathBuf> {
  base_disk_from(
    &format!("https://download.freebsd.org/releases/VM-IMAGES/{RELEASE}/aarch64/Latest"),
    cache,
  )
}

/// `base_disk`, from the release directory URL `directory`.
fn base_disk_from(directory: &str, cache: &Path) -> Result<PathBuf> {
  let raw = cache.join(BASE_DISK);

  if raw.exists() {
    return Ok(raw);
  }

  std::fs::create_dir_all(cache).map_err(Error::io(format!("making {}", cache.display())))?;
  let sums = cache.join("CHECKSUM.SHA256");
  let compressed = cache.join(IMAGE);

  fetch(&format!("{directory}/CHECKSUM.SHA256"), &sums, None)?;
  let sums = std::fs::read_to_string(&sums).map_err(Error::io("reading CHECKSUM.SHA256"))?;
  let expected =
    published_sha256(&sums, IMAGE).ok_or_else(|| Error::Guest(format!("CHECKSUM.SHA256 does not list {IMAGE}")))?;
  fetch(&format!("{directory}/{IMAGE}"), &compressed, Some(expected))?;

  let partial = raw.with_extension("partial");
  decompress_sparse(&compressed, &partial)?;
  std::fs::rename(&partial, &raw).map_err(Error::io("moving the base disk into place"))?;

  Ok(raw)
}

/// The guest bundle in `cache`, downloaded and verified if the cache lacks
/// it.
pub fn bundle(cache: &Path) -> Result<PathBuf> {
  pinned(cache, BUNDLE, BUNDLE_URL, BUNDLE_SHA256)
}

/// `RELEASE`'s `base.txz` in `cache`, downloaded and verified if the cache
/// lacks it. A jail's root starts as this userland.
pub fn userland(cache: &Path) -> Result<PathBuf> {
  pinned(cache, USERLAND, USERLAND_URL, USERLAND_SHA256)
}

fn pinned(cache: &Path, name: &str, url: &str, sha256: &str) -> Result<PathBuf> {
  let path = cache.join(name);

  if !path.exists() {
    std::fs::create_dir_all(cache).map_err(Error::io(format!("making {}", cache.display())))?;
    fetch(url, &path, Some(sha256))?;
  }
  Ok(path)
}

/// The sha256 that `CHECKSUM.SHA256`'s `sums` lists for `name`, on a line
/// `SHA256 (name) = …`.
fn published_sha256<'a>(sums: &'a str, name: &str) -> Option<&'a str> {
  sums
    .lines()
    .find(|line| line.contains(&format!("({name})")))
    .and_then(|line| line.rsplit(' ').next())
}

/// Decompresses the xz file `source` to `destination`, seeking over zeroed
/// chunks so the result is sparse.
fn decompress_sparse(source: &Path, destination: &Path) -> Result<()> {
  let decompressing = || format!("decompressing {}", source.display());
  let input = File::open(source).map_err(Error::io(decompressing()))?;
  let mut decoder = xz2::read::XzDecoder::new(BufReader::new(input));
  let mut output = File::create(destination).map_err(Error::io(decompressing()))?;
  let mut chunk = vec![0u8; 1 << 20];
  let mut length = 0u64;

  loop {
    let mut filled = 0;

    while filled < chunk.len() {
      match decoder.read(&mut chunk[filled..]) {
        Ok(0) => break,
        Ok(read) => filled += read,
        Err(error) => return Err(Error::io(decompressing())(error)),
      }
    }

    if filled == 0 {
      break;
    }

    let data = &chunk[..filled];
    if data.iter().all(|&byte| byte == 0) {
      output
        .seek(SeekFrom::Current(filled as i64))
        .map_err(Error::io(decompressing()))?;
    } else {
      output.write_all(data).map_err(Error::io(decompressing()))?;
    }
    length += filled as u64;
  }

  output.set_len(length).map_err(Error::io(decompressing()))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::testing::serve_files;

  #[test]
  fn reads_the_sha256_published_for_an_image() {
    let sums = "SHA256 (other.raw.xz) = 1111\nSHA256 (FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-zfs.raw.xz) = \
                abcd\n";

    assert_eq!(published_sha256(sums, IMAGE), Some("abcd"));
    assert_eq!(published_sha256(sums, "missing.raw.xz"), None);
  }

  #[test]
  fn decompresses_runs_of_zeros_to_holes_of_the_same_length() {
    let directory = tempfile::tempdir().unwrap();
    let directory = directory.path();
    let mut data = vec![0u8; 3 << 20];
    data[..5].copy_from_slice(b"start");
    data.extend_from_slice(b"end");

    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
    encoder.write_all(&data).unwrap();
    std::fs::write(directory.join("in.xz"), encoder.finish().unwrap()).unwrap();

    decompress_sparse(&directory.join("in.xz"), &directory.join("out")).unwrap();
    let out = std::fs::read(directory.join("out")).unwrap();

    assert_eq!(out, data);
  }

  /// Writes a release directory holding `data` as the image, with a
  /// `CHECKSUM.SHA256` listing `listed` or else its true sha256. Returns the
  /// URL of a server for the directory.
  fn release(directory: &Path, data: &[u8], listed: Option<&str>) -> String {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
    encoder.write_all(data).unwrap();
    std::fs::write(directory.join(IMAGE), encoder.finish().unwrap()).unwrap();

    let sha256 = match listed {
      Some(listed) => listed.to_string(),
      None => sha256_file(&directory.join(IMAGE)).unwrap().0,
    };
    std::fs::write(
      directory.join("CHECKSUM.SHA256"),
      format!("SHA256 ({IMAGE}) = {sha256}\n"),
    )
    .unwrap();

    serve_files(directory.to_path_buf())
  }

  #[test]
  fn downloads_verifies_and_decompresses_the_image_once() {
    let source = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let url = release(source.path(), b"disk", None);

    let raw = base_disk_from(&url, cache.path()).unwrap();
    assert_eq!(std::fs::read(&raw).unwrap(), b"disk");

    std::fs::remove_file(source.path().join(IMAGE)).unwrap();
    assert_eq!(base_disk_from(&url, cache.path()).unwrap(), raw);
  }

  #[test]
  fn refuses_and_discards_an_image_whose_sha256_differs() {
    let source = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let url = release(source.path(), b"disk", Some("0000"));

    let error = base_disk_from(&url, cache.path()).unwrap_err();
    assert!(matches!(error, Error::Checksum { .. }), "{error}");
    assert!(!cache.path().join(IMAGE).exists());
    assert!(!cache.path().join(BASE_DISK).exists());
  }

  #[test]
  fn fails_when_the_release_is_missing() {
    let (source, cache) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let empty = serve_files(source.path().to_path_buf());

    let error = base_disk_from(&empty, cache.path()).unwrap_err();
    assert!(
      matches!(&error, Error::Command { failure, .. } if failure.starts_with("HTTP 404")),
      "{error}"
    );
  }
}
