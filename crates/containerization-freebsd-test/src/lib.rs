//! What the suites share.

use containerization_freebsd::image;
use std::path::PathBuf;

/// FreeBSD's VM image, downloaded once across runs: about 700 MB.
pub fn cache() -> PathBuf {
  PathBuf::from(std::env::var_os("HOME").expect("HOME is set")).join(".cache/containerization-freebsd-tests")
}

/// The cached base disk. The suites never download it: `bin/dev/fetch-image` does.
pub fn base_disk() -> PathBuf {
  let disk = cache().join(image::BASE_DISK);

  assert!(disk.exists(), "{} is missing: run bin/dev/fetch-image", disk.display());
  disk
}
