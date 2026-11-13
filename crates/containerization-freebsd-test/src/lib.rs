//! What the suites share.

use containerization_freebsd::image;
use std::path::PathBuf;

/// FreeBSD's VM image and the guest bundle, downloaded once across runs:
/// about 700 MB.
pub fn cache() -> PathBuf {
  PathBuf::from(std::env::var_os("HOME").expect("HOME is set")).join(".cache/containerization-freebsd-tests")
}

/// The cached base disk. The suites never download it: `bin/dev/fetch-image` does.
pub fn base_disk() -> PathBuf {
  cached(image::BASE_DISK)
}

/// The cached guest bundle, which `bin/dev/fetch-image` downloads too.
pub fn bundle() -> PathBuf {
  cached(image::BUNDLE)
}

fn cached(name: &str) -> PathBuf {
  let path = cache().join(name);

  assert!(path.exists(), "{} is missing: run bin/dev/fetch-image", path.display());
  path
}
