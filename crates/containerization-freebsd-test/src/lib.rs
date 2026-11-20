//! Paths shared by the integration suites.

use containerization_freebsd::image;
use std::path::PathBuf;

/// The cache directory that holds FreeBSD's VM image, the guest bundle and
/// the userland for jails. They are downloaded once and kept across runs,
/// about 900 MB in all.
pub fn cache() -> PathBuf {
  PathBuf::from(std::env::var_os("HOME").expect("HOME is set")).join(".cache/containerization-freebsd-tests")
}

/// The cached base disk. The suites never download it; `bin/dev/fetch-image`
/// does.
pub fn base_disk() -> PathBuf {
  cached(image::BASE_DISK)
}

/// The guest bundle built from the working tree. nextest runs
/// `bin/dev/build-guest-bundle` to build it before the suites. The suites
/// never use the pinned release, because they test what the next release
/// would ship.
pub fn bundle() -> PathBuf {
  let local = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tmp/guest-bundle.tar.xz");

  assert!(
    local.exists(),
    "{} is missing: run bin/dev/build-guest-bundle",
    local.display()
  );
  local
}

/// The cached userland for jails, `base.txz`, which `bin/dev/fetch-image`
/// also downloads.
pub fn userland() -> PathBuf {
  cached(image::USERLAND)
}

fn cached(name: &str) -> PathBuf {
  let path = cache().join(name);

  assert!(path.exists(), "{} is missing: run bin/dev/fetch-image", path.display());
  path
}
