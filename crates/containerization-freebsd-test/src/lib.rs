//! What the suites share.

use containerization_freebsd::image;
use std::path::PathBuf;

/// FreeBSD's VM image, the guest bundle and the userland for jails,
/// downloaded once across runs: about 900 MB.
pub fn cache() -> PathBuf {
  PathBuf::from(std::env::var_os("HOME").expect("HOME is set")).join(".cache/containerization-freebsd-tests")
}

/// The cached base disk. The suites never download it: `bin/dev/fetch-image` does.
pub fn base_disk() -> PathBuf {
  cached(image::BASE_DISK)
}

/// The guest bundle built from the working tree, which nextest has
/// `bin/dev/build-guest-bundle` build before the suites. Never the pinned
/// release: the suites test what the next release would ship.
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
/// downloads too.
pub fn userland() -> PathBuf {
  cached(image::USERLAND)
}

fn cached(name: &str) -> PathBuf {
  let path = cache().join(name);

  assert!(path.exists(), "{} is missing: run bin/dev/fetch-image", path.display());
  path
}
