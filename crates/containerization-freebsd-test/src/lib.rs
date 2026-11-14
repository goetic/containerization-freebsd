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

/// The cached guest bundle, which `bin/dev/fetch-image` downloads too, or an
/// unreleased one from `guest/build-bundle` at `tmp/guest-bundle.tar.xz`.
pub fn bundle() -> PathBuf {
  let local = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tmp/guest-bundle.tar.xz");

  if local.exists() {
    eprintln!("using {}", local.display());
    return local;
  }
  cached(image::BUNDLE)
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
