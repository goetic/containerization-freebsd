//! Downloads and verifies FreeBSD's VM image (decompressed), the pinned guest
//! bundle, and the userland for jails into the suites' cache. Run it through
//! `bin/dev/fetch-image`.

use containerization_freebsd::release;
use containerization_freebsd_test::cache;
use std::process::ExitCode;

fn main() -> ExitCode {
  let cache = cache();

  eprintln!(
    "fetching {}, {} and {} into {}",
    release::IMAGE,
    release::BUNDLE,
    release::USERLAND,
    cache.display()
  );
  let fetched = [release::base_disk, release::bundle, release::userland]
    .iter()
    .map(|fetch| fetch(&cache))
    .collect::<Result<Vec<_>, _>>();

  match fetched {
    Ok(paths) => {
      for path in paths {
        println!("{}", path.display());
      }
      ExitCode::SUCCESS
    }
    Err(error) => {
      eprintln!("fetch-image: {error}");
      ExitCode::FAILURE
    }
  }
}
