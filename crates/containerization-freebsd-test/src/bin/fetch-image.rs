//! Downloads and verifies FreeBSD's VM image, decompressed, the guest
//! bundle, and the userland for jails into the suites' cache. Run through
//! `bin/dev/fetch-image`.

use containerization_freebsd::image;
use containerization_freebsd_test::cache;
use std::process::ExitCode;

fn main() -> ExitCode {
  let cache = cache();

  eprintln!(
    "fetching {}, {} and {} into {}",
    image::IMAGE,
    image::BUNDLE,
    image::USERLAND,
    cache.display()
  );
  let fetched = [image::base_disk, image::bundle, image::userland]
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
