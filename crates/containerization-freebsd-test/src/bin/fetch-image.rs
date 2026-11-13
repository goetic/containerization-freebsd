//! Downloads and verifies FreeBSD's VM image, decompressed, and the guest
//! bundle into the suites' cache. Run through `bin/dev/fetch-image`.

use containerization_freebsd::image;
use containerization_freebsd_test::cache;
use std::process::ExitCode;

fn main() -> ExitCode {
  let cache = cache();

  eprintln!(
    "fetching {} and {} into {}",
    image::IMAGE,
    image::BUNDLE,
    cache.display()
  );
  match image::base_disk(&cache).and_then(|disk| Ok((disk, image::bundle(&cache)?))) {
    Ok((disk, bundle)) => {
      println!("{}\n{}", disk.display(), bundle.display());
      ExitCode::SUCCESS
    }
    Err(error) => {
      eprintln!("fetch-image: {error}");
      ExitCode::FAILURE
    }
  }
}
