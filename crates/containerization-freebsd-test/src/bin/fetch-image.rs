//! Downloads, verifies and decompresses FreeBSD's VM image into the suites'
//! cache. Run through `bin/dev/fetch-image`.

use containerization_freebsd::image;
use containerization_freebsd_test::cache;
use std::process::ExitCode;

fn main() -> ExitCode {
  let cache = cache();

  eprintln!("fetching {} into {}", image::IMAGE, cache.display());
  match image::base_disk(&cache) {
    Ok(disk) => {
      println!("{}", disk.display());
      ExitCode::SUCCESS
    }
    Err(error) => {
      eprintln!("fetch-image: {error}");
      ExitCode::FAILURE
    }
  }
}
