//! Serves the host over the console port: `/dev/ttyV0.0`, or the path given.
//! Returns when the port closes, for daemon(8) to start it again.

use std::fs::File;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const CONSOLE: &str = "/dev/ttyV0.0";

fn main() -> ExitCode {
  let path = std::env::args_os()
    .nth(1)
    .map_or_else(|| PathBuf::from(CONSOLE), PathBuf::from);

  match run(&path) {
    Ok(()) => ExitCode::SUCCESS,
    Err(error) => {
      eprintln!("containerization-freebsd-agent: {}: {error}", path.display());
      ExitCode::FAILURE
    }
  }
}

fn run(path: &Path) -> io::Result<()> {
  let console = File::options()
    .read(true)
    .write(true)
    .custom_flags(libc::O_NOCTTY)
    .open(path)?;

  containerization_freebsd_agent::make_raw(&console)?;
  containerization_freebsd_agent::serve(console.try_clone()?, console)
}
