//! Serves the host over the console port: `/dev/ttyV0.0`, or the path given
//! as the first argument. Exits when the port closes, and daemon(8) restarts
//! it.
//!
//! `unpack <compression> <root> <staging> <diff-id>` instead unpacks the
//! image layer on stdin onto `root`, as the host runs it through the agent.

use std::fs::File;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const CONSOLE: &str = "/dev/ttyV0.0";

fn main() -> ExitCode {
  let mut args = std::env::args_os().skip(1);

  match args.next() {
    Some(command) if command == "unpack" => unpack(args.collect()),
    path => {
      let path = path.map_or_else(|| PathBuf::from(CONSOLE), PathBuf::from);
      match serve(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
          eprintln!("containerization-freebsd-agent: {}: {error}", path.display());
          ExitCode::FAILURE
        }
      }
    }
  }
}

fn serve(path: &Path) -> io::Result<()> {
  let console = File::options()
    .read(true)
    .write(true)
    .custom_flags(libc::O_NOCTTY)
    .open(path)?;

  containerization_freebsd_sys::terminal::make_raw(&console)?;
  containerization_freebsd_agent::session::serve(console.try_clone()?, console)
}

fn unpack(args: Vec<std::ffi::OsString>) -> ExitCode {
  let args: Vec<&str> = args.iter().filter_map(|arg| arg.to_str()).collect();
  let [compression, root, staging, diff_id] = args.as_slice() else {
    eprintln!("usage: containerization-freebsd-agent unpack <gzip|zstd|none> <root> <staging> <diff-id>");
    return ExitCode::from(2);
  };

  match containerization_freebsd_agent::unpack::unpack(
    io::stdin(),
    compression,
    Path::new(root),
    Path::new(staging),
    diff_id,
  ) {
    Ok(()) => ExitCode::SUCCESS,
    Err(error) => {
      eprintln!("containerization-freebsd-agent: unpacking onto {root}: {error}");
      ExitCode::FAILURE
    }
  }
}
