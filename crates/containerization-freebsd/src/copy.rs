//! Copying files and directories between the host and a jail, as
//! Containerization's `copyIn` and `copyOut` do. Each step in the jail runs
//! a tool of the guest's `/rescue`, so it works whatever the jail holds,
//! and resolves paths as the jail sees them: no symbolic link leads out. A
//! directory goes as a tar archive, with the host's `tar` at the other end.

use crate::agent::{Exec, Exit, Output, Process};
use crate::error::{Error, Result};
use crate::jail::Jail;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};

/// What a jail's tar leaves out, which the other system can't take.
const PORTABLE: [&str; 3] = ["--no-acls", "--no-fflags", "--no-xattrs"];

/// What a path in a jail is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
  Missing,
  Directory,
  Other,
}

pub(crate) fn copy_in(jail: &Jail, source: &Path, destination: &str, mode: u32, create_parents: bool) -> Result<()> {
  let directory = fs::metadata(source)
    .map_err(Error::io(format!("reading {}", source.display())))?
    .is_dir();
  let target = target(source, directory, destination, kind(jail, destination)?)?;
  if create_parents && let Some(parent) = parent(&target) {
    check(jail, &["mkdir", "-p", "--", parent])?;
  }

  if !directory {
    let mut file = File::open(source).map_err(Error::io(format!("reading {}", source.display())))?;
    let argv = ["dd", &format!("of={target}"), "bs=64k", "status=none"];
    feed(rescue(jail, &argv)?, &argv, &mut file, &source.display().to_string())?;
    // chmod(1) parses no options past the mode, so a `--` there would name a file.
    return check(jail, &["chmod", &format!("{mode:o}"), &target]);
  }

  if create_parents {
    check(jail, &["mkdir", "-p", "--", &target])?;
  } else if kind(jail, &target)? == Kind::Missing {
    check(jail, &["mkdir", "--", &target])?;
  }
  let mut tar = HostTar::start(
    Command::new("tar")
      .args(["-c", "-f", "-", "-C"])
      .arg(source)
      .arg(".")
      .stdout(Stdio::piped()),
  )?;
  let mut archive = tar.child.stdout.take().expect("stdout is piped");
  let mut argv = vec!["tar", "--no-same-owner"];
  argv.extend(PORTABLE);
  argv.extend(["-x", "-f", "-", "-C", &target]);
  let fed = feed(rescue(jail, &argv)?, &argv, &mut archive, "the host's tar");
  drop(archive);

  tar.finish().and(fed)
}

pub(crate) fn copy_out(jail: &Jail, source: &str, destination: &Path, create_parents: bool) -> Result<()> {
  let found = kind(jail, source)?;
  if found == Kind::Missing {
    return Err(Error::Invalid(format!(
      "{source} does not exist in jail {}",
      jail.name()
    )));
  }
  if create_parents && let Some(parent) = destination.parent() {
    fs::create_dir_all(parent).map_err(Error::io(format!("creating {}", parent.display())))?;
  }

  if found == Kind::Other {
    let mut file = OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .mode(0o644)
      .open(destination)
      .map_err(Error::io(format!("creating {}", destination.display())))?;
    let argv = ["cat", "--", source];
    let copied = finish(&rescue(jail, &argv)?, &argv, &mut file);
    if copied.is_err() {
      let _ = fs::remove_file(destination);
    }
    return copied;
  }

  match fs::create_dir(destination) {
    Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
      return Err(Error::io(format!("creating {}", destination.display()))(error));
    }
    _ => {}
  }
  let mut tar = HostTar::start(
    Command::new("tar")
      .args(["-x", "-f", "-", "-C"])
      .arg(destination)
      .stdin(Stdio::piped()),
  )?;
  let mut archive = tar.child.stdin.take().expect("stdin is piped");
  let mut argv = vec!["tar"];
  argv.extend(PORTABLE);
  argv.extend(["-c", "-f", "-", "-C", source, "."]);
  let copied = finish(&rescue(jail, &argv)?, &argv, &mut archive);
  drop(archive);

  tar.finish().and(copied)
}

/// Where `source`, a directory or not, goes for `destination`, which is
/// as `found`: as cp(1) would have it.
fn target(source: &Path, directory: bool, destination: &str, found: Kind) -> Result<String> {
  match found {
    Kind::Missing if destination.ends_with('/') && !directory => Err(Error::Invalid(format!(
      "the destination directory {destination} does not exist"
    ))),
    Kind::Missing => Ok(destination.to_string()),
    Kind::Directory => {
      let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Invalid(format!("{} has no name to copy it by", source.display())))?;
      Ok(format!("{}/{name}", destination.trim_end_matches('/')))
    }
    Kind::Other if directory => Err(Error::Invalid(format!(
      "cannot copy the directory {} over the file {destination}",
      source.display()
    ))),
    Kind::Other => Ok(destination.to_string()),
  }
}

/// The directory `path` is in, unless it is `/` or the working directory,
/// which exist.
fn parent(path: &str) -> Option<&str> {
  let (parent, _) = path.trim_end_matches('/').rsplit_once('/')?;
  let parent = parent.trim_end_matches('/');

  (!parent.is_empty()).then_some(parent)
}

fn kind(jail: &Jail, path: &str) -> Result<Kind> {
  let test = |primary: &str| -> Result<bool> {
    let argv = ["test", primary, path];
    let (exit, _) = wait(&rescue(jail, &argv)?, &mut io::sink())?;
    Ok(exit == Exit::Code(0))
  };

  Ok(if test("-d")? {
    Kind::Directory
  } else if test("-e")? {
    Kind::Other
  } else {
    Kind::Missing
  })
}

/// Starts the `/rescue` tool `argv` names in the jail.
fn rescue(jail: &Jail, argv: &[&str]) -> Result<Process> {
  jail.spawn(Exec {
    argv: argv.iter().map(|arg| arg.to_string()).collect(),
    rescue: true,
    ..Exec::default()
  })
}

fn check(jail: &Jail, argv: &[&str]) -> Result<()> {
  finish(&rescue(jail, argv)?, argv, &mut io::sink())
}

/// Writes what `source`, named `what`, reads to the process's stdin, then
/// waits for it to exit 0. If the process stops taking it, its own failure
/// is the error.
fn feed(process: Process, argv: &[&str], source: &mut impl Read, what: &str) -> Result<()> {
  let mut buffer = vec![0; 64 * 1024];
  let sent = loop {
    match source.read(&mut buffer) {
      Ok(0) => break process.close_input(),
      Ok(read) => {
        if let Err(error) = process.write(&buffer[..read]) {
          break Err(error);
        }
      }
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      // Dropping the process kills it.
      Err(error) => return Err(Error::io(format!("reading {what}"))(error)),
    }
  };

  finish(&process, argv, &mut io::sink()).and(sent)
}

/// Waits for the process to exit 0, its stdout going to `sink`.
fn finish(process: &Process, argv: &[&str], sink: &mut impl Write) -> Result<()> {
  match wait(process, sink)? {
    (Exit::Code(0), _) => Ok(()),
    (exit, stderr) => Err(Error::Guest(format!("{argv:?} exited {exit:?}: {}", stderr.trim_end()))),
  }
}

/// Waits for the process to exit, its stdout going to `sink`: how it
/// exited, and its stderr.
fn wait(process: &Process, sink: &mut impl Write) -> Result<(Exit, String)> {
  let mut stderr = Vec::new();

  loop {
    match process.recv()? {
      Output::Stdout(bytes) => sink.write_all(&bytes).map_err(Error::io("copying out"))?,
      Output::Stderr(bytes) => stderr.extend(bytes),
      Output::Exited(exit) => return Ok((exit, String::from_utf8_lossy(&stderr).into_owned())),
    }
  }
}

/// The host's tar, its stderr read as it runs so a full pipe can't stall it.
struct HostTar {
  child: Child,
  stderr: JoinHandle<String>,
}

impl HostTar {
  fn start(command: &mut Command) -> Result<Self> {
    // Without it, macOS's tar archives extended attributes as `._` files.
    let mut child = command
      .env("COPYFILE_DISABLE", "1")
      .stderr(Stdio::piped())
      .spawn()
      .map_err(Error::io("running tar"))?;
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let stderr = thread::spawn(move || {
      let mut text = String::new();
      let _ = stderr.read_to_string(&mut text);
      text
    });

    Ok(Self { child, stderr })
  }

  fn finish(mut self) -> Result<()> {
    let status = self.child.wait().map_err(Error::io("waiting for tar"))?;
    let stderr = self.stderr.join().unwrap_or_default();

    if status.success() {
      Ok(())
    } else {
      Err(Error::Command {
        command: "tar".to_string(),
        failure: format!("{status}: {}", stderr.trim_end()),
      })
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn target_of(source: &str, directory: bool, destination: &str, found: Kind) -> std::result::Result<String, String> {
    target(Path::new(source), directory, destination, found).map_err(|error| error.to_string())
  }

  #[test]
  fn targets_as_cp_does() {
    assert_eq!(
      target_of("/h/a.txt", false, "/srv/b.txt", Kind::Missing),
      Ok("/srv/b.txt".into())
    );
    assert_eq!(
      target_of("/h/a.txt", false, "/srv/b.txt", Kind::Other),
      Ok("/srv/b.txt".into())
    );
    assert_eq!(
      target_of("/h/a.txt", false, "/srv/", Kind::Directory),
      Ok("/srv/a.txt".into())
    );
    assert_eq!(target_of("/h/a.txt", false, "/", Kind::Directory), Ok("/a.txt".into()));
    assert_eq!(
      target_of("/h/d", true, "/srv/d2/", Kind::Missing),
      Ok("/srv/d2/".into())
    );
    assert_eq!(target_of("/h/d", true, "/srv", Kind::Directory), Ok("/srv/d".into()));
  }

  #[test]
  fn refuses_what_cp_refuses() {
    assert_eq!(
      target_of("/h/a.txt", false, "/srv/", Kind::Missing),
      Err("the destination directory /srv/ does not exist".into())
    );
    assert_eq!(
      target_of("/h/d", true, "/srv/f", Kind::Other),
      Err("cannot copy the directory /h/d over the file /srv/f".into())
    );
    assert!(target_of("/", false, "/srv", Kind::Directory).is_err());
  }

  #[test]
  fn finds_parents_that_may_be_missing() {
    assert_eq!(parent("/a/b/c"), Some("/a/b"));
    assert_eq!(parent("/a//b/"), Some("/a"));
    assert_eq!(parent("a/b"), Some("a"));
    assert_eq!(parent("/a"), None);
    assert_eq!(parent("a"), None);
  }
}
