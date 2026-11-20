//! Copies files and directories between the host and a jail, like
//! Containerization's `copyIn` and `copyOut`. Each step in the jail runs a
//! tool from the guest's `/rescue`, so it works whatever the jail contains.
//! The tools run inside the jail, so paths resolve as the jail sees them and
//! no symbolic link leads out of it. A directory is sent as a tar archive,
//! with the host's `tar` at the other end.

use crate::agent::{Exec, Exit, Output, Process};
use crate::error::{Error, Result};
use crate::jail::Jail;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};

/// Metadata the jail's tar leaves out because the other system cannot store
/// it.
const PORTABLE: [&str; 3] = ["--no-acls", "--no-fflags", "--no-xattrs"];

/// The type of file at a path in a jail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
  Missing,
  Directory,
  /// A regular file.
  File,
  /// A FIFO, device, or socket. Reading or writing one could block or never
  /// end.
  Other,
}

pub(crate) fn copy_in(jail: &Jail, source: &Path, destination: &str, mode: u32, create_parents: bool) -> Result<()> {
  let metadata = fs::metadata(source).map_err(Error::io(format!("reading {}", source.display())))?;
  if !metadata.is_dir() && !metadata.is_file() {
    return Err(Error::Invalid(format!(
      "{} is not a regular file or directory",
      source.display()
    )));
  }
  let directory = metadata.is_dir();
  let target = target(source, directory, destination, kind(jail, destination)?)?;
  if create_parents && let Some(parent) = parent(&target) {
    check(jail, &["mkdir", "-p", "--", parent])?;
  }

  if !directory {
    let mut file = File::open(source).map_err(Error::io(format!("reading {}", source.display())))?;
    let argv = ["dd", &format!("of={target}"), "bs=64k", "status=none"];
    // The umask keeps the file unreadable to the jail's users until chmod
    // gives it its mode.
    let dd = jail.spawn(Exec {
      umask: Some(0o077),
      ..rescue_exec(&argv)
    })?;
    feed(dd, &argv, &mut file, &source.display().to_string())?;
    // chmod(1) parses no options after the mode, so a `--` there would be
    // taken as a file name.
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
  let directory = match kind(jail, source)? {
    Kind::Missing => {
      return Err(Error::Invalid(format!(
        "{source} does not exist in jail {}",
        jail.name()
      )));
    }
    Kind::Other => {
      return Err(Error::Invalid(format!(
        "{source} in jail {} is not a regular file or directory",
        jail.name()
      )));
    }
    Kind::File => false,
    Kind::Directory => true,
  };
  if create_parents && let Some(parent) = destination.parent() {
    fs::create_dir_all(parent).map_err(Error::io(format!("creating {}", parent.display())))?;
  }

  if !directory {
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

/// Returns where cp(1) would put `source` when copied to `destination`,
/// whose existing type is `found`.
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
    Kind::File if directory => Err(Error::Invalid(format!(
      "cannot copy the directory {} over the file {destination}",
      source.display()
    ))),
    Kind::File => Ok(destination.to_string()),
    Kind::Other => Err(Error::Invalid(format!(
      "the destination {destination} is not a regular file or directory"
    ))),
  }
}

/// Returns the directory that contains `path`, unless that is `/` or the
/// working directory, which always exist.
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
  } else if test("-f")? {
    Kind::File
  } else if test("-e")? {
    Kind::Other
  } else {
    Kind::Missing
  })
}

/// Starts the `/rescue` tool that `argv` names in the jail.
fn rescue(jail: &Jail, argv: &[&str]) -> Result<Process> {
  jail.spawn(rescue_exec(argv))
}

/// Builds an `Exec` that runs the `/rescue` tool `argv` names.
fn rescue_exec(argv: &[&str]) -> Exec {
  Exec {
    argv: argv.iter().map(|arg| arg.to_string()).collect(),
    rescue: true,
    ..Exec::default()
  }
}

fn check(jail: &Jail, argv: &[&str]) -> Result<()> {
  finish(&rescue(jail, argv)?, argv, &mut io::sink())
}

/// Writes everything read from `source` (described by `what`) to the
/// process's stdin, then waits for the process to exit 0. If the process
/// stops accepting input, the process's own failure is the error returned.
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

/// Waits for the process to exit 0, writing its stdout to `sink`.
fn finish(process: &Process, argv: &[&str], sink: &mut impl Write) -> Result<()> {
  match wait(process, sink)? {
    (Exit::Code(0), _) => Ok(()),
    (exit, stderr) => Err(Error::Guest(format!("{argv:?} exited {exit:?}: {}", stderr.trim_end()))),
  }
}

/// Waits for the process to exit, writing its stdout to `sink`, and returns
/// its exit and its stderr.
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

/// The host's tar process. Its stderr is read while it runs so that a full
/// pipe cannot stall it. Dropping this before `finish` kills the process.
struct HostTar {
  child: Child,
  stderr: Option<JoinHandle<String>>,
}

impl Drop for HostTar {
  fn drop(&mut self) {
    // After `finish`, this does nothing: the child has been reaped, so `kill`
    // sends no signal.
    let _ = self.child.kill();
    let _ = self.child.wait();
  }
}

impl HostTar {
  fn start(command: &mut Command) -> Result<Self> {
    // Without COPYFILE_DISABLE, macOS's tar archives extended attributes as
    // `._` files.
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

    Ok(Self {
      child,
      stderr: Some(stderr),
    })
  }

  fn finish(mut self) -> Result<()> {
    let status = self.child.wait().map_err(Error::io("waiting for tar"))?;
    let stderr = self
      .stderr
      .take()
      .and_then(|stderr| stderr.join().ok())
      .unwrap_or_default();

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
      target_of("/h/a.txt", false, "/srv/b.txt", Kind::File),
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
      target_of("/h/d", true, "/srv/f", Kind::File),
      Err("cannot copy the directory /h/d over the file /srv/f".into())
    );
    assert_eq!(
      target_of("/h/a.txt", false, "/srv/fifo", Kind::Other),
      Err("the destination /srv/fifo is not a regular file or directory".into())
    );
    assert!(target_of("/", false, "/srv", Kind::Directory).is_err());
  }

  #[test]
  fn reaps_a_tar_it_drops_unfinished() {
    let tar = HostTar::start(Command::new("sleep").arg("30")).unwrap();
    let pid = tar.child.id().to_string();

    drop(tar);

    // An unreaped zombie would still accept signals.
    let signalled = Command::new("kill")
      .args(["-0", &pid])
      .stderr(Stdio::null())
      .status()
      .unwrap();
    assert!(!signalled.success(), "{pid} is still there");
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
