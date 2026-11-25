//! Copies files and directories between the host and a jail, like
//! Containerization's `copyIn` and `copyOut`. Jail-side steps run the guest's
//! `/rescue` tools inside the jail, so they work whatever the jail contains,
//! paths resolve as the jail sees them, and no symlink escapes it.
//! Directories travel as tar streams, with the host's `tar` at the other end.

use crate::agent::{self, Spawn};
use crate::{error, jail};
use containerization_freebsd_protocol::message;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};

/// Makes the jail's tar skip ACLs, file flags and xattrs, which don't carry
/// over between FreeBSD and macOS.
const PORTABLE: [&str; 3] = ["--no-acls", "--no-fflags", "--no-xattrs"];

/// Whether copying creates the destination's missing parent directories, as
/// `mkdir -p` does, or fails without them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parents {
  Create,
  Require,
}

pub(crate) fn copy_in(
  jail: &jail::Jail,
  source: &Path,
  destination: &str,
  mode: u32,
  parents: Parents,
) -> error::Result<()> {
  let metadata = fs::metadata(source).map_err(error::Error::io(format!("reading {}", source.display())))?;
  let copying = if metadata.is_dir() {
    message::FileType::Directory
  } else if metadata.is_file() {
    message::FileType::File
  } else {
    return Err(error::Error::Invalid(format!(
      "{} is not a regular file or directory",
      source.display()
    )));
  };
  let target = target(source, copying, destination, jail.file_type(destination)?)?;
  if parents == Parents::Create
    && let Some(parent) = parent(&target)
  {
    check(jail, &["mkdir", "-p", "--", parent])?;
  }

  if copying == message::FileType::File {
    let mut file = File::open(source).map_err(error::Error::io(format!("reading {}", source.display())))?;
    let argv = ["dd", &format!("of={target}"), "bs=64k", "status=none"];
    // The umask keeps the file private to its owner until chmod sets `mode`.
    let dd = jail.spawn(message::Exec {
      umask: Some(0o077),
      rescue: true,
      ..message::Exec::new(argv)
    })?;
    dd.feed(&mut file, &source.display().to_string(), &format!("{argv:?}"), None)?;
    // No `--`: chmod(1) parses no options after the mode, so it would be
    // taken as a file name.
    return check(jail, &["chmod", &format!("{mode:o}"), &target]);
  }

  if parents == Parents::Create {
    check(jail, &["mkdir", "-p", "--", &target])?;
  } else if jail.file_type(&target)? == message::FileType::Missing {
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
  let fed = rescue(jail, &argv)?.feed(&mut archive, "the host's tar", &format!("{argv:?}"), None);
  drop(archive);

  tar.finish().and(fed)
}

pub(crate) fn copy_out(jail: &jail::Jail, source: &str, destination: &Path, parents: Parents) -> error::Result<()> {
  let copying = match jail.file_type(source)? {
    message::FileType::Missing => {
      return Err(error::Error::Invalid(format!(
        "{source} does not exist in jail {}",
        jail.name()
      )));
    }
    message::FileType::Other => {
      return Err(error::Error::Invalid(format!(
        "{source} in jail {} is not a regular file or directory",
        jail.name()
      )));
    }
    found => found,
  };
  if parents == Parents::Create
    && let Some(parent) = destination.parent()
  {
    fs::create_dir_all(parent).map_err(error::Error::io(format!("creating {}", parent.display())))?;
  }

  if copying == message::FileType::File {
    let mut file = OpenOptions::new()
      .write(true)
      .create(true)
      .truncate(true)
      .mode(0o644)
      .open(destination)
      .map_err(error::Error::io(format!("creating {}", destination.display())))?;
    let argv = ["cat", "--", source];
    let copied = rescue(jail, &argv)?.finish(&format!("{argv:?}"), None, &mut file);
    if copied.is_err() {
      let _ = fs::remove_file(destination);
    }
    return copied;
  }

  match fs::create_dir(destination) {
    Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
      return Err(error::Error::io(format!("creating {}", destination.display()))(error));
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
  let copied = rescue(jail, &argv)?.finish(&format!("{argv:?}"), None, &mut archive);
  drop(archive);

  tar.finish().and(copied)
}

/// Returns where cp(1) would put `source`, a file or directory as `copying`
/// says, when copied to `destination`, whose existing type is `found`.
fn target(
  source: &Path,
  copying: message::FileType,
  destination: &str,
  found: message::FileType,
) -> error::Result<String> {
  let directory = copying == message::FileType::Directory;

  match found {
    message::FileType::Missing if destination.ends_with('/') && !directory => Err(error::Error::Invalid(format!(
      "the destination directory {destination} does not exist"
    ))),
    message::FileType::Missing => Ok(destination.to_string()),
    message::FileType::Directory => {
      let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| error::Error::Invalid(format!("{} has no name to copy it by", source.display())))?;
      Ok(format!("{}/{name}", destination.trim_end_matches('/')))
    }
    message::FileType::File if directory => Err(error::Error::Invalid(format!(
      "cannot copy the directory {} over the file {destination}",
      source.display()
    ))),
    message::FileType::File => Ok(destination.to_string()),
    message::FileType::Other => Err(error::Error::Invalid(format!(
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

/// Starts the `/rescue` tool that `argv` names, in the jail.
fn rescue(jail: &jail::Jail, argv: &[&str]) -> error::Result<agent::channel::Process> {
  jail.spawn(message::Exec {
    rescue: true,
    ..message::Exec::new(argv)
  })
}

fn check(jail: &jail::Jail, argv: &[&str]) -> error::Result<()> {
  rescue(jail, argv)?.finish(&format!("{argv:?}"), None, &mut io::sink())
}

/// The host's tar. Its stderr is drained while it runs so a full pipe can't
/// stall it. Dropping this before `finish` kills and reaps it.
struct HostTar {
  child: Child,
  stderr: Option<JoinHandle<String>>,
}

impl Drop for HostTar {
  fn drop(&mut self) {
    // A no-op after `finish`: the child is reaped, so `kill` sends no signal.
    let _ = self.child.kill();
    let _ = self.child.wait();
  }
}

impl HostTar {
  fn start(command: &mut Command) -> error::Result<Self> {
    // Without COPYFILE_DISABLE, macOS's tar archives xattrs as AppleDouble
    // `._` files.
    let mut child = command
      .env("COPYFILE_DISABLE", "1")
      .stderr(Stdio::piped())
      .spawn()
      .map_err(error::Error::io("running tar"))?;
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

  fn finish(mut self) -> error::Result<()> {
    let status = self
      .child
      .wait()
      .map_err(error::Error::io("waiting for tar"))?;
    let stderr = self
      .stderr
      .take()
      .and_then(|stderr| stderr.join().ok())
      .unwrap_or_default();

    if status.success() {
      Ok(())
    } else {
      Err(error::Error::Command {
        command: "tar".to_string(),
        failure: format!("{status}: {}", stderr.trim_end()),
      })
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn target_of(
    source: &str,
    copying: message::FileType,
    destination: &str,
    found: message::FileType,
  ) -> std::result::Result<String, String> {
    target(Path::new(source), copying, destination, found).map_err(|error| error.to_string())
  }

  #[test]
  fn targets_as_cp_does() {
    assert_eq!(
      target_of(
        "/h/a.txt",
        message::FileType::File,
        "/srv/b.txt",
        message::FileType::Missing
      ),
      Ok("/srv/b.txt".into())
    );
    assert_eq!(
      target_of(
        "/h/a.txt",
        message::FileType::File,
        "/srv/b.txt",
        message::FileType::File
      ),
      Ok("/srv/b.txt".into())
    );
    assert_eq!(
      target_of(
        "/h/a.txt",
        message::FileType::File,
        "/srv/",
        message::FileType::Directory
      ),
      Ok("/srv/a.txt".into())
    );
    assert_eq!(
      target_of("/h/a.txt", message::FileType::File, "/", message::FileType::Directory),
      Ok("/a.txt".into())
    );
    assert_eq!(
      target_of(
        "/h/d",
        message::FileType::Directory,
        "/srv/d2/",
        message::FileType::Missing
      ),
      Ok("/srv/d2/".into())
    );
    assert_eq!(
      target_of(
        "/h/d",
        message::FileType::Directory,
        "/srv",
        message::FileType::Directory
      ),
      Ok("/srv/d".into())
    );
  }

  #[test]
  fn refuses_what_cp_refuses() {
    assert_eq!(
      target_of("/h/a.txt", message::FileType::File, "/srv/", message::FileType::Missing),
      Err("the destination directory /srv/ does not exist".into())
    );
    assert_eq!(
      target_of("/h/d", message::FileType::Directory, "/srv/f", message::FileType::File),
      Err("cannot copy the directory /h/d over the file /srv/f".into())
    );
    assert_eq!(
      target_of(
        "/h/a.txt",
        message::FileType::File,
        "/srv/fifo",
        message::FileType::Other
      ),
      Err("the destination /srv/fifo is not a regular file or directory".into())
    );
    assert!(target_of("/", message::FileType::File, "/srv", message::FileType::Directory).is_err());
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
