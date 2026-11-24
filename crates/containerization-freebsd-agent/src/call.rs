//! The Calls the host makes: things the agent does in the guest or a jail
//! and reports back on.

use crate::{jail, mount, sys};
use containerization_freebsd_protocol::{Call, Disk, FileCopy, FileType, GuestPath, Return};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// What to report for a Call: known now, or once a thread has finished work
/// that only waits, which the session loop shouldn't wait for.
pub(crate) enum Answer {
  Now(io::Result<Return>),
  Later(Box<dyn FnOnce() -> io::Result<Return> + Send>),
}

/// Does what `call` asks, and returns what to report. Forks and spawns
/// happen here, on the session loop, and never in the work for `Later`.
pub(crate) fn answer(call: &Call) -> Answer {
  let done = |()| Return::Done;

  Answer::Now(match call {
    Call::FileType(path) => file_type(path).map(Return::FileType),
    Call::Mount(mounting) => mount::mount(mounting).map(done),
    Call::Unmount(path) => mount::unmount_under(path).map(done),
    Call::Disks => disks().map(Return::Disks),
    Call::CopyFile(copy) => copy_file(copy).map(done),
    Call::RemoveCopy(copy) => remove_copy(copy).map(done),
    Call::MountDataset(dataset) => mount::mount_dataset(dataset).map(Return::Path),
    Call::SetRules(rules) => jail::set_rules(rules).map(done),
    Call::Statistics(of) => jail::statistics(of).map(Return::Statistics),
    Call::Terminate(wait) => match jail::terminate(wait) {
      Ok(terminating) => return Answer::Later(Box::new(move || terminating().map(done))),
      Err(error) => Err(error),
    },
    Call::DropConnections(name) => jail::drop_connections(name).map(done),
    Call::AwaitRemoval(wait) => {
      let wait = wait.clone();
      return Answer::Later(Box::new(move || jail::await_removal(&wait).map(done)));
    }
  })
}

/// The type of file at `path`, looked up from inside its jail if it names
/// one. Symlinks are followed, so one that leads nowhere is missing.
fn file_type(path: &GuestPath) -> io::Result<FileType> {
  let found = match sys::jail_id(path.jail.as_deref())? {
    Some(jail) => sys::file_type_in(jail, &path.path)?,
    None => found(std::fs::metadata(&path.path))?.map(|metadata| {
      if metadata.is_dir() {
        sys::FileType::Directory
      } else if metadata.is_file() {
        sys::FileType::File
      } else {
        sys::FileType::Other
      }
    }),
  };

  Ok(match found {
    None => FileType::Missing,
    Some(sys::FileType::Directory) => FileType::Directory,
    Some(sys::FileType::File) => FileType::File,
    Some(sys::FileType::Other) => FileType::Other,
  })
}

fn disks() -> io::Result<Vec<Disk>> {
  Ok(
    sys::disks()?
      .into_iter()
      .map(|name| Disk {
        ident: sys::disk_ident(&name)
          .ok()
          .filter(|ident| !ident.is_empty()),
        device: format!("/dev/{name}"),
      })
      .collect(),
  )
}

/// Copies `copy.from` to `copy.to` with the same permissions, unless the
/// original is missing or something is already at the destination.
fn copy_file(copy: &FileCopy) -> io::Result<()> {
  let Some(mut from) = open(&copy.from)? else {
    return Ok(());
  };
  let metadata = from.metadata()?;
  if !metadata.is_file() {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "the original is not a regular file",
    ));
  }
  // The permission bits fit, since they are the low 12.
  let mode = (metadata.permissions().mode() & 0o7777) as u16;

  if let Some(mut to) = create(&copy.to, mode)? {
    io::copy(&mut from, &mut to)?;
  }
  Ok(())
}

/// Removes `copy.to` if it holds the same bytes as `copy.from`.
fn remove_copy(copy: &FileCopy) -> io::Result<()> {
  let (Some(from), Some(to)) = (open(&copy.from)?, open(&copy.to)?) else {
    return Ok(());
  };
  let Some(original) = contents(from, u64::MAX)? else {
    return Ok(());
  };
  // One byte more than the original shows whether the copy is longer.
  let limit = original.len() as u64 + 1;

  if contents(to, limit)?.is_some_and(|copied| copied == original) {
    remove(&copy.to)?;
  }
  Ok(())
}

/// Up to `limit` bytes of `file`, or `None` if it is not a regular file.
fn contents(file: File, limit: u64) -> io::Result<Option<Vec<u8>>> {
  if !file.metadata()?.is_file() {
    return Ok(None);
  }
  let mut contents = Vec::new();
  file.take(limit).read_to_end(&mut contents)?;
  Ok(Some(contents))
}

/// Opens the file at `path` for reading, from inside its jail if it names
/// one, without waiting for a writer if it is a FIFO. Returns `None` if
/// nothing is there.
fn open(path: &GuestPath) -> io::Result<Option<File>> {
  match sys::jail_id(path.jail.as_deref())? {
    Some(jail) => sys::open_in(jail, &path.path),
    None => found(
      OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path.path),
    ),
  }
}

/// Creates a file at `path` with permissions `mode`, less the umask, from
/// inside its jail if it names one. Returns `None` if something is already
/// there.
fn create(path: &GuestPath, mode: u16) -> io::Result<Option<File>> {
  match sys::jail_id(path.jail.as_deref())? {
    Some(jail) => sys::create_in(jail, &path.path, mode),
    None => match OpenOptions::new()
      .write(true)
      .create_new(true)
      .mode(u32::from(mode))
      .open(&path.path)
    {
      Ok(file) => Ok(Some(file)),
      Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(None),
      Err(error) => Err(error),
    },
  }
}

/// Removes the file at `path`, from inside its jail if it names one.
fn remove(path: &GuestPath) -> io::Result<()> {
  match sys::jail_id(path.jail.as_deref())? {
    Some(jail) => sys::remove_in(jail, &path.path),
    None => found(std::fs::remove_file(&path.path)).map(|_| ()),
  }
}

/// `None` in place of a failure because nothing is at the path.
fn found<T>(result: io::Result<T>) -> io::Result<Option<T>> {
  match result {
    Ok(value) => Ok(Some(value)),
    Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => Ok(None),
    Err(error) => Err(error),
  }
}
