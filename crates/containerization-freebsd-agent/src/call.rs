//! The Calls the host makes: things the agent does in the guest or a jail
//! and reports back on.

use crate::sys;
use containerization_freebsd_protocol::{Call, FileType, GuestPath, Return};
use std::io;

/// Does what `call` asks, and returns what to report.
pub(crate) fn answer(call: &Call) -> io::Result<Return> {
  match call {
    Call::FileType(path) => file_type(path).map(Return::FileType),
  }
}

/// The type of file at `path`, looked up from inside its jail if it names
/// one. Symlinks are followed, so one that leads nowhere is missing.
fn file_type(path: &GuestPath) -> io::Result<FileType> {
  let found = match sys::jail_id(path.jail.as_deref())? {
    Some(jail) => sys::file_type_in(jail, &path.path)?,
    None => match std::fs::metadata(&path.path) {
      Ok(metadata) if metadata.is_dir() => Some(sys::FileType::Directory),
      Ok(metadata) if metadata.is_file() => Some(sys::FileType::File),
      Ok(_) => Some(sys::FileType::Other),
      Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => None,
      Err(error) => return Err(error),
    },
  };

  Ok(match found {
    None => FileType::Missing,
    Some(sys::FileType::Directory) => FileType::Directory,
    Some(sys::FileType::File) => FileType::File,
    Some(sys::FileType::Other) => FileType::Other,
  })
}
