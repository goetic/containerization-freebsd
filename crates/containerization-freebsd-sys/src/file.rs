//! Files opened, created, and removed from a child process attached to a
//! jail, so that paths, and any symlinks along them, resolve as they do in
//! the jail. Opened files are passed back over SCM_RIGHTS. File flags are
//! cleared in the calling process.

use crate::{jail, socket};
use std::fs::File;
use std::io;
use std::path::Path;

/// Opens the file at `path` in `jail` for reading, without waiting for a
/// writer if it is a FIFO. Returns `None` if nothing is there or a symlink
/// there leads nowhere.
pub fn open_in(jail: jail::JailId, path: impl AsRef<Path>) -> io::Result<Option<File>> {
  let path = crate::c_string(path.as_ref())?;
  let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;

  // SAFETY: the closure makes only async-signal-safe system calls on data it
  // borrows, and allocates nothing.
  let opened = unsafe {
    socket::in_jail(jail, || match libc::open(path.as_ptr(), flags) {
      -1 => match crate::errno() {
        libc::ENOENT | libc::ENOTDIR => Ok(None),
        error => Err(error),
      },
      fd => Ok(Some(fd)),
    })
  }?;
  Ok(opened.map(File::from))
}

/// Creates a file at `path` in `jail` with permissions `mode`, less the
/// umask, and opens it for writing. Returns `None` if something is already
/// there, even a symlink that leads nowhere.
pub fn create_in(jail: jail::JailId, path: impl AsRef<Path>, mode: u16) -> io::Result<Option<File>> {
  let path = crate::c_string(path.as_ref())?;
  let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC;

  // SAFETY: as in `open_in`.
  let created = unsafe {
    socket::in_jail(jail, || {
      match libc::open(path.as_ptr(), flags, libc::c_uint::from(mode)) {
        -1 => match crate::errno() {
          libc::EEXIST => Ok(None),
          error => Err(error),
        },
        fd => Ok(Some(fd)),
      }
    })
  }?;
  Ok(created.map(File::from))
}

/// Clears the file flags, such as `schg`, of the file at `path`, without
/// following a symlink there.
pub fn clear_flags(path: impl AsRef<Path>) -> io::Result<()> {
  let path = crate::c_string(path.as_ref())?;

  // SAFETY: lchflags only reads the path, which outlives the call.
  crate::check(unsafe { libc::lchflags(path.as_ptr(), 0) })?;
  Ok(())
}

/// Removes the file at `path` in `jail`, if there is one.
pub fn remove_in(jail: jail::JailId, path: impl AsRef<Path>) -> io::Result<()> {
  let path = crate::c_string(path.as_ref())?;

  // SAFETY: as in `open_in`.
  unsafe {
    socket::in_jail(jail, || match libc::unlink(path.as_ptr()) {
      -1 => match crate::errno() {
        libc::ENOENT => Ok(None),
        error => Err(error),
      },
      _ => Ok(None),
    })
  }?;
  Ok(())
}
