//! Looking up jails by name, attaching to them, and finding the type of file
//! at a path in one.

use crate::process::reap;
use crate::{c_string, check, errno};
use std::io;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};

/// The id of a running jail, which only `find_jail` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JailId(libc::c_int);

/// The type of file a path names, following symlinks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
  Directory,
  /// A regular file.
  File,
  /// A FIFO, device, or socket.
  Other,
}

/// The type of file at `path` in `jail`, or `None` if nothing is there or a
/// symlink there leads nowhere. A child process attached to the jail calls
/// stat(2), so the path, and any symlinks along it, resolve as they do in the
/// jail.
pub fn file_type_in(jail: JailId, path: impl AsRef<Path>) -> io::Result<Option<FileType>> {
  // The child's exit status for each answer. A failure exits with its
  // errno, which is always lower.
  const MISSING: libc::c_int = 128;
  const DIRECTORY: libc::c_int = 129;
  const FILE: libc::c_int = 130;
  const OTHER: libc::c_int = 131;
  let path = c_string(path.as_ref())?;

  // SAFETY: the child only attaches, calls stat(2), and exits. Those calls
  // are async-signal-safe and allocate nothing, so they are safe after fork.
  let pid = check(unsafe { libc::fork() })?;
  if pid == 0 {
    let status = match attach(jail) {
      Err(error) => error.raw_os_error().unwrap_or(libc::EIO),
      Ok(()) => {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: stat fills the stat when it succeeds, and the stat is read
        // only after that.
        unsafe {
          if libc::stat(path.as_ptr(), stat.as_mut_ptr()) == -1 {
            match errno() {
              libc::ENOENT | libc::ENOTDIR => MISSING,
              error => error,
            }
          } else {
            match stat.assume_init().st_mode & libc::S_IFMT {
              libc::S_IFDIR => DIRECTORY,
              libc::S_IFREG => FILE,
              _ => OTHER,
            }
          }
        }
      }
    };
    // SAFETY: _exit ends the child at once, without running the parent's
    // exit handlers or destructors.
    unsafe { libc::_exit(status) }
  }

  let status = reap(pid)?;
  if !libc::WIFEXITED(status) {
    return Err(io::Error::other(format!(
      "the child died of signal {}",
      libc::WTERMSIG(status)
    )));
  }
  match libc::WEXITSTATUS(status) {
    MISSING => Ok(None),
    DIRECTORY => Ok(Some(FileType::Directory)),
    FILE => Ok(Some(FileType::File)),
    OTHER => Ok(Some(FileType::Other)),
    errno => Err(io::Error::from_raw_os_error(errno)),
  }
}

/// Finds the running jail named `name` and returns its id and the path of
/// its root in the guest.
#[cfg(target_os = "freebsd")]
pub fn find_jail(name: &str) -> io::Result<(JailId, PathBuf)> {
  use crate::iovec;
  use std::ffi::{CStr, OsString};
  use std::os::unix::ffi::OsStringExt;

  let wanted = crate::c_string(name)?;
  let mut path = vec![0u8; libc::PATH_MAX as usize];
  let mut parameters = [
    iovec(c"name".to_bytes_with_nul()),
    iovec(wanted.to_bytes_with_nul()),
    iovec(c"path".to_bytes_with_nul()),
    libc::iovec {
      iov_base: path.as_mut_ptr().cast(),
      iov_len: path.len(),
    },
  ];

  // SAFETY: jail_get reads the parameter names and the wanted jail name,
  // which outlive the call, and writes no more than the path buffer holds.
  let jid = unsafe { libc::jail_get(parameters.as_mut_ptr(), parameters.len() as libc::c_uint, 0) };
  if jid == -1 {
    let error = io::Error::last_os_error();
    return Err(match error.raw_os_error() {
      Some(libc::ENOENT) => io::Error::new(io::ErrorKind::NotFound, format!("no jail is named {name:?}")),
      _ => error,
    });
  }
  let path = CStr::from_bytes_until_nul(&path)
    .map_err(|_| io::Error::other(format!("jail {name:?}'s path has no end")))?
    .to_bytes()
    .to_vec();
  Ok((JailId(jid), PathBuf::from(OsString::from_vec(path))))
}

#[cfg(not(target_os = "freebsd"))]
pub fn find_jail(name: &str) -> io::Result<(JailId, PathBuf)> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    format!("jail {name:?}: jails are FreeBSD's"),
  ))
}

/// The id of the running jail named `name`, if a name is given.
pub fn jail_id(name: Option<&str>) -> io::Result<Option<JailId>> {
  name
    .map(|name| find_jail(name).map(|(jail, _)| jail))
    .transpose()
}

#[cfg(target_os = "freebsd")]
pub(crate) fn attach(jail: JailId) -> io::Result<()> {
  // SAFETY: jail_attach touches no memory.
  crate::check(unsafe { libc::jail_attach(jail.0) })?;
  Ok(())
}

/// Never called, because `find_jail` always fails off FreeBSD.
#[cfg(not(target_os = "freebsd"))]
pub(crate) fn attach(_: JailId) -> io::Result<()> {
  Err(io::ErrorKind::Unsupported.into())
}
