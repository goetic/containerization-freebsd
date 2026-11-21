//! Looking up jails by name, and attaching to them.

use std::io;
use std::path::PathBuf;

/// Finds the running jail named `name` and returns its id and the path of
/// its root in the guest.
#[cfg(target_os = "freebsd")]
pub fn find_jail(name: &str) -> io::Result<(libc::c_int, PathBuf)> {
  use std::ffi::{CStr, CString, OsString};
  use std::os::unix::ffi::OsStringExt;

  fn parameter(bytes: &[u8]) -> libc::iovec {
    libc::iovec {
      iov_base: bytes.as_ptr().cast_mut().cast(),
      iov_len: bytes.len(),
    }
  }

  let wanted =
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a jail's name has a NUL"))?;
  let mut path = vec![0u8; libc::PATH_MAX as usize];
  let mut parameters = [
    parameter(c"name".to_bytes_with_nul()),
    parameter(wanted.to_bytes_with_nul()),
    parameter(c"path".to_bytes_with_nul()),
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
  Ok((jid, PathBuf::from(OsString::from_vec(path))))
}

#[cfg(not(target_os = "freebsd"))]
pub fn find_jail(name: &str) -> io::Result<(libc::c_int, PathBuf)> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    format!("jail {name:?}: jails are FreeBSD's"),
  ))
}

/// The id of the running jail named `name`, if a name is given.
pub fn jail_id(name: Option<&str>) -> io::Result<Option<libc::c_int>> {
  name
    .map(|name| find_jail(name).map(|(jid, _)| jid))
    .transpose()
}

#[cfg(target_os = "freebsd")]
pub(crate) fn attach(jid: libc::c_int) -> io::Result<()> {
  // SAFETY: jail_attach touches no memory.
  crate::check(unsafe { libc::jail_attach(jid) })?;
  Ok(())
}

/// Never called, because `find_jail` always fails off FreeBSD.
#[cfg(not(target_os = "freebsd"))]
pub(crate) fn attach(_: libc::c_int) -> io::Result<()> {
  Err(io::ErrorKind::Unsupported.into())
}
