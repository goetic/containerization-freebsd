//! Looking up jails by name, attaching to them, finding the type of file at a
//! path in one, and ending a jail's processes.

use crate::process::{reap_code, reap_errno};
use crate::{c_string, check, errno};
use std::io;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::time::Duration;

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

  match reap_code(pid)? {
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

/// Whether a jail named `name` exists, even a removed one that is still
/// dying.
#[cfg(target_os = "freebsd")]
pub fn jail_remains(name: &str) -> io::Result<bool> {
  // jail_get writes the name back, so it gets a buffer of its own.
  let mut wanted = c_string(name)?.into_bytes_with_nul();
  let mut parameters = [
    crate::iovec(c"name".to_bytes_with_nul()),
    libc::iovec {
      iov_base: wanted.as_mut_ptr().cast(),
      iov_len: wanted.len(),
    },
  ];

  // SAFETY: jail_get reads the parameter name and writes no more than the
  // wanted name's buffer holds.
  match unsafe {
    libc::jail_get(
      parameters.as_mut_ptr(),
      parameters.len() as libc::c_uint,
      libc::JAIL_DYING,
    )
  } {
    -1 if errno() == libc::ENOENT => Ok(false),
    -1 => Err(io::Error::last_os_error()),
    _ => Ok(true),
  }
}

#[cfg(not(target_os = "freebsd"))]
pub fn jail_remains(name: &str) -> io::Result<bool> {
  crate::unsupported(format_args!("looking up jail {name:?}"))
}

/// Whether `jail` has a network stack of its own: whether it is a VNET jail.
#[cfg(target_os = "freebsd")]
pub fn has_vnet(jail: JailId) -> io::Result<bool> {
  /// The `vnet` parameter's value for a jail with its own stack, from
  /// <sys/jail.h>.
  const JAIL_SYS_NEW: libc::c_int = 1;
  let mut jid = jail.0;
  let mut vnet: libc::c_int = 0;
  let int = |value: &mut libc::c_int| libc::iovec {
    iov_base: (value as *mut libc::c_int).cast(),
    iov_len: size_of::<libc::c_int>(),
  };
  let mut parameters = [
    crate::iovec(c"jid".to_bytes_with_nul()),
    int(&mut jid),
    crate::iovec(c"vnet".to_bytes_with_nul()),
    int(&mut vnet),
  ];

  // SAFETY: jail_get reads the parameter names and writes no more than the
  // two ints hold.
  check(unsafe { libc::jail_get(parameters.as_mut_ptr(), parameters.len() as libc::c_uint, 0) })?;
  Ok(vnet == JAIL_SYS_NEW)
}

#[cfg(not(target_os = "freebsd"))]
pub fn has_vnet(_: JailId) -> io::Result<bool> {
  crate::unsupported("finding a jail's network stack")
}

/// A child process attached to a jail that is ending the jail's processes,
/// which `terminate_in` returns. Wait for it from any thread.
#[must_use]
pub struct Terminating(libc::pid_t);

impl Terminating {
  /// Waits for the child to finish.
  pub fn wait(self) -> io::Result<()> {
    reap_errno(self.0)
  }
}

/// Sends SIGTERM to every process in `jail` from a child process attached to
/// it, which then waits up to `grace` for them to exit. The child first
/// closes every descriptor it inherited, so that it holds no pipe or terminal
/// open while it waits.
#[cfg(target_os = "freebsd")]
pub fn terminate_in(jail: JailId, grace: Duration) -> io::Result<Terminating> {
  unsafe extern "C" {
    fn closefrom(lowfd: libc::c_int);
  }
  const POLL: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 100_000_000,
  };
  let polls = grace.as_millis() / 100;

  // SAFETY: the child only closes descriptors, attaches, signals, sleeps, and
  // exits. Those calls are async-signal-safe and allocate nothing, so they
  // are safe after fork.
  let pid = check(unsafe { libc::fork() })?;
  if pid == 0 {
    // SAFETY: as above. kill(-1) reaches every process in the jail but the
    // child, and fails once none is left.
    let status = unsafe {
      closefrom(0);
      match attach(jail) {
        Err(error) => error.raw_os_error().unwrap_or(libc::EIO),
        Ok(()) => {
          libc::kill(-1, libc::SIGTERM);
          let mut left = polls;
          while left > 0 && libc::kill(-1, 0) == 0 {
            libc::nanosleep(&POLL, std::ptr::null_mut());
            left -= 1;
          }
          0
        }
      }
    };
    // SAFETY: _exit ends the child at once, without running the parent's
    // exit handlers or destructors.
    unsafe { libc::_exit(status) }
  }
  Ok(Terminating(pid))
}

#[cfg(not(target_os = "freebsd"))]
pub fn terminate_in(_: JailId, _: Duration) -> io::Result<Terminating> {
  crate::unsupported("terminating a jail's processes")
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
