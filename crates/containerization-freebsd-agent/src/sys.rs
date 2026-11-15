//! The calls std has no safe API for: pseudo-terminals, raw mode, signals,
//! waiting for an exit without reaping it, jails, and what a process takes
//! on before it starts. The crate's only unsafe code.

#![allow(unsafe_code)]

use crate::user::Ids;
use containerization_freebsd_protocol::{Limit, WindowSize};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

fn check(result: libc::c_int) -> io::Result<libc::c_int> {
  if result == -1 {
    Err(io::Error::last_os_error())
  } else {
    Ok(result)
  }
}

/// Puts a terminal in raw mode, at 115200 baud: bytes pass as they are, with
/// no echo, line editing or signals. FreeBSD sizes a tty's input queue by its
/// speed: 23,040 bytes at 115200, against 1,920 at the default 9600.
pub fn make_raw(terminal: &impl AsFd) -> io::Result<()> {
  let fd = terminal.as_fd().as_raw_fd();
  let mut termios = MaybeUninit::<libc::termios>::uninit();

  // SAFETY: tcgetattr fills the termios when it succeeds, and only then is it
  // read.
  unsafe {
    check(libc::tcgetattr(fd, termios.as_mut_ptr()))?;
    let mut termios = termios.assume_init();
    libc::cfmakeraw(&mut termios);
    check(libc::cfsetspeed(&mut termios, libc::B115200))?;
    check(libc::tcsetattr(fd, libc::TCSANOW, &termios))?;
  }
  Ok(())
}

/// A pseudo-terminal of `size`: the end the agent reads and writes, and the
/// end a process takes as its terminal.
pub(crate) fn open_terminal(size: WindowSize) -> io::Result<(File, OwnedFd)> {
  let (mut controller, mut child) = (-1, -1);
  let mut size = window(size);

  // SAFETY: openpty writes the two descriptors it opens; the name and
  // termios may be null.
  check(unsafe {
    libc::openpty(
      &mut controller,
      &mut child,
      std::ptr::null_mut(),
      std::ptr::null_mut(),
      &mut size,
    )
  })?;
  // SAFETY: openpty opened both, and nothing else owns them.
  let (controller, child) = unsafe { (OwnedFd::from_raw_fd(controller), OwnedFd::from_raw_fd(child)) };

  // openpty leaves both inheritable, so every process spawned later would hold
  // them, and the terminal would not end until those exit too. Only the
  // session loop spawns processes, so none can start before this.
  close_on_exec(controller.as_fd())?;
  close_on_exec(child.as_fd())?;
  Ok((File::from(controller), child))
}

fn close_on_exec(fd: BorrowedFd) -> io::Result<()> {
  // SAFETY: fcntl reads and sets the flags of a descriptor `fd` keeps open.
  unsafe {
    let flags = check(libc::fcntl(fd.as_raw_fd(), libc::F_GETFD))?;
    check(libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC))?;
  }
  Ok(())
}

/// Has the command's process start a session of its own, whose controlling
/// terminal is the process's stdin.
pub(crate) fn take_terminal_on_exec(command: &mut Command) {
  // SAFETY: between fork and exec, the closure calls only setsid and ioctl,
  // which are async-signal-safe, and allocates nothing.
  unsafe {
    command.pre_exec(|| {
      check(libc::setsid())?;
      check(libc::ioctl(0, libc::TIOCSCTTY as _, 0))?;
      Ok(())
    });
  }
}

pub(crate) fn resize(terminal: &File, size: WindowSize) -> io::Result<()> {
  let size = window(size);

  // SAFETY: TIOCSWINSZ reads a winsize, which outlives the call.
  check(unsafe { libc::ioctl(terminal.as_raw_fd(), libc::TIOCSWINSZ as _, &raw const size) })?;
  Ok(())
}

fn window(size: WindowSize) -> libc::winsize {
  libc::winsize {
    ws_row: size.rows,
    ws_col: size.columns,
    ws_xpixel: 0,
    ws_ypixel: 0,
  }
}

/// The running jail named `name`: its id, and its root's path in the guest.
#[cfg(target_os = "freebsd")]
pub(crate) fn find_jail(name: &str) -> io::Result<(libc::c_int, PathBuf)> {
  use std::ffi::{CStr, OsString};
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

  // SAFETY: jail_get reads the names and the jail's name, which outlive the
  // call, and writes no more than the path's buffer holds.
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
pub(crate) fn find_jail(name: &str) -> io::Result<(libc::c_int, PathBuf)> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    format!("jail {name:?}: jails are FreeBSD's"),
  ))
}

#[cfg(target_os = "freebsd")]
fn attach(jid: libc::c_int) -> io::Result<()> {
  // SAFETY: jail_attach touches no memory.
  check(unsafe { libc::jail_attach(jid) })?;
  Ok(())
}

/// Never called: `find_jail` finds none.
#[cfg(not(target_os = "freebsd"))]
fn attach(_: libc::c_int) -> io::Result<()> {
  Err(io::ErrorKind::Unsupported.into())
}

/// What a process takes on before it starts.
pub(crate) struct Entry {
  pub(crate) jail: Option<libc::c_int>,
  pub(crate) limits: Vec<Limit>,
  pub(crate) umask: Option<u16>,
  pub(crate) ids: Option<Ids>,
  pub(crate) cwd: Option<CString>,
}

/// Has the command's process take on `entry` between fork and exec, in
/// this order: its jail, its limits and umask, its user, and its working
/// directory, which it reaches as that user, as std would.
// rlim_t is signed on FreeBSD, and mode_t is u16 on FreeBSD and macOS but
// u32 on Linux.
#[allow(clippy::unnecessary_cast)]
pub(crate) fn enter_on_exec(command: &mut Command, entry: Entry) {
  let rlim = |value: u64| value.min(libc::RLIM_INFINITY as u64) as libc::rlim_t;
  let limits: Vec<(libc::c_int, libc::rlimit)> = entry
    .limits
    .iter()
    .map(|limit| {
      let rlimit = libc::rlimit {
        rlim_cur: rlim(limit.soft),
        rlim_max: rlim(limit.hard),
      };
      (limit.resource.0, rlimit)
    })
    .collect();
  let umask = entry.umask.map(|umask| umask as libc::mode_t);
  let Entry { jail, ids, cwd, .. } = entry;

  // SAFETY: between fork and exec, the closure makes only system calls,
  // which are async-signal-safe, reading what it owns, and allocates
  // nothing.
  unsafe {
    command.pre_exec(move || {
      if let Some(jid) = jail {
        attach(jid)?;
      }
      for (resource, limit) in &limits {
        check(libc::setrlimit(*resource as _, limit))?;
      }
      if let Some(umask) = umask {
        libc::umask(umask);
      }
      if let Some(ids) = &ids {
        // Supplementary groups only, on FreeBSD 15 as elsewhere.
        check(libc::setgroups(ids.groups.len() as _, ids.groups.as_ptr()))?;
        check(libc::setgid(ids.gid))?;
        check(libc::setuid(ids.uid))?;
      }
      if let Some(cwd) = &cwd {
        check(libc::chdir(cwd.as_ptr()))?;
      }
      Ok(())
    });
  }
}

/// Sends `signal` to `target`: a pid, or a process group's id negated.
pub(crate) fn signal(target: libc::pid_t, signal: i32) -> io::Result<()> {
  // SAFETY: kill touches no memory.
  check(unsafe { libc::kill(target, signal) })?;
  Ok(())
}

/// Waits for `pid` to exit, leaving it for std to reap. Until then, its pid
/// cannot be another process's.
pub(crate) fn wait_exited(pid: libc::pid_t) -> io::Result<()> {
  loop {
    let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();

    // SAFETY: waitid writes only the siginfo it is given.
    let result = unsafe {
      libc::waitid(
        libc::P_PID,
        pid as libc::id_t,
        info.as_mut_ptr(),
        libc::WEXITED | libc::WNOWAIT,
      )
    };
    match check(result) {
      Ok(_) => return Ok(()),
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      Err(error) => return Err(error),
    }
  }
}
