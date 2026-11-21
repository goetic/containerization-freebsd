//! Safe wrappers for the system calls the guest agent needs and std does not
//! provide: pseudo-terminals, raw mode, signals, waiting for an exit without
//! reaping it, the clock, jails, pre-exec process setup, and sockets opened
//! from inside a jail. This crate holds all of the agent's unsafe code.
//!
//! Descriptors from openpty(3) and SCM_RIGHTS get FD_CLOEXEC only after the
//! call returns, so they are briefly inheritable. Spawn processes from one
//! thread only, as the agent's session loop does; otherwise a process spawned
//! in that window inherits them.

mod clock;
mod exec;
mod jail;
mod process;
mod socket;
mod terminal;

pub use clock::set_time;
pub use exec::{Entering, Entry, Ids, Limit, Step, enter_on_exec, rescue_on_exec};
pub use jail::{find_jail, jail_id};
pub use process::{signal, wait_exited};
pub use socket::{SocketAddress, connect_in, listen_in, remove_socket_in, wait_for_connection};
pub use terminal::{WindowSize, make_raw, open_terminal, resize, take_terminal_on_exec};

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

fn check(result: libc::c_int) -> io::Result<libc::c_int> {
  if result == -1 {
    Err(io::Error::last_os_error())
  } else {
    Ok(result)
  }
}

fn close_on_exec(fd: BorrowedFd) -> io::Result<()> {
  // SAFETY: fcntl only reads and sets the flags of `fd`, which the borrow
  // keeps open.
  unsafe {
    let flags = check(libc::fcntl(fd.as_raw_fd(), libc::F_GETFD))?;
    check(libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC))?;
  }
  Ok(())
}

/// Converts `path` to a C string, failing if it contains a NUL.
pub fn path(path: &str) -> io::Result<CString> {
  CString::new(path).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{path:?} has a NUL")))
}
