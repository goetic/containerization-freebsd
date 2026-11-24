//! Safe wrappers for the system calls the guest agent needs and std does not
//! provide: pseudo-terminals, raw mode, signals, waiting for an exit without
//! reaping it, the clock, jails, pre-exec process setup, and sockets opened
//! and files looked up from inside a jail. This crate holds all of the
//! agent's unsafe code.
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
pub use jail::{FileType, JailId, file_type_in, find_jail, jail_id};
pub use process::{kill_group, signal, wait_exited};
pub use socket::{Ready, SocketAddress, connect_in, listen_in, remove_socket_in, wait_for_connection};
pub use terminal::{WindowSize, make_raw, open_terminal, resize, take_terminal_on_exec};

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;

fn check(result: libc::c_int) -> io::Result<libc::c_int> {
  if result == -1 {
    Err(io::Error::last_os_error())
  } else {
    Ok(result)
  }
}

/// The calling thread's errno. Allocates nothing, so a forked child may call
/// it.
fn errno() -> libc::c_int {
  io::Error::last_os_error()
    .raw_os_error()
    .unwrap_or(libc::EIO)
}

/// Retries `call` while it fails with EINTR, and checks its result.
fn retry(mut call: impl FnMut() -> libc::c_int) -> io::Result<libc::c_int> {
  loop {
    match check(call()) {
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      result => return result,
    }
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

/// Converts a path, name, argument, or variable to a C string, failing if it
/// contains a NUL.
fn c_string(string: impl AsRef<OsStr>) -> io::Result<CString> {
  let string = string.as_ref();
  CString::new(string.as_bytes())
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{string:?} has a NUL")))
}
