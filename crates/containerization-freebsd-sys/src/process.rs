//! Signaling processes and waiting for them to exit.

use crate::check;
use std::io;
use std::mem::MaybeUninit;

/// Sends `signal` to `target`: a pid, or a negated process group id.
pub fn signal(target: libc::pid_t, signal: i32) -> io::Result<()> {
  // SAFETY: kill touches no memory.
  check(unsafe { libc::kill(target, signal) })?;
  Ok(())
}

/// Waits for `pid` to exit without reaping it, so std can reap it later.
/// Until it is reaped, the pid cannot be reused by another process.
pub fn wait_exited(pid: libc::pid_t) -> io::Result<()> {
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

/// Waits for `pid` to exit, reaps it, and returns its wait status.
pub(crate) fn reap(pid: libc::pid_t) -> io::Result<libc::c_int> {
  let mut status = 0;

  loop {
    // SAFETY: waitpid writes only the status.
    match check(unsafe { libc::waitpid(pid, &mut status, 0) }) {
      Ok(_) => return Ok(status),
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      Err(error) => return Err(error),
    }
  }
}
