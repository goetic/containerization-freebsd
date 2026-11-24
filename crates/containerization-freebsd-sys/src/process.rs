//! Signaling processes and waiting for them to exit.

use crate::{check, retry};
use std::io;
use std::mem::MaybeUninit;

/// Sends `signal` to process `pid`.
pub fn signal(pid: libc::pid_t, signal: i32) -> io::Result<()> {
  // SAFETY: kill touches no memory.
  check(unsafe { libc::kill(pid, signal) })?;
  Ok(())
}

/// Kills every process in the process group that `leader` leads.
pub fn kill_group(leader: libc::pid_t) -> io::Result<()> {
  // SAFETY: kill touches no memory.
  check(unsafe { libc::kill(-leader, libc::SIGKILL) })?;
  Ok(())
}

/// Waits for `pid` to exit without reaping it, so std can reap it later.
/// Until it is reaped, the pid cannot be reused by another process.
pub fn wait_exited(pid: libc::pid_t) -> io::Result<()> {
  let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();

  // SAFETY: waitid writes only the siginfo it is given.
  retry(|| unsafe {
    libc::waitid(
      libc::P_PID,
      pid as libc::id_t,
      info.as_mut_ptr(),
      libc::WEXITED | libc::WNOWAIT,
    )
  })?;
  Ok(())
}

/// Waits for `pid` to exit, reaps it, and returns its wait status.
pub(crate) fn reap(pid: libc::pid_t) -> io::Result<libc::c_int> {
  let mut status = 0;

  // SAFETY: waitpid writes only the status.
  retry(|| unsafe { libc::waitpid(pid, &mut status, 0) })?;
  Ok(status)
}

/// Waits for the forked child `pid` to exit, reaps it, and returns its exit
/// code, or a failure if it died of a signal.
pub(crate) fn reap_code(pid: libc::pid_t) -> io::Result<libc::c_int> {
  let status = reap(pid)?;

  if !libc::WIFEXITED(status) {
    return Err(io::Error::other(format!(
      "the child died of signal {}",
      libc::WTERMSIG(status)
    )));
  }
  Ok(libc::WEXITSTATUS(status))
}

/// Like `reap_code`, for a child whose exit code is an errno, or 0 if it
/// succeeded.
pub(crate) fn reap_errno(pid: libc::pid_t) -> io::Result<()> {
  match reap_code(pid)? {
    0 => Ok(()),
    errno => Err(io::Error::from_raw_os_error(errno)),
  }
}
