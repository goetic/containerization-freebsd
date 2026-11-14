//! The calls std has no safe API for: pseudo-terminals, raw mode, signals,
//! and waiting for an exit without reaping it. The crate's only unsafe code.

#![allow(unsafe_code)]

use containerization_freebsd_protocol::WindowSize;
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
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
