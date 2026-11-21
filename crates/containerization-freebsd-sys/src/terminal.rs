//! Pseudo-terminals, raw mode and window sizes.

use crate::{check, close_on_exec};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

/// A terminal's size, in characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowSize {
  pub rows: u16,
  pub columns: u16,
}

/// Puts a terminal in raw mode at 115200 baud: bytes pass through unchanged,
/// with no echo, line editing or signals. The speed matters because FreeBSD
/// sizes a tty's input queue by it: 23,040 bytes at 115200, against 1,920 at
/// the default 9600.
pub fn make_raw(terminal: &impl AsFd) -> io::Result<()> {
  let fd = terminal.as_fd().as_raw_fd();
  let mut termios = MaybeUninit::<libc::termios>::uninit();

  // SAFETY: tcgetattr fills the termios when it succeeds, and the termios is
  // read only after that.
  unsafe {
    check(libc::tcgetattr(fd, termios.as_mut_ptr()))?;
    let mut termios = termios.assume_init();
    libc::cfmakeraw(&mut termios);
    check(libc::cfsetspeed(&mut termios, libc::B115200))?;
    check(libc::tcsetattr(fd, libc::TCSANOW, &termios))?;
  }
  Ok(())
}

/// Opens a pseudo-terminal of `size`. Returns the controller end, which the
/// caller reads and writes, and the child end, which a process uses as its
/// terminal.
pub fn open_terminal(size: WindowSize) -> io::Result<(File, OwnedFd)> {
  let (mut controller, mut child) = (-1, -1);
  let mut size = window(size);

  // SAFETY: openpty writes only the two descriptors and reads the winsize,
  // all of which outlive the call; the name and termios may be null.
  check(unsafe {
    libc::openpty(
      &mut controller,
      &mut child,
      std::ptr::null_mut(),
      std::ptr::null_mut(),
      &mut size,
    )
  })?;
  // SAFETY: openpty opened both descriptors, and nothing else owns them.
  let (controller, child) = unsafe { (OwnedFd::from_raw_fd(controller), OwnedFd::from_raw_fd(child)) };

  // openpty leaves both inheritable. Every process spawned later would inherit
  // them, and the terminal would not end until those processes exit too.
  close_on_exec(controller.as_fd())?;
  close_on_exec(child.as_fd())?;
  Ok((File::from(controller), child))
}

/// Makes the command's process start its own session, with its stdin as the
/// controlling terminal.
pub fn take_terminal_on_exec(command: &mut Command) {
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

pub fn resize(terminal: &File, size: WindowSize) -> io::Result<()> {
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
