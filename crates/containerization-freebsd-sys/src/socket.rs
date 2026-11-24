//! Sockets opened from a child process attached to a jail, so that paths and
//! loopback are the jail's, and passed back over SCM_RIGHTS.

use crate::jail::{JailId, attach};
use crate::process::reap;
use crate::{c_string, check, close_on_exec, errno, retry};
use std::ffi::CStr;
use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::ptr;

/// A socket address in the kernel's format.
pub struct SocketAddress {
  storage: libc::sockaddr_storage,
  length: libc::socklen_t,
}

impl SocketAddress {
  /// Port `port` on 127.0.0.1 and on ::1, in that order.
  pub fn loopback(port: u16) -> [Self; 2] {
    // SAFETY: all zeros is a valid address of either family; the fields that
    // matter are set below.
    let (mut ipv4, mut ipv6): (libc::sockaddr_in, libc::sockaddr_in6) = unsafe { (mem::zeroed(), mem::zeroed()) };
    ipv4.sin_family = libc::AF_INET as libc::sa_family_t;
    ipv4.sin_port = port.to_be();
    ipv4.sin_addr.s_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();
    ipv6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    ipv6.sin6_port = port.to_be();
    ipv6.sin6_addr.s6_addr = Ipv6Addr::LOCALHOST.octets();

    [
      Self::new(ipv4, size_of::<libc::sockaddr_in>()),
      Self::new(ipv6, size_of::<libc::sockaddr_in6>()),
    ]
  }

  /// The Unix socket at `path`.
  pub fn unix(path: impl AsRef<Path>) -> io::Result<Self> {
    let path = path.as_ref();
    let bytes = c_string(path)?.into_bytes();
    // SAFETY: all zeros is a valid, unnamed Unix socket address; the path is
    // filled in below.
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // Leave room for a terminating NUL.
    let longest = address.sun_path.len() - 1;
    if bytes.len() > longest {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{path:?} is over the {longest} bytes a socket's path may have"),
      ));
    }
    for (to, &from) in address.sun_path.iter_mut().zip(&bytes) {
      *to = from as libc::c_char;
    }

    Ok(Self::new(
      address,
      mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1,
    ))
  }

  fn new<T>(address: T, length: usize) -> Self {
    const { assert!(size_of::<T>() <= size_of::<libc::sockaddr_storage>()) };
    // SAFETY: all zeros is a valid sockaddr_storage, which is aligned for
    // any address and, as checked, large enough for this one.
    let storage = unsafe {
      let mut storage: libc::sockaddr_storage = mem::zeroed();
      ptr::write((&raw mut storage).cast::<T>(), address);
      storage
    };

    Self {
      storage,
      length: length as libc::socklen_t,
    }
  }

  fn family(&self) -> libc::c_int {
    libc::c_int::from(self.storage.ss_family)
  }

  fn as_ptr(&self) -> *const libc::sockaddr {
    (&raw const self.storage).cast()
  }
}

/// Connects to the first of `addresses` that accepts, from a child process
/// attached to `jail`, so paths and loopback are the jail's.
pub fn connect_in(jail: JailId, addresses: &[SocketAddress]) -> io::Result<OwnedFd> {
  // SAFETY: the closure makes only async-signal-safe system calls on data it
  // borrows, and allocates nothing.
  let connected = unsafe {
    in_jail(jail, || {
      let mut error = libc::EADDRNOTAVAIL;
      for address in addresses {
        let socket = libc::socket(address.family(), libc::SOCK_STREAM, 0);
        if socket == -1 {
          return Err(errno());
        }
        if libc::connect(socket, address.as_ptr(), address.length) == 0 {
          return Ok(Some(socket));
        }
        error = errno();
        libc::close(socket);
      }
      Err(error)
    })
  };
  connected?.ok_or_else(|| io::Error::other("the child sent no socket"))
}

/// Creates a Unix socket listening at `path` from a child process attached
/// to `jail`, so the path is the jail's. Any socket already at `path` is
/// replaced. If `mode` is given, the socket file gets those permissions.
// mode_t is u16 on FreeBSD and macOS, but u32 on Linux.
#[allow(clippy::unnecessary_cast)]
pub fn listen_in(jail: JailId, path: impl AsRef<Path>, mode: Option<u16>) -> io::Result<OwnedFd> {
  let address = SocketAddress::unix(&path)?;
  let path = c_string(path.as_ref())?;
  // bind(2) creates the socket file as 0777 & ~umask.
  let mask = mode.map(|mode| !mode & 0o777);

  // SAFETY: as in `connect_in`.
  let listening = unsafe {
    in_jail(jail, || {
      unlink_socket(&path)?;
      if let Some(mask) = mask {
        libc::umask(mask as libc::mode_t);
      }
      let socket = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
      if socket == -1
        || libc::bind(socket, address.as_ptr(), address.length) == -1
        || libc::listen(socket, libc::SOMAXCONN) == -1
      {
        return Err(errno());
      }
      Ok(Some(socket))
    })
  };
  listening?.ok_or_else(|| io::Error::other("the child sent no socket"))
}

/// Removes the socket at `path`, if there is one, from a child process
/// attached to `jail`.
pub fn remove_socket_in(jail: JailId, path: impl AsRef<Path>) -> io::Result<()> {
  let path = c_string(path.as_ref())?;

  // SAFETY: as in `connect_in`.
  unsafe { in_jail(jail, || unlink_socket(&path).map(|()| None)) }?;
  Ok(())
}

/// What `wait_for_connection` found ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ready {
  Connection,
  /// The stop descriptor, even if a connection is pending too.
  Stop,
}

/// Waits until `listener` has a connection or `stop` is ready.
pub fn wait_for_connection(listener: BorrowedFd, stop: BorrowedFd) -> io::Result<Ready> {
  let mut descriptors = [listener, stop].map(|fd| libc::pollfd {
    fd: fd.as_raw_fd(),
    events: libc::POLLIN,
    revents: 0,
  });

  // SAFETY: poll writes only the revents of the descriptors it is given.
  retry(|| unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as libc::nfds_t, -1) })?;
  Ok(if descriptors[1].revents == 0 {
    Ready::Connection
  } else {
    Ready::Stop
  })
}

/// Unlinks `path` if it is a socket. Allocates nothing, so a forked child
/// may call it.
fn unlink_socket(path: &CStr) -> Result<(), libc::c_int> {
  let mut status = MaybeUninit::<libc::stat>::uninit();

  // SAFETY: lstat fills the stat when it succeeds, and the stat is read only
  // after that.
  unsafe {
    if libc::lstat(path.as_ptr(), status.as_mut_ptr()) == -1 {
      return match errno() {
        libc::ENOENT => Ok(()),
        error => Err(error),
      };
    }
    if status.assume_init().st_mode & libc::S_IFMT == libc::S_IFSOCK && libc::unlink(path.as_ptr()) == -1 {
      return Err(errno());
    }
  }
  Ok(())
}

/// Runs `act` in a child process attached to `jail` and receives the
/// descriptor `act` returns, if it returns one. If `act` fails, the child
/// exits with the errno as its status.
///
/// A child that sends a descriptor waits until the parent has received it
/// before exiting. Otherwise the kernel may garbage-collect a descriptor
/// still in flight when its sender closes, flushing the socket and leaving
/// it unreadable.
///
/// # Safety
///
/// The child is a fork of a multithreaded process, so `act` must make only
/// async-signal-safe calls and allocate nothing.
pub(crate) unsafe fn in_jail(
  jail: JailId,
  act: impl FnOnce() -> Result<Option<libc::c_int>, libc::c_int>,
) -> io::Result<Option<OwnedFd>> {
  let (ours, theirs) = UnixStream::pair()?;

  // SAFETY: the child only attaches, runs `act`, sends the result and exits,
  // which the caller's guarantee about `act` makes safe after fork.
  let pid = check(unsafe { libc::fork() })?;
  if pid == 0 {
    let done = attach(jail)
      .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
      .and_then(|()| act())
      .and_then(|fd| {
        let Some(fd) = fd else {
          return Ok(());
        };
        send_fd(theirs.as_raw_fd(), fd)?;
        // Wait for the parent to receive the descriptor and close its end.
        // The child inherited a copy of that end, so it closes it first.
        let mut byte = 0u8;
        // SAFETY: the child never uses its copy of `ours` again, and read
        // writes at most the one byte.
        unsafe {
          libc::close(ours.as_raw_fd());
          libc::read(theirs.as_raw_fd(), (&raw mut byte).cast(), 1);
        }
        Ok(())
      });
    // SAFETY: _exit ends the child at once, without running the parent's
    // exit handlers or destructors.
    unsafe { libc::_exit(done.err().unwrap_or(0)) }
  }
  drop(theirs);

  let received = receive_fd(&ours);
  drop(ours);
  let status = reap(pid)?;
  if !libc::WIFEXITED(status) {
    return Err(io::Error::other(format!(
      "the child died of signal {}",
      libc::WTERMSIG(status)
    )));
  }
  match libc::WEXITSTATUS(status) {
    0 => received,
    errno => Err(io::Error::from_raw_os_error(errno)),
  }
}

/// The size of a control message carrying one descriptor.
// SAFETY: CMSG_SPACE only computes.
const SPACE: libc::c_uint = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as libc::c_uint) };

/// Room for a control message carrying a descriptor, aligned for its header.
#[repr(C, align(8))]
struct Control([u8; SPACE as usize]);

/// A message carrying the one byte `part` points to, with `control` as its
/// control buffer.
fn message(part: &mut libc::iovec, control: &mut Control) -> libc::msghdr {
  // SAFETY: all zeros is a valid empty message; its buffers are set below.
  let mut message: libc::msghdr = unsafe { mem::zeroed() };
  message.msg_iov = part;
  message.msg_iovlen = 1;
  message.msg_control = (control as *mut Control).cast();
  message.msg_controllen = SPACE as _;
  message
}

/// Sends `fd` over `socket`. Allocates nothing, so a forked child may call
/// it.
fn send_fd(socket: libc::c_int, fd: libc::c_int) -> Result<(), libc::c_int> {
  let mut byte = 0u8;
  let mut part = libc::iovec {
    iov_base: (&raw mut byte).cast(),
    iov_len: 1,
  };
  let mut control = Control([0; SPACE as usize]);
  let message = message(&mut part, &mut control);

  // SAFETY: the control buffer has room for the header and the descriptor,
  // as SPACE measured, and outlives sendmsg, as do the byte and its iovec.
  unsafe {
    let header = libc::CMSG_FIRSTHDR(&message);
    (*header).cmsg_level = libc::SOL_SOCKET;
    (*header).cmsg_type = libc::SCM_RIGHTS;
    (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as libc::c_uint) as _;
    ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), fd);
    if libc::sendmsg(socket, &message, 0) == -1 {
      return Err(errno());
    }
  }
  Ok(())
}

/// Receives the descriptor a child sent over `socket`, or `None` if the
/// child exited without sending one.
fn receive_fd(socket: &UnixStream) -> io::Result<Option<OwnedFd>> {
  let mut byte = 0u8;
  let mut part = libc::iovec {
    iov_base: (&raw mut byte).cast(),
    iov_len: 1,
  };
  let mut control = Control([0; SPACE as usize]);
  let mut message = message(&mut part, &mut control);

  // SAFETY: recvmsg writes no more than the byte and the control buffer
  // hold.
  match unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) } {
    -1 => return Err(io::Error::last_os_error()),
    0 => return Ok(None),
    _ => {}
  }
  // SAFETY: CMSG_FIRSTHDR returns the header recvmsg wrote in the control
  // buffer, or null. An SCM_RIGHTS header is followed by a descriptor, which
  // this process now owns.
  let fd = unsafe {
    let header = libc::CMSG_FIRSTHDR(&message);
    if header.is_null() || (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS {
      return Err(io::Error::other("the child sent no descriptor"));
    }
    OwnedFd::from_raw_fd(ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>()))
  };

  close_on_exec(fd.as_fd())?;
  Ok(Some(fd))
}
