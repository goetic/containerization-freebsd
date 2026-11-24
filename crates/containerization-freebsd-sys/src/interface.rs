//! The counters of a jail's network interfaces, read from inside the jail,
//! since a VNET jail's interfaces are in its own network stack.

use crate::jail::JailId;
use std::io;

/// An interface's counters since it was created.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interface {
  pub name: String,
  pub received_packets: u64,
  pub transmitted_packets: u64,
  pub received_bytes: u64,
  pub transmitted_bytes: u64,
  pub received_errors: u64,
  pub transmitted_errors: u64,
  pub received_dropped: u64,
  pub transmitted_dropped: u64,
}

/// The interfaces in `jail`'s network stack, as `NET_RT_IFLIST` lists them
/// to a child process attached to the jail. The child writes the list into
/// a buffer allocated before the fork, and passes it back over a socket.
#[cfg(target_os = "freebsd")]
pub fn interfaces_in(jail: JailId) -> io::Result<Vec<Interface>> {
  use crate::jail::attach;
  use crate::process::reap_errno;
  use crate::{check, errno};
  use std::io::Read;
  use std::os::fd::AsRawFd;
  use std::os::unix::net::UnixStream;

  /// Writes all of `bytes` to `fd`. Allocates nothing, so a forked child may
  /// call it.
  fn write_all(fd: libc::c_int, mut bytes: &[u8]) -> Result<(), libc::c_int> {
    while !bytes.is_empty() {
      // SAFETY: write reads no more than `bytes` holds.
      match unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) } {
        -1 if errno() == libc::EINTR => {}
        -1 => return Err(errno()),
        written => bytes = &bytes[written as usize..],
      }
    }
    Ok(())
  }

  // Room for the messages of a few hundred interfaces.
  let mut buffer = vec![0u8; 64 << 10];
  let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, libc::AF_LINK, libc::NET_RT_IFLIST, 0];
  let (ours, theirs) = UnixStream::pair()?;

  // SAFETY: the child only attaches, reads the sysctl into the buffer, writes
  // it to the socket, and exits. Those calls are async-signal-safe and
  // allocate nothing, so they are safe after fork.
  let pid = check(unsafe { libc::fork() })?;
  if pid == 0 {
    let done = attach(jail)
      .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
      .and_then(|()| {
        let mut length = buffer.len();
        // SAFETY: sysctl writes no more than `length` bytes to the buffer,
        // which holds that many, and sets `length` to how many it wrote.
        let read = unsafe {
          libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null(),
            0,
          )
        };
        if read == -1 {
          return Err(errno());
        }
        write_all(theirs.as_raw_fd(), &buffer[..length])
      });
    // SAFETY: _exit ends the child at once, without running the parent's
    // exit handlers or destructors.
    unsafe { libc::_exit(done.err().unwrap_or(0)) }
  }
  drop(theirs);

  let mut messages = Vec::new();
  let read = (&ours).read_to_end(&mut messages);
  reap_errno(pid)?;
  read?;
  Ok(parse(&messages))
}

#[cfg(not(target_os = "freebsd"))]
pub fn interfaces_in(_: JailId) -> io::Result<Vec<Interface>> {
  crate::unsupported("listing a jail's interfaces")
}

/// The interfaces in routing messages: each RTM_IFINFO's counters, and the
/// name in the link address that follows its header.
#[cfg(target_os = "freebsd")]
fn parse(messages: &[u8]) -> Vec<Interface> {
  use std::mem::offset_of;

  const HEADER: usize = size_of::<libc::if_msghdr>();
  let mut interfaces = Vec::new();
  let mut rest = messages;

  while let [low, high, _, kind, ..] = *rest {
    let length = usize::from(u16::from_ne_bytes([low, high]));
    if length < 4 || length > rest.len() {
      break;
    }
    let (message, after) = rest.split_at(length);
    rest = after;
    if i32::from(kind) != libc::RTM_IFINFO || message.len() < HEADER {
      continue;
    }
    // SAFETY: the message is an if_msghdr, as its type says and its length
    // allows, and read_unaligned copes with any alignment.
    let header = unsafe { std::ptr::read_unaligned(message.as_ptr().cast::<libc::if_msghdr>()) };
    let link = &message[HEADER..];
    let start = offset_of!(libc::sockaddr_dl, sdl_data);
    let name = match link.get(offset_of!(libc::sockaddr_dl, sdl_nlen)) {
      Some(&length) if header.ifm_addrs & libc::RTA_IFP != 0 => link.get(start..start + usize::from(length)),
      _ => None,
    };
    let Some(name) = name else {
      continue;
    };
    let data = header.ifm_data;

    interfaces.push(Interface {
      name: String::from_utf8_lossy(name).into_owned(),
      received_packets: data.ifi_ipackets,
      transmitted_packets: data.ifi_opackets,
      received_bytes: data.ifi_ibytes,
      transmitted_bytes: data.ifi_obytes,
      received_errors: data.ifi_ierrors,
      transmitted_errors: data.ifi_oerrors,
      received_dropped: data.ifi_iqdrops,
      transmitted_dropped: data.ifi_oqdrops,
    });
  }
  interfaces
}
