//! Network interfaces and routes: creating, naming, addressing, bridging,
//! and bringing up interfaces with ioctl(2), moving them into VNET jails,
//! addressing them from inside one, the default route through the routing
//! socket, kernel modules, and pf.

use std::io;
use std::net::Ipv4Addr;

/// What `address_in` sets up in a VNET jail's network stack, besides lo0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addressing<'a> {
  /// A device in the jail, and the address and prefix length to give it.
  pub device: Option<(&'a str, Ipv4Addr, u8)>,
  /// The default route's gateway.
  pub gateway: Option<Ipv4Addr>,
}

/// Whether the guest has an interface named `name`.
pub fn interface_exists(name: &str) -> io::Result<bool> {
  let name = crate::c_string(name)?;

  // SAFETY: if_nametoindex only reads the name, which outlives the call.
  Ok(unsafe { libc::if_nametoindex(name.as_ptr()) } != 0)
}

pub use imp::{
  add_address, address_in, bridge_add, bring_down, bring_up, create_interface, default_route, destroy_interface,
  load_module, move_to_vnet, rename_interface, start_pf,
};

#[cfg(target_os = "freebsd")]
mod imp {
  use super::Addressing;
  use crate::jail::{JailId, attach};
  use crate::process::reap_errno;
  use crate::{c_string, check, errno};
  use libc::{c_char, c_int, c_ulong};
  use std::fs::OpenOptions;
  use std::io;
  use std::mem;
  use std::net::Ipv4Addr;
  use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

  // ioctl requests, from <sys/sockio.h> for a 32-byte ifreq, a 68-byte
  // ifaliasreq, and a 40-byte ifdrv.
  const SIOCSIFFLAGS: c_ulong = 0x8020_6910;
  const SIOCGIFFLAGS: c_ulong = 0xc020_6911;
  const SIOCGIFADDR: c_ulong = 0xc020_6921;
  const SIOCSIFNAME: c_ulong = 0x8020_6928;
  const SIOCAIFADDR: c_ulong = 0x8044_692b;
  const SIOCSIFVNET: c_ulong = 0xc020_695a;
  const SIOCIFDESTROY: c_ulong = 0x8020_6979;
  const SIOCSDRVSPEC: c_ulong = 0x8028_697b;
  const SIOCIFCREATE2: c_ulong = 0xc020_697c;
  /// `_IO('D', 1)`, from <net/pfvar.h>.
  const DIOCSTART: c_ulong = 0x2000_4401;
  /// The bridge's driver command that adds a member, from
  /// <net/if_bridgevar.h>.
  const BRDGADD: c_ulong = 0;
  /// The `rtm_seq` of this process's routing messages.
  const SEQUENCE: c_int = 1;

  unsafe extern "C" {
    fn kldload(file: *const c_char) -> c_int;
  }

  /// <netinet/in_var.h>'s `struct in_aliasreq`.
  #[repr(C)]
  struct AliasRequest {
    name: [c_char; libc::IFNAMSIZ],
    address: libc::sockaddr_in,
    broadcast: libc::sockaddr_in,
    mask: libc::sockaddr_in,
    vhid: c_int,
  }

  /// <net/if_bridgevar.h>'s `struct ifbreq`: the member's name, then fields
  /// that adding a member leaves zero.
  #[repr(C, align(4))]
  struct BridgeMember {
    name: [c_char; libc::IFNAMSIZ],
    rest: [u8; 64],
  }

  /// <net/if.h>'s `struct ifdrv`.
  #[repr(C)]
  struct DriverRequest {
    name: [c_char; libc::IFNAMSIZ],
    command: c_ulong,
    length: libc::size_t,
    data: *mut libc::c_void,
  }

  /// <net/route.h>'s `struct rt_msghdr`, with `struct rt_metrics` as its
  /// fourteen longs.
  #[repr(C)]
  #[derive(Clone, Copy)]
  struct RouteHeader {
    length: u16,
    version: u8,
    kind: u8,
    index: u16,
    spare: u16,
    flags: c_int,
    addresses: c_int,
    pid: libc::pid_t,
    sequence: c_int,
    errno: c_int,
    fmask: c_int,
    inits: c_ulong,
    metrics: [c_ulong; 14],
  }

  /// A routing message about the default route: the destination, then the
  /// gateway if there is one, then the netmask, all 0.0.0.0 but the gateway.
  #[repr(C)]
  #[derive(Clone, Copy)]
  struct RouteMessage {
    header: RouteHeader,
    addresses: [libc::sockaddr_in; 3],
  }

  // The kernel checks these sizes, so a wrong layout fails the build rather
  // than an ioctl.
  const _: () = assert!(size_of::<libc::ifreq>() == 32);
  const _: () = assert!(size_of::<AliasRequest>() == 68);
  const _: () = assert!(size_of::<BridgeMember>() == 80);
  const _: () = assert!(size_of::<DriverRequest>() == 40);
  const _: () = assert!(size_of::<RouteHeader>() == 152);

  /// Moves the interface `name` into the VNET jail `jail`.
  pub fn move_to_vnet(name: &str, jail: JailId) -> io::Result<()> {
    let mut request = request(name)?;
    request.ifr_ifru.ifru_jid = jail.0;

    // SAFETY: SIOCSIFVNET takes an ifreq.
    unsafe { on_socket(SIOCSIFVNET, &mut request) }
  }

  /// Creates an interface of `kind`, such as `bridge` or `epair`, and returns
  /// its name, such as `bridge0` or, for an epair, its `a` end's `epair3a`.
  pub fn create_interface(kind: &str) -> io::Result<String> {
    let mut request = request(kind)?;

    // SAFETY: SIOCIFCREATE2 takes an ifreq, and writes the new name in it.
    unsafe { on_socket(SIOCIFCREATE2, &mut request) }?;
    Ok(name(&request.ifr_name))
  }

  /// Destroys the interface `name`, and for an epair, both its ends.
  pub fn destroy_interface(name: &str) -> io::Result<()> {
    let mut request = request(name)?;

    // SAFETY: SIOCIFDESTROY takes an ifreq.
    unsafe { on_socket(SIOCIFDESTROY, &mut request) }
  }

  /// Renames the interface `name` to `to`.
  pub fn rename_interface(name: &str, to: &str) -> io::Result<()> {
    let mut new = [0; libc::IFNAMSIZ];
    copy_name(&mut new, to)?;
    let mut request = request(name)?;
    request.ifr_ifru.ifru_data = new.as_mut_ptr();

    // SAFETY: SIOCSIFNAME takes an ifreq whose data points at the new name,
    // which outlives the call.
    unsafe { on_socket(SIOCSIFNAME, &mut request) }
  }

  /// Gives the interface `name` the IPv4 address `address`, with a prefix
  /// of `prefix` bits.
  pub fn add_address(name: &str, address: Ipv4Addr, prefix: u8) -> io::Result<()> {
    let mut alias = alias(name, address, prefix)?;

    // SAFETY: SIOCAIFADDR takes an in_aliasreq.
    unsafe { on_socket(SIOCAIFADDR, &mut alias) }
  }

  /// Brings the interface `name` up.
  pub fn bring_up(name: &str) -> io::Result<()> {
    let socket = socket()?;
    change_flags(socket.as_raw_fd(), request(name)?, up).map_err(io::Error::from_raw_os_error)
  }

  /// Takes the interface `name` down.
  pub fn bring_down(name: &str) -> io::Result<()> {
    let socket = socket()?;
    change_flags(socket.as_raw_fd(), request(name)?, |flags| {
      *flags &= !(libc::IFF_UP as libc::c_short);
    })
    .map_err(io::Error::from_raw_os_error)
  }

  /// Adds the interface `member` to the bridge `bridge`.
  pub fn bridge_add(bridge: &str, member: &str) -> io::Result<()> {
    let mut add = BridgeMember {
      name: [0; libc::IFNAMSIZ],
      rest: [0; 64],
    };
    copy_name(&mut add.name, member)?;
    let mut request = DriverRequest {
      name: [0; libc::IFNAMSIZ],
      command: BRDGADD,
      length: size_of::<BridgeMember>(),
      data: (&raw mut add).cast(),
    };
    copy_name(&mut request.name, bridge)?;

    // SAFETY: SIOCSDRVSPEC takes an ifdrv, whose data points at the ifbreq
    // that BRDGADD takes, which outlives the call.
    unsafe { on_socket(SIOCSDRVSPEC, &mut request) }
  }

  /// Sets up a VNET jail's network stack from a child process attached to
  /// it: brings up lo0 at 127.0.0.1, unless it has the address already, then
  /// gives a device its address and adds the default route, as `addressing`
  /// asks. The child gets every request built before the fork.
  pub fn address_in(jail: JailId, addressing: &Addressing) -> io::Result<()> {
    let loopback = (request("lo0")?, alias("lo0", Ipv4Addr::LOCALHOST, 8)?);
    let device = match addressing.device {
      Some((name, address, prefix)) => Some((request(name)?, alias(name, address, prefix)?)),
      None => None,
    };
    let route = addressing.gateway.map(|gateway| {
      let any = inet(Ipv4Addr::UNSPECIFIED);
      message(
        libc::RTM_ADD,
        libc::RTF_UP | libc::RTF_GATEWAY | libc::RTF_STATIC,
        [any, inet(gateway), any],
        libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK,
      )
    });

    // SAFETY: the child only attaches, makes ioctls and a write on the
    // requests built above, and exits. Those calls are async-signal-safe and
    // allocate nothing, so they are safe after fork.
    let pid = check(unsafe { libc::fork() })?;
    if pid == 0 {
      let done = attach(jail)
        .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
        .and_then(|()| set_up(loopback, device, route));
      // SAFETY: _exit ends the child at once, without running the parent's
      // exit handlers or destructors.
      unsafe { libc::_exit(done.err().unwrap_or(0)) }
    }
    reap_errno(pid)
  }

  /// The steps of `address_in`, in its child. Allocates nothing.
  fn set_up(
    (loopback, mut loopback_alias): (libc::ifreq, AliasRequest),
    device: Option<(libc::ifreq, AliasRequest)>,
    route: Option<RouteMessage>,
  ) -> Result<(), c_int> {
    // SAFETY: socket returns a new descriptor, which the child closes as it
    // exits.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd == -1 {
      return Err(errno());
    }
    let mut probe = loopback;
    // SAFETY: SIOCGIFADDR takes an ifreq, and SIOCAIFADDR an in_aliasreq.
    // The address read back is a sockaddr_in, which fits in the ifreq.
    unsafe {
      let has_loopback = ioctl(fd, SIOCGIFADDR, &mut probe).is_ok()
        && std::ptr::read_unaligned((&raw const probe.ifr_ifru.ifru_addr).cast::<libc::sockaddr_in>())
          .sin_addr
          .s_addr
          == u32::from(Ipv4Addr::LOCALHOST).to_be();
      if !has_loopback {
        ioctl(fd, SIOCAIFADDR, &mut loopback_alias)?;
      }
    }
    change_flags(fd, loopback, up)?;
    if let Some((request, mut alias)) = device {
      // SAFETY: SIOCAIFADDR takes an in_aliasreq.
      unsafe { ioctl(fd, SIOCAIFADDR, &mut alias) }?;
      change_flags(fd, request, up)?;
    }
    if let Some(message) = route {
      // SAFETY: socket returns a new descriptor, which the child closes as it
      // exits, and write reads no more than the message holds.
      unsafe {
        let routes = libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_INET);
        if routes == -1 || libc::write(routes, (&raw const message).cast(), usize::from(message.header.length)) == -1 {
          return Err(errno());
        }
      }
    }
    Ok(())
  }

  /// The index of the default route's interface, or `None` if the guest has
  /// no default route.
  pub fn default_route() -> io::Result<Option<u16>> {
    // SAFETY: socket returns a new descriptor, which the OwnedFd then owns.
    let socket = unsafe {
      OwnedFd::from_raw_fd(check(libc::socket(
        libc::PF_ROUTE,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
        libc::AF_INET,
      ))?)
    };
    let fd = socket.as_raw_fd();
    // Give up on a reply after a second, rather than hang.
    let timeout = libc::timeval { tv_sec: 1, tv_usec: 0 };
    // SAFETY: setsockopt reads only the timeval.
    check(unsafe {
      libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_RCVTIMEO,
        (&raw const timeout).cast(),
        size_of::<libc::timeval>() as libc::socklen_t,
      )
    })?;
    let any = inet(Ipv4Addr::UNSPECIFIED);
    // SAFETY: all zeros is a valid sockaddr_in, which this message leaves
    // unsent.
    let unused = unsafe { mem::zeroed() };
    let question = message(libc::RTM_GET, 0, [any, any, unused], libc::RTA_DST | libc::RTA_NETMASK);

    // SAFETY: write reads no more than the message holds.
    if unsafe { libc::write(fd, (&raw const question).cast(), usize::from(question.header.length)) } == -1 {
      let error = io::Error::last_os_error();
      return match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(None),
        _ => Err(error),
      };
    }
    // Every routing socket hears every routing message, so look for the one
    // that answers this process.
    let pid = std::process::id() as libc::pid_t;
    let mut reply = [0u8; 2048];
    loop {
      // SAFETY: read writes no more than the reply holds.
      let read = unsafe { libc::read(fd, reply.as_mut_ptr().cast(), reply.len()) };
      if read == -1 {
        return Err(io::Error::last_os_error());
      }
      if (read as usize) < size_of::<RouteHeader>() {
        continue;
      }
      // SAFETY: the reply holds a whole header, and read_unaligned copes
      // with any alignment.
      let header = unsafe { std::ptr::read_unaligned(reply.as_ptr().cast::<RouteHeader>()) };
      if i32::from(header.kind) == libc::RTM_GET && header.pid == pid && header.sequence == SEQUENCE {
        return Ok((header.errno == 0).then_some(header.index));
      }
    }
  }

  /// Loads the kernel module `name`, unless it is loaded already.
  pub fn load_module(name: &str) -> io::Result<()> {
    let name = c_string(name)?;

    // SAFETY: kldload only reads the name, which outlives the call.
    match check(unsafe { kldload(name.as_ptr()) }) {
      Err(error) if error.raw_os_error() != Some(libc::EEXIST) => Err(error),
      _ => Ok(()),
    }
  }

  /// Enables pf, unless it is enabled already.
  pub fn start_pf() -> io::Result<()> {
    let pf = OpenOptions::new().read(true).write(true).open("/dev/pf")?;

    // SAFETY: DIOCSTART takes no argument, and the file keeps the descriptor
    // open.
    match check(unsafe { libc::ioctl(pf.as_raw_fd(), DIOCSTART) }) {
      Err(error) if error.raw_os_error() != Some(libc::EEXIST) => Err(error),
      _ => Ok(()),
    }
  }

  /// Makes the ioctl `request` with `argument` on a socket of its own.
  ///
  /// # Safety
  ///
  /// `request` must take a `T`.
  unsafe fn on_socket<T>(request: c_ulong, argument: &mut T) -> io::Result<()> {
    let socket = socket()?;

    // SAFETY: the caller's guarantee.
    unsafe { ioctl(socket.as_raw_fd(), request, argument) }.map_err(io::Error::from_raw_os_error)
  }

  /// Makes the ioctl `request` on `fd` with `argument`. Allocates nothing, so
  /// a forked child may call it.
  ///
  /// # Safety
  ///
  /// `request` must take a `T`.
  unsafe fn ioctl<T>(fd: c_int, request: c_ulong, argument: &mut T) -> Result<(), c_int> {
    // SAFETY: the request reads and writes no more than the `T` it takes.
    match unsafe { libc::ioctl(fd, request, argument as *mut T) } {
      -1 => Err(errno()),
      _ => Ok(()),
    }
  }

  /// Reads the flags of the interface `request` names, has `change` change
  /// their low half, and sets them. Allocates nothing.
  fn change_flags(fd: c_int, mut request: libc::ifreq, change: impl FnOnce(&mut libc::c_short)) -> Result<(), c_int> {
    // SAFETY: SIOCGIFFLAGS and SIOCSIFFLAGS take an ifreq, and the first
    // fills in the flags that the second sets.
    unsafe {
      ioctl(fd, SIOCGIFFLAGS, &mut request)?;
      change(&mut request.ifr_ifru.ifru_flags[0]);
      ioctl(fd, SIOCSIFFLAGS, &mut request)
    }
  }

  /// Sets IFF_UP.
  fn up(flags: &mut libc::c_short) {
    *flags |= libc::IFF_UP as libc::c_short;
  }

  /// A datagram socket for interface ioctls.
  fn socket() -> io::Result<OwnedFd> {
    // SAFETY: socket returns a new descriptor, which the OwnedFd then owns.
    unsafe {
      let fd = check(libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0))?;
      Ok(OwnedFd::from_raw_fd(fd))
    }
  }

  /// An ifreq naming the interface `name`, with the rest zeroed.
  fn request(name: &str) -> io::Result<libc::ifreq> {
    // SAFETY: all zeros is a valid ifreq.
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    copy_name(&mut request.ifr_name, name)?;
    Ok(request)
  }

  /// An in_aliasreq giving `name` the address `address` with a prefix of
  /// `prefix` bits. The broadcast address is left zero for the kernel to
  /// work out.
  fn alias(name: &str, address: Ipv4Addr, prefix: u8) -> io::Result<AliasRequest> {
    if prefix > 32 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("/{prefix} is longer than an IPv4 address"),
      ));
    }
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    // SAFETY: all zeros is a valid in_aliasreq.
    let mut alias: AliasRequest = unsafe { mem::zeroed() };
    copy_name(&mut alias.name, name)?;
    alias.address = inet(address);
    alias.mask = inet(Ipv4Addr::from(mask));
    Ok(alias)
  }

  /// The sockaddr_in of `address`, with no port.
  fn inet(address: Ipv4Addr) -> libc::sockaddr_in {
    // SAFETY: all zeros is a valid sockaddr_in.
    let mut inet: libc::sockaddr_in = unsafe { mem::zeroed() };
    inet.sin_len = size_of::<libc::sockaddr_in>() as u8;
    inet.sin_family = libc::AF_INET as libc::sa_family_t;
    inet.sin_addr.s_addr = u32::from(address).to_be();
    inet
  }

  /// A routing message of `kind` with `flags`, carrying the first of
  /// `addresses` that the bits of `present` count.
  fn message(kind: c_int, flags: c_int, addresses: [libc::sockaddr_in; 3], present: c_int) -> RouteMessage {
    let count = present.count_ones() as usize;
    // SAFETY: all zeros is a valid header; the fields that matter are set
    // below.
    let mut header: RouteHeader = unsafe { mem::zeroed() };
    header.length = (size_of::<RouteHeader>() + count * size_of::<libc::sockaddr_in>()) as u16;
    header.version = libc::RTM_VERSION as u8;
    header.kind = kind as u8;
    header.flags = flags;
    header.addresses = present;
    header.sequence = SEQUENCE;
    RouteMessage { header, addresses }
  }

  /// Copies `name` into an interface name field, leaving room for its NUL.
  fn copy_name(field: &mut [c_char; libc::IFNAMSIZ], name: &str) -> io::Result<()> {
    if name.len() >= field.len() || name.contains('\0') {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{name:?} can't name an interface"),
      ));
    }
    for (to, &from) in field.iter_mut().zip(name.as_bytes()) {
      *to = from as c_char;
    }
    Ok(())
  }

  /// The name in an interface name field.
  fn name(field: &[c_char; libc::IFNAMSIZ]) -> String {
    let bytes: Vec<u8> = field
      .iter()
      .take_while(|&&char| char != 0)
      .map(|&char| char as u8)
      .collect();
    String::from_utf8_lossy(&bytes).into_owned()
  }
}

#[cfg(not(target_os = "freebsd"))]
mod imp {
  use super::Addressing;
  use crate::jail::JailId;
  use crate::unsupported;
  use std::io;
  use std::net::Ipv4Addr;

  pub fn move_to_vnet(name: &str, _: JailId) -> io::Result<()> {
    unsupported(format_args!("moving {name} into a jail"))
  }

  pub fn create_interface(kind: &str) -> io::Result<String> {
    unsupported(format_args!("creating a {kind}"))
  }

  pub fn destroy_interface(name: &str) -> io::Result<()> {
    unsupported(format_args!("destroying {name}"))
  }

  pub fn rename_interface(name: &str, _: &str) -> io::Result<()> {
    unsupported(format_args!("renaming {name}"))
  }

  pub fn add_address(name: &str, _: Ipv4Addr, _: u8) -> io::Result<()> {
    unsupported(format_args!("addressing {name}"))
  }

  pub fn bring_up(name: &str) -> io::Result<()> {
    unsupported(format_args!("bringing {name} up"))
  }

  pub fn bring_down(name: &str) -> io::Result<()> {
    unsupported(format_args!("taking {name} down"))
  }

  pub fn bridge_add(bridge: &str, _: &str) -> io::Result<()> {
    unsupported(format_args!("adding to {bridge}"))
  }

  pub fn address_in(_: JailId, _: &Addressing) -> io::Result<()> {
    unsupported("addressing a jail")
  }

  pub fn default_route() -> io::Result<Option<u16>> {
    unsupported("finding the default route")
  }

  pub fn load_module(name: &str) -> io::Result<()> {
    unsupported(format_args!("loading {name}"))
  }

  pub fn start_pf() -> io::Result<()> {
    unsupported("enabling pf")
  }
}
