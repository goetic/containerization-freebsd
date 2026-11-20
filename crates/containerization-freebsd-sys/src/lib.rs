//! The calls containerization-freebsd's guest agent makes that std has no
//! safe API for: pseudo-terminals, raw mode, signals, waiting for an exit
//! without reaping it, the clock, jails, what a process takes on before it
//! starts, and sockets opened from inside a jail. The agent's only unsafe
//! code.
//!
//! The descriptors it opens close on exec, but are inheritable for a moment
//! first: spawn processes from one thread only, as the agent's session loop
//! does, or a process spawned meanwhile holds them.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, PipeReader, Read};
use std::mem::{self, MaybeUninit};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;

fn check(result: libc::c_int) -> io::Result<libc::c_int> {
  if result == -1 {
    Err(io::Error::last_os_error())
  } else {
    Ok(result)
  }
}

/// A terminal's size, in characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowSize {
  pub rows: u16,
  pub columns: u16,
}

/// A resource limit: setrlimit(2)'s resource number, and its soft and hard
/// values, any past `RLIM_INFINITY` being none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
  pub resource: i32,
  pub soft: u64,
  pub hard: u64,
}

/// The user and groups a process takes on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ids {
  pub uid: u32,
  pub gid: u32,
  /// Supplementary groups.
  pub groups: Vec<u32>,
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

/// A pseudo-terminal of `size`: the end the caller reads and writes, and the
/// end a process takes as its terminal.
pub fn open_terminal(size: WindowSize) -> io::Result<(File, OwnedFd)> {
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
  // them, and the terminal would not end until those exit too.
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

/// The running jail named `name`: its id, and its root's path in the guest.
#[cfg(target_os = "freebsd")]
pub fn find_jail(name: &str) -> io::Result<(libc::c_int, PathBuf)> {
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
pub fn find_jail(name: &str) -> io::Result<(libc::c_int, PathBuf)> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    format!("jail {name:?}: jails are FreeBSD's"),
  ))
}

/// The id of the running jail named `name`, if a name is given.
pub fn jail_id(name: Option<&str>) -> io::Result<Option<libc::c_int>> {
  name
    .map(|name| find_jail(name).map(|(jid, _)| jid))
    .transpose()
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
pub struct Entry {
  pub jail: Option<libc::c_int>,
  pub limits: Vec<Limit>,
  pub umask: Option<u16>,
  pub ids: Option<Ids>,
  pub cwd: Option<CString>,
}

/// The part of an `Entry` a process failed to take on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
  Jail = 1,
  Limits,
  User,
  Directory,
}

/// Where a process taking on an `Entry` says which step failed: spawning it
/// fails with only an errno, the same whether a step or exec failed.
pub struct Entering(PipeReader);

impl Entering {
  /// The step the process failed at, once spawning it has failed; none if
  /// it took on all of its entry, and running its program failed.
  pub fn failed(&mut self) -> Option<Step> {
    let mut byte = 0u8;
    match self.0.read(std::slice::from_mut(&mut byte)) {
      Ok(1) => [Step::Jail, Step::Limits, Step::User, Step::Directory]
        .into_iter()
        .find(|step| *step as u8 == byte),
      _ => None,
    }
  }
}

/// Has the child report that it failed at `step` over `report`, allocating
/// nothing, and passes on its `error`.
fn failed_at(report: BorrowedFd, step: Step) -> impl Fn(io::Error) -> io::Error {
  move |error| {
    let byte = step as u8;
    // SAFETY: write reads the one byte. The pipe has room for it, and the
    // error is the child's either way.
    unsafe { libc::write(report.as_raw_fd(), (&raw const byte).cast(), 1) };
    error
  }
}

/// Has the command's process take on `entry` between fork and exec, in
/// this order: its jail, its limits and umask, its user, and its working
/// directory, which it reaches as that user, as std would.
// rlim_t is signed on FreeBSD, and mode_t is u16 on FreeBSD and macOS but
// u32 on Linux.
#[allow(clippy::unnecessary_cast)]
pub fn enter_on_exec(command: &mut Command, entry: Entry) -> io::Result<Entering> {
  let (reader, writer) = io::pipe()?;
  // Read once spawning has failed, while the command still holds the write
  // end: so as not to wait for it to close.
  // SAFETY: fcntl changes only the descriptor's flags.
  check(unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) })?;
  let rlim = |value: u64| value.min(libc::RLIM_INFINITY as u64) as libc::rlim_t;
  let limits: Vec<(libc::c_int, libc::rlimit)> = entry
    .limits
    .iter()
    .map(|limit| {
      let rlimit = libc::rlimit {
        rlim_cur: rlim(limit.soft),
        rlim_max: rlim(limit.hard),
      };
      (limit.resource, rlimit)
    })
    .collect();
  let umask = entry.umask.map(|umask| umask as libc::mode_t);
  let Entry { jail, ids, cwd, .. } = entry;

  // SAFETY: between fork and exec, the closure makes only system calls,
  // which are async-signal-safe, reading what it owns, and allocates
  // nothing.
  unsafe {
    command.pre_exec(move || {
      let report = writer.as_fd();
      if let Some(jid) = jail {
        attach(jid).map_err(failed_at(report, Step::Jail))?;
      }
      for (resource, limit) in &limits {
        check(libc::setrlimit(*resource as _, limit)).map_err(failed_at(report, Step::Limits))?;
      }
      if let Some(umask) = umask {
        libc::umask(umask);
      }
      if let Some(ids) = &ids {
        // Supplementary groups only, on FreeBSD 15 as elsewhere.
        check(libc::setgroups(ids.groups.len() as _, ids.groups.as_ptr()))
          .and_then(|_| check(libc::setgid(ids.gid)))
          .and_then(|_| check(libc::setuid(ids.uid)))
          .map_err(failed_at(report, Step::User))?;
      }
      if let Some(cwd) = &cwd {
        check(libc::chdir(cwd.as_ptr())).map_err(failed_at(report, Step::Directory))?;
      }
      Ok(())
    });
  }
  Ok(Entering(reader))
}

/// The guest's `/rescue` tool a process runs in place of its program, with
/// its arguments and environment ready for fexecve(2), which takes them
/// after fork, when nothing can be allocated.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
struct Rescue {
  tool: File,
  _strings: Vec<CString>,
  argv: Vec<*const libc::c_char>,
  envp: Vec<*const libc::c_char>,
}

// SAFETY: the pointers point into `_strings`, which the struct owns and
// never changes, so they stay valid wherever it goes.
unsafe impl Send for Rescue {}
// SAFETY: as for Send; nothing is written through the pointers.
unsafe impl Sync for Rescue {}

/// Has the command's process run the guest's `/rescue` tool named
/// `argv[0]`, with `argv`, once it has taken on all else: in its jail too,
/// whose root needn't hold the tool. The environment is the agent's, with
/// the command's on top.
pub fn rescue_on_exec(command: &mut Command, argv: &[String]) -> io::Result<()> {
  use std::collections::BTreeMap;
  use std::os::unix::ffi::OsStrExt;

  let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, what.to_string());
  let name = argv
    .first()
    .filter(|name| !name.is_empty() && !name.contains('/') && *name != "." && *name != "..")
    .ok_or_else(|| invalid("no rescue tool is named"))?;
  let tool = File::open(format!("/rescue/{name}"))
    .map_err(|error| io::Error::new(error.kind(), format!("/rescue/{name}: {error}")))?;

  let mut environment: BTreeMap<_, _> = std::env::vars_os().collect();
  for (name, value) in command.get_envs() {
    match value {
      Some(value) => environment.insert(name.to_owned(), value.to_owned()),
      None => environment.remove(name),
    };
  }
  let cstring = |bytes: Vec<u8>| CString::new(bytes).map_err(|_| invalid("an argument or variable has a NUL"));
  let args = argv
    .iter()
    .map(|arg| cstring(arg.clone().into_bytes()))
    .collect::<io::Result<Vec<_>>>()?;
  let variables = environment
    .iter()
    .map(|(name, value)| cstring([name.as_bytes(), b"=", value.as_bytes()].concat()))
    .collect::<io::Result<Vec<_>>>()?;
  let pointers = |strings: &[CString]| {
    let mut pointers: Vec<_> = strings.iter().map(|string| string.as_ptr()).collect();
    pointers.push(ptr::null());
    pointers
  };
  let rescue = Rescue {
    tool,
    argv: pointers(&args),
    envp: pointers(&variables),
    _strings: args.into_iter().chain(variables).collect(),
  };

  // SAFETY: between fork and exec, the closure calls only fexecve, which is
  // async-signal-safe, with what `rescue` owns, and allocates nothing.
  unsafe {
    command.pre_exec(move || Err(fexecve(&rescue)));
  }
  Ok(())
}

/// Returns only when it fails.
#[cfg(target_os = "freebsd")]
fn fexecve(rescue: &Rescue) -> io::Error {
  // SAFETY: the arrays end in nulls, and point at strings `rescue` owns.
  unsafe { libc::fexecve(rescue.tool.as_raw_fd(), rescue.argv.as_ptr(), rescue.envp.as_ptr()) };
  io::Error::last_os_error()
}

/// Never called: no other system has `/rescue`.
#[cfg(not(target_os = "freebsd"))]
fn fexecve(_: &Rescue) -> io::Error {
  io::ErrorKind::Unsupported.into()
}

/// Sets the clock to `seconds` and `nanoseconds` past the Unix epoch.
pub fn set_time(seconds: u64, nanoseconds: u32) -> io::Result<()> {
  let time = libc::timespec {
    tv_sec: seconds as libc::time_t,
    tv_nsec: libc::c_long::from(nanoseconds.min(999_999_999)),
  };

  // SAFETY: clock_settime reads a timespec, which outlives the call.
  check(unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &raw const time) })?;
  Ok(())
}

/// Sends `signal` to `target`: a pid, or a process group's id negated.
pub fn signal(target: libc::pid_t, signal: i32) -> io::Result<()> {
  // SAFETY: kill touches no memory.
  check(unsafe { libc::kill(target, signal) })?;
  Ok(())
}

/// Waits for `pid` to exit, leaving it for std to reap. Until then, its pid
/// cannot be another process's.
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

/// `path` as system calls take it.
pub fn path(path: &str) -> io::Result<CString> {
  CString::new(path).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{path:?} has a NUL")))
}

/// A socket's address, as the kernel takes it.
pub struct SocketAddress {
  storage: libc::sockaddr_storage,
  length: libc::socklen_t,
}

impl SocketAddress {
  /// Port `port` on 127.0.0.1, and on ::1.
  pub fn loopback(port: u16) -> [Self; 2] {
    // SAFETY: all zeros is an unspecified address of either family, given
    // its fields below.
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
  pub fn unix(path: &CStr) -> io::Result<Self> {
    // SAFETY: all zeros is an unnamed Unix socket's address, named below.
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.to_bytes();
    // The path keeps a NUL after it.
    let longest = address.sun_path.len() - 1;
    if bytes.len() > longest {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{path:?} is over the {longest} bytes a socket's path may have"),
      ));
    }
    for (to, &from) in address.sun_path.iter_mut().zip(bytes) {
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

/// Connects to the first of `addresses` that answers, from a child process
/// in jail `jid`, so paths and loopback are the jail's.
pub fn connect_in(jid: libc::c_int, addresses: &[SocketAddress]) -> io::Result<OwnedFd> {
  // SAFETY: the child makes only system calls, on what it was handed, and
  // allocates nothing.
  let connected = unsafe {
    in_jail(jid, || {
      let mut error = libc::EADDRNOTAVAIL;
      for address in addresses {
        let socket = libc::socket(address.family(), libc::SOCK_STREAM, 0);
        if socket == -1 {
          return Err(errno());
        }
        if libc::connect(socket, address.as_ptr(), address.length) == 0 {
          return Ok(socket);
        }
        error = errno();
        libc::close(socket);
      }
      Err(error)
    })
  };
  connected?.ok_or_else(|| io::Error::other("the child sent no socket"))
}

/// A Unix socket listening at `path`, made by a child process in jail `jid`,
/// so the path is the jail's. A socket already at `path` is replaced.
/// With `mode`, it is made with those permissions.
// mode_t is u16 on FreeBSD and macOS, but u32 on Linux.
#[allow(clippy::unnecessary_cast)]
pub fn listen_in(jid: libc::c_int, path: &CStr, mode: Option<u16>) -> io::Result<OwnedFd> {
  let address = SocketAddress::unix(path)?;
  let mask = mode.map(|mode| !mode & 0o777);

  // SAFETY: as in `connect_in`.
  let listening = unsafe {
    in_jail(jid, || {
      unlink_socket(path)?;
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
      Ok(socket)
    })
  };
  listening?.ok_or_else(|| io::Error::other("the child sent no socket"))
}

/// Removes the socket at `path`, if there is one, from a child process in
/// jail `jid`.
pub fn remove_socket_in(jid: libc::c_int, path: &CStr) -> io::Result<()> {
  // SAFETY: as in `connect_in`.
  unsafe { in_jail(jid, || unlink_socket(path).map(|()| -1)) }?;
  Ok(())
}

/// Unlinks `path` if it is a socket, allocating nothing, for a forked child.
fn unlink_socket(path: &CStr) -> Result<(), libc::c_int> {
  let mut status = MaybeUninit::<libc::stat>::uninit();

  // SAFETY: lstat fills the stat when it succeeds, and only then is it
  // read.
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

/// Runs `act` in a child process attached to jail `jid`, and takes the
/// descriptor `act` returns, unless that is -1. The child exits with the
/// errno `act` fails with.
///
/// A child that sends a descriptor exits only once it has been received:
/// one in flight when its sender closes can be taken for garbage, its
/// socket flushed and left unable to read.
///
/// # Safety
///
/// The child is a copy of a multithreaded process: `act` must make only
/// async-signal-safe calls, and allocate nothing.
unsafe fn in_jail(
  jid: libc::c_int,
  act: impl FnOnce() -> Result<libc::c_int, libc::c_int>,
) -> io::Result<Option<OwnedFd>> {
  let (ours, theirs) = UnixStream::pair()?;

  // SAFETY: the child attaches, acts and sends, then exits, as the caller
  // allows.
  let pid = check(unsafe { libc::fork() })?;
  if pid == 0 {
    let done = attach(jid)
      .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
      .and_then(|()| act())
      .and_then(|fd| {
        if fd == -1 {
          return Ok(());
        }
        send_fd(theirs.as_raw_fd(), fd)?;
        // Waits until the parent, having received it, closes its end: so
        // the child must close its own copy of that end first.
        let mut byte = 0u8;
        // SAFETY: the child never uses its copy of `ours` again, and read
        // writes at most the one byte.
        unsafe {
          libc::close(ours.as_raw_fd());
          libc::read(theirs.as_raw_fd(), (&raw mut byte).cast(), 1);
        }
        Ok(())
      });
    // SAFETY: _exit ends the child at once, running nothing of the parent's.
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

fn errno() -> libc::c_int {
  io::Error::last_os_error()
    .raw_os_error()
    .unwrap_or(libc::EIO)
}

fn reap(pid: libc::pid_t) -> io::Result<libc::c_int> {
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

/// A control message's room for one descriptor.
// SAFETY: CMSG_SPACE only computes.
const SPACE: libc::c_uint = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as libc::c_uint) };

/// Room for a control message carrying a descriptor, aligned for its header.
#[repr(C, align(8))]
struct Control([u8; SPACE as usize]);

/// A message of the one byte `part` points to, with `control`'s room.
fn message(part: &mut libc::iovec, control: &mut Control) -> libc::msghdr {
  // SAFETY: all zeros is an empty message, given its parts below.
  let mut message: libc::msghdr = unsafe { mem::zeroed() };
  message.msg_iov = part;
  message.msg_iovlen = 1;
  message.msg_control = (control as *mut Control).cast();
  message.msg_controllen = SPACE as _;
  message
}

/// Sends `fd` over `socket`, allocating nothing, for a forked child.
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

/// The descriptor a child sent over `socket`, if it sent one before it
/// exited.
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
  // SAFETY: CMSG_FIRSTHDR finds the header recvmsg wrote within the control
  // buffer, if it wrote one; a header for SCM_RIGHTS precedes a descriptor,
  // which is now this process's.
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

/// Waits for a connection to `listener`, or for `stop` to be readable:
/// whether a connection came.
pub fn wait_for_connection(listener: BorrowedFd, stop: BorrowedFd) -> io::Result<bool> {
  let mut descriptors = [listener, stop].map(|fd| libc::pollfd {
    fd: fd.as_raw_fd(),
    events: libc::POLLIN,
    revents: 0,
  });

  loop {
    // SAFETY: poll writes only the revents of the descriptors it is given.
    match check(unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as libc::nfds_t, -1) }) {
      Ok(_) => return Ok(descriptors[1].revents == 0),
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      Err(error) => return Err(error),
    }
  }
}
