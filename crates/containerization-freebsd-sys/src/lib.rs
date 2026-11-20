//! Safe wrappers for the system calls the guest agent needs and std does not
//! provide: pseudo-terminals, raw mode, signals, waiting for an exit without
//! reaping it, the clock, jails, pre-exec process setup, and sockets opened
//! from inside a jail. This crate holds all of the agent's unsafe code.
//!
//! Descriptors this crate opens are set to close on exec, but are briefly
//! inheritable first. Spawn processes from one thread only, as the agent's
//! session loop does; otherwise a process spawned in that window inherits
//! them.

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

/// A resource limit: setrlimit(2)'s resource number and the soft and hard
/// values. A value above `RLIM_INFINITY` means no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
  pub resource: i32,
  pub soft: u64,
  pub hard: u64,
}

/// The user and groups a process switches to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ids {
  pub uid: u32,
  pub gid: u32,
  /// Supplementary groups.
  pub groups: Vec<u32>,
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

fn close_on_exec(fd: BorrowedFd) -> io::Result<()> {
  // SAFETY: fcntl only reads and sets the flags of `fd`, which the borrow
  // keeps open.
  unsafe {
    let flags = check(libc::fcntl(fd.as_raw_fd(), libc::F_GETFD))?;
    check(libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC))?;
  }
  Ok(())
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

/// Finds the running jail named `name` and returns its id and the path of
/// its root in the guest.
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

  // SAFETY: jail_get reads the parameter names and the wanted jail name,
  // which outlive the call, and writes no more than the path buffer holds.
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

/// Never called, because `find_jail` always fails off FreeBSD.
#[cfg(not(target_os = "freebsd"))]
fn attach(_: libc::c_int) -> io::Result<()> {
  Err(io::ErrorKind::Unsupported.into())
}

/// The setup a process performs between fork and exec.
pub struct Entry {
  pub jail: Option<libc::c_int>,
  pub limits: Vec<Limit>,
  pub umask: Option<u16>,
  pub ids: Option<Ids>,
  pub cwd: Option<CString>,
}

/// The step of an `Entry` that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
  Jail = 1,
  Limits,
  User,
  Directory,
}

/// The read end of a pipe on which the child reports which `Entry` step
/// failed. A failed spawn returns only an errno, the same whether a setup
/// step or exec failed.
pub struct Entering(PipeReader);

impl Entering {
  /// Call after spawning has failed. Returns the step that failed, or `None`
  /// if every step succeeded and exec itself failed.
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

/// Returns an error mapper for the child that writes `step` to `report`,
/// without allocating, and passes the error through.
fn failed_at(report: BorrowedFd, step: Step) -> impl Fn(io::Error) -> io::Error {
  move |error| {
    let byte = step as u8;
    // SAFETY: write reads only the one byte. Its result is ignored: the pipe
    // has room for the byte, and the child returns `error` regardless.
    unsafe { libc::write(report.as_raw_fd(), (&raw const byte).cast(), 1) };
    error
  }
}

/// Makes the command's process apply `entry` between fork and exec, in this
/// order: attach to the jail, set limits and umask, drop privileges, then change
/// to the working directory. The directory change happens as the new user,
/// as std's own `current_dir` does.
// rlim_t is signed on FreeBSD, and mode_t is u16 on FreeBSD and macOS but
// u32 on Linux.
#[allow(clippy::unnecessary_cast)]
pub fn enter_on_exec(command: &mut Command, entry: Entry) -> io::Result<Entering> {
  let (reader, writer) = io::pipe()?;
  // The reader is nonblocking because it is read after a failed spawn while
  // the command still holds the write end, so a blocking read would hang.
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

  // SAFETY: between fork and exec, the closure makes only async-signal-safe
  // system calls on data it owns, and allocates nothing.
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
        // setgroups sets only the supplementary groups, on FreeBSD 15 as on
        // other systems.
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

/// A guest `/rescue` tool that a process runs in place of its program. The
/// arguments and environment are prepared before fork, because fexecve(2)
/// runs after fork, where nothing may be allocated.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
struct Rescue {
  tool: File,
  _strings: Vec<CString>,
  argv: Vec<*const libc::c_char>,
  envp: Vec<*const libc::c_char>,
}

// SAFETY: the pointers point into `_strings`, which the struct owns and never
// changes, so they stay valid when the struct moves between threads.
unsafe impl Send for Rescue {}
// SAFETY: as for Send, and nothing is written through the pointers.
unsafe impl Sync for Rescue {}

/// Makes the command's process run the guest's `/rescue` tool named
/// `argv[0]` with `argv`, after all other pre-exec setup. The tool is opened
/// now, in the guest, so it can run in a jail whose root does not contain it.
/// The environment is the agent's, overlaid with the command's.
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
  // async-signal-safe, on data `rescue` owns, and allocates nothing.
  unsafe {
    command.pre_exec(move || Err(fexecve(&rescue)));
  }
  Ok(())
}

/// Returns only if fexecve fails.
#[cfg(target_os = "freebsd")]
fn fexecve(rescue: &Rescue) -> io::Error {
  // SAFETY: the arrays are null-terminated and point at strings `rescue`
  // owns.
  unsafe { libc::fexecve(rescue.tool.as_raw_fd(), rescue.argv.as_ptr(), rescue.envp.as_ptr()) };
  io::Error::last_os_error()
}

/// Never called, because only FreeBSD has `/rescue`.
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

/// Converts `path` to a C string, failing if it contains a NUL.
pub fn path(path: &str) -> io::Result<CString> {
  CString::new(path).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{path:?} has a NUL")))
}

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
  pub fn unix(path: &CStr) -> io::Result<Self> {
    // SAFETY: all zeros is a valid, unnamed Unix socket address; the path is
    // filled in below.
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.to_bytes();
    // Leave room for a terminating NUL.
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

/// Connects to the first of `addresses` that accepts, from a child process
/// attached to jail `jid`, so paths and loopback are the jail's.
pub fn connect_in(jid: libc::c_int, addresses: &[SocketAddress]) -> io::Result<OwnedFd> {
  // SAFETY: the closure makes only system calls on data it borrows, and
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

/// Creates a Unix socket listening at `path` from a child process attached
/// to jail `jid`, so the path is the jail's. Any socket already at `path` is
/// replaced. If `mode` is given, the socket file gets those permissions.
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

/// Removes the socket at `path`, if there is one, from a child process
/// attached to jail `jid`.
pub fn remove_socket_in(jid: libc::c_int, path: &CStr) -> io::Result<()> {
  // SAFETY: as in `connect_in`.
  unsafe { in_jail(jid, || unlink_socket(path).map(|()| -1)) }?;
  Ok(())
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

/// Runs `act` in a child process attached to jail `jid` and receives the
/// descriptor `act` returns, unless it returns -1. If `act` fails, the child
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
unsafe fn in_jail(
  jid: libc::c_int,
  act: impl FnOnce() -> Result<libc::c_int, libc::c_int>,
) -> io::Result<Option<OwnedFd>> {
  let (ours, theirs) = UnixStream::pair()?;

  // SAFETY: the child only attaches, runs `act`, sends the result and exits,
  // which the caller's guarantee about `act` makes safe after fork.
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

/// Waits until `listener` has a connection or `stop` is readable. Returns
/// true for a connection, false once `stop` is readable.
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
