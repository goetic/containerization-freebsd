//! The setup a process performs between fork and exec: entering a jail,
//! limits, umask, user and directory, or running a guest `/rescue` tool in
//! place of its program.

use crate::jail;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, PipeReader, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;

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

/// The setup a process performs between fork and exec.
pub struct Entry {
  pub jail: Option<jail::JailId>,
  pub limits: Vec<Limit>,
  pub umask: Option<u16>,
  pub ids: Option<Ids>,
  pub cwd: Option<PathBuf>,
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
  crate::check(unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) })?;
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
  let cwd = entry.cwd.as_ref().map(crate::c_string).transpose()?;
  let Entry { jail, ids, .. } = entry;

  // SAFETY: between fork and exec, the closure makes only async-signal-safe
  // system calls on data it owns, and allocates nothing.
  unsafe {
    command.pre_exec(move || {
      let report = writer.as_fd();
      if let Some(jail) = jail {
        jail::attach(jail).map_err(failed_at(report, Step::Jail))?;
      }
      for (resource, limit) in &limits {
        crate::check(libc::setrlimit(*resource as _, limit)).map_err(failed_at(report, Step::Limits))?;
      }
      if let Some(umask) = umask {
        libc::umask(umask);
      }
      if let Some(ids) = &ids {
        // On FreeBSD 15, as on other systems, setgroups sets only the
        // supplementary groups; earlier FreeBSD took the first entry as egid.
        crate::check(libc::setgroups(ids.groups.len() as _, ids.groups.as_ptr()))
          .and_then(|_| crate::check(libc::setgid(ids.gid)))
          .and_then(|_| crate::check(libc::setuid(ids.uid)))
          .map_err(failed_at(report, Step::User))?;
      }
      if let Some(cwd) = &cwd {
        crate::check(libc::chdir(cwd.as_ptr())).map_err(failed_at(report, Step::Directory))?;
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

/// Makes the command's process fexecve the guest's `/rescue` tool named
/// `argv[0]` with `argv`. Register it after every other pre_exec hook: hooks
/// run in registration order, and later ones never would. The tool is
/// opened now, in the guest, so it can run in a jail whose root does not
/// contain it. The environment is the agent's, overlaid with the command's.
pub fn rescue_on_exec(command: &mut Command, argv: &[String]) -> io::Result<()> {
  use std::collections::BTreeMap;

  let name = argv
    .first()
    .filter(|name| !name.is_empty() && !name.contains('/') && *name != "." && *name != "..")
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no rescue tool is named"))?;
  let tool = File::open(format!("/rescue/{name}"))
    .map_err(|error| io::Error::new(error.kind(), format!("/rescue/{name}: {error}")))?;

  let mut environment: BTreeMap<_, _> = std::env::vars_os().collect();
  for (name, value) in command.get_envs() {
    match value {
      Some(value) => environment.insert(name.to_owned(), value.to_owned()),
      None => environment.remove(name),
    };
  }
  let args = argv
    .iter()
    .map(crate::c_string)
    .collect::<io::Result<Vec<_>>>()?;
  let variables = environment
    .into_iter()
    .map(|(name, value)| {
      let mut variable = name.clone();
      variable.push("=");
      variable.push(value);
      // The error names only the variable, since its value may be a secret.
      crate::c_string(variable)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("variable {name:?} has a NUL")))
    })
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
