//! Processes the host runs with Exec, on pipes or in a pseudo-terminal, in the
//! guest or in a jail.
//!
//! Each process has a thread per output stream, one feeding its input, and
//! one that reaps it. Exited closes the channel, so it is sent only once the
//! output has ended and the process has exited.
//! If a child inherits the process's stdout and keeps it open, the host sees
//! the process as running until that child exits too.

use crate::{pipe, session, sys, user};
use containerization_freebsd_protocol::message;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};

/// A running process, which the session loop signals and resizes.
pub(crate) struct Process {
  pid: libc::pid_t,
  /// Cleared after the process exits and before it is reaped, so no signal
  /// reaches another process that reuses the pid.
  alive: Mutex<bool>,
  terminal: Option<Arc<File>>,
}

impl Process {
  fn new(child: &Child, terminal: Option<Arc<File>>) -> Self {
    Self {
      // The cast cannot overflow: FreeBSD's pids stop at 99999.
      pid: child.id() as libc::pid_t,
      alive: Mutex::new(true),
      terminal,
    }
  }

  /// Sends `signal`, numbered as on the guest, to the process.
  pub(crate) fn signal(&self, signal: i32) -> io::Result<()> {
    self.while_alive(|pid| sys::process::signal(pid, signal))
  }

  /// Kills the process and the rest of its process group.
  pub(crate) fn kill(&self) {
    let _ = self.while_alive(sys::process::kill_group);
  }

  pub(crate) fn resize(&self, size: message::WindowSize) -> io::Result<()> {
    match &self.terminal {
      Some(terminal) => sys::terminal::resize(terminal, window(size)),
      None => Ok(()),
    }
  }

  /// Calls `send` with the pid unless the process has exited.
  fn while_alive(&self, send: impl FnOnce(libc::pid_t) -> io::Result<()>) -> io::Result<()> {
    let alive = self.alive.lock().unwrap_or_else(PoisonError::into_inner);

    if *alive { send(self.pid) } else { Ok(()) }
  }

  /// Waits for the process to exit without reaping it, then disables
  /// signalling it.
  fn exited(&self) {
    if let Err(error) = sys::process::wait_exited(self.pid) {
      eprintln!("agent: waiting for process {}: {error}", self.pid);
    }
    *self.alive.lock().unwrap_or_else(PoisonError::into_inner) = false;
  }
}

/// Starts the process `exec` describes and sends its output to `outbox`.
/// `exec`'s environment is added to the agent's. An error names the step
/// that failed.
pub(crate) fn spawn(exec: &message::Exec, outbox: session::Outbox) -> io::Result<session::Handle> {
  let (program, args) = exec
    .argv
    .split_first()
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no command"))?;
  let mut command = Command::new(program);
  command
    .args(args)
    .envs(exec.env.iter().map(|(name, value)| (name, value)));
  if exec.pty.is_some() {
    // Make the process a session leader with the pty as its controlling
    // terminal, as for a login shell. Registered first, so the hook runs
    // before privileges are dropped.
    sys::terminal::take_terminal_on_exec(&mut command);
  }
  let mut entering = enter(&mut command, exec)?;
  if exec.rescue {
    sys::exec::rescue_on_exec(&mut command, &exec.argv)?;
  }

  let started = match exec.pty {
    Some(size) => in_terminal(command, size, outbox),
    None => on_pipes(command, outbox),
  };
  started.map_err(|error| {
    let doing = match entering.as_mut().and_then(sys::exec::Entering::failed) {
      Some(sys::exec::Step::Jail) => format!("entering jail {:?}", exec.jail.as_deref().unwrap_or_default()),
      Some(sys::exec::Step::Limits) => "setting its resource limits".to_string(),
      Some(sys::exec::Step::User) => format!(
        "becoming {:?}",
        exec.user.as_ref().map_or("", |user| user.name.as_str())
      ),
      Some(sys::exec::Step::Directory) => format!("changing to {:?}", exec.cwd.as_deref().unwrap_or("/")),
      None => format!("running {program:?}"),
    };
    io::Error::new(error.kind(), format!("{doing}: {error}"))
  })
}

/// Sets up the process to enter its jail, set its limits and umask, drop
/// privileges to its user, then change directory. In a jail, the directory
/// defaults to `/`. The returned `Entering` reports which step failed; it is
/// `None` when `exec` asks for none of these steps.
fn enter(command: &mut Command, exec: &message::Exec) -> io::Result<Option<sys::exec::Entering>> {
  if exec.jail.is_none() && exec.user.is_none() && exec.umask.is_none() && exec.limits.is_empty() && exec.cwd.is_none()
  {
    return Ok(None);
  }

  let (jail, root) = match &exec.jail {
    Some(name) => {
      let (jail, root) = sys::jail::find_jail(name)?;
      (Some(jail), root)
    }
    None => (None, PathBuf::from("/")),
  };
  let identity = exec
    .user
    .as_ref()
    .map(|user| user::look_up(user, &root))
    .transpose()?;
  if let Some(identity) = &identity
    && !exec.env.iter().any(|(name, _)| name == "HOME")
  {
    command.env("HOME", &identity.home);
  }
  let cwd = exec.cwd.as_deref().or(jail.map(|_| "/")).map(PathBuf::from);

  sys::exec::enter_on_exec(
    command,
    sys::exec::Entry {
      jail,
      limits: exec
        .limits
        .iter()
        .map(|limit| sys::exec::Limit {
          resource: limit.resource.0,
          soft: limit.soft,
          hard: limit.hard,
        })
        .collect(),
      umask: exec.umask,
      ids: identity.map(|identity| identity.ids),
      cwd,
    },
  )
  .map(Some)
}

fn window(size: message::WindowSize) -> sys::terminal::WindowSize {
  sys::terminal::WindowSize {
    rows: size.rows,
    columns: size.columns,
  }
}

fn on_pipes(mut command: Command, outbox: session::Outbox) -> io::Result<session::Handle> {
  // A process group of its own, so ending the channel also kills the
  // process's children.
  command
    .process_group(0)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  let mut child = command.spawn()?;
  let (Some(stdin), Some(stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take()) else {
    unreachable!("all three are piped");
  };
  let process = Arc::new(Process::new(&child, None));

  let (input, inputs) = mpsc::channel();
  thread::spawn(move || {
    let mut stdin = stdin;
    // Returning drops stdin, which closes the process's input.
    pipe::write_until_eof(&mut stdin, &inputs);
  });
  let output = vec![
    pump(stdout, outbox.clone(), Output::Stdout),
    pump(stderr, outbox.clone(), Output::Stderr),
  ];
  watch(child, process.clone(), output, outbox);

  Ok(session::Handle::Process { input, process })
}

fn in_terminal(
  mut command: Command,
  size: message::WindowSize,
  outbox: session::Outbox,
) -> io::Result<session::Handle> {
  let (terminal, child_end) = sys::terminal::open_terminal(window(size))?;
  let terminal = Arc::new(terminal);
  command
    .stdin(child_end.try_clone()?)
    .stdout(child_end.try_clone()?)
    .stderr(child_end);
  let child = command.spawn();
  // The command holds the agent's descriptors for the pty's child end. Until
  // they close, reading the controller end never returns EOF.
  drop(command);
  let child = child?;
  let process = Arc::new(Process::new(&child, Some(terminal.clone())));

  let (input, inputs) = mpsc::channel();
  let mut writer = terminal.clone();
  // A terminal has no end of input to send: the host sends ^D as Data, so its
  // Eof is ignored.
  thread::spawn(move || while pipe::write_until_eof(&mut writer, &inputs) {});
  let output = vec![pump(terminal, outbox.clone(), Output::Stdout)];
  watch(child, process.clone(), output, outbox);

  Ok(session::Handle::Process { input, process })
}

/// Which of a process's outputs `pump` reads. On a terminal, stdout carries
/// stderr too.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Output {
  Stdout,
  Stderr,
}

/// Reads `source` until it ends, sending each read as Data for stdout or as
/// Stderr, and then Eof for stdout.
fn pump(source: impl Read + Send + 'static, outbox: session::Outbox, output: Output) -> JoinHandle<()> {
  thread::spawn(move || {
    let wrap = match output {
      Output::Stdout => message::Message::Data,
      Output::Stderr => message::Message::Stderr,
    };
    // Once no descriptor for a pty's child end is open, reading the
    // controller end fails instead of returning EOF, so failing ends the
    // output too.
    if let pipe::Stopped::Refused = pipe::read_chunks(source, |bytes| outbox.send(wrap(bytes))) {
      return;
    }
    if output == Output::Stdout {
      outbox.send(message::Message::Eof);
    }
  })
}

/// Sends Exited once the output has ended and the process has exited.
/// Signalling is disabled before `child.wait()` reaps the process.
fn watch(mut child: Child, process: Arc<Process>, output: Vec<JoinHandle<()>>, outbox: session::Outbox) {
  thread::spawn(move || {
    for pump in output {
      let _ = pump.join();
    }
    process.exited();

    let message = match child.wait() {
      Ok(status) => message::Message::Exited(exit(status)),
      Err(error) => message::Message::Error(format!("waiting for the process: {error}")),
    };
    outbox.send(message);
  });
}

fn exit(status: ExitStatus) -> message::Exit {
  match status.code() {
    Some(code) => message::Exit::Code(code),
    None => message::Exit::Signal(status.signal().unwrap_or_default()),
  }
}
