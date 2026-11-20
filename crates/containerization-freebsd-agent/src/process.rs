//! Processes the host runs with Exec: on pipes, or in a pseudo-terminal; in
//! the guest, or a jail.
//!
//! Each has a thread per output, one feeding its input, and one that waits
//! for it. Exited closes the channel, so it waits for the output to end as
//! well as the process: a process that leaves a child holding its output
//! open runs on, as far as the host can tell, until that child exits too.

use crate::session::{Handle, Input, Outbox, READ};
use crate::{sys, user};
use containerization_freebsd_protocol::{Exec, Exit, Message, WindowSize};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};

/// A running process, which the session loop signals and resizes.
pub(crate) struct Process {
  pid: libc::pid_t,
  /// False once the process has exited, just before it is reaped: after
  /// that, its pid could be another process's, which no signal must reach.
  alive: Mutex<bool>,
  terminal: Option<File>,
}

impl Process {
  fn new(child: &Child, terminal: Option<File>) -> Self {
    Self {
      // FreeBSD's pids stop at 99999.
      pid: child.id() as libc::pid_t,
      alive: Mutex::new(true),
      terminal,
    }
  }

  /// Signal numbers are the guest's.
  pub(crate) fn signal(&self, signal: i32) -> io::Result<()> {
    self.send(self.pid, signal)
  }

  /// Kills the process and the rest of its process group.
  pub(crate) fn kill(&self) {
    let _ = self.send(-self.pid, libc::SIGKILL);
  }

  pub(crate) fn resize(&self, size: WindowSize) -> io::Result<()> {
    match &self.terminal {
      Some(terminal) => sys::resize(terminal, window(size)),
      None => Ok(()),
    }
  }

  fn send(&self, target: libc::pid_t, signal: i32) -> io::Result<()> {
    let alive = self.alive.lock().unwrap_or_else(PoisonError::into_inner);

    if *alive { sys::signal(target, signal) } else { Ok(()) }
  }

  /// Waits for the process to exit, and stops signalling it.
  fn exited(&self) {
    if let Err(error) = sys::wait_exited(self.pid) {
      eprintln!("agent: waiting for process {}: {error}", self.pid);
    }
    *self.alive.lock().unwrap_or_else(PoisonError::into_inner) = false;
  }
}

/// Starts `exec`'s process, whose output goes to `outbox`. The environment
/// adds to the agent's.
pub(crate) fn spawn(exec: &Exec, outbox: Outbox) -> io::Result<Handle> {
  let (program, args) = exec
    .argv
    .split_first()
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no command"))?;
  let mut command = Command::new(program);
  command
    .args(args)
    .envs(exec.env.iter().map(|(name, value)| (name, value)));
  if exec.pty.is_some() {
    // Its own session, with the terminal as its controlling terminal, as a
    // login shell has; taken while it is still root.
    sys::take_terminal_on_exec(&mut command);
  }
  let mut entering = enter(&mut command, exec)?;
  if exec.rescue {
    sys::rescue_on_exec(&mut command, &exec.argv)?;
  }

  let started = match exec.pty {
    Some(size) => in_terminal(command, size, outbox),
    None => on_pipes(command, outbox),
  };
  started.map_err(|error| {
    let doing = match entering.as_mut().and_then(sys::Entering::failed) {
      Some(sys::Step::Jail) => format!("entering jail {:?}", exec.jail.as_deref().unwrap_or_default()),
      Some(sys::Step::Limits) => "setting its resource limits".to_string(),
      Some(sys::Step::User) => format!(
        "becoming {:?}",
        exec.user.as_ref().map_or("", |user| user.name.as_str())
      ),
      Some(sys::Step::Directory) => format!("changing to {:?}", exec.cwd.as_deref().unwrap_or("/")),
      None => format!("running {program:?}"),
    };
    io::Error::new(error.kind(), format!("{doing}: {error}"))
  })
}

/// Has the process enter its jail and take on its user, limits and umask,
/// then change directory: in its jail, to `/` if to nowhere else. Says
/// which of those failed, if one did; with none, there is nothing to say.
fn enter(command: &mut Command, exec: &Exec) -> io::Result<Option<sys::Entering>> {
  if exec.jail.is_none() && exec.user.is_none() && exec.umask.is_none() && exec.limits.is_empty() && exec.cwd.is_none()
  {
    return Ok(None);
  }

  let (jail, root) = match &exec.jail {
    Some(name) => {
      let (jid, root) = sys::find_jail(name)?;
      (Some(jid), root)
    }
    None => (None, PathBuf::from("/")),
  };
  let ids = exec
    .user
    .as_ref()
    .map(|user| user::look_up(user, &root))
    .transpose()?;
  if let Some(ids) = &ids
    && !exec.env.iter().any(|(name, _)| name == "HOME")
  {
    command.env("HOME", &ids.home);
  }
  let cwd = exec
    .cwd
    .as_deref()
    .or(jail.map(|_| "/"))
    .map(CString::new)
    .transpose()
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the working directory has a NUL"))?;

  sys::enter_on_exec(
    command,
    sys::Entry {
      jail,
      limits: exec
        .limits
        .iter()
        .map(|limit| sys::Limit {
          resource: limit.resource.0,
          soft: limit.soft,
          hard: limit.hard,
        })
        .collect(),
      umask: exec.umask,
      ids: ids.map(|ids| sys::Ids {
        uid: ids.uid,
        gid: ids.gid,
        groups: ids.groups,
      }),
      cwd,
    },
  )
  .map(Some)
}

fn window(size: WindowSize) -> sys::WindowSize {
  sys::WindowSize {
    rows: size.rows,
    columns: size.columns,
  }
}

fn on_pipes(mut command: Command, outbox: Outbox) -> io::Result<Handle> {
  // A process group of its own, so ending the channel ends what the process
  // started too.
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
  thread::spawn(move || feed(stdin, &inputs, true));
  let output = vec![
    pump(stdout, outbox.clone(), Message::Data, true),
    pump(stderr, outbox.clone(), Message::Stderr, false),
  ];
  watch(child, process.clone(), output, outbox);

  Ok(Handle::Process { input, process })
}

fn in_terminal(mut command: Command, size: WindowSize, outbox: Outbox) -> io::Result<Handle> {
  let (terminal, child_end) = sys::open_terminal(window(size))?;
  let (reader, writer, resizer) = (terminal.try_clone()?, terminal.try_clone()?, terminal);
  command
    .stdin(child_end.try_clone()?)
    .stdout(child_end.try_clone()?)
    .stderr(child_end);
  let child = command.spawn();
  // The parent's copies of the terminal's child end: until they close,
  // reading the terminal never ends.
  drop(command);
  let child = child?;
  let process = Arc::new(Process::new(&child, Some(resizer)));

  let (input, inputs) = mpsc::channel();
  // A terminal has no end of input to send; the host sends ^D as Data.
  thread::spawn(move || feed(writer, &inputs, false));
  let output = vec![pump(reader, outbox.clone(), Message::Data, true)];
  watch(child, process.clone(), output, outbox);

  Ok(Handle::Process { input, process })
}

/// Writes the host's Data to `sink`. Its Eof closes `sink`, or with
/// `closes` false is ignored.
fn feed(mut sink: impl Write, inputs: &Receiver<Input>, closes: bool) {
  for input in inputs {
    match input {
      Input::Data(bytes) => {
        // The process closed its input: the rest has nowhere to go.
        if sink.write_all(&bytes).is_err() {
          return;
        }
      }
      Input::Eof if closes => return,
      Input::Eof => {}
    }
  }
}

/// Sends what `source` reads as messages `wrap` makes, until it ends; then
/// Eof, if `eof`.
fn pump(
  mut source: impl Read + Send + 'static,
  outbox: Outbox,
  wrap: fn(Vec<u8>) -> Message,
  eof: bool,
) -> JoinHandle<()> {
  thread::spawn(move || {
    let mut buffer = vec![0; READ];

    loop {
      match source.read(&mut buffer) {
        Ok(0) => break,
        Ok(read) => {
          if !outbox.send(wrap(buffer[..read].to_vec())) {
            return;
          }
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
        // How a terminal ends once no process holds its child end.
        Err(_) => break,
      }
    }
    if eof {
      outbox.send(Message::Eof);
    }
  })
}

/// Sends Exited once the output has ended and the process has exited.
fn watch(mut child: Child, process: Arc<Process>, output: Vec<JoinHandle<()>>, outbox: Outbox) {
  thread::spawn(move || {
    for pump in output {
      let _ = pump.join();
    }
    process.exited();

    let message = match child.wait() {
      Ok(status) => Message::Exited(exit(status)),
      Err(error) => Message::Error(format!("waiting for the process: {error}")),
    };
    outbox.send(message);
  });
}

fn exit(status: ExitStatus) -> Exit {
  match status.code() {
    Some(code) => Exit::Code(code),
    None => Exit::Signal(status.signal().unwrap_or_default()),
  }
}
