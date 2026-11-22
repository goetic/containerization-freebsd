//! The host's end of the guest agent protocol, over the console port.
//!
//! The host sends a Hello only when it must: when the agent announces itself,
//! when the host loses frames, and once after a restore. Every Hello the
//! agent reads ends its current session and everything that session ran. A
//! Hello sent on a timer could therefore arrive after the session it was
//! meant to start, and end that session.
//!
//! The guest's tty drops input it has no room for, so the host keeps at most
//! `WINDOW` bytes in flight and writes frames in slices that fit. One
//! thread reads the console and counts the agent's Received reports. Another
//! thread handles everything else, so a writer blocked on a full window can't
//! deadlock the reader whose Received counts reopen it.

mod channel;
mod console;
mod session;

pub(crate) use channel::Listener;
pub use channel::{Output, Process, Relay};
pub use containerization_freebsd_protocol::{Exec, Exit, Limit, Resource, User, WindowSize};

use crate::error::{Error, Result};
use channel::Stream;
use containerization_freebsd_protocol::{Address, Connect, Listen, Message};
use session::Shared;
use std::io::{PipeReader, PipeWriter};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

/// How long the agent has to open or close a channel, or to drain a full
/// window.
const AGENT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Agent {
  shared: Arc<Shared>,
}

/// The output and exit status of a finished command.
#[derive(Debug)]
pub struct Ran {
  pub exit: Exit,
  pub stdout: String,
  pub stderr: String,
  pub seconds: f64,
}

impl Ran {
  pub fn lines(&self) -> Vec<&str> {
    self.stdout.lines().collect()
  }
}

impl Agent {
  pub(crate) fn new(output: PipeReader, input: PipeWriter) -> Self {
    Self {
      shared: Shared::start(output, input),
    }
  }

  /// Returns another handle on the same agent, for the crate's own threads.
  pub(crate) fn share(&self) -> Self {
    Self {
      shared: self.shared.clone(),
    }
  }

  /// Starts a session with an agent that is already running and so will not
  /// announce itself, as after a restore.
  pub(crate) fn rejoin(&self) -> Result<()> {
    self.shared.lock().hello()
  }

  /// How many sessions with the agent have started. Each boot and restore
  /// starts one, as does the host losing frames.
  pub fn sessions(&self) -> u64 {
    self.shared.lock().sessions
  }

  /// Waits for a session with the agent, which starts when the agent
  /// announces itself or answers `rejoin`.
  pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    let mut state = self.shared.lock();

    loop {
      if let Some(mismatch) = state.mismatch {
        return Err(Error::Guest(format!("the guest agent: {mismatch}")));
      }
      if state.mux.in_session() {
        return Ok(());
      }
      if state.closed {
        return Err(Error::Guest("the console closed".to_string()));
      }
      let left = timeout
        .checked_sub(started.elapsed())
        .ok_or_else(|| Error::Timeout(format!("the guest agent did not start within {}s", timeout.as_secs())))?;
      state = self
        .shared
        .changed
        .wait_timeout(state, left)
        .unwrap_or_else(PoisonError::into_inner)
        .0;
    }
  }

  /// Starts the process `exec` describes, in the guest or its jail. The
  /// process inherits the agent's environment plus `exec.env`. With `pty`,
  /// it runs on a terminal of that size. With a user, `HOME` is set to the
  /// user's home directory unless `exec.env` sets it.
  pub fn spawn(&self, exec: Exec) -> Result<Process> {
    let what = format!("{:?}", exec.argv);

    self.open(Message::Exec(exec), what, None).map(Process::new)
  }

  /// Connects to `port` on the guest's loopback.
  pub fn connect(&self, port: u16) -> Result<Relay> {
    self.relay(Connect {
      to: Address::Port(port),
      jail: None,
    })
  }

  /// Connects to the Unix socket at `path` in the guest.
  pub fn connect_unix(&self, path: &str) -> Result<Relay> {
    self.relay(Connect {
      to: Address::Unix(path.to_string()),
      jail: None,
    })
  }

  pub(crate) fn relay(&self, connect: Connect) -> Result<Relay> {
    let what = match &connect.to {
      Address::Port(port) => format!("port {port}"),
      Address::Unix(path) => path.clone(),
    };

    self
      .open(Message::Connect(connect), what, None)
      .map(Relay::new)
  }

  /// Makes the agent listen on the Unix socket `listen` describes, and relays
  /// each connection to the host's socket at `host`.
  pub(crate) fn listen(&self, listen: Listen, host: PathBuf) -> Result<Listener> {
    let what = listen.path.clone();

    self
      .open(Message::Listen(listen), what, Some(host))
      .map(Listener::new)
  }

  /// Runs `argv` in the guest with no input and collects its output. If the
  /// command is still running after `timeout`, it is killed.
  pub fn run(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.run_exec(command(argv), timeout)
  }

  /// Like `run`, for the process `exec` describes.
  pub(crate) fn run_exec(&self, exec: Exec, timeout: Duration) -> Result<Ran> {
    let started = Instant::now();
    let argv = exec.argv.clone();
    let process = self.spawn(exec)?;
    process.close_input()?;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());

    loop {
      let left = timeout.saturating_sub(started.elapsed());

      match process.recv_timeout(left)? {
        Some(Output::Stdout(bytes)) => stdout.extend(bytes),
        Some(Output::Stderr(bytes)) => stderr.extend(bytes),
        Some(Output::Exited(exit)) => {
          return Ok(Ran {
            exit,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            seconds: started.elapsed().as_secs_f64(),
          });
        }
        // Dropping the process kills it.
        None => {
          return Err(Error::Timeout(format!(
            "{argv:?} did not finish within {}s",
            timeout.as_secs()
          )));
        }
      }
    }
  }

  /// Like `run`, but fails unless the command exits with status 0.
  pub fn check(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.check_exec(command(argv), timeout)
  }

  /// Like `check`, for the process `exec` describes.
  pub(crate) fn check_exec(&self, exec: Exec, timeout: Duration) -> Result<Ran> {
    let argv = exec.argv.clone();
    let ran = self.run_exec(exec, timeout)?;

    match ran.exit {
      Exit::Code(0) => Ok(ran),
      exit => {
        let lines: Vec<&str> = ran.stderr.lines().collect();
        let tail = lines[lines.len().saturating_sub(20)..].join("\n");

        Err(Error::Guest(format!(
          "{argv:?} exited {exit:?} after {:.1}s: {tail}",
          ran.seconds
        )))
      }
    }
  }

  /// Sets the guest's clock to the host's, if there is a session. The clock
  /// is synced at the start of each session, and a machine also syncs it
  /// every 30 seconds while it runs.
  pub fn sync_clock(&self) -> Result<()> {
    self.shared.lock().sync_clock()
  }

  /// Starts `argv` in the guest without waiting for Opened, for commands
  /// that may never report back, such as one that powers off the guest.
  pub fn launch(&self, argv: &[&str]) -> Result<()> {
    let mut state = self.shared.lock();
    let protocol = |error| Error::Guest(format!("{argv:?}: {error}"));

    let (channel, frame) = state
      .mux
      .open(Message::Exec(command(argv)))
      .map_err(protocol)?;
    state.write(&frame)?;
    let eof = state.mux.send(channel, Message::Eof).map_err(protocol)?;
    state.write(&eof)
  }

  /// Opens a channel with `message` and waits for the agent to send Opened.
  /// For a Listen channel, connections are relayed to `host`.
  fn open(&self, message: Message, what: String, host: Option<PathBuf>) -> Result<Stream> {
    let (sender, receiver) = mpsc::channel();
    let channel = {
      let mut state = self.shared.lock();
      let (channel, frame) = state
        .mux
        .open(message)
        .map_err(|error| Error::Guest(format!("{what}: {error}")))?;
      state.channels.insert(channel, sender);
      if let Some(host) = host {
        state.listeners.insert(channel, host);
      }
      state.write(&frame)?;
      channel
    };

    Stream::new(channel, self.shared.clone(), receiver, what).opened()
  }
}

fn command(argv: &[&str]) -> Exec {
  Exec {
    argv: argv.iter().map(|arg| arg.to_string()).collect(),
    ..Exec::default()
  }
}

#[cfg(test)]
pub(crate) mod tests {
  use super::*;
  use containerization_freebsd_protocol::{VERSION, WINDOW};
  use std::io::{Read, Write};
  use std::net::TcpListener;

  const PATIENCE: Duration = Duration::from_secs(10);
  const TERMINAL: WindowSize = WindowSize { rows: 24, columns: 80 };
  /// FreeBSD and macOS use the same number for SIGTERM.
  const SIGTERM: i32 = 15;

  /// Runs the real agent over pipes in place of the console, and returns the
  /// ends the host reads and writes.
  fn serve() -> (PipeReader, PipeWriter) {
    let (output, agent_output) = std::io::pipe().unwrap();
    let (agent_input, input) = std::io::pipe().unwrap();
    std::thread::spawn(move || containerization_freebsd_agent::serve(agent_input, agent_output));
    (output, input)
  }

  pub(crate) fn started() -> Agent {
    let (output, input) = serve();
    let agent = Agent::new(output, input);
    agent.wait_ready(PATIENCE).expect("a session");
    agent
  }

  /// Reads the process's stdout until it contains `text`.
  fn read_until(process: &Process, text: &str) -> String {
    let mut output = String::new();

    while !output.contains(text) {
      match process.recv_timeout(PATIENCE).unwrap() {
        Some(Output::Stdout(bytes)) => output.push_str(&String::from_utf8_lossy(&bytes)),
        other => panic!("{other:?} before {text:?}, after {output:?}"),
      }
    }
    output
  }

  /// Reads the process's stdout until it exits, and returns the output and
  /// exit status.
  fn finish(process: &Process) -> (String, Exit) {
    let mut output = String::new();

    loop {
      match process.recv_timeout(PATIENCE).unwrap() {
        Some(Output::Stdout(bytes)) => output.push_str(&String::from_utf8_lossy(&bytes)),
        Some(Output::Exited(exit)) => return (output, exit),
        other => panic!("{other:?} after {output:?}"),
      }
    }
  }

  fn running(pid: &str) -> bool {
    std::process::Command::new("kill")
      .args(["-0", pid])
      .stderr(std::process::Stdio::null())
      .status()
      .unwrap()
      .success()
  }

  #[test]
  fn starts_a_session_when_the_agent_announces_itself() {
    started();
  }

  #[test]
  fn rejoins_an_agent_that_does_not_announce_itself() {
    let (mut output, input) = serve();
    // Simulates a restore: the agent announced itself to an earlier host.
    let announcement = Message::Hello {
      version: VERSION,
      answer: false,
    }
    .frame(0)
    .to_bytes();
    output.read_exact(&mut vec![0; announcement.len()]).unwrap();

    let agent = Agent::new(output, input);
    agent.rejoin().unwrap();

    agent.wait_ready(PATIENCE).expect("a session");
  }

  #[test]
  fn counts_the_sessions_that_start() {
    let agent = started();
    assert_eq!(agent.sessions(), 1);

    agent.rejoin().unwrap();
    agent.wait_ready(PATIENCE).expect("a session");

    assert_eq!(agent.sessions(), 2);
  }

  #[test]
  fn runs_a_command() {
    let agent = started();

    let ran = agent
      .run(&["sh", "-c", "echo out; echo err >&2; exit 2"], PATIENCE)
      .unwrap();

    assert_eq!(ran.exit, Exit::Code(2));
    assert_eq!(ran.lines(), ["out"]);
    assert_eq!(ran.stderr, "err\n");
  }

  #[test]
  fn check_fails_unless_the_command_succeeds() {
    let agent = started();

    let error = agent
      .check(&["sh", "-c", "echo why >&2; exit 1"], PATIENCE)
      .unwrap_err();

    assert!(error.to_string().contains("why"), "{error}");
  }

  #[test]
  fn kills_a_command_that_times_out() {
    let agent = started();

    let error = agent
      .run(&["sleep", "30"], Duration::from_millis(200))
      .unwrap_err();
    assert!(matches!(error, Error::Timeout(_)), "{error}");

    let ran = agent.check(&["echo", "next"], PATIENCE).unwrap();
    assert_eq!(ran.lines(), ["next"]);
  }

  #[test]
  fn refuses_a_command_that_does_not_exist() {
    let agent = started();

    let error = agent
      .spawn(command(&["/nonexistent/command"]))
      .err()
      .unwrap();

    assert!(error.to_string().contains("/nonexistent/command"), "{error}");
  }

  #[test]
  fn feeds_a_process_its_input() {
    let agent = started();

    let process = agent.spawn(command(&["cat"])).unwrap();
    process.write(b"fed\n").unwrap();
    process.close_input().unwrap();

    assert_eq!(finish(&process), ("fed\n".to_string(), Exit::Code(0)));
  }

  #[test]
  fn closing_the_input_of_a_process_that_exited_does_nothing() {
    let agent = started();

    let process = agent.spawn(command(&["true"])).unwrap();
    assert_eq!(finish(&process), (String::new(), Exit::Code(0)));

    process.close_input().unwrap();
  }

  #[test]
  fn feeds_input_many_windows_long() {
    let agent = started();
    let input = vec![b'x'; 300 * WINDOW + 1];

    let process = agent.spawn(command(&["wc", "-c"])).unwrap();
    process.write(&input).unwrap();
    process.close_input().unwrap();

    let (output, exit) = finish(&process);
    assert_eq!((output.trim(), exit), (input.len().to_string().as_str(), Exit::Code(0)));
  }

  #[test]
  fn sends_a_frame_longer_than_the_window() {
    let agent = started();
    let argument = "y".repeat(4 * WINDOW);

    let ran = agent.check(&["printf", "%s", &argument], PATIENCE).unwrap();

    assert_eq!(ran.stdout, argument);
  }

  #[test]
  fn signals_a_process() {
    let agent = started();

    let process = agent.spawn(command(&["sleep", "30"])).unwrap();
    process.signal(SIGTERM).unwrap();

    assert_eq!(finish(&process).1, Exit::Signal(SIGTERM));
  }

  #[test]
  fn runs_and_resizes_a_terminal() {
    let agent = started();

    let process = agent
      .spawn(Exec {
        pty: Some(TERMINAL),
        ..command(&["sh", "-c", "stty size; read line; stty size"])
      })
      .unwrap();
    read_until(&process, "24 80");
    process
      .resize(WindowSize { rows: 40, columns: 100 })
      .unwrap();
    process.write(b"\n").unwrap();

    let (output, exit) = finish(&process);
    assert!(output.contains("40 100"), "{output:?}");
    assert_eq!(exit, Exit::Code(0));
  }

  #[test]
  fn dropping_a_process_kills_it() {
    let agent = started();
    let process = agent
      .spawn(command(&["sh", "-c", "echo $$; exec sleep 30"]))
      .unwrap();
    let pid = read_until(&process, "\n").trim().to_string();

    drop(process);

    let started = Instant::now();
    while running(&pid) {
      assert!(started.elapsed() < PATIENCE, "process {pid} outlived its handle");
      std::thread::sleep(Duration::from_millis(20));
    }
  }

  #[test]
  fn relays_to_a_port() {
    let agent = started();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
      let (mut stream, _) = listener.accept().unwrap();
      let mut received = Vec::new();
      stream.read_to_end(&mut received).unwrap();
      stream.write_all(&received.to_ascii_uppercase()).unwrap();
    });

    let relay = agent.connect(port).unwrap();
    relay.write(b"relayed").unwrap();
    relay.close_write().unwrap();
    let mut received = Vec::new();
    while let Some(bytes) = relay.read().unwrap() {
      received.extend(bytes);
    }
    server.join().unwrap();

    assert_eq!(received, b"RELAYED");
  }

  #[test]
  fn refuses_a_port_nothing_listens_on() {
    let agent = started();
    let port = TcpListener::bind("127.0.0.1:0")
      .unwrap()
      .local_addr()
      .unwrap()
      .port();

    assert!(agent.connect(port).is_err());
  }
}
