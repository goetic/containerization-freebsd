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
pub use containerization_freebsd_protocol::{Exec, Exit, FileType, Limit, Resource, User, WindowSize};

use crate::error::{Error, Result};
use channel::Stream;
use containerization_freebsd_protocol::{
  Address, Call, Connect, Disk, FileCopy, GuestPath, Listen, Message, Mount, Return,
};
use session::{Route, Shared};
use std::io::{PipeReader, PipeWriter};
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

/// How long the agent has to open or close a channel, or to drain a full
/// window.
const AGENT_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a quick guest command, such as one zfs(8) or ifconfig(8) call,
/// may take.
pub(crate) const QUICK: Duration = Duration::from_secs(60);

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

/// Starts processes in one place: the guest, a jail, or a container. `run`
/// and `check` build on `spawn`.
pub trait Spawn {
  /// Starts the process `exec` describes. The process inherits the agent's
  /// environment plus `exec.env`. With `pty`, it runs on a terminal of that
  /// size. With a user, `HOME` is set to the user's home directory unless
  /// `exec.env` sets it.
  fn spawn(&self, exec: Exec) -> Result<Process>;

  /// Runs `argv` with no input and collects its output. If the command is
  /// still running after `timeout`, it is killed.
  fn run(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.run_exec(Exec::new(argv), timeout)
  }

  /// Like `run`, for the process `exec` describes.
  fn run_exec(&self, exec: Exec, timeout: Duration) -> Result<Ran> {
    let started = Instant::now();
    let what = described(&exec);
    let process = self.spawn(exec)?;
    process.close_input()?;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    // Dropping the process on a timeout kills it.
    let exit = process
      .wait_timeout(timeout, &mut stdout, &mut stderr)?
      .ok_or_else(|| Error::Timeout(format!("{what} did not finish within {}s", timeout.as_secs())))?;

    Ok(Ran {
      exit,
      stdout: String::from_utf8_lossy(&stdout).into_owned(),
      stderr: String::from_utf8_lossy(&stderr).into_owned(),
      seconds: started.elapsed().as_secs_f64(),
    })
  }

  /// Like `run`, but fails unless the command exits with status 0.
  fn check(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.check_exec(Exec::new(argv), timeout)
  }

  /// Like `check`, for the process `exec` describes.
  fn check_exec(&self, exec: Exec, timeout: Duration) -> Result<Ran> {
    let what = described(&exec);
    let ran = self.run_exec(exec, timeout)?;

    if ran.exit.success() {
      return Ok(ran);
    }
    let lines: Vec<&str> = ran.stderr.lines().collect();
    let tail = lines[lines.len().saturating_sub(20)..].join("\n");

    Err(Error::Guest(format!(
      "{what} exited with {} after {:.1}s: {tail}",
      ran.exit, ran.seconds
    )))
  }
}

impl Spawn for Agent {
  fn spawn(&self, exec: Exec) -> Result<Process> {
    let what = described(&exec);

    self.open(Message::Exec(exec), what, None).map(Process::new)
  }
}

/// `exec`'s argv, and its jail if it has one, for error messages.
fn described(exec: &Exec) -> String {
  match &exec.jail {
    Some(jail) => format!("{:?} in jail {jail}", exec.argv),
    None => format!("{:?}", exec.argv),
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
    let written = self.shared.lock().hello();
    written.wait()
  }

  /// How many sessions with the agent have started. Each boot and restore
  /// starts one, as does the host losing frames.
  pub fn sessions(&self) -> u64 {
    self.shared.lock().sessions
  }

  /// Waits for a session with the agent, which starts when the agent
  /// announces itself or answers `rejoin`.
  pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
    let (state, _) = self
      .shared
      .changed
      .wait_timeout_while(self.shared.lock(), timeout, |state| {
        state.mismatch.is_none() && !state.mux.in_session() && !state.closed
      })
      .unwrap_or_else(PoisonError::into_inner);

    if let Some(mismatch) = state.mismatch {
      return Err(Error::Guest(format!("the guest agent: {mismatch}")));
    }
    if state.mux.in_session() {
      return Ok(());
    }
    if state.closed {
      return Err(Error::Guest("the console closed".to_string()));
    }
    Err(Error::Timeout(format!(
      "the guest agent did not start within {}s",
      timeout.as_secs()
    )))
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
    let what = connect.to_string();

    self
      .open(Message::Connect(connect), what, None)
      .map(Relay::new)
  }

  /// Makes the agent listen on the Unix socket `listen` describes, and relays
  /// each connection to the host's socket at `host`.
  pub(crate) fn listen(&self, listen: Listen, host: PathBuf) -> Result<Listener> {
    let what = listen.to_string();

    self
      .open(Message::Listen(listen), what, Some(host))
      .map(Listener::new)
  }

  /// Sets the guest's clock to the host's, if there is a session. The clock
  /// is synced at the start of each session, and a machine also syncs it
  /// every 30 seconds while it runs.
  pub fn sync_clock(&self) -> Result<()> {
    let written = self.shared.lock().sync_clock()?;
    written.wait()
  }

  /// Starts `argv` in the guest without waiting for Opened, for commands
  /// that may never report back, such as one that powers off the guest.
  pub fn launch(&self, argv: &[&str]) -> Result<()> {
    let what = format!("{argv:?}");
    let (opened, ended) = {
      let mut state = self.shared.lock();
      let (channel, frame) = state
        .mux
        .open(Message::Exec(Exec::new(argv)))
        .map_err(Error::protocol(&what))?;
      (state.queue(frame), state.send(channel, Message::Eof, &what)?)
    };

    opened.wait()?;
    ended.wait()
  }

  /// The type of file at `path` in the guest, following symlinks.
  pub fn file_type(&self, path: &str) -> Result<FileType> {
    self.file_type_at(GuestPath {
      path: path.to_string(),
      jail: None,
    })
  }

  /// The type of file at `path`, which the agent looks up from inside the
  /// jail if `path` names one.
  pub(crate) fn file_type_at(&self, path: GuestPath) -> Result<FileType> {
    self.call(Call::FileType(path), |value| match value {
      Return::FileType(found) => Some(found),
      _ => None,
    })
  }

  /// Mounts what `mount` describes.
  pub(crate) fn mount(&self, mount: Mount) -> Result<()> {
    self.call_for_nothing(Call::Mount(mount))
  }

  /// Unmounts every file system mounted under the guest path `path`, except
  /// ZFS datasets.
  pub(crate) fn unmount_under(&self, path: &str) -> Result<()> {
    self.call_for_nothing(Call::Unmount(path.to_string()))
  }

  pub(crate) fn disks(&self) -> Result<Vec<Disk>> {
    self.call(Call::Disks, |value| match value {
      Return::Disks(disks) => Some(disks),
      _ => None,
    })
  }

  /// Copies a regular file and its permissions, unless the original is
  /// missing or something is already at the destination.
  pub(crate) fn copy_file(&self, copy: FileCopy) -> Result<()> {
    self.call_for_nothing(Call::CopyFile(copy))
  }

  /// Removes the copy `copy_file` made, unless something has changed it.
  pub(crate) fn remove_copy(&self, copy: FileCopy) -> Result<()> {
    self.call_for_nothing(Call::RemoveCopy(copy))
  }

  /// Creates the ZFS dataset `dataset` if it doesn't exist, makes sure ZFS
  /// mounts it, and returns the directory it is mounted at.
  pub(crate) fn mount_dataset(&self, dataset: &str) -> Result<String> {
    self.call(Call::MountDataset(dataset.to_string()), |value| match value {
      Return::Path(path) => Some(path),
      _ => None,
    })
  }

  /// Makes `call`, which returns Done.
  fn call_for_nothing(&self, call: Call) -> Result<()> {
    self.call(call, |value| matches!(value, Return::Done).then_some(()))
  }

  /// Makes `call`, and returns what `take` finds in the agent's answer:
  /// `None` if the answer isn't the variant the call returns.
  fn call<T>(&self, call: Call, take: impl FnOnce(Return) -> Option<T>) -> Result<T> {
    let what = call.to_string();
    let stream = self.open_unanswered(Message::Call(call), what, None)?;

    match stream.answer()? {
      Message::Return(value) => take(value).ok_or_else(|| stream.misreturned()),
      other => Err(stream.unexpected(&other)),
    }
  }

  /// Opens a channel with `message` and waits for the agent to send Opened.
  /// For a Listen channel, connections are relayed to `host`.
  fn open(&self, message: Message, what: String, host: Option<PathBuf>) -> Result<Stream> {
    self.open_unanswered(message, what, host)?.opened()
  }

  /// Opens a channel with `message`, without waiting for the agent.
  fn open_unanswered(&self, message: Message, what: String, host: Option<PathBuf>) -> Result<Stream> {
    let (sender, receiver) = mpsc::channel();
    let (channel, written) = {
      let mut state = self.shared.lock();
      let (channel, frame) = state.mux.open(message).map_err(Error::protocol(&what))?;
      state
        .channels
        .insert(channel, Route { sender, relay_to: host });
      (channel, state.queue(frame))
    };

    written.wait()?;
    Ok(Stream::new(channel, self.shared.clone(), receiver, what))
  }
}

#[cfg(test)]
pub(crate) mod tests {
  use super::*;
  use containerization_freebsd_protocol::{Decoder, Mux, Side, VERSION, WINDOW};
  use std::io::{Read, Write};
  use std::net::TcpListener;

  /// Far longer than any of these tests' commands take.
  const TIMEOUT: Duration = Duration::from_secs(10);
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
    agent.wait_ready(TIMEOUT).expect("a session");
    agent
  }

  /// Reads the process's stdout until it contains `text`.
  fn read_until(process: &Process, text: &str) -> String {
    let mut output = String::new();

    while !output.contains(text) {
      match process.recv_timeout(TIMEOUT).unwrap() {
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
      match process.recv_timeout(TIMEOUT).unwrap() {
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

    agent.wait_ready(TIMEOUT).expect("a session");
  }

  #[test]
  fn counts_the_sessions_that_start() {
    let agent = started();
    assert_eq!(agent.sessions(), 1);

    agent.rejoin().unwrap();
    agent.wait_ready(TIMEOUT).expect("a session");

    assert_eq!(agent.sessions(), 2);
  }

  #[test]
  fn says_when_there_is_no_session() {
    // Nothing serves the other ends, so no session starts.
    let (output, _agent_output) = std::io::pipe().unwrap();
    let (_agent_input, input) = std::io::pipe().unwrap();
    let agent = Agent::new(output, input);

    let error = agent.launch(&["true"]).unwrap_err();

    assert!(
      matches!(
        &error,
        Error::Protocol {
          error: containerization_freebsd_protocol::Error::NoSession,
          ..
        }
      ),
      "{error:?}"
    );
    assert!(std::error::Error::source(&error).is_some());
  }

  #[test]
  fn runs_a_command() {
    let agent = started();

    let ran = agent
      .run(&["sh", "-c", "echo out; echo err >&2; exit 2"], TIMEOUT)
      .unwrap();

    assert_eq!(ran.exit, Exit::Code(2));
    assert_eq!(ran.lines(), ["out"]);
    assert_eq!(ran.stderr, "err\n");
  }

  #[test]
  fn check_fails_unless_the_command_succeeds() {
    let agent = started();

    let error = agent
      .check(&["sh", "-c", "echo why >&2; exit 1"], TIMEOUT)
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

    let ran = agent.check(&["echo", "next"], TIMEOUT).unwrap();
    assert_eq!(ran.lines(), ["next"]);
  }

  #[test]
  fn refuses_a_command_that_does_not_exist() {
    let agent = started();

    let error = agent
      .spawn(Exec::new(["/nonexistent/command"]))
      .err()
      .unwrap();

    assert!(error.to_string().contains("/nonexistent/command"), "{error}");
  }

  #[test]
  fn finds_the_type_of_file_at_a_path() {
    let agent = started();
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().to_str().unwrap();
    std::fs::write(directory.path().join("file"), "").unwrap();

    assert_eq!(agent.file_type(root).unwrap(), FileType::Directory);
    assert_eq!(agent.file_type(&format!("{root}/file")).unwrap(), FileType::File);
    assert_eq!(
      agent.file_type(&format!("{root}/file/under")).unwrap(),
      FileType::Missing
    );
    let error = agent
      .file_type_at(GuestPath {
        path: root.to_string(),
        jail: Some("cfbsd-no-such-jail".into()),
      })
      .unwrap_err();
    assert!(error.to_string().contains("cfbsd-no-such-jail"), "{error}");
  }

  #[test]
  fn feeds_a_process_its_input() {
    let agent = started();

    let process = agent.spawn(Exec::new(["cat"])).unwrap();
    process.write(b"fed\n").unwrap();
    process.close_input().unwrap();

    assert_eq!(finish(&process), ("fed\n".to_string(), Exit::Code(0)));
  }

  #[test]
  fn closing_the_input_of_a_process_that_exited_does_nothing() {
    let agent = started();

    let process = agent.spawn(Exec::new(["true"])).unwrap();
    assert_eq!(finish(&process), (String::new(), Exit::Code(0)));

    process.close_input().unwrap();
  }

  #[test]
  fn feeds_input_many_windows_long() {
    let agent = started();
    let input = vec![b'x'; 300 * WINDOW + 1];

    let process = agent.spawn(Exec::new(["wc", "-c"])).unwrap();
    process.write(&input).unwrap();
    process.close_input().unwrap();

    let (output, exit) = finish(&process);
    assert_eq!((output.trim(), exit), (input.len().to_string().as_str(), Exit::Code(0)));
  }

  /// A guest that speaks the protocol by hand and never reports what it read
  /// from the console, so the host's window stays shut once it fills.
  struct SilentGuest {
    mux: Mux,
    decoder: Decoder,
    input: PipeReader,
    output: PipeWriter,
  }

  impl SilentGuest {
    /// Starts a session with a new agent, and returns both.
    fn start() -> (Agent, Self) {
      let (output, guest_output) = std::io::pipe().unwrap();
      let (guest_input, input) = std::io::pipe().unwrap();
      let agent = Agent::new(output, input);
      let mut guest = Self {
        mux: Mux::new(Side::Guest),
        decoder: Decoder::new(),
        input: guest_input,
        output: guest_output,
      };

      // The guest announces itself, then answers the host's Hello.
      guest.hello();
      guest.receive();
      guest.hello();
      agent.wait_ready(TIMEOUT).expect("a session");
      (agent, guest)
    }

    fn hello(&mut self) {
      let hello = self.mux.hello();
      self.output.write_all(&hello.to_bytes()).unwrap();
    }

    fn send(&mut self, channel: u32, message: Message) {
      let frame = self.mux.send(channel, message).unwrap();
      self.output.write_all(&frame.to_bytes()).unwrap();
    }

    /// Returns the host's next message.
    fn receive(&mut self) -> (u32, Message) {
      loop {
        if let Some(decoded) = self.decoder.decode() {
          return self.mux.receive(decoded.unwrap()).unwrap();
        }
        self.read();
      }
    }

    /// Waits for more of the host's bytes.
    fn read(&mut self) {
      let mut buffer = [0; 4096];
      let read = self.input.read(&mut buffer).unwrap();
      self.decoder.push(&buffer[..read]);
    }
  }

  #[test]
  fn routes_what_the_agent_sends_while_a_write_waits_for_room() {
    let (agent, mut guest) = SilentGuest::start();
    let (cat, channel) = std::thread::scope(|scope| {
      let spawning = scope.spawn(|| agent.spawn(Exec::new(["cat"])).unwrap());
      // The host sets the guest's clock first.
      let channel = loop {
        if let (channel, Message::Exec(_)) = guest.receive() {
          break channel;
        }
      };
      guest.send(channel, Message::Opened);
      (spawning.join().unwrap(), channel)
    });

    // The Exec frame is longer than the window, so writing it stops partway.
    let argument = "y".repeat(2 * WINDOW);
    std::thread::scope(|scope| {
      let blocked = scope.spawn(|| agent.spawn(Exec::new(["echo", argument.as_str()])));
      guest.read();

      guest.send(channel, Message::Data(b"routed".to_vec()));
      assert!(matches!(
        cat.recv_timeout(TIMEOUT).unwrap(),
        Some(Output::Stdout(bytes)) if bytes == b"routed"
      ));
      assert!(!blocked.is_finished());
      // Closing the console fails the write instead of leaving it to time out.
      drop(guest);
      assert!(blocked.join().unwrap().is_err());
    });
  }

  #[test]
  fn sends_a_frame_longer_than_the_window() {
    let agent = started();
    let argument = "y".repeat(4 * WINDOW);

    let ran = agent.check(&["printf", "%s", &argument], TIMEOUT).unwrap();

    assert_eq!(ran.stdout, argument);
  }

  #[test]
  fn signals_a_process() {
    let agent = started();

    let process = agent.spawn(Exec::new(["sleep", "30"])).unwrap();
    process.signal(SIGTERM).unwrap();

    assert_eq!(finish(&process).1, Exit::Signal(SIGTERM));
  }

  #[test]
  fn runs_and_resizes_a_terminal() {
    let agent = started();

    let process = agent
      .spawn(Exec {
        pty: Some(TERMINAL),
        ..Exec::new(["sh", "-c", "stty size; read line; stty size"])
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
      .spawn(Exec::new(["sh", "-c", "echo $$; exec sleep 30"]))
      .unwrap();
    let pid = read_until(&process, "\n").trim().to_string();

    drop(process);

    let started = Instant::now();
    while running(&pid) {
      assert!(started.elapsed() < TIMEOUT, "process {pid} outlived its handle");
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
