//! The host's end of the guest agent's protocol, over the console port.
//!
//! The host sends a Hello only when it must: in answer to the agent
//! announcing itself, after it lost frames, and once after a restore. Every
//! Hello the agent reads ends its session and what that session ran, so one
//! sent on a timer could arrive after the session it was meant to start,
//! and end it.
//!
//! The guest drops console bytes it has no room for, so the host keeps at
//! most `WINDOW` of them unreceived, writing frames in slices that fit. One
//! thread reads the console and counts what the agent Received; another
//! handles the rest, so a writer waiting for room never holds up the count.

use crate::error::{Error, Result};
use containerization_freebsd_protocol::{
  CONTROL, Decoder, Frame, Message, Mux, Side, Skipped, VersionMismatch, WINDOW,
};
use std::collections::HashMap;
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub use containerization_freebsd_protocol::{Exec, Exit, WindowSize};

/// How long the agent has to start a process or connect a relay, and to read
/// the console when the host has a window's worth unreceived.
const OPENING: Duration = Duration::from_secs(60);
/// Data goes in frames of at most this, so channels take turns on the console.
const CHUNK: usize = WINDOW / 2;

pub struct Agent {
  shared: Arc<Shared>,
}

/// What a command printed, and how it ended.
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

/// A process the agent runs. Dropping it before it exits kills it.
pub struct Process {
  stream: Stream,
  exited: AtomicBool,
}

/// What a process sends back.
#[derive(Debug, PartialEq, Eq)]
pub enum Output {
  /// Its stdout; in a terminal, stderr too.
  Stdout(Vec<u8>),
  Stderr(Vec<u8>),
  /// The last of its output.
  Exited(Exit),
}

/// A connection to a TCP port on the guest's loopback. Dropping it closes
/// the connection.
pub struct Relay {
  stream: Stream,
  ended: AtomicBool,
}

/// An open channel: its number, and the messages the agent sends on it.
struct Stream {
  channel: u32,
  shared: Arc<Shared>,
  messages: Mutex<Receiver<Message>>,
  /// The process or port, for errors.
  what: String,
}

struct Shared {
  state: Mutex<State>,
  /// Notified when a session starts, or the console closes.
  changed: Condvar,
}

struct State {
  mux: Mux,
  console: PipeWriter,
  credit: Arc<Credit>,
  /// Where each open channel's messages go.
  channels: HashMap<u32, mpsc::Sender<Message>>,
  mismatch: Option<VersionMismatch>,
  closed: bool,
}

/// What the console reader hands the thread that handles it.
enum Event {
  /// Bytes as read, for the console text before a session.
  Read(Vec<u8>),
  Frame(Frame),
  Skipped,
}

/// The console bytes the host has written that the agent hasn't yet said it
/// Received.
#[derive(Default)]
struct Credit {
  window: Mutex<Window>,
  changed: Condvar,
}

#[derive(Default)]
struct Window {
  unreceived: usize,
  closed: bool,
}

impl Agent {
  pub(crate) fn new(output: PipeReader, input: PipeWriter) -> Self {
    let credit = Arc::new(Credit::default());
    let shared = Arc::new(Shared {
      state: Mutex::new(State {
        mux: Mux::new(Side::Host),
        console: input,
        credit: credit.clone(),
        channels: HashMap::new(),
        mismatch: None,
        closed: false,
      }),
      changed: Condvar::new(),
    });
    let (events, queue) = mpsc::channel();
    std::thread::spawn(move || read(output, &credit, &events));
    let handler = shared.clone();
    std::thread::spawn(move || handle(&queue, &handler));

    Self { shared }
  }

  /// Starts a session with an agent that is already running, as after a
  /// restore, when it will not announce itself.
  pub(crate) fn rejoin(&self) -> Result<()> {
    self.shared.lock().hello()
  }

  /// Waits for a session with the agent: for it to start and announce
  /// itself, or to answer `rejoin`.
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

  /// Starts `exec`'s process in the guest. The environment adds to the
  /// agent's; with `pty`, it runs in a terminal of that size.
  pub fn spawn(&self, exec: Exec) -> Result<Process> {
    let what = format!("{:?}", exec.argv);

    Ok(Process {
      stream: self.open(Message::Exec(exec), what)?,
      exited: AtomicBool::new(false),
    })
  }

  /// Connects to `port` on the guest's loopback.
  pub fn connect(&self, port: u16) -> Result<Relay> {
    Ok(Relay {
      stream: self.open(Message::Connect { port }, format!("port {port}"))?,
      ended: AtomicBool::new(false),
    })
  }

  /// Runs `argv` in the guest, with no input, and collects what it prints.
  /// One still running after `timeout` is killed.
  pub fn run(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    let started = Instant::now();
    let process = self.spawn(command(argv))?;
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

  /// As `run`, failing unless the command exits 0.
  pub fn check(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    let ran = self.run(argv, timeout)?;

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

  /// Starts `argv` in the guest without waiting for it, for a command that
  /// may never report back, such as one that powers the guest off.
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

  /// Opens a channel with `message`, and waits for the agent to start what
  /// it asks for.
  fn open(&self, message: Message, what: String) -> Result<Stream> {
    let (sender, receiver) = mpsc::channel();
    let channel = {
      let mut state = self.shared.lock();
      let (channel, frame) = state
        .mux
        .open(message)
        .map_err(|error| Error::Guest(format!("{what}: {error}")))?;
      state.channels.insert(channel, sender);
      state.write(&frame)?;
      channel
    };
    let stream = Stream {
      channel,
      shared: self.shared.clone(),
      messages: Mutex::new(receiver),
      what,
    };

    match stream.recv(Some(OPENING))? {
      Some(Message::Opened) => Ok(stream),
      Some(other) => Err(Error::Guest(format!(
        "{}: the agent sent {} before opened",
        stream.what,
        other.name()
      ))),
      None => Err(Error::Timeout(format!(
        "{}: the agent did not open it within {}s",
        stream.what,
        OPENING.as_secs()
      ))),
    }
  }
}

fn command(argv: &[&str]) -> Exec {
  Exec {
    argv: argv.iter().map(|arg| arg.to_string()).collect(),
    ..Exec::default()
  }
}

impl Process {
  /// Writes to its stdin.
  pub fn write(&self, bytes: &[u8]) -> Result<()> {
    self.stream.write(bytes)
  }

  /// Ends its stdin. In a terminal, write ^D instead.
  pub fn close_input(&self) -> Result<()> {
    self.stream.send(Message::Eof)
  }

  /// Resizes its terminal.
  pub fn resize(&self, size: WindowSize) -> Result<()> {
    self.stream.send(Message::Resize(size))
  }

  /// Sends it a signal, numbered as in the guest.
  pub fn signal(&self, signal: i32) -> Result<()> {
    self.stream.send(Message::Signal(signal))
  }

  /// Its next output, waiting as long as that takes.
  pub fn recv(&self) -> Result<Output> {
    self
      .next(None)?
      .ok_or_else(|| Error::Guest(format!("{}: no output", self.stream.what)))
  }

  /// Its next output, or `None` if none came within `timeout`.
  pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<Output>> {
    self.next(Some(timeout))
  }

  fn next(&self, timeout: Option<Duration>) -> Result<Option<Output>> {
    if self.exited.load(Ordering::Relaxed) {
      return Err(Error::Guest(format!("{} has exited", self.stream.what)));
    }

    loop {
      match self.stream.recv(timeout)? {
        Some(Message::Data(bytes)) => return Ok(Some(Output::Stdout(bytes))),
        Some(Message::Stderr(bytes)) => return Ok(Some(Output::Stderr(bytes))),
        Some(Message::Exited(exit)) => {
          self.exited.store(true, Ordering::Relaxed);
          return Ok(Some(Output::Exited(exit)));
        }
        // The end of stdout, which Exited follows.
        Some(_) => {}
        None => return Ok(None),
      }
    }
  }
}

impl Relay {
  /// Writes to the connection.
  pub fn write(&self, bytes: &[u8]) -> Result<()> {
    self.stream.write(bytes)
  }

  /// Shuts the connection's write side.
  pub fn close_write(&self) -> Result<()> {
    self.stream.send(Message::Eof)
  }

  /// What the connection sends next, or `None` at its end.
  pub fn read(&self) -> Result<Option<Vec<u8>>> {
    if self.ended.load(Ordering::Relaxed) {
      return Ok(None);
    }

    loop {
      match self.stream.recv(None)? {
        Some(Message::Data(bytes)) => return Ok(Some(bytes)),
        Some(Message::Eof) => {
          self.ended.store(true, Ordering::Relaxed);
          return Ok(None);
        }
        Some(_) => {}
        None => return Ok(None),
      }
    }
  }
}

impl Stream {
  fn send(&self, message: Message) -> Result<()> {
    let mut state = self.shared.lock();
    let frame = state
      .mux
      .send(self.channel, message)
      .map_err(|error| Error::Guest(format!("{}: {error}", self.what)))?;
    state.write(&frame)
  }

  fn write(&self, bytes: &[u8]) -> Result<()> {
    bytes
      .chunks(CHUNK)
      .try_for_each(|chunk| self.send(Message::Data(chunk.to_vec())))
  }

  /// The next message, or `None` if none came within `timeout`. The
  /// agent's Error, and the session's end, are errors.
  fn recv(&self, timeout: Option<Duration>) -> Result<Option<Message>> {
    let messages = self.messages.lock().unwrap_or_else(PoisonError::into_inner);
    let message = match timeout {
      Some(timeout) => messages.recv_timeout(timeout),
      None => messages.recv().map_err(|_| RecvTimeoutError::Disconnected),
    };

    match message {
      Ok(Message::Error(reason)) => Err(Error::Guest(format!("{}: {reason}", self.what))),
      Ok(message) => Ok(Some(message)),
      Err(RecvTimeoutError::Timeout) => Ok(None),
      Err(RecvTimeoutError::Disconnected) => Err(Error::SessionEnded(format!("{} was open", self.what))),
    }
  }
}

impl Drop for Stream {
  /// Closes the channel if it is still open, which kills the process or
  /// closes the connection.
  fn drop(&mut self) {
    let mut state = self.shared.lock();

    if state.channels.contains_key(&self.channel) && state.mux.is_open(self.channel) {
      state.close(self.channel, "closed by the host");
    }
    state.channels.remove(&self.channel);
  }
}

impl Shared {
  fn lock(&self) -> MutexGuard<'_, State> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }
}

impl State {
  /// Writes `frame` as the window makes room for it.
  fn write(&mut self, frame: &Frame) -> Result<()> {
    let bytes = frame.to_bytes();
    let mut rest = bytes.as_slice();

    while !rest.is_empty() {
      let (now, later) = rest.split_at(self.credit.take(rest.len())?);
      self
        .console
        .write_all(now)
        .map_err(Error::io("writing to the guest agent"))?;
      rest = later;
    }
    Ok(())
  }

  /// Starts a session; ends any there was, and what it ran.
  fn hello(&mut self) -> Result<()> {
    self.channels.clear();
    let hello = self.mux.hello();
    self.write(&hello)
  }

  fn close(&mut self, channel: u32, reason: &str) {
    if let Ok(frame) = self.mux.send(channel, Message::Error(reason.to_string())) {
      let _ = self.write(&frame);
    }
  }

  fn receive(&mut self, frame: Frame) -> bool {
    let channel = frame.channel;

    match self.mux.receive(frame) {
      // The agent has no session: it started, or lost frames.
      Ok((_, Message::Hello { answer: false, .. })) => {
        let _ = self.hello();
        false
      }
      Ok((_, Message::Hello { answer: true, .. })) => true,
      // The console reader counted it.
      Ok((_, Message::Received(_))) => false,
      Ok((_, Message::Ping(number))) => {
        if let Ok(pong) = self.mux.send(channel, Message::Pong(number)) {
          let _ = self.write(&pong);
        }
        false
      }
      Ok((_, message)) => {
        if let Some(sender) = self.channels.get(&channel) {
          let _ = sender.send(message);
        }
        if !self.mux.is_open(channel) {
          self.channels.remove(&channel);
        }
        false
      }
      Err(containerization_freebsd_protocol::Error::Version(mismatch)) => {
        self.mismatch = Some(mismatch);
        true
      }
      // Such as a message that crossed its channel's closing.
      Err(_) => false,
    }
  }
}

impl Credit {
  /// Room for up to `wanted` more bytes, counted as written, as soon as there
  /// is any.
  fn take(&self, wanted: usize) -> Result<usize> {
    let window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
    let mut window = self
      .changed
      .wait_timeout_while(window, OPENING, |window| !window.closed && window.unreceived >= WINDOW)
      .unwrap_or_else(PoisonError::into_inner)
      .0;

    if window.closed {
      return Err(Error::Guest("the console closed".to_string()));
    }
    if window.unreceived >= WINDOW {
      return Err(Error::Timeout(format!(
        "the guest agent read none of the console's last {} bytes within {}s",
        window.unreceived,
        OPENING.as_secs()
      )));
    }
    let room = (WINDOW - window.unreceived).min(wanted);
    window.unreceived += room;
    Ok(room)
  }

  /// Counts what `frame`, from the agent, says of the console.
  fn hear(&self, frame: &Frame) {
    if frame.channel != CONTROL {
      return;
    }
    let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);

    match Message::from_frame(frame.clone()) {
      Ok(Message::Received(bytes)) => {
        window.unreceived = window.unreceived.saturating_sub(bytes as usize);
      }
      // A new agent, or one starting over: what the old one never read is
      // gone, or the agent has read past it.
      Ok(Message::Hello { .. }) => window.unreceived = 0,
      _ => return,
    }
    self.changed.notify_all();
  }

  fn close(&self) {
    self
      .window
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .closed = true;
    self.changed.notify_all();
  }
}

/// Reads the console, counting what the agent Received, and hands the rest
/// on. Never waits on the session's state, which a writer holds while it
/// waits for room.
fn read(mut output: PipeReader, credit: &Credit, events: &mpsc::Sender<Event>) {
  let mut decoder = Decoder::new();
  let mut buffer = vec![0; 64 << 10];

  while let Ok(read @ 1..) = output.read(&mut buffer) {
    let _ = events.send(Event::Read(buffer[..read].to_vec()));
    decoder.push(&buffer[..read]);

    while let Some(decoded) = decoder.decode() {
      let event = match decoded {
        Ok(frame) => {
          credit.hear(&frame);
          Event::Frame(frame)
        }
        Err(Skipped(_)) => Event::Skipped,
      };
      let _ = events.send(event);
    }
  }
  credit.close();
}

/// Handles what the console brings, until it closes.
fn handle(queue: &Receiver<Event>, shared: &Shared) {
  let mut line = Vec::new();

  for event in queue {
    let mut state = shared.lock();
    let changed = match event {
      // Before a session, console text is the guest explaining why there is
      // none, such as first-boot.sh failing.
      Event::Read(bytes) => {
        if !state.mux.in_session() {
          echo(&mut line, &bytes);
        }
        false
      }
      Event::Frame(frame) => state.receive(frame),
      // Frames were lost mid-session: start over.
      Event::Skipped if state.mux.in_session() => {
        let _ = state.hello();
        false
      }
      Event::Skipped => false,
    };
    if changed {
      shared.changed.notify_all();
    }
  }

  let mut state = shared.lock();
  state.closed = true;
  state.channels.clear();
  shared.changed.notify_all();
}

/// Copies the text among `bytes` to stderr, a line at a time.
fn echo(line: &mut Vec<u8>, bytes: &[u8]) {
  for &byte in bytes {
    match byte {
      b'\n' if !line.is_empty() => {
        eprintln!("guest| {}", String::from_utf8_lossy(line));
        line.clear();
      }
      b' '..=b'~' | b'\t' => line.push(byte),
      _ => {}
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use containerization_freebsd_protocol::VERSION;
  use std::net::TcpListener;

  const PATIENCE: Duration = Duration::from_secs(10);
  const TERMINAL: WindowSize = WindowSize { rows: 24, columns: 80 };
  /// FreeBSD and macOS number it alike.
  const SIGTERM: i32 = 15;

  /// The real agent, serving over pipes as it would the console; and the
  /// ends the host reads and writes.
  fn serve() -> (PipeReader, PipeWriter) {
    let (output, agent_output) = std::io::pipe().unwrap();
    let (agent_input, input) = std::io::pipe().unwrap();
    std::thread::spawn(move || containerization_freebsd_agent::serve(agent_input, agent_output));
    (output, input)
  }

  fn started() -> Agent {
    let (output, input) = serve();
    let agent = Agent::new(output, input);
    agent.wait_ready(PATIENCE).expect("a session");
    agent
  }

  /// Its stdout until it holds `text`.
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

  /// Its stdout until it exits, and how.
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
    // As after a restore: the agent announced itself to an earlier host.
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
