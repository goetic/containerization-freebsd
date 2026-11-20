//! The host's end of the guest agent protocol, over the console port.
//!
//! The host sends a Hello only when it must: when the agent announces itself,
//! when the host loses frames, and once after a restore. Every Hello the
//! agent reads ends its current session and everything that session ran. A
//! Hello sent on a timer could therefore arrive after the session it was
//! meant to start, and end that session.
//!
//! The guest drops console bytes it has no room for, so the host keeps at
//! most `WINDOW` bytes in flight and writes frames in slices that fit. One
//! thread reads the console and counts the agent's Received reports. Another
//! thread handles everything else, so a writer blocked on a full window can't
//! deadlock the reader whose Received counts reopen it.

use crate::error::{Error, Result};
use containerization_freebsd_protocol::{
  Address, CONTROL, Connect, Decoder, Frame, Listen, Message, Mux, Side, Skipped, VersionMismatch, WINDOW,
};
use std::collections::HashMap;
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use containerization_freebsd_protocol::{Exec, Exit, Limit, Resource, User, WindowSize};

/// How long the agent has to open or close a channel, and to read the console
/// once the window is full.
const OPENING: Duration = Duration::from_secs(60);
/// The largest Data payload the host sends, so that channels take turns on
/// the console.
const CHUNK: usize = WINDOW / 2;

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

/// A process the agent runs. Dropping it before it exits kills it.
pub struct Process {
  stream: Stream,
  exited: AtomicBool,
}

/// Output from a process.
#[derive(Debug, PartialEq, Eq)]
pub enum Output {
  /// Stdout. On a terminal, this includes stderr.
  Stdout(Vec<u8>),
  Stderr(Vec<u8>),
  /// The process exited. Nothing follows this.
  Exited(Exit),
}

/// A connection to a socket in the guest: a TCP port on the loopback of the
/// guest or a jail, or a Unix socket. Dropping it closes the connection.
pub struct Relay {
  stream: Stream,
  ended: AtomicBool,
}

/// A Unix socket the agent listens on. Each connection is relayed to a socket
/// on the host. Dropping the listener closes the socket in the guest but
/// leaves its file; `close` removes the file too.
pub(crate) struct Listener {
  stream: Stream,
}

/// An open channel and the messages the agent sends on it.
struct Stream {
  channel: u32,
  shared: Arc<Shared>,
  messages: Mutex<Receiver<Message>>,
  /// A description of the process or socket, for error messages.
  what: String,
}

struct Shared {
  state: Mutex<State>,
  /// Notified when a session starts or fails, or the console closes.
  changed: Condvar,
}

struct State {
  mux: Mux,
  console: PipeWriter,
  credit: Arc<Credit>,
  /// The sender for each open channel's messages.
  channels: HashMap<u32, mpsc::Sender<Message>>,
  /// For each open Listen channel, the host socket its connections relay to.
  listeners: HashMap<u32, PathBuf>,
  mismatch: Option<VersionMismatch>,
  closed: bool,
}

/// The follow-up work, if any, that a frame from the agent leaves for
/// `handle`.
enum Heard {
  Nothing,
  /// The session started or cannot start. Wake the threads waiting for it.
  Changed,
  /// A connection to a Listen channel's socket, to pass to `relay_accepted`.
  Accepted {
    channel: u32,
    host: PathBuf,
    messages: Receiver<Message>,
  },
}

/// What the console reader passes to the handler thread.
enum Event {
  /// Raw bytes as read, so that console text before a session can be shown.
  Read(Vec<u8>),
  Frame(Frame),
  Skipped,
}

/// Tracks the console bytes the host has written that the agent has not yet
/// reported with Received.
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
        listeners: HashMap::new(),
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

    Ok(Process {
      stream: self.open(Message::Exec(exec), what, None)?,
      exited: AtomicBool::new(false),
    })
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

    Ok(Relay {
      stream: self.open(Message::Connect(connect), what, None)?,
      ended: AtomicBool::new(false),
    })
  }

  /// Makes the agent listen on the Unix socket `listen` describes, and relays
  /// each connection to the host's socket at `host`.
  pub(crate) fn listen(&self, listen: Listen, host: PathBuf) -> Result<Listener> {
    let what = listen.path.clone();

    Ok(Listener {
      stream: self.open(Message::Listen(listen), what, Some(host))?,
    })
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
  /// Writes to the process's stdin.
  pub fn write(&self, bytes: &[u8]) -> Result<()> {
    self.stream.write(bytes)
  }

  /// Closes the process's stdin. On a terminal, write ^D instead. Does
  /// nothing once the process has exited.
  pub fn close_input(&self) -> Result<()> {
    self.stream.send_while_open(Message::Eof).map(|_| ())
  }

  /// Resizes the process's terminal.
  pub fn resize(&self, size: WindowSize) -> Result<()> {
    self.stream.send(Message::Resize(size))
  }

  /// Sends the process a signal. Signal numbers are the guest's.
  pub fn signal(&self, signal: i32) -> Result<()> {
    self.stream.send(Message::Signal(signal))
  }

  /// Returns the process's next output, waiting as long as it takes.
  pub fn recv(&self) -> Result<Output> {
    self
      .next(None)?
      .ok_or_else(|| Error::Guest(format!("{}: no output", self.stream.what)))
  }

  /// Returns the process's next output, or `None` if none arrives within
  /// `timeout`.
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
        // Eof ends stdout. Exited follows it.
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

  /// Half-closes the connection.
  pub fn close_write(&self) -> Result<()> {
    self.stream.send(Message::Eof)
  }

  /// Returns the next bytes from the connection, or `None` once it has ended.
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

impl Listener {
  /// Stops the listener and waits for the agent to close and remove the
  /// socket.
  pub(crate) fn close(self) -> Result<()> {
    if !self.stream.send_while_open(Message::Eof)? {
      return Ok(());
    }

    loop {
      match self.stream.recv(Some(OPENING))? {
        Some(Message::Eof) => return Ok(()),
        Some(_) => {}
        None => {
          return Err(Error::Timeout(format!(
            "{}: the agent did not close it within {}s",
            self.stream.what,
            OPENING.as_secs()
          )));
        }
      }
    }
  }
}

/// Relays a connection the agent accepted to the host's socket at `host`.
fn relay_accepted(stream: Stream, host: &Path) {
  match UnixStream::connect(host) {
    Ok(local) => {
      if stream.send(Message::Opened).is_ok() {
        let relay = Relay {
          stream,
          ended: AtomicBool::new(false),
        };
        crate::socket::pump(relay, local);
      }
    }
    Err(error) => {
      let _ = stream.send(Message::Error(format!("connecting to {}: {error}", host.display())));
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

  /// Like `send`, but only if the channel is still open. Returns whether it
  /// was. A process's channel closes when the process exits, which can happen
  /// before the host has acted on Opened.
  fn send_while_open(&self, message: Message) -> Result<bool> {
    let mut state = self.shared.lock();
    if !state.mux.is_open(self.channel) {
      return Ok(false);
    }
    let frame = state
      .mux
      .send(self.channel, message)
      .map_err(|error| Error::Guest(format!("{}: {error}", self.what)))?;
    state.write(&frame)?;
    Ok(true)
  }

  fn write(&self, bytes: &[u8]) -> Result<()> {
    bytes
      .chunks(CHUNK)
      .try_for_each(|chunk| self.send(Message::Data(chunk.to_vec())))
  }

  /// Returns the next message, or `None` if none arrives within `timeout`.
  /// An Error message from the agent, or the end of the session, is returned
  /// as an error.
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
    state.forget(self.channel);
  }
}

impl Shared {
  fn lock(&self) -> MutexGuard<'_, State> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }
}

impl State {
  /// Writes `frame` in slices as the window makes room for them.
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

  /// Starts a new session, ending any current session and everything it ran.
  fn hello(&mut self) -> Result<()> {
    self.channels.clear();
    self.listeners.clear();
    let hello = self.mux.hello();
    self.write(&hello)
  }

  fn sync_clock(&mut self) -> Result<()> {
    if !self.mux.in_session() {
      return Ok(());
    }
    let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default();
    let time = Message::SetTime {
      seconds: now.as_secs(),
      nanoseconds: now.subsec_nanos(),
    };
    let frame = self
      .mux
      .send(CONTROL, time)
      .map_err(|error| Error::Guest(format!("setting the guest's clock: {error}")))?;
    self.write(&frame)
  }

  fn close(&mut self, channel: u32, reason: &str) {
    if let Ok(frame) = self.mux.send(channel, Message::Error(reason.to_string())) {
      let _ = self.write(&frame);
    }
  }

  fn forget(&mut self, channel: u32) {
    self.channels.remove(&channel);
    self.listeners.remove(&channel);
  }

  fn receive(&mut self, frame: Frame) -> Heard {
    let channel = frame.channel;

    match self.mux.receive(frame) {
      // The agent has no session because it just started or lost frames.
      Ok((_, Message::Hello { answer: false, .. })) => {
        let _ = self.hello();
        Heard::Nothing
      }
      // A session has started. The guest just booted or was restored, so its
      // clock may be behind.
      Ok((_, Message::Hello { answer: true, .. })) => {
        let _ = self.sync_clock();
        Heard::Changed
      }
      // The console reader thread has already counted it.
      Ok((_, Message::Received(_))) => Heard::Nothing,
      Ok((_, Message::Ping(number))) => {
        if let Ok(pong) = self.mux.send(channel, Message::Pong(number)) {
          let _ = self.write(&pong);
        }
        Heard::Nothing
      }
      Ok((_, Message::Accepted { listener })) => match self.listeners.get(&listener) {
        Some(host) => {
          let host = host.clone();
          let (sender, messages) = mpsc::channel();
          self.channels.insert(channel, sender);
          Heard::Accepted {
            channel,
            host,
            messages,
          }
        }
        // The listener closed while the agent was accepting the connection.
        None => {
          self.close(channel, "nothing listens there any more");
          Heard::Nothing
        }
      },
      Ok((_, message)) => {
        if let Some(sender) = self.channels.get(&channel) {
          let _ = sender.send(message);
        }
        if !self.mux.is_open(channel) {
          self.forget(channel);
        }
        Heard::Nothing
      }
      Err(containerization_freebsd_protocol::Error::Version(mismatch)) => {
        self.mismatch = Some(mismatch);
        Heard::Changed
      }
      // For example, a message that was in flight when its channel closed.
      Err(_) => Heard::Nothing,
    }
  }
}

impl Credit {
  /// Waits until the window has room, then reserves and returns up to
  /// `wanted` bytes of it.
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

  /// Updates the window from a frame the agent sent.
  fn hear(&self, frame: &Frame) {
    if frame.channel != CONTROL {
      return;
    }
    let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);

    match Message::from_frame(frame.clone()) {
      Ok(Message::Received(bytes)) => {
        window.unreceived = window.unreceived.saturating_sub(bytes as usize);
      }
      // The agent is new or starting over. Bytes the old agent never read
      // are lost, or the agent has already read past them.
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

/// Reads the console, counts the agent's Received reports, and passes
/// everything to the handler thread. This thread must never lock the
/// session's state, because a writer holds that lock while it waits for room.
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

/// Handles events from the console reader until the console closes.
fn handle(queue: &Receiver<Event>, shared: &Arc<Shared>) {
  let mut line = Vec::new();

  for event in queue {
    let mut state = shared.lock();
    let heard = match event {
      // Console text before a session usually explains why there is none,
      // such as first-boot.sh failing.
      Event::Read(bytes) => {
        if !state.mux.in_session() {
          echo(&mut line, &bytes);
        }
        Heard::Nothing
      }
      Event::Frame(frame) => state.receive(frame),
      // Frames were lost during a session, so start a new one.
      Event::Skipped if state.mux.in_session() => {
        let _ = state.hello();
        Heard::Nothing
      }
      Event::Skipped => Heard::Nothing,
    };
    match heard {
      Heard::Nothing => {}
      Heard::Changed => shared.changed.notify_all(),
      Heard::Accepted {
        channel,
        host,
        messages,
      } => {
        let stream = Stream {
          channel,
          shared: shared.clone(),
          messages: Mutex::new(messages),
          what: format!("a connection to {}", host.display()),
        };
        std::thread::spawn(move || relay_accepted(stream, &host));
      }
    }
  }

  let mut state = shared.lock();
  state.closed = true;
  state.channels.clear();
  state.listeners.clear();
  shared.changed.notify_all();
}

/// Copies the printable text in `bytes` to stderr, one line at a time.
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
pub(crate) mod tests {
  use super::*;
  use containerization_freebsd_protocol::VERSION;
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
