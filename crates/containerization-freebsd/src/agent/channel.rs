//! The channels the host opens with the agent: processes, relays and
//! listeners, each over a stream of the agent's messages.

use super::OPENING;
use super::session::Shared;
use crate::error::{Error, Result};
use containerization_freebsd_protocol::{Exit, Message, WINDOW, WindowSize};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// The largest Data payload the host sends, so that channels take turns on
/// the console.
const CHUNK: usize = WINDOW / 2;

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
pub(super) struct Stream {
  channel: u32,
  shared: Arc<Shared>,
  messages: Mutex<Receiver<Message>>,
  /// A description of the process or socket, for error messages.
  what: String,
}

impl Process {
  pub(super) fn new(stream: Stream) -> Self {
    Self {
      stream,
      exited: AtomicBool::new(false),
    }
  }

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
  pub(super) fn new(stream: Stream) -> Self {
    Self {
      stream,
      ended: AtomicBool::new(false),
    }
  }

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
  pub(super) fn new(stream: Stream) -> Self {
    Self { stream }
  }

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
pub(super) fn relay_accepted(stream: Stream, host: &Path) {
  match UnixStream::connect(host) {
    Ok(local) => {
      if stream.send(Message::Opened).is_ok() {
        crate::socket::pump(Relay::new(stream), local);
      }
    }
    Err(error) => {
      let _ = stream.send(Message::Error(format!("connecting to {}: {error}", host.display())));
    }
  }
}

impl Stream {
  pub(super) fn new(channel: u32, shared: Arc<Shared>, messages: Receiver<Message>, what: String) -> Self {
    Self {
      channel,
      shared,
      messages: Mutex::new(messages),
      what,
    }
  }

  /// Waits for the agent to send Opened on the new channel.
  pub(super) fn opened(self) -> Result<Self> {
    match self.recv(Some(OPENING))? {
      Some(Message::Opened) => Ok(self),
      Some(other) => Err(Error::Guest(format!(
        "{}: the agent sent {} before opened",
        self.what,
        other.name()
      ))),
      None => Err(Error::Timeout(format!(
        "{}: the agent did not open it within {}s",
        self.what,
        OPENING.as_secs()
      ))),
    }
  }

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
