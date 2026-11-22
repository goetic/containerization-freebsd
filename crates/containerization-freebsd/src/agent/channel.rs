//! The channels the host opens with the agent: processes, relays and
//! listeners, each over a stream of the agent's messages.

use super::AGENT_TIMEOUT;
use super::session::Shared;
use crate::error::{Error, Result};
use containerization_freebsd_protocol::{Exit, Message, WINDOW, WindowSize};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// The largest Data payload the host sends, so that channels take turns on
/// the console.
const CHUNK: usize = WINDOW / 2;
/// The most `Relay::splice` reads from the host connection at once.
const READ: usize = 64 << 10;

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

  /// Waits up to `timeout` for the process to exit 0, discarding its stdout.
  /// Errors name the process by `what` and carry its stderr.
  pub(crate) fn finish(&self, what: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut stderr = Vec::new();

    loop {
      match self.recv_timeout(deadline.saturating_duration_since(Instant::now()))? {
        Some(Output::Exited(Exit::Code(0))) => return Ok(()),
        Some(Output::Exited(exit)) => {
          return Err(Error::Guest(format!(
            "{what} exited {exit:?}: {}",
            String::from_utf8_lossy(&stderr).trim()
          )));
        }
        Some(Output::Stderr(bytes)) => stderr.extend(bytes),
        Some(Output::Stdout(_)) => {}
        None => {
          return Err(Error::Timeout(format!(
            "{what} did not finish within {}s",
            timeout.as_secs()
          )));
        }
      }
    }
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

  /// Relays between the connection and `local`, a host connection, until
  /// both directions finish.
  pub(crate) fn splice(self, local: UnixStream) {
    let Ok(mut to_local) = local.try_clone() else {
      return;
    };
    let relay = Arc::new(self);
    let back = {
      let relay = relay.clone();
      thread::spawn(move || {
        loop {
          match relay.read() {
            Ok(Some(bytes)) if to_local.write_all(&bytes).is_ok() => {}
            Ok(None) => {
              let _ = to_local.shutdown(Shutdown::Write);
              return;
            }
            // If either end failed, shut down the other one too.
            _ => {
              let _ = to_local.shutdown(Shutdown::Both);
              return;
            }
          }
        }
      })
    };

    let mut from_local = local;
    let mut buffer = vec![0; READ];
    loop {
      match from_local.read(&mut buffer) {
        Ok(0) => break,
        Ok(read) => {
          if relay.write(&buffer[..read]).is_err() {
            break;
          }
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
        Err(_) => break,
      }
    }
    let _ = relay.close_write();
    let _ = back.join();
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
      match self.stream.recv(Some(AGENT_TIMEOUT))? {
        Some(Message::Eof) => return Ok(()),
        Some(_) => {}
        None => {
          return Err(Error::Timeout(format!(
            "{}: the agent did not close it within {}s",
            self.stream.what,
            AGENT_TIMEOUT.as_secs()
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
        Relay::new(stream).splice(local);
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
    match self.recv(Some(AGENT_TIMEOUT))? {
      Some(Message::Opened) => Ok(self),
      Some(other) => Err(Error::Guest(format!(
        "{}: the agent sent {} before opened",
        self.what,
        other.name()
      ))),
      None => Err(Error::Timeout(format!(
        "{}: the agent did not open it within {}s",
        self.what,
        AGENT_TIMEOUT.as_secs()
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::agent::Exec;
  use crate::agent::Spawn;
  use crate::agent::tests::started;

  #[test]
  fn finish_times_out_while_the_process_writes_to_stderr() {
    let agent = started();
    // Writes to stderr every 100ms for 5s, then exits 0.
    let process = agent
      .spawn(Exec::new([
        "sh",
        "-c",
        "for i in $(seq 50); do echo $i >&2; sleep 0.1; done",
      ]))
      .unwrap();
    let started = Instant::now();

    let result = process.finish("writing", Duration::from_millis(500));

    assert!(matches!(result, Err(Error::Timeout(_))), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
  }

  #[test]
  fn finish_reports_a_failure_with_its_stderr() {
    let agent = started();
    let process = agent
      .spawn(Exec::new(["sh", "-c", "echo out; echo broken >&2; exit 3"]))
      .unwrap();

    let result = process.finish("writing", Duration::from_secs(10));

    assert!(
      matches!(&result, Err(Error::Guest(message)) if message == "writing exited Code(3): broken"),
      "{result:?}"
    );
  }
}
