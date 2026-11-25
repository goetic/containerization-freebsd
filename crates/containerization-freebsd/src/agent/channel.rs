//! The channels the host opens with the agent: processes, relays and
//! listeners, each over a stream of the agent's messages.

use super::session;
use crate::error;
use containerization_freebsd_protocol::{message, mux};
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
const CHUNK: usize = mux::WINDOW / 2;

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
  Exited(message::Exit),
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
  shared: Arc<session::Shared>,
  messages: Mutex<Receiver<message::Message>>,
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
  pub fn write(&self, bytes: &[u8]) -> error::Result<()> {
    self.stream.write(bytes)
  }

  /// Closes the process's stdin. On a terminal, write ^D instead. Does
  /// nothing once the process has exited.
  pub fn close_input(&self) -> error::Result<()> {
    self
      .stream
      .send_while_open(message::Message::Eof)
      .map(|_| ())
  }

  /// Resizes the process's terminal.
  pub fn resize(&self, size: message::WindowSize) -> error::Result<()> {
    self.stream.send(message::Message::Resize(size))
  }

  /// Sends the process a signal. Signal numbers are the guest's.
  pub fn signal(&self, signal: i32) -> error::Result<()> {
    self.stream.send(message::Message::Signal(signal))
  }

  /// Returns the process's next output, waiting as long as it takes.
  pub fn recv(&self) -> error::Result<Output> {
    self.check_running()?;
    loop {
      if let Some(output) = self.output(self.stream.recv()?) {
        return Ok(output);
      }
    }
  }

  /// Returns the process's next output, or `None` if none arrives within
  /// `timeout`.
  pub fn recv_timeout(&self, timeout: Duration) -> error::Result<Option<Output>> {
    self.check_running()?;
    loop {
      let Some(message) = self.stream.recv_timeout(timeout)? else {
        return Ok(None);
      };
      if let Some(output) = self.output(message) {
        return Ok(Some(output));
      }
    }
  }

  /// Waits for the process to exit, writing its stdout to `stdout` and its
  /// stderr to `stderr`, and returns how it exited.
  pub fn wait(&self, stdout: &mut dyn Write, stderr: &mut dyn Write) -> error::Result<message::Exit> {
    loop {
      if let Some(exit) = self.write_out(self.recv()?, stdout, stderr)? {
        return Ok(exit);
      }
    }
  }

  /// Like `wait`, but returns `None` once `timeout` has passed in all,
  /// however much output arrives meanwhile. Dropping the process then kills
  /// it.
  pub fn wait_timeout(
    &self,
    timeout: Duration,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
  ) -> error::Result<Option<message::Exit>> {
    let deadline = Instant::now() + timeout;

    loop {
      let Some(output) = self.recv_timeout(deadline.saturating_duration_since(Instant::now()))? else {
        return Ok(None);
      };
      if let Some(exit) = self.write_out(output, stdout, stderr)? {
        return Ok(Some(exit));
      }
    }
  }

  /// Waits up to `timeout`, if given, for the process to exit 0, writing its
  /// stdout to `stdout`. Errors describe the process by `what` and carry its
  /// stderr.
  pub(crate) fn finish(&self, what: &str, timeout: Option<Duration>, stdout: &mut dyn Write) -> error::Result<()> {
    let mut stderr = Vec::new();
    let exit = match timeout {
      None => self.wait(stdout, &mut stderr)?,
      Some(timeout) => self
        .wait_timeout(timeout, stdout, &mut stderr)?
        .ok_or_else(|| error::Error::Timeout(format!("{what} did not finish within {}s", timeout.as_secs())))?,
    };

    if exit.success() {
      return Ok(());
    }
    Err(error::Error::Guest(format!(
      "{what} exited with {exit}: {}",
      String::from_utf8_lossy(&stderr).trim()
    )))
  }

  /// Writes what it reads from `source` to the process's stdin, closes stdin,
  /// and waits for the process to exit 0 as `finish` does, discarding its
  /// stdout. If the process exits early, writing fails, and the process's
  /// own failure is the error returned. Errors reading `source` name it
  /// `source_what`.
  pub(crate) fn feed(
    &self,
    source: &mut dyn Read,
    source_what: &str,
    what: &str,
    timeout: Option<Duration>,
  ) -> error::Result<()> {
    let sent = match io::copy(source, &mut &*self) {
      Ok(_) => self.close_input(),
      // Only writing to the process wraps an `Error`.
      Err(error) => match error.downcast::<error::Error>() {
        Ok(error) => Err(error),
        // The caller drops the process, which kills it.
        Err(error) => return Err(error::Error::io(format!("reading {source_what}"))(error)),
      },
    };

    self.finish(what, timeout, &mut io::sink()).and(sent)
  }

  /// Writes `output` to `stdout` or `stderr`, or returns the exit it reports.
  fn write_out(
    &self,
    output: Output,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
  ) -> error::Result<Option<message::Exit>> {
    let written = match output {
      Output::Stdout(bytes) => stdout.write_all(&bytes),
      Output::Stderr(bytes) => stderr.write_all(&bytes),
      Output::Exited(exit) => return Ok(Some(exit)),
    };
    // This runs for every chunk of output, so the message is built only on
    // failure.
    written.map_err(|error| error::Error::Io {
      action: format!("writing the output of {}", self.stream.what),
      error,
    })?;
    Ok(None)
  }

  /// Fails once the process has exited, since nothing follows Exited.
  fn check_running(&self) -> error::Result<()> {
    if self.exited.load(Ordering::Relaxed) {
      return Err(error::Error::Guest(format!("{} has exited", self.stream.what)));
    }
    Ok(())
  }

  /// The output `message` carries, if any.
  fn output(&self, message: message::Message) -> Option<Output> {
    match message {
      message::Message::Data(bytes) => Some(Output::Stdout(bytes)),
      message::Message::Stderr(bytes) => Some(Output::Stderr(bytes)),
      message::Message::Exited(exit) => {
        self.exited.store(true, Ordering::Relaxed);
        Some(Output::Exited(exit))
      }
      // Eof ends stdout. Exited follows it.
      _ => None,
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
  pub fn write(&self, bytes: &[u8]) -> error::Result<()> {
    self.stream.write(bytes)
  }

  /// Half-closes the connection.
  pub fn close_write(&self) -> error::Result<()> {
    self.stream.send(message::Message::Eof)
  }

  /// Returns the next bytes from the connection, or `None` once it has ended.
  pub fn read(&self) -> error::Result<Option<Vec<u8>>> {
    if self.ended.load(Ordering::Relaxed) {
      return Ok(None);
    }

    loop {
      match self.stream.recv()? {
        message::Message::Data(bytes) => return Ok(Some(bytes)),
        message::Message::Eof => {
          self.ended.store(true, Ordering::Relaxed);
          return Ok(None);
        }
        _ => {}
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

    // Either end failing ends this direction.
    let _ = io::copy(&mut &local, &mut &*relay);
    let _ = relay.close_write();
    let _ = back.join();
  }
}

/// Writes to the process's stdin, as `Process::write` does. A failed write's
/// `io::Error` wraps the crate's `Error`.
impl Write for &Process {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    Process::write(self, bytes).map_err(io::Error::other)?;
    Ok(bytes.len())
  }

  fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }
}

/// Writes to the connection, as `Relay::write` does. A failed write's
/// `io::Error` wraps the crate's `Error`.
impl Write for &Relay {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    Relay::write(self, bytes).map_err(io::Error::other)?;
    Ok(bytes.len())
  }

  fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }
}

impl Listener {
  pub(super) fn new(stream: Stream) -> Self {
    Self { stream }
  }

  /// Stops the listener and waits for the agent to close and remove the
  /// socket.
  pub(crate) fn close(self) -> error::Result<()> {
    if !self.stream.send_while_open(message::Message::Eof)? {
      return Ok(());
    }

    loop {
      match self.stream.recv_timeout(super::AGENT_TIMEOUT)? {
        Some(message::Message::Eof) => return Ok(()),
        Some(_) => {}
        None => {
          return Err(error::Error::Timeout(format!(
            "{}: the agent did not close it within {}s",
            self.stream.what,
            super::AGENT_TIMEOUT.as_secs()
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
      if stream.send(message::Message::Opened).is_ok() {
        Relay::new(stream).splice(local);
      }
    }
    Err(error) => {
      let _ = stream.send(message::Message::Error(format!(
        "connecting to {}: {error}",
        host.display()
      )));
    }
  }
}

impl Stream {
  pub(super) fn new(
    channel: u32,
    shared: Arc<session::Shared>,
    messages: Receiver<message::Message>,
    what: String,
  ) -> Self {
    Self {
      channel,
      shared,
      messages: Mutex::new(messages),
      what,
    }
  }

  /// Waits for the agent to send Opened on the new channel.
  pub(super) fn opened(self) -> error::Result<Self> {
    match self.recv_timeout(super::AGENT_TIMEOUT)? {
      Some(message::Message::Opened) => Ok(self),
      Some(other) => Err(error::Error::Guest(format!(
        "{}: the agent sent {} before opened",
        self.what,
        other.name()
      ))),
      None => Err(error::Error::Timeout(format!(
        "{}: the agent did not open it within {}s",
        self.what,
        super::AGENT_TIMEOUT.as_secs()
      ))),
    }
  }

  /// Waits up to `timeout` for the agent's answer on a channel that carries
  /// just one message from it, such as a Call channel. An Error fails the
  /// channel.
  pub(super) fn answer(&self, timeout: Duration) -> error::Result<message::Message> {
    match self.recv_timeout(timeout)? {
      Some(message) => Ok(message),
      None => Err(error::Error::Timeout(format!(
        "{}: the agent did not answer within {}s",
        self.what,
        timeout.as_secs()
      ))),
    }
  }

  /// The error for a message from the agent that the channel didn't expect.
  pub(super) fn unexpected(&self, message: &message::Message) -> error::Error {
    error::Error::Guest(format!("{}: the agent sent {}", self.what, message.name()))
  }

  /// The error for a Return that doesn't answer the channel's Call.
  pub(super) fn misreturned(&self) -> error::Error {
    error::Error::Guest(format!("{}: the agent returned the wrong kind of answer", self.what))
  }

  fn send(&self, message: message::Message) -> error::Result<()> {
    let written = self.shared.lock().send(self.channel, message, &self.what)?;
    written.wait()
  }

  /// Like `send`, but only if the channel is still open. Returns whether it
  /// was. A process's channel closes when the process exits, which can happen
  /// before the host has acted on Opened.
  fn send_while_open(&self, message: message::Message) -> error::Result<bool> {
    let written = {
      let mut state = self.shared.lock();
      if !state.mux.is_open(self.channel) {
        return Ok(false);
      }
      state.send(self.channel, message, &self.what)?
    };
    written.wait()?;
    Ok(true)
  }

  /// Sends `bytes` as Data in chunks, each framed straight from the slice.
  fn write(&self, bytes: &[u8]) -> error::Result<()> {
    bytes.chunks(CHUNK).try_for_each(|chunk| {
      let written = self
        .shared
        .lock()
        .send_data(self.channel, chunk, &self.what)?;
      written.wait()
    })
  }

  /// Returns the next message, waiting as long as it takes. An Error message
  /// from the agent, or the end of the session, is returned as an error.
  fn recv(&self) -> error::Result<message::Message> {
    let messages = self.messages.lock().unwrap_or_else(PoisonError::into_inner);
    let message = messages.recv().map_err(|_| self.session_ended())?;

    self.unless_error(message)
  }

  /// Like `recv`, but returns `None` if no message arrives within `timeout`.
  fn recv_timeout(&self, timeout: Duration) -> error::Result<Option<message::Message>> {
    let messages = self.messages.lock().unwrap_or_else(PoisonError::into_inner);

    match messages.recv_timeout(timeout) {
      Ok(message) => self.unless_error(message).map(Some),
      Err(RecvTimeoutError::Timeout) => Ok(None),
      Err(RecvTimeoutError::Disconnected) => Err(self.session_ended()),
    }
  }

  /// `message`, unless it is the agent's Error, which fails the channel.
  fn unless_error(&self, message: message::Message) -> error::Result<message::Message> {
    match message {
      message::Message::Error(reason) => Err(error::Error::Guest(format!("{}: {reason}", self.what))),
      message => Ok(message),
    }
  }

  fn session_ended(&self) -> error::Error {
    error::Error::SessionEnded(format!("{} was open", self.what))
  }
}

impl Drop for Stream {
  /// Closes the channel if it is still open, which kills the process or
  /// closes the connection.
  fn drop(&mut self) {
    let written = {
      let mut state = self.shared.lock();
      let written = if state.channels.contains_key(&self.channel) && state.mux.is_open(self.channel) {
        state.close(self.channel, "closed by the host")
      } else {
        session::Written::nothing()
      };
      state.forget(self.channel);
      written
    };
    let _ = written.wait();
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::agent::{self, Spawn};

  /// Far longer than any of these tests' commands take.
  const TIMEOUT: Option<Duration> = Some(Duration::from_secs(10));

  #[test]
  fn waits_for_the_exit_keeping_stdout_and_stderr_apart() {
    let agent = agent::tests::started();
    let process = agent
      .spawn(message::Exec::new(["sh", "-c", "echo out; echo err >&2; exit 2"]))
      .unwrap();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());

    let exit = process.wait(&mut stdout, &mut stderr).unwrap();

    assert_eq!(
      (exit, stdout.as_slice(), stderr.as_slice()),
      (message::Exit::Code(2), &b"out\n"[..], &b"err\n"[..])
    );
  }

  #[test]
  fn finish_times_out_while_the_process_writes_to_stderr() {
    let agent = agent::tests::started();
    // Writes to stderr every 100ms for 5s, then exits 0.
    let process = agent
      .spawn(message::Exec::new([
        "sh",
        "-c",
        "for i in $(seq 50); do echo $i >&2; sleep 0.1; done",
      ]))
      .unwrap();
    let started = Instant::now();

    let result = process.finish("writing", Some(Duration::from_millis(500)), &mut io::sink());

    assert!(matches!(result, Err(error::Error::Timeout(_))), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
  }

  #[test]
  fn finish_reports_a_failure_with_its_stderr() {
    let agent = agent::tests::started();
    let process = agent
      .spawn(message::Exec::new(["sh", "-c", "echo out; echo broken >&2; exit 3"]))
      .unwrap();
    let mut stdout = Vec::new();

    let result = process.finish("writing", TIMEOUT, &mut stdout);

    assert!(
      matches!(&result, Err(error::Error::Guest(message)) if message == "writing exited with status 3: broken"),
      "{result:?}"
    );
    assert_eq!(stdout, b"out\n");
  }

  #[test]
  fn feeds_a_reader_to_stdin() {
    let agent = agent::tests::started();
    let process = agent
      .spawn(message::Exec::new(["sh", "-c", "[ $(wc -c) -eq 1000000 ]"]))
      .unwrap();

    process
      .feed(&mut io::repeat(b'x').take(1_000_000), "the input", "counting", TIMEOUT)
      .unwrap();
  }

  #[test]
  fn reports_a_source_it_cannot_read() {
    struct Unreadable;

    impl Read for Unreadable {
      fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("the disk is gone"))
      }
    }

    let agent = agent::tests::started();
    let process = agent.spawn(message::Exec::new(["cat"])).unwrap();

    let result = process.feed(&mut Unreadable, "the input", "copying", TIMEOUT);

    assert!(
      matches!(&result, Err(error::Error::Io { action, .. }) if action == "reading the input"),
      "{result:?}"
    );
  }

  #[test]
  fn reports_why_a_process_stopped_reading() {
    let agent = agent::tests::started();
    let process = agent
      .spawn(message::Exec::new(["sh", "-c", "echo refused >&2; exit 3"]))
      .unwrap();

    let result = process.feed(&mut io::repeat(b'x').take(16 << 20), "the input", "refusing", TIMEOUT);

    assert!(
      matches!(&result, Err(error::Error::Guest(message)) if message == "refusing exited with status 3: refused"),
      "{result:?}"
    );
  }
}
