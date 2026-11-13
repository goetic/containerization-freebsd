//! The host's end of the guest agent's protocol, over the console port.
//!
//! The host sends a Hello only when it must: in answer to the agent
//! announcing itself, after it lost frames, and once after a restore. Every
//! Hello the agent reads ends its session and what that session ran, so one
//! sent on a timer could arrive after the session it was meant to start,
//! and end it.

use crate::error::{Error, Result};
use containerization_freebsd_protocol::{Decoder, Exec, Frame, Message, Mux, Side, Skipped, VersionMismatch};
use std::collections::HashMap;
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub use containerization_freebsd_protocol::Exit;

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

struct Shared {
  state: Mutex<State>,
  /// Notified when a session starts, or the console closes.
  changed: Condvar,
}

struct State {
  mux: Mux,
  console: PipeWriter,
  /// Where each open channel's messages go: the command waiting on it.
  channels: HashMap<u32, mpsc::Sender<Message>>,
  mismatch: Option<VersionMismatch>,
  closed: bool,
}

impl Agent {
  pub(crate) fn new(output: PipeReader, input: PipeWriter) -> Self {
    let shared = Arc::new(Shared {
      state: Mutex::new(State {
        mux: Mux::new(Side::Host),
        console: input,
        channels: HashMap::new(),
        mismatch: None,
        closed: false,
      }),
      changed: Condvar::new(),
    });
    let reader = shared.clone();
    std::thread::spawn(move || read(output, &reader));

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

  /// Runs `argv` in the guest, with no input, and collects what it prints.
  /// One still running after `timeout` is killed.
  pub fn run(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    let started = Instant::now();
    let (sender, receiver) = mpsc::channel();
    let channel = self.shared.lock().exec(argv, Some(sender))?;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());

    loop {
      let left = timeout.saturating_sub(started.elapsed());

      match receiver.recv_timeout(left) {
        Ok(Message::Data(bytes)) => stdout.extend(bytes),
        Ok(Message::Stderr(bytes)) => stderr.extend(bytes),
        Ok(Message::Exited(exit)) => {
          return Ok(Ran {
            exit,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            seconds: started.elapsed().as_secs_f64(),
          });
        }
        Ok(Message::Error(reason)) => return Err(Error::Guest(format!("{argv:?}: {reason}"))),
        Ok(_) => {}
        Err(RecvTimeoutError::Timeout) => {
          // Error closes the channel, and the agent kills what it ran.
          self.shared.lock().close(channel, "timed out");
          return Err(Error::Timeout(format!(
            "{argv:?} did not finish within {}s",
            timeout.as_secs()
          )));
        }
        Err(RecvTimeoutError::Disconnected) => {
          return Err(Error::SessionEnded(format!("{argv:?} was running")));
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
    self.shared.lock().exec(argv, None).map(|_| ())
  }
}

impl Shared {
  fn lock(&self) -> MutexGuard<'_, State> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }
}

impl State {
  fn write(&mut self, frame: &Frame) -> Result<()> {
    self
      .console
      .write_all(&frame.to_bytes())
      .map_err(Error::io("writing to the guest agent"))
  }

  /// Starts a session; ends any there was, and what it ran.
  fn hello(&mut self) -> Result<()> {
    self.channels.clear();
    let hello = self.mux.hello();
    self.write(&hello)
  }

  /// Opens a channel running `argv`, whose messages go to `sender`.
  fn exec(&mut self, argv: &[&str], sender: Option<mpsc::Sender<Message>>) -> Result<u32> {
    let protocol = |error| Error::Guest(format!("{argv:?}: {error}"));
    let exec = Exec {
      argv: argv.iter().map(|arg| arg.to_string()).collect(),
      ..Exec::default()
    };

    let (channel, frame) = self.mux.open(Message::Exec(exec)).map_err(protocol)?;
    if let Some(sender) = sender {
      self.channels.insert(channel, sender);
    }
    self.write(&frame)?;
    let eof = self.mux.send(channel, Message::Eof).map_err(protocol)?;
    self.write(&eof)?;
    Ok(channel)
  }

  fn close(&mut self, channel: u32, reason: &str) {
    self.channels.remove(&channel);
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

fn read(mut output: PipeReader, shared: &Shared) {
  let mut decoder = Decoder::new();
  let mut buffer = vec![0; 64 << 10];

  while let Ok(read @ 1..) = output.read(&mut buffer) {
    decoder.push(&buffer[..read]);

    while let Some(decoded) = decoder.decode() {
      let mut state = shared.lock();
      let changed = match decoded {
        Ok(frame) => state.receive(frame),
        // Frames were lost mid-session: start over.
        Err(Skipped(_)) if state.mux.in_session() => {
          let _ = state.hello();
          false
        }
        Err(Skipped(_)) => false,
      };
      if changed {
        shared.changed.notify_all();
      }
    }
  }

  let mut state = shared.lock();
  state.closed = true;
  state.channels.clear();
  shared.changed.notify_all();
}

#[cfg(test)]
mod tests {
  use super::*;
  use containerization_freebsd_protocol::VERSION;

  const PATIENCE: Duration = Duration::from_secs(10);

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
}
