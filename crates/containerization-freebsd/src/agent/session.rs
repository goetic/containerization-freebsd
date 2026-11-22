//! The session state an agent's handles share, and the thread that handles
//! what the agent sends.

use super::channel::{Stream, relay_accepted};
use super::credit::{self, Credit};
use crate::error::{Error, Result};
use containerization_freebsd_protocol::{CONTROL, Frame, Message, Mux, Side, VersionMismatch};
use std::collections::HashMap;
use std::io::{PipeReader, PipeWriter, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct Shared {
  state: Mutex<State>,
  /// Notified when a session starts or fails, or the console closes.
  pub(super) changed: Condvar,
}

pub(super) struct State {
  pub(super) mux: Mux,
  console: PipeWriter,
  credit: Arc<Credit>,
  /// The sender for each open channel's messages.
  pub(super) channels: HashMap<u32, mpsc::Sender<Message>>,
  /// For each open Listen channel, the host socket its connections relay to.
  pub(super) listeners: HashMap<u32, PathBuf>,
  pub(super) mismatch: Option<VersionMismatch>,
  pub(super) closed: bool,
  /// How many sessions have started.
  pub(super) sessions: u64,
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
pub(super) enum Event {
  /// Raw bytes as read, so that console text before a session can be shown.
  Read(Vec<u8>),
  Frame(Frame),
  Skipped,
}

impl Shared {
  /// Starts the console reader on `output` and the handler thread, and
  /// returns the state they share with the agent's handles, which write to
  /// the console through `input`.
  pub(super) fn start(output: PipeReader, input: PipeWriter) -> Arc<Self> {
    let credit = Arc::new(Credit::default());
    let shared = Arc::new(Self {
      state: Mutex::new(State {
        mux: Mux::new(Side::Host),
        console: input,
        credit: credit.clone(),
        channels: HashMap::new(),
        listeners: HashMap::new(),
        mismatch: None,
        closed: false,
        sessions: 0,
      }),
      changed: Condvar::new(),
    });
    let (events, queue) = mpsc::channel();
    std::thread::spawn(move || credit::read(output, &credit, &events));
    let handler = shared.clone();
    std::thread::spawn(move || handle(&queue, &handler));

    shared
  }

  pub(super) fn lock(&self) -> MutexGuard<'_, State> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }
}

impl State {
  /// Writes `frame` in slices as the window makes room for them.
  pub(super) fn write(&mut self, frame: &Frame) -> Result<()> {
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
  pub(super) fn hello(&mut self) -> Result<()> {
    self.channels.clear();
    self.listeners.clear();
    let hello = self.mux.hello();
    self.write(&hello)
  }

  pub(super) fn sync_clock(&mut self) -> Result<()> {
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

  pub(super) fn close(&mut self, channel: u32, reason: &str) {
    if let Ok(frame) = self.mux.send(channel, Message::Error(reason.to_string())) {
      let _ = self.write(&frame);
    }
  }

  pub(super) fn forget(&mut self, channel: u32) {
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
        self.sessions += 1;
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

/// Handles events from the console reader until the console closes.
fn handle(queue: &Receiver<Event>, shared: &Arc<Shared>) {
  let mut line = Vec::new();

  for event in queue {
    let mut state = shared.lock();
    let heard = match event {
      // Console text before a session usually explains why there is none,
      // such as the seed's user-data script failing.
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
        let what = format!("a connection to {}", host.display());
        let stream = Stream::new(channel, shared.clone(), messages, what);
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
