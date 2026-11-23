//! The session state an agent's handles share, and the thread that handles
//! what the agent sends.

use super::channel::{Stream, relay_accepted};
use super::console::{self, Credit, Outgoing};
use crate::error::{Error, Result};
use containerization_freebsd_protocol::{CONTROL, Frame, Message, Mux, Side, VersionMismatch};
use std::collections::HashMap;
use std::io::{PipeReader, PipeWriter};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct Shared {
  state: Mutex<State>,
  /// Notified when a session starts or fails, or the console closes.
  pub(super) changed: Condvar,
}

pub(super) struct State {
  pub(super) mux: Mux,
  /// The writer thread's queue. Frames go on it while the mux that made them
  /// is locked, so they reach the console in the order it made them.
  outgoing: Sender<Outgoing>,
  /// Where each open channel's messages go.
  pub(super) channels: HashMap<u32, Route>,
  pub(super) mismatch: Option<VersionMismatch>,
  pub(super) closed: bool,
  /// How many sessions have started.
  pub(super) sessions: u64,
}

/// Where an open channel's messages go.
pub(super) struct Route {
  pub(super) sender: mpsc::Sender<Message>,
  /// For a Listen channel, the host socket its connections are relayed to.
  pub(super) relay_to: Option<PathBuf>,
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

/// The result of writing a queued frame, which `wait` returns once the
/// writer thread has written it. Wait after unlocking the state, so that the
/// handler thread can route what the agent sends while the frame waits for
/// room in the window.
#[must_use]
pub(super) struct Written(Option<Receiver<Result<()>>>);

impl Written {
  /// Nothing was queued, so there is nothing to wait for.
  pub(super) fn nothing() -> Self {
    Self(None)
  }

  pub(super) fn wait(self) -> Result<()> {
    match self.0 {
      Some(written) => written
        .recv()
        .unwrap_or_else(|_| Err(Error::Guest("the thread writing to the console stopped".to_string()))),
      None => Ok(()),
    }
  }
}

impl Shared {
  /// Starts the console's reader on `output`, its writer on `input`, and the
  /// handler thread, and returns the state they share with the agent's
  /// handles.
  pub(super) fn start(output: PipeReader, input: PipeWriter) -> Arc<Self> {
    let credit = Arc::new(Credit::default());
    let (outgoing, queue) = mpsc::channel();
    let shared = Arc::new(Self {
      state: Mutex::new(State {
        mux: Mux::new(Side::Host),
        outgoing,
        channels: HashMap::new(),
        mismatch: None,
        closed: false,
        sessions: 0,
      }),
      changed: Condvar::new(),
    });
    let (events, inbound) = mpsc::channel();
    let reader = credit.clone();
    std::thread::spawn(move || console::read(output, &reader, &events));
    std::thread::spawn(move || console::write(&queue, input, &credit));
    let handler = shared.clone();
    std::thread::spawn(move || handle(&inbound, &handler));

    shared
  }

  pub(super) fn lock(&self) -> MutexGuard<'_, State> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }
}

impl State {
  /// Queues `frame` for the console, after every frame queued before it.
  pub(super) fn queue(&self, frame: Frame) -> Written {
    let (done, written) = mpsc::sync_channel(1);

    // If the writer thread has stopped, `wait` reports it.
    let _ = self.outgoing.send(Outgoing { frame, done });
    Written(Some(written))
  }

  /// Frames `message` for `channel` and queues it. Errors name what the
  /// message was for as `what`.
  pub(super) fn send(&mut self, channel: u32, message: Message, what: &str) -> Result<Written> {
    let frame = self
      .mux
      .send(channel, message)
      .map_err(Error::protocol(what))?;
    Ok(self.queue(frame))
  }

  /// Starts a new session, ending any current session and everything it ran.
  pub(super) fn hello(&mut self) -> Written {
    self.channels.clear();
    let hello = self.mux.hello();
    self.queue(hello)
  }

  pub(super) fn sync_clock(&mut self) -> Result<Written> {
    if !self.mux.in_session() {
      return Ok(Written::nothing());
    }
    let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default();
    let time = Message::SetTime {
      seconds: now.as_secs(),
      nanoseconds: now.subsec_nanos(),
    };
    self.send(CONTROL, time, "setting the guest's clock")
  }

  pub(super) fn close(&mut self, channel: u32, reason: &str) -> Written {
    self
      .send(channel, Message::Error(reason.to_string()), "closing a channel")
      .unwrap_or_else(|_| Written::nothing())
  }

  pub(super) fn forget(&mut self, channel: u32) {
    self.channels.remove(&channel);
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
        let _ = self.send(channel, Message::Pong(number), "answering a ping");
        Heard::Nothing
      }
      Ok((_, Message::Accepted { listener })) => match self
        .channels
        .get(&listener)
        .and_then(|route| route.relay_to.clone())
      {
        Some(host) => {
          let (sender, messages) = mpsc::channel();
          self
            .channels
            .insert(channel, Route { sender, relay_to: None });
          Heard::Accepted {
            channel,
            host,
            messages,
          }
        }
        // The listener closed while the agent was accepting the connection.
        None => {
          let _ = self.close(channel, "nothing listens there any more");
          Heard::Nothing
        }
      },
      Ok((_, message)) => {
        if let Some(route) = self.channels.get(&channel) {
          let _ = route.sender.send(message);
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

/// Handles events from the console reader until the console closes. What it
/// sends the agent, it queues without waiting for the write.
fn handle(inbound: &Receiver<Event>, shared: &Arc<Shared>) {
  let mut line = Vec::new();

  for event in inbound {
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
