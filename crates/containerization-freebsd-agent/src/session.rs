//! The session loop. One thread owns the protocol state and is the only
//! writer to the console. The channels' threads send it events, and the
//! console reader passes it the host's bytes on a queue of their own, which
//! the loop empties before it takes each event.

use crate::listener::{self, Listening};
use crate::pipe::{READ, Stopped, read_chunks};
use crate::process::{self, Process};
use crate::relay::{self, Connection};
use crate::{call, sys};
use containerization_freebsd_protocol::{
  CONTROL, Call, Connect, Decoder, Error, Exec, Frame, Listen, Message, Mux, Side, Skipped,
};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};

/// The event queue is bounded, so a channel whose output outpaces the console
/// blocks until the console catches up.
const QUEUE: usize = 64;
/// The most bytes of frames the loop gathers before writing them. A full
/// read's Data frame reaches it alone, so it goes out at once.
const BATCH: usize = READ;

/// What the console reader passes the session loop. Its queue is unbounded,
/// but the host sends no more than the window allows before the loop reports
/// what it read.
enum FromConsole {
  Read(Vec<u8>),
  /// The console's read end closed or failed.
  Closed(io::Result<()>),
}

// Nearly every event carries a Message, so boxing it would cost an
// allocation per event and save nothing.
#[allow(clippy::large_enum_variant)]
enum Event {
  /// Wakes the session loop for what the console reader has queued.
  Console,
  /// A message a channel's thread has for the host.
  Channel { id: u64, channel: u32, message: Message },
  /// A new connection to the socket of the Listen channel `listener`.
  Accepted { id: u64, listener: u32, stream: UnixStream },
}

/// Where a channel's threads send messages for the host. Each opened channel
/// gets a unique id, so messages from a closed channel, or from an earlier
/// session, never reach a later channel that reuses the same number.
#[derive(Clone)]
pub(crate) struct Outbox {
  events: SyncSender<Event>,
  id: u64,
  channel: u32,
}

impl Outbox {
  /// Returns false once the session loop has stopped.
  pub(crate) fn send(&self, message: Message) -> bool {
    self
      .events
      .send(Event::Channel {
        id: self.id,
        channel: self.channel,
        message,
      })
      .is_ok()
  }

  /// Passes the session loop a connection accepted on this Listen channel's
  /// socket. Returns false once the session loop has stopped.
  pub(crate) fn accepted(&self, stream: UnixStream) -> bool {
    self
      .events
      .send(Event::Accepted {
        id: self.id,
        listener: self.channel,
        stream,
      })
      .is_ok()
  }
}

/// Input from the host for a channel's threads.
pub(crate) enum Input {
  Data(Vec<u8>),
  Eof,
}

/// The session loop's handle on the process, relay or listener that an open
/// channel runs.
pub(crate) enum Handle {
  Process {
    input: Sender<Input>,
    process: Arc<Process>,
  },
  Relay {
    input: Sender<Input>,
    connection: Arc<Connection>,
  },
  Listener(Listening),
}

impl Handle {
  /// Ends the channel's work early: kills the process and its group, shuts
  /// down the relay's connection, or closes the listener's socket by dropping
  /// it.
  fn stop(self) {
    match self {
      Self::Process { process, .. } => process.kill(),
      Self::Relay { connection, .. } => {
        let _ = connection.shutdown(Shutdown::Both);
      }
      Self::Listener(_) => {}
    }
  }
}

struct Open {
  id: u64,
  handle: Handle,
}

struct Agent<W> {
  mux: Mux,
  decoder: Decoder,
  output: W,
  events: SyncSender<Event>,
  channels: HashMap<u32, Open>,
  ids: u64,
  /// Whether the agent has announced itself since its last session ended.
  /// Frames from the old session that are still in flight then draw one
  /// announcement in total, not one each.
  announced: bool,
  /// Frames waiting to be written. The loop writes them before it waits for
  /// an event, or once there are `BATCH` bytes of them, so the frames it
  /// sends in between share one write.
  pending: Vec<u8>,
}

/// Serves sessions over a console until its read end closes. The agent
/// announces itself, answers the host's Hellos, and runs what the host's
/// channels request. Returns an error only if reading or writing the console
/// fails.
pub fn serve(input: impl Read + Send + 'static, output: impl Write) -> io::Result<()> {
  let (events, queue) = mpsc::sync_channel(QUEUE);
  let (console, from_console) = mpsc::channel();
  let wake = events.clone();
  std::thread::spawn(move || read(input, &console, &wake));

  let mut agent = Agent {
    mux: Mux::new(Side::Guest),
    decoder: Decoder::new(),
    output,
    events,
    channels: HashMap::new(),
    ids: 0,
    announced: false,
    pending: Vec::new(),
  };
  let result = agent.run(&queue, &from_console);
  agent.end_channels();
  result
}

/// Passes what the console reads to the session loop, and wakes the loop
/// for it unless the event queue is full. A full queue means the loop is
/// busy, and it empties the reader's queue before taking its next event.
fn read(input: impl Read, console: &Sender<FromConsole>, wake: &SyncSender<Event>) {
  let pass = |from_console| {
    let passed = console.send(from_console).is_ok();
    let _ = wake.try_send(Event::Console);
    passed
  };

  let closed = match read_chunks(input, |bytes| pass(FromConsole::Read(bytes))) {
    Stopped::Eof => Ok(()),
    // The session loop has stopped.
    Stopped::Refused => return,
    Stopped::Failed(error) => Err(error),
  };
  pass(FromConsole::Closed(closed));
}

impl<W: Write> Agent<W> {
  fn run(&mut self, queue: &Receiver<Event>, from_console: &Receiver<FromConsole>) -> io::Result<()> {
    self.announce();

    loop {
      // The host's bytes go ahead of the channels' queued output, so the
      // host's input, and the Received that lets it send more, wait for no
      // more than the frame being written.
      while let Ok(from_console) = from_console.try_recv() {
        match from_console {
          FromConsole::Read(bytes) => self.console(&bytes),
          FromConsole::Closed(result) => return self.flush().and(result),
        }
      }

      let event = match queue.try_recv() {
        Ok(event) => event,
        Err(_) => {
          // Nothing else is ready, so write what has gathered before waiting.
          self.flush()?;
          // The agent holds a sender itself, so the queue never disconnects.
          let Ok(event) = queue.recv() else {
            return Ok(());
          };
          event
        }
      };
      match event {
        Event::Console => {}
        Event::Channel { id, channel, message } => {
          if self.holds(channel, id) {
            self.send(channel, message);
          }
        }
        Event::Accepted { id, listener, stream } => {
          if self.holds(listener, id) {
            self.accepted(listener, stream);
          }
        }
      }
      if self.pending.len() >= BATCH {
        self.flush()?;
      }
    }
  }

  /// Whether `channel` is open and is still the opening identified by `id`.
  fn holds(&self, channel: u32, id: u64) -> bool {
    self
      .channels
      .get(&channel)
      .is_some_and(|open| open.id == id)
  }

  fn console(&mut self, bytes: &[u8]) {
    // These bytes have left the tty's input queue, so the host may send that
    // many more.
    let read = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    self.send(CONTROL, Message::Received(read));
    self.decoder.push(bytes);

    while let Some(decoded) = self.decoder.decode() {
      match decoded {
        Ok(frame) => self.receive(frame),
        // Frames were lost. The announcement makes the host start a new
        // session.
        Err(Skipped(count)) => {
          eprintln!("agent: dropped {count} bytes between frames");
          self.announce();
        }
      }
    }
  }

  fn receive(&mut self, frame: Frame) {
    let channel = frame.channel;

    match self.mux.receive(frame) {
      // The host's Hello starts a session. The agent answers even when the
      // versions differ, so the host learns the agent's version.
      Ok((_, Message::Hello { .. })) | Err(Error::Version(_)) => {
        self.end_channels();
        self.announced = false;
        let answer = self.mux.hello();
        self.write(&answer);
      }
      Ok((_, Message::Ping(number))) => self.send(CONTROL, Message::Pong(number)),
      Ok((_, Message::SetTime { seconds, nanoseconds })) => {
        if let Err(error) = sys::set_time(seconds, nanoseconds) {
          eprintln!("agent: setting the clock: {error}");
        }
      }
      Ok((_, Message::Exec(exec))) => self.exec(channel, &exec),
      Ok((_, Message::Connect(connect))) => self.connect(channel, &connect),
      Ok((_, Message::Listen(listen))) => self.listen(channel, &listen),
      Ok((_, Message::Call(call))) => self.call(channel, &call),
      Ok((_, message)) => self.deliver(channel, message),
      // The host has a session that the agent does not. The agent announces
      // itself once so the host starts a new one; frames still arriving
      // from the old session are then dropped.
      Err(Error::NoSession) if !self.announced => self.announce(),
      // A frame from the old session after the announcement, or one that
      // crossed its channel's close in flight.
      Err(Error::NoSession | Error::UnknownChannel(_)) => {}
      Err(error) => eprintln!("agent: refused a frame on channel {channel}: {error}"),
    }
  }

  /// Passes the host's message to an open channel.
  fn deliver(&mut self, channel: u32, message: Message) {
    let Some(open) = self.channels.get_mut(&channel) else {
      return;
    };
    let ends = matches!(message, Message::Error(_));

    let result = match (message, &mut open.handle) {
      (Message::Data(bytes), Handle::Process { input, .. } | Handle::Relay { input, .. }) => {
        let _ = input.send(Input::Data(bytes));
        Ok(())
      }
      (Message::Eof, Handle::Process { input, .. } | Handle::Relay { input, .. }) => {
        let _ = input.send(Input::Eof);
        Ok(())
      }
      (Message::Eof, Handle::Listener(listening)) => listening.remove(),
      (Message::Resize(size), Handle::Process { process, .. }) => process.resize(size),
      (Message::Signal(signal), Handle::Process { process, .. }) => process.signal(signal),
      (Message::Error(reason), _) => {
        eprintln!("agent: the host closed channel {channel}: {reason}");
        Ok(())
      }
      _ => Ok(()),
    };
    if let Err(error) = result {
      eprintln!("agent: channel {channel}: {error}");
    }

    // If the host's message closed the channel, forget it. Only an Error
    // stops the channel's work. A relay closed by the final Eof is left to
    // write the Data queued before it and then half-close.
    if !self.mux.is_open(channel)
      && let Some(open) = self.channels.remove(&channel)
      && ends
    {
      open.handle.stop();
    }
  }

  fn exec(&mut self, channel: u32, exec: &Exec) {
    // spawn's errors already say which step failed, so they need no prefix.
    self.start(channel, |outbox| {
      process::spawn(exec, outbox).map_err(|error| error.to_string())
    });
  }

  fn connect(&mut self, channel: u32, connect: &Connect) {
    self.start(channel, |outbox| {
      relay::connect(connect, outbox).map_err(|error| format!("connecting to {connect}: {error}"))
    });
  }

  fn listen(&mut self, channel: u32, listen: &Listen) {
    self.start(channel, |outbox| {
      listener::listen(listen, outbox).map_err(|error| format!("listening on {listen}: {error}"))
    });
  }

  /// Answers the Call channel `channel` with what the call returns, or with
  /// an Error. Either answer closes the channel. A call in a jail forks, and
  /// MountDataset may spawn zfs(8), which only the session loop may do.
  fn call(&mut self, channel: u32, call: &Call) {
    let answer = match call::answer(call) {
      Ok(value) => Message::Return(value),
      Err(error) => Message::Error(format!("{call}: {error}")),
    };
    self.send(channel, answer);
  }

  /// Calls `start` to start the process, relay, or listener that opening
  /// `channel` asks for, then sends Opened, or an Error with the reason it
  /// failed.
  fn start(&mut self, channel: u32, start: impl FnOnce(Outbox) -> Result<Handle, String>) {
    let outbox = self.outbox(channel);
    let id = outbox.id;

    match start(outbox) {
      Ok(handle) => {
        self.channels.insert(channel, Open { id, handle });
        self.send(channel, Message::Opened)
      }
      Err(reason) => self.send(channel, Message::Error(reason)),
    }
  }

  /// Opens an Accepted channel for a connection to the socket of the Listen
  /// channel `listener`, and relays the connection on it.
  fn accepted(&mut self, listener: u32, stream: UnixStream) {
    let (channel, frame) = match self.mux.open(Message::Accepted { listener }) {
      Ok(opened) => opened,
      Err(error) => {
        eprintln!("agent: could not relay a connection to listener {listener}: {error}");
        return;
      }
    };
    self.write(&frame);
    let outbox = self.outbox(channel);
    let id = outbox.id;

    let handle = relay::start(Connection::Unix(stream), outbox);
    self.channels.insert(channel, Open { id, handle });
  }

  fn outbox(&mut self, channel: u32) -> Outbox {
    self.ids += 1;
    Outbox {
      events: self.events.clone(),
      id: self.ids,
      channel,
    }
  }

  /// Queues a message for the host. If it closes the channel (Exited, Error,
  /// or the second Eof on a relay or listener), the channel is forgotten.
  fn send(&mut self, channel: u32, message: Message) {
    match self.mux.send(channel, message) {
      Ok(frame) => self.write(&frame),
      Err(error) => eprintln!("agent: could not send on channel {channel}: {error}"),
    }
    if channel != CONTROL && !self.mux.is_open(channel) {
      self.channels.remove(&channel);
    }
  }

  /// Tells the host that the agent has no session, which ends the host's.
  fn announce(&mut self) {
    self.end_channels();
    self.announced = true;
    let hello = self.mux.hello();
    self.write(&hello);
  }

  /// Stops the work of every channel when the session ends.
  fn end_channels(&mut self) {
    for (_, open) in self.channels.drain() {
      open.handle.stop();
    }
  }

  /// Adds `frame` to those waiting to be written.
  fn write(&mut self, frame: &Frame) {
    frame.encode(&mut self.pending);
  }

  /// Writes the frames waiting to be written, all at once.
  fn flush(&mut self) -> io::Result<()> {
    if self.pending.is_empty() {
      return Ok(());
    }
    let written = self
      .output
      .write_all(&self.pending)
      .and_then(|()| self.output.flush());
    self.pending.clear();
    written
  }
}
