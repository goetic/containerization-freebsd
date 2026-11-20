//! The session loop. One thread owns the protocol state and is the only
//! writer to the console; the console reader and the channels' threads send
//! it events.

use crate::listener::{self, Listening};
use crate::process::{self, Process};
use crate::relay::{self, Connection};
use crate::sys;
use containerization_freebsd_protocol::{
  Address, CONTROL, Connect, Decoder, Error, Exec, Frame, Listen, Message, Mux, Side, Skipped,
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
/// Read buffer size, under MAX_PAYLOAD so every read fits in one frame.
pub(crate) const READ: usize = 64 << 10;

enum Event {
  Console(Vec<u8>),
  /// The console's read end closed or failed.
  Closed(io::Result<()>),
  /// A message a channel's thread has for the host.
  Channel {
    id: u64,
    channel: u32,
    message: Message,
  },
  /// A new connection to the socket of the Listen channel `listener`.
  Accepted {
    id: u64,
    listener: u32,
    stream: UnixStream,
  },
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
    connection: Connection,
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
}

/// Serves sessions over a console until its read end closes. The agent
/// announces itself, answers the host's Hellos, and runs what the host's
/// channels request. Returns an error only if reading or writing the console
/// fails.
pub fn serve(input: impl Read + Send + 'static, output: impl Write) -> io::Result<()> {
  let (events, queue) = mpsc::sync_channel(QUEUE);
  let reader = events.clone();
  std::thread::spawn(move || read(input, reader));

  let mut agent = Agent {
    mux: Mux::new(Side::Guest),
    decoder: Decoder::new(),
    output,
    events,
    channels: HashMap::new(),
    ids: 0,
    announced: false,
  };
  let result = agent.run(&queue);
  agent.end_channels();
  result
}

fn read(mut input: impl Read, events: SyncSender<Event>) {
  let mut buffer = vec![0; READ];

  let closed = loop {
    match input.read(&mut buffer) {
      Ok(0) => break Ok(()),
      Ok(read) => {
        if events
          .send(Event::Console(buffer[..read].to_vec()))
          .is_err()
        {
          return;
        }
      }
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      Err(error) => break Err(error),
    }
  };
  let _ = events.send(Event::Closed(closed));
}

impl<W: Write> Agent<W> {
  fn run(&mut self, queue: &Receiver<Event>) -> io::Result<()> {
    self.announce()?;

    // The agent holds a sender itself, so the queue never disconnects.
    while let Ok(event) = queue.recv() {
      match event {
        Event::Console(bytes) => self.console(&bytes)?,
        Event::Closed(result) => return result,
        Event::Channel { id, channel, message } => {
          if self.holds(channel, id) {
            self.send(channel, message)?;
          }
        }
        Event::Accepted { id, listener, stream } => {
          if self.holds(listener, id) {
            self.accepted(listener, stream)?;
          }
        }
      }
    }
    Ok(())
  }

  /// Whether `channel` is open and is still the opening identified by `id`.
  fn holds(&self, channel: u32, id: u64) -> bool {
    self
      .channels
      .get(&channel)
      .is_some_and(|open| open.id == id)
  }

  fn console(&mut self, bytes: &[u8]) -> io::Result<()> {
    // These bytes have left the tty's input queue, so the host may send that
    // many more.
    let read = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    self.send(CONTROL, Message::Received(read))?;
    self.decoder.push(bytes);

    while let Some(decoded) = self.decoder.decode() {
      match decoded {
        Ok(frame) => self.receive(frame)?,
        // Frames were lost. The announcement makes the host start a new
        // session.
        Err(Skipped(count)) => {
          eprintln!("agent: dropped {count} bytes between frames");
          self.announce()?;
        }
      }
    }
    Ok(())
  }

  fn receive(&mut self, frame: Frame) -> io::Result<()> {
    let channel = frame.channel;

    match self.mux.receive(frame) {
      // The host's Hello starts a session. The agent answers even when the
      // versions differ, so the host learns the agent's version.
      Ok((_, Message::Hello { .. })) | Err(Error::Version(_)) => {
        self.end_channels();
        self.announced = false;
        let answer = self.mux.hello();
        self.write(&answer)
      }
      Ok((_, Message::Ping(number))) => self.send(CONTROL, Message::Pong(number)),
      Ok((_, Message::SetTime { seconds, nanoseconds })) => {
        if let Err(error) = sys::set_time(seconds, nanoseconds) {
          eprintln!("agent: setting the clock: {error}");
        }
        Ok(())
      }
      Ok((_, Message::Exec(exec))) => self.exec(channel, &exec),
      Ok((_, Message::Connect(connect))) => self.connect(channel, &connect),
      Ok((_, Message::Listen(listen))) => self.listen(channel, &listen),
      Ok((_, message)) => {
        self.deliver(channel, message);
        Ok(())
      }
      // The host has a session that the agent does not. The agent announces
      // itself once so the host starts a new one; frames still arriving
      // from the old session are then dropped.
      Err(Error::NoSession) if !self.announced => self.announce(),
      // The frame crossed the channel's close in flight.
      Err(Error::NoSession | Error::UnknownChannel(_)) => Ok(()),
      Err(error) => {
        eprintln!("agent: refused a frame on channel {channel}: {error}");
        Ok(())
      }
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

  fn exec(&mut self, channel: u32, exec: &Exec) -> io::Result<()> {
    let outbox = self.outbox(channel);
    let id = outbox.id;
    // spawn's errors already say which step failed, so they need no prefix.
    let started = process::spawn(exec, outbox).map_err(|error| error.to_string());

    self.opened(channel, id, started)
  }

  fn connect(&mut self, channel: u32, connect: &Connect) -> io::Result<()> {
    let outbox = self.outbox(channel);
    let id = outbox.id;
    let started = relay::connect(connect, outbox).map_err(|error| {
      let to = match &connect.to {
        Address::Port(port) => format!("port {port}"),
        Address::Unix(path) => format!("{path:?}"),
      };
      format!("connecting to {to}{}: {error}", in_jail(connect.jail.as_deref()))
    });

    self.opened(channel, id, started)
  }

  fn listen(&mut self, channel: u32, listen: &Listen) -> io::Result<()> {
    let outbox = self.outbox(channel);
    let id = outbox.id;
    let started = listener::listen(listen, outbox).map_err(|error| {
      format!(
        "listening on {:?}{}: {error}",
        listen.path,
        in_jail(listen.jail.as_deref())
      )
    });

    self.opened(channel, id, started)
  }

  /// Records what opening `channel` started and sends Opened, or sends an
  /// Error with the reason it failed.
  fn opened(&mut self, channel: u32, id: u64, started: Result<Handle, String>) -> io::Result<()> {
    match started {
      Ok(handle) => {
        self.channels.insert(channel, Open { id, handle });
        self.send(channel, Message::Opened)
      }
      Err(reason) => self.send(channel, Message::Error(reason)),
    }
  }

  /// Opens an Accepted channel for a connection to the socket of the Listen
  /// channel `listener`, and relays the connection on it.
  fn accepted(&mut self, listener: u32, stream: UnixStream) -> io::Result<()> {
    let (channel, frame) = match self.mux.open(Message::Accepted { listener }) {
      Ok(opened) => opened,
      Err(error) => {
        eprintln!("agent: could not relay a connection to listener {listener}: {error}");
        return Ok(());
      }
    };
    self.write(&frame)?;
    let outbox = self.outbox(channel);
    let id = outbox.id;

    match relay::start(Connection::Unix(stream), outbox) {
      Ok(handle) => {
        self.channels.insert(channel, Open { id, handle });
        Ok(())
      }
      Err(error) => self.send(channel, Message::Error(format!("relaying a connection: {error}"))),
    }
  }

  fn outbox(&mut self, channel: u32) -> Outbox {
    self.ids += 1;
    Outbox {
      events: self.events.clone(),
      id: self.ids,
      channel,
    }
  }

  /// Sends a message to the host. If the message closes the channel (Exited,
  /// Error, or a relay's final Eof), the channel is forgotten, since its work
  /// has finished.
  fn send(&mut self, channel: u32, message: Message) -> io::Result<()> {
    match self.mux.send(channel, message) {
      Ok(frame) => self.write(&frame)?,
      Err(error) => eprintln!("agent: could not send on channel {channel}: {error}"),
    }
    if channel != CONTROL && !self.mux.is_open(channel) {
      self.channels.remove(&channel);
    }
    Ok(())
  }

  /// Tells the host that the agent has no session, which ends the host's.
  fn announce(&mut self) -> io::Result<()> {
    self.end_channels();
    self.announced = true;
    let hello = self.mux.hello();
    self.write(&hello)
  }

  /// Stops the work of every channel when the session ends.
  fn end_channels(&mut self) {
    for (_, open) in self.channels.drain() {
      open.handle.stop();
    }
  }

  fn write(&mut self, frame: &Frame) -> io::Result<()> {
    self.output.write_all(&frame.to_bytes())?;
    self.output.flush()
  }
}

fn in_jail(jail: Option<&str>) -> String {
  jail
    .map(|jail| format!(" in jail {jail:?}"))
    .unwrap_or_default()
}
