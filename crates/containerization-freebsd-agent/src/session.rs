//! The session loop. One thread owns the protocol's state and writes the
//! console; the console's reader and every channel's threads send it events.

use crate::process::{self, Process};
use crate::relay;
use containerization_freebsd_protocol::{CONTROL, Decoder, Error, Exec, Frame, Message, Mux, Side, Skipped};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};

/// Bounded, so a channel whose output outpaces the console waits for it.
const QUEUE: usize = 64;
/// Under MAX_PAYLOAD, so every read fits one frame.
pub(crate) const READ: usize = 64 << 10;

enum Event {
  Console(Vec<u8>),
  /// The console's read end closed, or failed.
  Closed(io::Result<()>),
  /// A message a channel's thread has for the host.
  Channel {
    id: u64,
    channel: u32,
    message: Message,
  },
}

/// Where a channel's threads send its messages for the host. The id is the
/// channel's own, so nothing from a closed channel, or from an earlier
/// session, reaches a later channel of the same number.
#[derive(Clone)]
pub(crate) struct Outbox {
  events: SyncSender<Event>,
  id: u64,
  channel: u32,
}

impl Outbox {
  /// False once the session loop has stopped.
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
}

/// What a channel's threads take from the host.
pub(crate) enum Input {
  Data(Vec<u8>),
  Eof,
}

/// The session loop's hold on what an open channel runs.
pub(crate) struct Handle {
  pub(crate) input: Sender<Input>,
  pub(crate) running: Running,
}

pub(crate) enum Running {
  Process(Arc<Process>),
  Relay(TcpStream),
}

impl Handle {
  /// Ends it before it finishes: kills the process and its group, or closes
  /// the relay.
  fn stop(self) {
    match self.running {
      Running::Process(process) => process.kill(),
      Running::Relay(stream) => {
        let _ = stream.shutdown(Shutdown::Both);
      }
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
  /// Whether the agent has announced itself since its session ended: the old
  /// session's frames in flight draw one announcement, not one each.
  announced: bool,
}

/// Serves sessions over a console until its read end closes. Announces
/// itself, answers the host's Hellos, and runs what the host's channels ask
/// for. Errors only when the console does.
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

    // The agent holds a sender, so the queue never disconnects.
    while let Ok(event) = queue.recv() {
      match event {
        Event::Console(bytes) => self.console(&bytes)?,
        Event::Closed(result) => return result,
        Event::Channel { id, channel, message } => {
          if self
            .channels
            .get(&channel)
            .is_some_and(|open| open.id == id)
          {
            self.send(channel, message)?;
          }
        }
      }
    }
    Ok(())
  }

  fn console(&mut self, bytes: &[u8]) -> io::Result<()> {
    self.decoder.push(bytes);

    while let Some(decoded) = self.decoder.decode() {
      match decoded {
        Ok(frame) => self.receive(frame)?,
        // Frames were lost: the host starts over once it hears this.
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
      // The host's Hello, which starts a session. Answered even when the
      // versions differ, so the host learns the agent's.
      Ok((_, Message::Hello { .. })) | Err(Error::Version(_)) => {
        self.end_channels();
        self.announced = false;
        let answer = self.mux.hello();
        self.write(&answer)
      }
      Ok((_, Message::Ping(number))) => self.send(CONTROL, Message::Pong(number)),
      Ok((_, Message::Exec(exec))) => self.exec(channel, exec),
      Ok((_, Message::Connect { port })) => self.connect(channel, port),
      Ok((_, message)) => {
        self.deliver(channel, message);
        Ok(())
      }
      // The host has a session the agent doesn't: the agent restarted, or
      // announced itself and the old session's frames are still arriving.
      Err(Error::NoSession) if !self.announced => self.announce(),
      // Crossed the channel's closing in flight.
      Err(Error::NoSession | Error::UnknownChannel(_)) => Ok(()),
      Err(error) => {
        eprintln!("agent: refused a frame on channel {channel}: {error}");
        Ok(())
      }
    }
  }

  /// Hands an open channel the host's message.
  fn deliver(&mut self, channel: u32, message: Message) {
    let Some(open) = self.channels.get(&channel) else {
      return;
    };
    let process = match &open.handle.running {
      Running::Process(process) => Some(process),
      Running::Relay(_) => None,
    };

    let result = match message {
      Message::Data(bytes) => {
        let _ = open.handle.input.send(Input::Data(bytes));
        Ok(())
      }
      Message::Eof => {
        let _ = open.handle.input.send(Input::Eof);
        Ok(())
      }
      Message::Resize(size) => process.map_or(Ok(()), |process| process.resize(size)),
      Message::Signal(signal) => process.map_or(Ok(()), |process| process.signal(signal)),
      Message::Error(reason) => {
        eprintln!("agent: the host closed channel {channel}: {reason}");
        Ok(())
      }
      _ => Ok(()),
    };
    if let Err(error) = result {
      eprintln!("agent: channel {channel}: {error}");
    }

    // Closed by the host: its Error, or a relay's last Eof.
    if !self.mux.is_open(channel)
      && let Some(open) = self.channels.remove(&channel)
    {
      open.handle.stop();
    }
  }

  fn exec(&mut self, channel: u32, exec: Exec) -> io::Result<()> {
    let outbox = self.outbox(channel);
    let id = outbox.id;

    match process::spawn(&exec, outbox) {
      Ok(handle) => {
        self.channels.insert(channel, Open { id, handle });
        self.send(channel, Message::Opened)
      }
      Err(error) => {
        let program = exec.argv.first().map_or("", String::as_str);
        self.send(channel, Message::Error(format!("running {program:?}: {error}")))
      }
    }
  }

  fn connect(&mut self, channel: u32, port: u16) -> io::Result<()> {
    let outbox = self.outbox(channel);
    let id = outbox.id;

    match relay::connect(port, outbox) {
      Ok(handle) => {
        self.channels.insert(channel, Open { id, handle });
        self.send(channel, Message::Opened)
      }
      Err(error) => self.send(channel, Message::Error(format!("connecting to port {port}: {error}"))),
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

  /// Sends a message for the host. A channel it closes, with Exited or Error
  /// or a relay's last Eof, is forgotten; what it ran has finished.
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

  /// Tells the host the agent has no session, which ends any it had.
  fn announce(&mut self) -> io::Result<()> {
    self.end_channels();
    self.announced = true;
    let hello = self.mux.hello();
    self.write(&hello)
  }

  /// Stops everything the session's channels run: the session is over.
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
