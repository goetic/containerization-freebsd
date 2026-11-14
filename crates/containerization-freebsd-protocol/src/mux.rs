//! A session's channels, from one side: who may send what, and when.
//!
//! Channel 0 is control. The host opens even channels; odd ones are the
//! guest's, so it could open channels without asking, though nothing it sends
//! opens one yet.

use crate::frame::{Frame, MAX_PAYLOAD};
use crate::message::{DecodeError, Message};
use std::collections::HashMap;
use std::{fmt, mem};

pub const CONTROL: u32 = 0;

/// The version this crate speaks, which the other side's must match.
pub const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
  Host,
  Guest,
}

impl Side {
  fn peer(self) -> Self {
    match self {
      Self::Host => Self::Guest,
      Self::Guest => Self::Host,
    }
  }

  fn first_channel(self) -> u32 {
    match self {
      Self::Host => 2,
      Self::Guest => 1,
    }
  }

  /// The side's channel after `channel`: numbers wrap around, past control.
  fn after(self, channel: u32) -> u32 {
    channel.checked_add(2).unwrap_or(self.first_channel())
  }

  fn owns(self, channel: u32) -> bool {
    channel != CONTROL && channel % 2 == self.first_channel() % 2
  }

  fn opens(self, message: &Message) -> bool {
    match message {
      Message::Exec(_) | Message::Connect { .. } => self == Self::Host,
      _ => false,
    }
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionMismatch {
  pub ours: u16,
  pub theirs: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
  Decode(DecodeError),
  Version(VersionMismatch),
  /// Only control messages pass until the Hellos start a session.
  NoSession,
  /// Often a message that crossed the channel's closing in flight.
  UnknownChannel(u32),
  /// An opening message on a channel that is open already, or the other side's to open.
  BadChannel(u32),
  NotAllowed {
    channel: u32,
    message: &'static str,
  },
  TooLarge(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
  Exec { pty: bool },
  Relay,
}

impl Kind {
  fn of(message: &Message) -> Option<Self> {
    match message {
      Message::Exec(exec) => Some(Self::Exec {
        pty: exec.pty.is_some(),
      }),
      Message::Connect { .. } => Some(Self::Relay),
      _ => None,
    }
  }
}

#[derive(Debug)]
struct Channel {
  kind: Kind,
  opener: Side,
  opened: bool,
  opener_eof: bool,
  runner_eof: bool,
}

impl Channel {
  fn new(kind: Kind, opener: Side) -> Self {
    Self {
      kind,
      opener,
      opened: false,
      opener_eof: false,
      runner_eof: false,
    }
  }

  /// Applies `message` from the opener, or from the runner, if the channel
  /// allows it now: whether the channel is closed after it.
  fn step(&mut self, from_opener: bool, message: &Message) -> Option<bool> {
    let runner = !from_opener;
    let process = self.kind != Kind::Relay;
    let ended = if from_opener { self.opener_eof } else { self.runner_eof };
    // The opener may send stdin before the runner has started the process.
    let started = from_opener || self.opened;

    let allowed = match message {
      Message::Opened => runner && !self.opened,
      Message::Data(_) | Message::Eof => started && !ended,
      Message::Stderr(_) => runner && self.opened && process && self.kind != Kind::Exec { pty: true },
      Message::Resize(_) => from_opener && self.kind == Kind::Exec { pty: true },
      Message::Signal(_) => from_opener && process,
      Message::Exited(_) => runner && self.opened && process,
      Message::Error(_) => true,
      _ => false,
    };
    if !allowed {
      return None;
    }

    match message {
      Message::Opened => self.opened = true,
      Message::Eof if from_opener => self.opener_eof = true,
      Message::Eof => self.runner_eof = true,
      _ => {}
    }

    Some(match message {
      Message::Exited(_) | Message::Error(_) => true,
      Message::Eof => !process && self.opener_eof && self.runner_eof,
      _ => false,
    })
  }
}

#[derive(Debug)]
pub struct Mux {
  side: Side,
  session: bool,
  /// The host's Hellos the guest hasn't answered.
  unanswered: u32,
  /// Whether the guest owes the host's last Hello an answer.
  answer_due: bool,
  next: u32,
  channels: HashMap<u32, Channel>,
}

impl Mux {
  pub fn new(side: Side) -> Self {
    Self {
      side,
      session: false,
      unanswered: 0,
      answer_due: false,
      next: side.first_channel(),
      channels: HashMap::new(),
    }
  }

  /// Whether both sides' Hellos have started a session.
  pub fn in_session(&self) -> bool {
    self.session
  }

  pub fn is_open(&self, channel: u32) -> bool {
    self.channels.contains_key(&channel)
  }

  /// From the host, a Hello starts a session: the host forgets every channel,
  /// and opens none until the guest answers. From the guest, it answers the
  /// host's last, or if no answer is due, announces that the agent has no
  /// session: it just started, or lost frames.
  pub fn hello(&mut self) -> Frame {
    let answer = match self.side {
      Side::Host => {
        self.unanswered = self.unanswered.saturating_add(1);
        false
      }
      Side::Guest => mem::take(&mut self.answer_due),
    };
    if !answer {
      self.end_session();
    }

    Message::Hello {
      version: VERSION,
      answer,
    }
    .frame(CONTROL)
  }

  /// Opens a channel with Exec or Connect, which only the host opens.
  pub fn open(&mut self, message: Message) -> Result<(u32, Frame), Error> {
    self.require_session()?;
    let channel = self.free_channel();
    let kind = Kind::of(&message)
      .filter(|_| self.side.opens(&message))
      .ok_or_else(|| not_allowed(channel, &message))?;
    let frame = sized(message.frame(channel))?;

    self.next = self.side.after(channel);
    self.channels.insert(channel, Channel::new(kind, self.side));
    Ok((channel, frame))
  }

  /// Ping or Pong on [`CONTROL`], or a message on an open channel.
  pub fn send(&mut self, channel: u32, message: Message) -> Result<Frame, Error> {
    if channel == CONTROL {
      return match message {
        Message::Ping(_) | Message::Pong(_) => Ok(message.frame(CONTROL)),
        _ => Err(not_allowed(channel, &message)),
      };
    }

    self.require_session()?;
    let frame = sized(message.frame(channel))?;
    self.step(channel, self.side, &message)?;
    Ok(frame)
  }

  /// The channel and message a frame from the other side carries, if they
  /// may send it now. Answer a Hello that isn't an answer itself with
  /// [`Mux::hello`]: it ended the session before it, and every channel is
  /// forgotten.
  pub fn receive(&mut self, frame: Frame) -> Result<(u32, Message), Error> {
    let channel = frame.channel;
    let message = Message::from_frame(frame).map_err(Error::Decode)?;

    if channel == CONTROL {
      match message {
        Message::Hello { version, answer } => self.hear_hello(version, answer)?,
        Message::Ping(_) | Message::Pong(_) => {}
        _ => return Err(not_allowed(channel, &message)),
      }
      return Ok((channel, message));
    }

    self.require_session()?;
    let peer = self.side.peer();
    match Kind::of(&message) {
      Some(_) if !peer.opens(&message) => return Err(not_allowed(channel, &message)),
      Some(_) if !peer.owns(channel) || self.is_open(channel) => return Err(Error::BadChannel(channel)),
      Some(kind) => {
        self.channels.insert(channel, Channel::new(kind, peer));
      }
      None => self.step(channel, peer, &message)?,
    }
    Ok((channel, message))
  }

  fn hear_hello(&mut self, theirs: u16, answer: bool) -> Result<(), Error> {
    match (self.side, answer) {
      (Side::Guest, false) => {
        self.end_session();
        self.answer_due = true;
      }
      // The agent has no session; the host's next Hello starts one.
      (Side::Host, false) => {
        self.end_session();
        return Ok(());
      }
      (Side::Host, true) if self.unanswered > 0 => self.unanswered -= 1,
      // Such as an answer to the Hello of the host before a restore.
      _ => {
        return Err(Error::NotAllowed {
          channel: CONTROL,
          message: "hello",
        });
      }
    }
    self.session = theirs == VERSION;

    if self.session {
      Ok(())
    } else {
      Err(Error::Version(VersionMismatch { ours: VERSION, theirs }))
    }
  }

  fn end_session(&mut self) {
    self.session = false;
    self.channels.clear();
  }

  fn require_session(&self) -> Result<(), Error> {
    if self.session { Ok(()) } else { Err(Error::NoSession) }
  }

  /// This side's first channel from `next` that isn't open.
  fn free_channel(&self) -> u32 {
    let mut channel = self.next;
    while self.is_open(channel) {
      channel = self.side.after(channel);
    }
    channel
  }

  fn step(&mut self, channel: u32, sender: Side, message: &Message) -> Result<(), Error> {
    let state = self
      .channels
      .get_mut(&channel)
      .ok_or(Error::UnknownChannel(channel))?;
    let closed = state
      .step(sender == state.opener, message)
      .ok_or_else(|| not_allowed(channel, message))?;

    if closed {
      self.channels.remove(&channel);
    }
    Ok(())
  }
}

fn not_allowed(channel: u32, message: &Message) -> Error {
  Error::NotAllowed {
    channel,
    message: message.name(),
  }
}

fn sized(frame: Frame) -> Result<Frame, Error> {
  if frame.payload.len() > MAX_PAYLOAD {
    Err(Error::TooLarge(frame.payload.len()))
  } else {
    Ok(frame)
  }
}

impl fmt::Display for VersionMismatch {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "the other side speaks protocol version {}, not {}",
      self.theirs, self.ours
    )
  }
}

impl std::error::Error for VersionMismatch {}

impl fmt::Display for Error {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Decode(error) => write!(formatter, "undecodable message: {error}"),
      Self::Version(mismatch) => write!(formatter, "{mismatch}"),
      Self::NoSession => formatter.write_str("no session yet"),
      Self::UnknownChannel(channel) => write!(formatter, "channel {channel} is not open"),
      Self::BadChannel(channel) => write!(
        formatter,
        "channel {channel} is open already, or the other side's to open"
      ),
      Self::NotAllowed { channel, message } => write!(formatter, "{message} is not allowed on channel {channel} now"),
      Self::TooLarge(length) => write!(
        formatter,
        "a {length}-byte payload is over the {MAX_PAYLOAD}-byte limit"
      ),
    }
  }
}

impl std::error::Error for Error {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Decode(error) => Some(error),
      Self::Version(mismatch) => Some(mismatch),
      _ => None,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::message::Exec;

  #[test]
  fn wraps_channel_numbers_around_past_control_and_open_channels() {
    let mut host = Mux::new(Side::Host);
    let mut guest = Mux::new(Side::Guest);
    guest.receive(host.hello()).unwrap();
    host.receive(guest.hello()).unwrap();
    let open = |mux: &mut Mux| mux.open(Message::Exec(Exec::default())).unwrap().0;

    assert_eq!(open(&mut host), 2);
    host.next = u32::MAX - 1;
    assert_eq!([open(&mut host), open(&mut host)], [u32::MAX - 1, 4]);
  }
}
