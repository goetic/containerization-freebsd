//! One side's view of a session's channels, and the rules for who may send
//! what, and when.
//!
//! Channel 0 is the control channel. The host opens even-numbered channels
//! and the guest opens odd-numbered ones, so the guest can open a channel for
//! each connection to a socket it listens on without asking the host first.

use crate::codec::DecodeError;
use crate::frame::{Frame, MAX_PAYLOAD, encode_frame, encoded_len};
use crate::message::{Message, kind};
use std::collections::HashMap;
use std::{fmt, mem};

pub const CONTROL: u32 = 0;

/// The protocol version this crate speaks. The other side must speak the same.
pub const VERSION: u16 = 4;

/// The flow-control window: the most bytes the host may write to the console
/// before the agent reports them with Received. FreeBSD's virtio console
/// drops bytes that overflow the guest tty's input queue. At 115200 baud, the
/// fastest rate the console allows, that queue holds 23,040 bytes.
pub const WINDOW: usize = 16 << 10;

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

  /// Returns this side's next channel number after `channel`. Numbers wrap
  /// around and skip the control channel.
  fn after(self, channel: u32) -> u32 {
    channel.checked_add(2).unwrap_or(self.first_channel())
  }

  fn owns(self, channel: u32) -> bool {
    channel != CONTROL && channel % 2 == self.first_channel() % 2
  }

  fn opens(self, message: &Message) -> bool {
    match message {
      Message::Exec(_) | Message::Connect(_) | Message::Listen(_) | Message::Call(_) => self == Self::Host,
      Message::Accepted { .. } => self == Self::Guest,
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
  /// A channel was opened, or a non-control message sent or received, before
  /// the Hellos started a session.
  NoSession,
  /// A message for a channel that is not open. Often the message was in
  /// flight when the channel closed.
  UnknownChannel(u32),
  /// An opening message on a channel that is already open, or whose number
  /// belongs to the receiver.
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
  Listener,
  Call,
}

impl Kind {
  fn of(message: &Message) -> Option<Self> {
    match message {
      Message::Exec(exec) => Some(Self::Exec {
        pty: exec.pty.is_some(),
      }),
      Message::Connect(_) | Message::Accepted { .. } => Some(Self::Relay),
      Message::Listen(_) => Some(Self::Listener),
      Message::Call(_) => Some(Self::Call),
      _ => None,
    }
  }
}

/// The role a message's sender has on its channel: the initiator opened the
/// channel, and the responder runs the process, relay, or listener it asked
/// for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
  Initiator,
  Responder,
}

/// Whether a channel is still open after a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
  Open,
  Closed,
}

#[derive(Clone, Copy, Debug)]
struct Channel {
  kind: Kind,
  initiator: Side,
  opened: bool,
  initiator_eof: bool,
  responder_eof: bool,
}

impl Channel {
  fn new(kind: Kind, initiator: Side) -> Self {
    Self {
      kind,
      initiator,
      opened: false,
      initiator_eof: false,
      responder_eof: false,
    }
  }

  /// The channel as it would be after `message` from `sender`, and whether
  /// it would still be open, or `None` if the channel does not allow the
  /// message now. The channel itself is left as it is.
  fn after(mut self, sender: Role, message: &Message) -> Option<(Self, Status)> {
    let (initiator, responder) = (sender == Role::Initiator, sender == Role::Responder);
    // A Call channel carries only the responder's Return, or an Error, and
    // either closes it.
    if self.kind == Kind::Call {
      let allowed = matches!(message, Message::Error(_)) || (responder && matches!(message, Message::Return(_)));
      return allowed.then_some((self, Status::Closed));
    }
    let process = matches!(self.kind, Kind::Exec { .. });
    let ended = if initiator {
      self.initiator_eof
    } else {
      self.responder_eof
    };
    // The initiator may send stdin before the responder has started the
    // process.
    let started = initiator || self.opened;

    let allowed = match message {
      Message::Opened => responder && !self.opened,
      Message::Data(_) => started && !ended && self.kind != Kind::Listener,
      Message::Eof => started && !ended,
      Message::Stderr(_) => responder && self.opened && self.kind == Kind::Exec { pty: false },
      Message::Resize(_) => initiator && self.kind == Kind::Exec { pty: true },
      Message::Signal(_) => initiator && process,
      Message::Exited(_) => responder && self.opened && process,
      Message::Error(_) => true,
      _ => false,
    };
    if !allowed {
      return None;
    }

    match message {
      Message::Opened => self.opened = true,
      Message::Eof if initiator => self.initiator_eof = true,
      Message::Eof => self.responder_eof = true,
      _ => {}
    }

    let closed = match message {
      Message::Exited(_) | Message::Error(_) => true,
      Message::Eof => !process && self.initiator_eof && self.responder_eof,
      _ => false,
    };
    Some((self, if closed { Status::Closed } else { Status::Open }))
  }
}

#[derive(Debug)]
pub struct Mux {
  side: Side,
  session: bool,
  /// On the host, the number of Hellos the guest has not answered yet.
  unanswered: u32,
  /// On the guest, whether the host's last Hello still needs an answer.
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

  /// Returns a Hello for this side to send.
  ///
  /// On the host, the Hello starts a new session: the host forgets every
  /// channel and can open none until the guest answers. On the guest, the
  /// Hello answers the host's last Hello. If no answer is due, it announces
  /// that the agent has no session because it just started or lost frames.
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

  /// Opens a channel with `message`, which must be Exec, Connect or Listen on
  /// the host, or Accepted on the guest.
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

  /// Frames a message for an open channel or [`CONTROL`], if this side may
  /// send it now. The control channel accepts Ping and Pong from either side,
  /// Received from the guest, and SetTime from the host.
  pub fn send(&mut self, channel: u32, message: Message) -> Result<Frame, Error> {
    if channel == CONTROL {
      return match message {
        Message::Ping(_) | Message::Pong(_) => Ok(message.frame(CONTROL)),
        Message::Received(_) if self.side == Side::Guest => Ok(message.frame(CONTROL)),
        Message::SetTime { .. } if self.side == Side::Host => Ok(message.frame(CONTROL)),
        _ => Err(not_allowed(channel, &message)),
      };
    }

    self.require_session()?;
    let next = self.check(channel, self.side, &message)?;
    let frame = sized(message.frame(channel))?;
    self.commit(channel, next);
    Ok(frame)
  }

  /// Like `send` with Data holding `bytes`, but encodes the frame into `out`
  /// without first copying `bytes` into a Message.
  pub fn send_data(&mut self, channel: u32, bytes: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    // The rules for Data don't depend on what it holds, so an empty one,
    // which allocates nothing, stands in for `bytes`.
    let data = Message::Data(Vec::new());
    if channel == CONTROL {
      return Err(not_allowed(channel, &data));
    }
    self.require_session()?;
    let next = self.check(channel, self.side, &data)?;
    if bytes.len() > MAX_PAYLOAD {
      return Err(Error::TooLarge(bytes.len()));
    }

    out.reserve(encoded_len(bytes));
    encode_frame(channel, kind::DATA, bytes, out);
    self.commit(channel, next);
    Ok(())
  }

  /// Decodes a frame from the other side into its channel and message, and
  /// checks that the other side may send that message now.
  ///
  /// A received Hello that is not itself an answer ends the session, and
  /// every channel is forgotten. Respond to it with [`Mux::hello`], which on
  /// the guest answers the host and on the host starts a new session.
  pub fn receive(&mut self, frame: Frame) -> Result<(u32, Message), Error> {
    let channel = frame.channel;
    let message = Message::from_frame(frame).map_err(Error::Decode)?;

    if channel == CONTROL {
      match message {
        Message::Hello { version, answer } => self.hear_hello(version, answer)?,
        Message::Ping(_) | Message::Pong(_) => {}
        Message::Received(_) if self.side == Side::Host => {}
        Message::SetTime { .. } if self.side == Side::Guest => {}
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
      None => {
        let next = self.check(channel, peer, &message)?;
        self.commit(channel, next);
      }
    }
    Ok((channel, message))
  }

  fn hear_hello(&mut self, theirs: u16, answer: bool) -> Result<(), Error> {
    match (self.side, answer) {
      (Side::Guest, false) => {
        self.end_session();
        self.answer_due = true;
      }
      // The agent has no session. The host's next Hello starts one.
      (Side::Host, false) => {
        self.end_session();
        return Ok(());
      }
      (Side::Host, true) if self.unanswered > 0 => self.unanswered -= 1,
      // For example, an answer to a Hello that the host sent before a restore.
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

  /// Returns this side's first channel, starting at `next`, that is not open.
  fn free_channel(&self) -> u32 {
    let mut channel = self.next;
    while self.is_open(channel) {
      channel = self.side.after(channel);
    }
    channel
  }

  /// The state `channel` would have after `sender` sends `message` on it, if
  /// the channel allows that. Nothing changes until `commit`.
  fn check(&self, channel: u32, sender: Side, message: &Message) -> Result<(Channel, Status), Error> {
    let state = *self
      .channels
      .get(&channel)
      .ok_or(Error::UnknownChannel(channel))?;
    let role = if sender == state.initiator {
      Role::Initiator
    } else {
      Role::Responder
    };

    state
      .after(role, message)
      .ok_or_else(|| not_allowed(channel, message))
  }

  /// Gives `channel` the state `check` returned, or forgets it if it closed.
  fn commit(&mut self, channel: u32, (state, status): (Channel, Status)) {
    match status {
      Status::Open => self.channels.insert(channel, state),
      Status::Closed => self.channels.remove(&channel),
    };
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
