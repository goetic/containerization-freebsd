//! What frames carry: a message is a frame's kind and payload.
//!
//! Payloads are little-endian integers, and strings with a u32 length, and
//! nothing after. Data, Stderr and Error are their bytes alone.

use crate::frame::Frame;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
  /// The version a side speaks, which must match. Control. From the guest,
  /// `answer` tells an answer to the host's Hello from an announcement that
  /// the agent has no session, which the host answers by starting one.
  Hello {
    version: u16,
    answer: bool,
  },
  /// Answered with a Pong of the same number. Control.
  Ping(u64),
  Pong(u64),
  /// From the guest, how many more of the console's bytes it has read: the
  /// host's credit to send more. Control.
  Received(u32),
  /// Runs a process in the guest. Opens a channel, from the host.
  Exec(Exec),
  /// Relays to a TCP port on the guest's loopback. Opens a channel, from the host.
  Connect {
    port: u16,
  },
  /// The runner started the process, or connected the relay.
  Opened,
  /// From the opener, stdin or relay bytes; from the runner, stdout or relay bytes.
  Data(Vec<u8>),
  Stderr(Vec<u8>),
  /// The end of the sender's Data.
  Eof,
  Resize(WindowSize),
  Signal(i32),
  Exited(Exit),
  /// The channel failed or was refused, and is closed.
  Error(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exec {
  pub argv: Vec<String>,
  pub env: Vec<(String, String)>,
  pub cwd: Option<String>,
  /// A pseudo-terminal of this size, which merges stderr into Data; or pipes.
  pub pty: Option<WindowSize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowSize {
  pub rows: u16,
  pub columns: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
  Code(i32),
  Signal(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
  UnknownKind(u8),
  Truncated,
  /// Bytes after the message's fields.
  TooLong,
  NotUtf8,
  UnknownTag(u8),
}

mod kind {
  pub const HELLO: u8 = 0x01;
  pub const PING: u8 = 0x02;
  pub const PONG: u8 = 0x03;
  pub const RECEIVED: u8 = 0x04;
  pub const EXEC: u8 = 0x10;
  pub const CONNECT: u8 = 0x11;
  pub const OPENED: u8 = 0x20;
  pub const DATA: u8 = 0x21;
  pub const STDERR: u8 = 0x22;
  pub const EOF: u8 = 0x23;
  pub const RESIZE: u8 = 0x24;
  pub const SIGNAL: u8 = 0x25;
  pub const EXITED: u8 = 0x26;
  pub const ERROR: u8 = 0x27;
}

impl Message {
  pub fn name(&self) -> &'static str {
    match self {
      Self::Hello { .. } => "hello",
      Self::Ping(_) => "ping",
      Self::Pong(_) => "pong",
      Self::Received(_) => "received",
      Self::Exec(_) => "exec",
      Self::Connect { .. } => "connect",
      Self::Opened => "opened",
      Self::Data(_) => "data",
      Self::Stderr(_) => "stderr",
      Self::Eof => "eof",
      Self::Resize(_) => "resize",
      Self::Signal(_) => "signal",
      Self::Exited(_) => "exited",
      Self::Error(_) => "error",
    }
  }

  pub fn frame(&self, channel: u32) -> Frame {
    let mut payload = Writer::default();
    let kind = match self {
      Self::Hello { version, answer } => {
        payload.u16(*version).u8(u8::from(*answer));
        kind::HELLO
      }
      Self::Ping(number) => {
        payload.u64(*number);
        kind::PING
      }
      Self::Pong(number) => {
        payload.u64(*number);
        kind::PONG
      }
      Self::Received(bytes) => {
        payload.u32(*bytes);
        kind::RECEIVED
      }
      Self::Exec(exec) => {
        payload.strings(&exec.argv).u32(length(exec.env.len()));
        for (name, value) in &exec.env {
          payload.string(name).string(value);
        }
        match &exec.cwd {
          Some(cwd) => payload.u8(1).string(cwd),
          None => payload.u8(0),
        };
        match exec.pty {
          Some(size) => payload.u8(1).window(size),
          None => payload.u8(0),
        };
        kind::EXEC
      }
      Self::Connect { port } => {
        payload.u16(*port);
        kind::CONNECT
      }
      Self::Opened => kind::OPENED,
      Self::Data(bytes) => {
        payload.0.extend_from_slice(bytes);
        kind::DATA
      }
      Self::Stderr(bytes) => {
        payload.0.extend_from_slice(bytes);
        kind::STDERR
      }
      Self::Eof => kind::EOF,
      Self::Resize(size) => {
        payload.window(*size);
        kind::RESIZE
      }
      Self::Signal(signal) => {
        payload.i32(*signal);
        kind::SIGNAL
      }
      Self::Exited(Exit::Code(code)) => {
        payload.u8(0).i32(*code);
        kind::EXITED
      }
      Self::Exited(Exit::Signal(signal)) => {
        payload.u8(1).i32(*signal);
        kind::EXITED
      }
      Self::Error(message) => {
        payload.0.extend_from_slice(message.as_bytes());
        kind::ERROR
      }
    };

    Frame {
      channel,
      kind,
      payload: payload.0,
    }
  }

  pub fn from_frame(frame: Frame) -> Result<Self, DecodeError> {
    let Frame { kind, payload, .. } = frame;

    match kind {
      kind::DATA => return Ok(Self::Data(payload)),
      kind::STDERR => return Ok(Self::Stderr(payload)),
      kind::ERROR => {
        return String::from_utf8(payload)
          .map(Self::Error)
          .map_err(|_| DecodeError::NotUtf8);
      }
      _ => {}
    }

    let mut reader = Reader(&payload);
    let reader = &mut reader;
    let message = match kind {
      kind::HELLO => Self::Hello {
        version: reader.u16()?,
        answer: reader.flag()?,
      },
      kind::PING => Self::Ping(reader.u64()?),
      kind::PONG => Self::Pong(reader.u64()?),
      kind::RECEIVED => Self::Received(reader.u32()?),
      kind::EXEC => Self::Exec(Exec {
        argv: reader.strings()?,
        env: (0..reader.u32()?)
          .map(|_| Ok((reader.string()?, reader.string()?)))
          .collect::<Result<_, DecodeError>>()?,
        cwd: reader.option(Reader::string)?,
        pty: reader.option(Reader::window)?,
      }),
      kind::CONNECT => Self::Connect { port: reader.u16()? },
      kind::OPENED => Self::Opened,
      kind::EOF => Self::Eof,
      kind::RESIZE => Self::Resize(reader.window()?),
      kind::SIGNAL => Self::Signal(reader.i32()?),
      kind::EXITED => Self::Exited(match reader.u8()? {
        0 => Exit::Code(reader.i32()?),
        1 => Exit::Signal(reader.i32()?),
        tag => return Err(DecodeError::UnknownTag(tag)),
      }),
      kind => return Err(DecodeError::UnknownKind(kind)),
    };

    if reader.0.is_empty() {
      Ok(message)
    } else {
      Err(DecodeError::TooLong)
    }
  }
}

/// A length on the wire. Anything over u32 is over MAX_PAYLOAD too, and is
/// refused before it is sent.
fn length(length: usize) -> u32 {
  u32::try_from(length).unwrap_or(u32::MAX)
}

#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
  fn u8(&mut self, value: u8) -> &mut Self {
    self.0.push(value);
    self
  }

  fn u16(&mut self, value: u16) -> &mut Self {
    self.0.extend_from_slice(&value.to_le_bytes());
    self
  }

  fn u32(&mut self, value: u32) -> &mut Self {
    self.0.extend_from_slice(&value.to_le_bytes());
    self
  }

  fn u64(&mut self, value: u64) -> &mut Self {
    self.0.extend_from_slice(&value.to_le_bytes());
    self
  }

  fn i32(&mut self, value: i32) -> &mut Self {
    self.0.extend_from_slice(&value.to_le_bytes());
    self
  }

  fn string(&mut self, value: &str) -> &mut Self {
    self.u32(length(value.len()));
    self.0.extend_from_slice(value.as_bytes());
    self
  }

  fn strings(&mut self, values: &[String]) -> &mut Self {
    self.u32(length(values.len()));
    for value in values {
      self.string(value);
    }
    self
  }

  fn window(&mut self, size: WindowSize) -> &mut Self {
    self.u16(size.rows).u16(size.columns)
  }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
  fn take<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
    let (taken, rest) = self.0.split_first_chunk().ok_or(DecodeError::Truncated)?;

    self.0 = rest;
    Ok(*taken)
  }

  fn u8(&mut self) -> Result<u8, DecodeError> {
    self.take().map(u8::from_le_bytes)
  }

  fn u16(&mut self) -> Result<u16, DecodeError> {
    self.take().map(u16::from_le_bytes)
  }

  fn u32(&mut self) -> Result<u32, DecodeError> {
    self.take().map(u32::from_le_bytes)
  }

  fn u64(&mut self) -> Result<u64, DecodeError> {
    self.take().map(u64::from_le_bytes)
  }

  fn i32(&mut self) -> Result<i32, DecodeError> {
    self.take().map(i32::from_le_bytes)
  }

  fn string(&mut self) -> Result<String, DecodeError> {
    let length = self.u32()? as usize;
    if self.0.len() < length {
      return Err(DecodeError::Truncated);
    }
    let (bytes, rest) = self.0.split_at(length);

    self.0 = rest;
    String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::NotUtf8)
  }

  fn strings(&mut self) -> Result<Vec<String>, DecodeError> {
    (0..self.u32()?).map(|_| self.string()).collect()
  }

  fn window(&mut self) -> Result<WindowSize, DecodeError> {
    Ok(WindowSize {
      rows: self.u16()?,
      columns: self.u16()?,
    })
  }

  fn flag(&mut self) -> Result<bool, DecodeError> {
    match self.u8()? {
      0 => Ok(false),
      1 => Ok(true),
      tag => Err(DecodeError::UnknownTag(tag)),
    }
  }

  fn option<T>(&mut self, read: impl FnOnce(&mut Self) -> Result<T, DecodeError>) -> Result<Option<T>, DecodeError> {
    if self.flag()? { read(self).map(Some) } else { Ok(None) }
  }
}

impl fmt::Display for DecodeError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::UnknownKind(kind) => write!(formatter, "unknown message kind {kind:#04x}"),
      Self::Truncated => formatter.write_str("the payload ends early"),
      Self::TooLong => formatter.write_str("the payload goes on after the message"),
      Self::NotUtf8 => formatter.write_str("a string is not UTF-8"),
      Self::UnknownTag(tag) => write!(formatter, "unknown tag {tag}"),
    }
  }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn decodes_every_message_it_encodes() {
    let messages = [
      Message::Hello {
        version: 1,
        answer: true,
      },
      Message::Ping(7),
      Message::Pong(u64::MAX),
      Message::Received(16 << 10),
      Message::Exec(Exec {
        argv: vec!["sh".into(), "-c".into(), "echo hi".into()],
        env: vec![("TERM".into(), "xterm".into())],
        cwd: Some("/src".into()),
        pty: Some(WindowSize { rows: 24, columns: 80 }),
      }),
      Message::Exec(Exec::default()),
      Message::Connect { port: 8080 },
      Message::Opened,
      Message::Data(b"stdin".to_vec()),
      Message::Stderr(vec![0xFF]),
      Message::Eof,
      Message::Resize(WindowSize { rows: 50, columns: 132 }),
      Message::Signal(15),
      Message::Exited(Exit::Code(3)),
      Message::Exited(Exit::Signal(9)),
      Message::Error("refused".into()),
    ];

    for message in messages {
      assert_eq!(Message::from_frame(message.frame(5)), Ok(message));
    }
  }

  #[test]
  fn refuses_unknown_kinds_and_payloads_of_the_wrong_length() {
    let unknown = Frame {
      channel: 0,
      kind: 0x7F,
      payload: Vec::new(),
    };
    let mut short = Message::Connect { port: 80 }.frame(2);
    short.payload.pop();
    let mut long = Message::Eof.frame(2);
    long.payload.push(0);

    assert_eq!(Message::from_frame(unknown), Err(DecodeError::UnknownKind(0x7F)));
    assert_eq!(Message::from_frame(short), Err(DecodeError::Truncated));
    assert_eq!(Message::from_frame(long), Err(DecodeError::TooLong));
  }
}
