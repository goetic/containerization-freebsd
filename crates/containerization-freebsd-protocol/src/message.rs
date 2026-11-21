//! The messages that frames carry. A message is encoded as a frame's kind and
//! a payload of its fields in order, encoded as `codec` describes, with no
//! trailing bytes. An enum's variant is a u8 tag before its fields. The
//! payload of Data, Stderr and Error is the raw bytes alone.

use crate::codec::{Decode, Encode, Reader, Writer, encode};
use crate::frame::Frame;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
  /// Control. Carries the protocol version a side speaks, which must match
  /// the other side's. On a guest Hello, `answer` distinguishes an answer to
  /// the host's Hello from an announcement that the agent has no session.
  /// The host responds to an announcement by starting a session.
  Hello {
    version: u16,
    answer: bool,
  },
  /// Control. The receiver answers with a Pong of the same number.
  Ping(u64),
  Pong(u64),
  /// Control, from the guest. The number of console bytes the agent has read
  /// since its last Received. Each report lets the host send that many more.
  Received(u32),
  /// Control, from the host. The time since the Unix epoch, to which the
  /// guest sets its clock.
  SetTime {
    seconds: u64,
    nanoseconds: u32,
  },
  /// Opens a channel, from the host, that runs a process in the guest.
  Exec(Exec),
  /// Opens a channel, from the host, that relays to a socket in the guest.
  Connect(Connect),
  /// Opens a channel, from the host, that listens on a Unix socket in the
  /// guest.
  Listen(Listen),
  /// Opens a channel, from the guest, for the host to relay a connection
  /// accepted on the socket of the Listen channel `listener`.
  Accepted {
    listener: u32,
  },
  /// The runner started the process, connected the relay, or is listening.
  Opened,
  /// Stdin or relay bytes from the opener, or stdout or relay bytes from the
  /// runner.
  Data(Vec<u8>),
  Stderr(Vec<u8>),
  /// Ends the sender's Data. On a Listen channel, the host's Eof stops the
  /// listener, and the agent sends its own Eof once the socket is closed and
  /// removed.
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
  /// The working directory, as a path inside the jail if there is one.
  pub cwd: Option<String>,
  /// Runs the process on a pseudo-terminal of this size, which merges stderr
  /// into Data. `None` uses pipes.
  pub pty: Option<WindowSize>,
  /// The name of the jail to run in. `None` runs in the guest.
  pub jail: Option<String>,
  /// The user to run as. `None` runs as root, like the agent.
  pub user: Option<User>,
  /// The file mode creation mask. `None` inherits the agent's.
  pub umask: Option<u16>,
  pub limits: Vec<Limit>,
  /// Runs the tool in the guest's `/rescue` that `argv[0]` names. Those tools
  /// are static binaries, so they need not exist inside the jail.
  pub rescue: bool,
}

/// The user a process runs as. Names are looked up in the `/etc/passwd` and
/// `/etc/group` of the process's root: its jail's, or the guest's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct User {
  /// A user name, or a uid. A uid need not be listed in `/etc/passwd`.
  pub name: String,
  /// A group name or gid. If set, it replaces the user's primary group and
  /// the groups that list the user.
  pub group: Option<String>,
  /// Additional groups, by name or gid.
  pub groups: Vec<String>,
}

/// A resource limit, as setrlimit(2) sets it. A value above the guest's
/// `RLIM_INFINITY`, such as `u64::MAX`, means unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
  pub resource: Resource,
  pub soft: u64,
  pub hard: u64,
}

/// A resource that setrlimit(2) limits. Like signal numbers, resource numbers
/// are the guest's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Resource(pub i32);

impl Resource {
  /// CPU time, in seconds.
  pub const CPU: Self = Self(0);
  /// The largest file the process may write.
  pub const FILE_SIZE: Self = Self(1);
  pub const DATA: Self = Self(2);
  pub const STACK: Self = Self(3);
  /// The size of a core dump.
  pub const CORE: Self = Self(4);
  pub const RESIDENT: Self = Self(5);
  pub const LOCKED_MEMORY: Self = Self(6);
  /// Processes, counted per real user.
  pub const PROCESSES: Self = Self(7);
  pub const OPEN_FILES: Self = Self(8);
  /// Socket buffer space, counted per real user.
  pub const SOCKET_BUFFERS: Self = Self(9);
  pub const ADDRESS_SPACE: Self = Self(10);
  /// Pseudo-terminals, counted per real user.
  pub const PSEUDO_TERMINALS: Self = Self(11);
  /// Reserved swap space, counted per real user.
  pub const SWAP: Self = Self(12);
  /// Kqueues, counted per real user.
  pub const KQUEUES: Self = Self(13);
}

/// Where a relay connects. The agent connects from inside the jail, if there
/// is one, so that paths and loopback resolve as they do in the jail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connect {
  pub to: Address,
  /// The name of the jail. `None` means the guest.
  pub jail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
  /// A TCP port on loopback: 127.0.0.1, or ::1 if that fails.
  Port(u16),
  /// The path of a Unix socket.
  Unix(String),
}

/// A Unix socket for the agent to listen on. The agent creates the socket
/// from inside the jail, if there is one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listen {
  /// The socket's path. An existing socket at this path is replaced.
  pub path: String,
  /// The name of the jail. `None` means the guest.
  pub jail: Option<String>,
  /// The socket's permissions. `None` leaves those the agent's umask allows.
  pub mode: Option<u16>,
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
  /// The payload has bytes after the message's last field.
  TooLong,
  NotUtf8,
  UnknownTag(u8),
}

mod kind {
  pub const HELLO: u8 = 0x01;
  pub const PING: u8 = 0x02;
  pub const PONG: u8 = 0x03;
  pub const RECEIVED: u8 = 0x04;
  pub const SET_TIME: u8 = 0x05;
  pub const EXEC: u8 = 0x10;
  pub const CONNECT: u8 = 0x11;
  pub const LISTEN: u8 = 0x12;
  pub const ACCEPTED: u8 = 0x13;
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
      Self::SetTime { .. } => "set time",
      Self::Exec(_) => "exec",
      Self::Connect(_) => "connect",
      Self::Listen(_) => "listen",
      Self::Accepted { .. } => "accepted",
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
    let (kind, payload) = match self {
      Self::Hello { version, answer } => (kind::HELLO, encode(&(*version, *answer))),
      Self::Ping(number) => (kind::PING, encode(number)),
      Self::Pong(number) => (kind::PONG, encode(number)),
      Self::Received(bytes) => (kind::RECEIVED, encode(bytes)),
      Self::SetTime { seconds, nanoseconds } => (kind::SET_TIME, encode(&(*seconds, *nanoseconds))),
      Self::Exec(exec) => (kind::EXEC, encode(exec)),
      Self::Connect(connect) => (kind::CONNECT, encode(connect)),
      Self::Listen(listen) => (kind::LISTEN, encode(listen)),
      Self::Accepted { listener } => (kind::ACCEPTED, encode(listener)),
      Self::Opened => (kind::OPENED, Vec::new()),
      Self::Data(bytes) => (kind::DATA, bytes.clone()),
      Self::Stderr(bytes) => (kind::STDERR, bytes.clone()),
      Self::Eof => (kind::EOF, Vec::new()),
      Self::Resize(size) => (kind::RESIZE, encode(size)),
      Self::Signal(signal) => (kind::SIGNAL, encode(signal)),
      Self::Exited(exit) => (kind::EXITED, encode(exit)),
      Self::Error(message) => (kind::ERROR, message.as_bytes().to_vec()),
    };

    Frame { channel, kind, payload }
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

    let mut reader = Reader::new(&payload);
    let message = match kind {
      kind::HELLO => Self::Hello {
        version: reader.get()?,
        answer: reader.get()?,
      },
      kind::PING => Self::Ping(reader.get()?),
      kind::PONG => Self::Pong(reader.get()?),
      kind::RECEIVED => Self::Received(reader.get()?),
      kind::SET_TIME => Self::SetTime {
        seconds: reader.get()?,
        nanoseconds: reader.get()?,
      },
      kind::EXEC => Self::Exec(reader.get()?),
      kind::CONNECT => Self::Connect(reader.get()?),
      kind::LISTEN => Self::Listen(reader.get()?),
      kind::ACCEPTED => Self::Accepted {
        listener: reader.get()?,
      },
      kind::OPENED => Self::Opened,
      kind::EOF => Self::Eof,
      kind::RESIZE => Self::Resize(reader.get()?),
      kind::SIGNAL => Self::Signal(reader.get()?),
      kind::EXITED => Self::Exited(reader.get()?),
      kind => return Err(DecodeError::UnknownKind(kind)),
    };

    reader.finish()?;
    Ok(message)
  }
}

impl Encode for Exec {
  fn encode(&self, out: &mut Writer) {
    out
      .put(&self.argv)
      .put(&self.env)
      .put(&self.cwd)
      .put(&self.pty)
      .put(&self.jail)
      .put(&self.user)
      .put(&self.umask)
      .put(&self.limits)
      .put(&self.rescue);
  }
}

impl Decode for Exec {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    Ok(Self {
      argv: reader.get()?,
      env: reader.get()?,
      cwd: reader.get()?,
      pty: reader.get()?,
      jail: reader.get()?,
      user: reader.get()?,
      umask: reader.get()?,
      limits: reader.get()?,
      rescue: reader.get()?,
    })
  }
}

impl Encode for User {
  fn encode(&self, out: &mut Writer) {
    out.put(&self.name).put(&self.group).put(&self.groups);
  }
}

impl Decode for User {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    Ok(Self {
      name: reader.get()?,
      group: reader.get()?,
      groups: reader.get()?,
    })
  }
}

impl Encode for Limit {
  fn encode(&self, out: &mut Writer) {
    out.put(&self.resource.0).put(&self.soft).put(&self.hard);
  }
}

impl Decode for Limit {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    Ok(Self {
      resource: Resource(reader.get()?),
      soft: reader.get()?,
      hard: reader.get()?,
    })
  }
}

impl Encode for Connect {
  fn encode(&self, out: &mut Writer) {
    out.put(&self.to).put(&self.jail);
  }
}

impl Decode for Connect {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    Ok(Self {
      to: reader.get()?,
      jail: reader.get()?,
    })
  }
}

impl Encode for Address {
  fn encode(&self, out: &mut Writer) {
    match self {
      Self::Port(port) => out.put(&0u8).put(port),
      Self::Unix(path) => out.put(&1u8).put(path),
    };
  }
}

impl Decode for Address {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    match reader.get()? {
      0u8 => Ok(Self::Port(reader.get()?)),
      1 => Ok(Self::Unix(reader.get()?)),
      tag => Err(DecodeError::UnknownTag(tag)),
    }
  }
}

impl Encode for Listen {
  fn encode(&self, out: &mut Writer) {
    out.put(&self.path).put(&self.jail).put(&self.mode);
  }
}

impl Decode for Listen {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    Ok(Self {
      path: reader.get()?,
      jail: reader.get()?,
      mode: reader.get()?,
    })
  }
}

impl Encode for WindowSize {
  fn encode(&self, out: &mut Writer) {
    out.put(&self.rows).put(&self.columns);
  }
}

impl Decode for WindowSize {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    Ok(Self {
      rows: reader.get()?,
      columns: reader.get()?,
    })
  }
}

impl Encode for Exit {
  fn encode(&self, out: &mut Writer) {
    match self {
      Self::Code(code) => out.put(&0u8).put(code),
      Self::Signal(signal) => out.put(&1u8).put(signal),
    };
  }
}

impl Decode for Exit {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    match reader.get()? {
      0u8 => Ok(Self::Code(reader.get()?)),
      1 => Ok(Self::Signal(reader.get()?)),
      tag => Err(DecodeError::UnknownTag(tag)),
    }
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
      Message::SetTime {
        seconds: 1_794_787_200,
        nanoseconds: 999_999_999,
      },
      Message::Exec(Exec {
        argv: vec!["sh".into(), "-c".into(), "echo hi".into()],
        env: vec![("TERM".into(), "xterm".into())],
        cwd: Some("/src".into()),
        pty: Some(WindowSize { rows: 24, columns: 80 }),
        jail: Some("web".into()),
        user: Some(User {
          name: "www".into(),
          group: Some("0".into()),
          groups: vec!["wheel".into(), "5".into()],
        }),
        umask: Some(0o027),
        limits: vec![
          Limit {
            resource: Resource::OPEN_FILES,
            soft: 1024,
            hard: u64::MAX,
          },
          Limit {
            resource: Resource(-1),
            soft: 0,
            hard: 0,
          },
        ],
        rescue: true,
      }),
      Message::Exec(Exec {
        user: Some(User {
          name: "1000".into(),
          ..User::default()
        }),
        ..Exec::default()
      }),
      Message::Exec(Exec::default()),
      Message::Connect(Connect {
        to: Address::Port(8080),
        jail: None,
      }),
      Message::Connect(Connect {
        to: Address::Unix("/var/run/app.sock".into()),
        jail: Some("web".into()),
      }),
      Message::Listen(Listen {
        path: "/var/run/host.sock".into(),
        jail: Some("web".into()),
        mode: Some(0o660),
      }),
      Message::Listen(Listen::default()),
      Message::Accepted { listener: 4 },
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

  /// Agents in released guest bundles decode these bytes.
  #[test]
  fn keeps_its_wire_format() {
    let exec = Message::Exec(Exec {
      argv: vec!["sh".into()],
      env: vec![("A".into(), "b".into())],
      cwd: Some("/".into()),
      pty: Some(WindowSize { rows: 24, columns: 80 }),
      jail: None,
      user: Some(User {
        name: "u".into(),
        group: None,
        groups: vec!["g".into()],
      }),
      umask: Some(0o022),
      limits: vec![Limit {
        resource: Resource::CPU,
        soft: 1,
        hard: 2,
      }],
      rescue: true,
    });
    let encoded: &[&[u8]] = &[
      &[1, 0, 0, 0, 2, 0, 0, 0],
      b"sh",
      &[1, 0, 0, 0, 1, 0, 0, 0],
      b"A",
      &[1, 0, 0, 0],
      b"b",
      &[1, 1, 0, 0, 0],
      b"/",
      &[1, 24, 0, 80, 0],
      &[0],
      &[1, 1, 0, 0, 0],
      b"u",
      &[0, 1, 0, 0, 0, 1, 0, 0, 0],
      b"g",
      &[1, 0o022, 0],
      &[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0],
      &[1],
    ];
    let listen = Message::Listen(Listen {
      path: "/s".into(),
      jail: Some("j".into()),
      mode: None,
    });

    assert_eq!(exec.frame(0).payload, encoded.concat());
    assert_eq!(
      listen.frame(0).payload,
      [&[2, 0, 0, 0][..], b"/s", &[1, 1, 0, 0, 0], b"j", &[0]].concat()
    );
    let connect = Message::Connect(Connect {
      to: Address::Port(80),
      jail: None,
    });
    assert_eq!(connect.frame(0).payload, [0, 80, 0, 0]);
    let hello = Message::Hello {
      version: 2,
      answer: true,
    };
    assert_eq!(hello.frame(0).payload, [2, 0, 1]);
    assert_eq!(Message::Exited(Exit::Signal(9)).frame(0).payload, [1, 9, 0, 0, 0]);
  }

  #[test]
  fn refuses_unknown_kinds_and_payloads_of_the_wrong_length() {
    let unknown = Frame {
      channel: 0,
      kind: 0x7F,
      payload: Vec::new(),
    };
    let mut short = Message::Accepted { listener: 2 }.frame(1);
    short.payload.pop();
    let mut long = Message::Eof.frame(2);
    long.payload.push(0);

    assert_eq!(Message::from_frame(unknown), Err(DecodeError::UnknownKind(0x7F)));
    assert_eq!(Message::from_frame(short), Err(DecodeError::Truncated));
    assert_eq!(Message::from_frame(long), Err(DecodeError::TooLong));
  }
}
