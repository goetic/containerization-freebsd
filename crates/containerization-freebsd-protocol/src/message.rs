//! The messages that frames carry. A message is a frame's kind and a payload
//! of its fields in order, encoded as `codec` describes, with no trailing
//! bytes. An enum's variant is a u8 tag before its fields. The payload of
//! Data, Stderr and Error is the raw bytes alone.

use crate::codec::{Decode, DecodeError, Encode, Reader, Writer, encode, record, tagged};
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
  /// Control, from the host. Sets the guest's clock to this time since the
  /// Unix epoch.
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
  /// Opens a channel, from the host, that asks the agent to do one thing and
  /// report back. The agent answers with Return or Error, either of which
  /// closes the channel.
  Call(Call),
  /// The agent's answer to a Call.
  Return(Return),
  /// The responder started the process, connected the relay, or is
  /// listening.
  Opened,
  /// Stdin or relay bytes from the initiator, or stdout or relay bytes from
  /// the responder.
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
  /// Runs the process on a pty of this size, which merges stderr into Data.
  /// `None` uses pipes.
  pub pty: Option<WindowSize>,
  /// The name of the jail to run in. `None` runs in the guest.
  pub jail: Option<String>,
  /// The user to run as. `None` runs as root, like the agent.
  pub user: Option<User>,
  /// `None` inherits the agent's.
  pub umask: Option<u16>,
  pub limits: Vec<Limit>,
  /// Runs the guest's `/rescue` tool that `argv[0]` names. The tools are
  /// statically linked, so they need not exist inside the jail.
  pub rescue: bool,
}

impl Exec {
  /// Runs `argv` with every other field at its default: on pipes, in the
  /// guest, as root.
  pub fn new(argv: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
    Self {
      argv: argv
        .into_iter()
        .map(|arg| arg.as_ref().to_string())
        .collect(),
      ..Self::default()
    }
  }
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
  /// Supplementary groups, by name or gid, added even if `group` is set.
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
  /// The largest core dump.
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

/// `port 80`, or a Unix socket's path in quotes.
impl fmt::Display for Address {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Port(port) => write!(formatter, "port {port}"),
      Self::Unix(path) => write!(formatter, "{path:?}"),
    }
  }
}

/// The address, then the jail if there is one: `port 80 in jail "web"`.
impl fmt::Display for Connect {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{}", self.to)?;
    in_jail(formatter, self.jail.as_deref())
  }
}

/// The socket's path in quotes, then the jail if there is one.
impl fmt::Display for Listen {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{:?}", self.path)?;
    in_jail(formatter, self.jail.as_deref())
  }
}

fn in_jail(formatter: &mut fmt::Formatter<'_>, jail: Option<&str>) -> fmt::Result {
  match jail {
    Some(jail) => write!(formatter, " in jail {jail:?}"),
    None => Ok(()),
  }
}

/// A Unix socket for the agent to listen on. The agent creates the socket
/// from inside the jail, if there is one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listen {
  /// Replaces any socket already at this path.
  pub path: String,
  /// The name of the jail. `None` means the guest.
  pub jail: Option<String>,
  /// The socket's permissions. `None` leaves those the agent's umask allows.
  pub mode: Option<u16>,
}

/// What a Call asks the agent to do. Each variant says which Return answers
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
  /// Finds the type of file at the path, following symlinks. Returns
  /// FileType.
  FileType(GuestPath),
  /// Mounts a file system. Returns Done.
  Mount(Mount),
  /// Unmounts every file system mounted under the guest path, except ZFS
  /// datasets, the most recently mounted first. Returns Done.
  Unmount(String),
  /// Lists the guest's disks. Returns Disks.
  Disks,
  /// Copies a regular file and its permissions, unless the original is
  /// missing or something is already at the destination. Returns Done.
  CopyFile(FileCopy),
  /// Removes the destination if it holds the same bytes as the original, as
  /// a copy that nothing has changed does. Returns Done.
  RemoveCopy(FileCopy),
  /// Creates the ZFS dataset and any missing parents, and makes sure ZFS
  /// mounts it. A dataset whose mountpoint is `none` or `legacy`, as under
  /// the pool of FreeBSD's VM image, gets `/<dataset>`, which its children
  /// inherit. Returns Path, the directory it is mounted at.
  MountDataset(String),
}

/// Names what the call does, for errors: `finding the type of "/etc"`.
impl fmt::Display for Call {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::FileType(path) => write!(formatter, "finding the type of {path}"),
      Self::Mount(mount) => write!(
        formatter,
        "mounting {} {:?} at {}",
        mount.kind, mount.source, mount.destination
      ),
      Self::Unmount(path) => write!(formatter, "unmounting what is mounted under {path:?}"),
      Self::Disks => write!(formatter, "listing the disks"),
      Self::CopyFile(copy) => write!(formatter, "copying {} to {}", copy.from, copy.to),
      Self::RemoveCopy(copy) => write!(formatter, "removing {} if it is a copy of {}", copy.to, copy.from),
      Self::MountDataset(dataset) => write!(formatter, "mounting dataset {dataset:?}"),
    }
  }
}

/// What the agent reports for a Call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Return {
  FileType(FileType),
  /// The call succeeded and has nothing to report.
  Done,
  Disks(Vec<Disk>),
  Path(String),
}

/// A file system to mount, and where.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mount {
  /// The file system's type, such as `nullfs`, `tmpfs`, or `virtiofs`.
  pub kind: String,
  /// What to mount, such as a guest directory for nullfs or a share's tag
  /// for virtio-fs.
  pub source: String,
  /// Where to mount it. Missing directories are created. In a jail, the path
  /// resolves within the jail's root, as under chroot(2): absolute symlinks
  /// start at the root, and `..` stops there.
  pub destination: GuestPath,
  /// Options such as `ro`, or tmpfs's `size=64m`.
  pub options: Vec<String>,
}

/// A file and where to copy it. Either path may be in a jail.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileCopy {
  pub from: GuestPath,
  pub to: GuestPath,
}

/// One of the guest's disks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Disk {
  /// Such as `/dev/vtbd1`.
  pub device: String,
  /// The disk's ident, which for a virtio-blk disk is its serial. `None` if
  /// the disk has none or it can't be read.
  pub ident: Option<String>,
}

/// A path in the guest, or in a jail if one is named. The agent works from
/// inside the jail, so that the path, and any symlinks along it, resolve as
/// they do there.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuestPath {
  pub path: String,
  /// The name of the jail. `None` means the guest.
  pub jail: Option<String>,
}

/// The path in quotes, then the jail if there is one.
impl fmt::Display for GuestPath {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{:?}", self.path)?;
    in_jail(formatter, self.jail.as_deref())
  }
}

/// The type of file at a path, following symlinks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
  /// Nothing is there, or a symlink there leads nowhere.
  Missing,
  Directory,
  /// A regular file.
  File,
  /// A FIFO, device, or socket.
  Other,
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

impl Exit {
  /// Whether the process exited with status 0, like
  /// `std::process::ExitStatus::success`.
  pub fn success(self) -> bool {
    self == Self::Code(0)
  }
}

/// Formats as `status 1` or `signal 15`, to read after "exited with".
impl fmt::Display for Exit {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Code(code) => write!(formatter, "status {code}"),
      Self::Signal(signal) => write!(formatter, "signal {signal}"),
    }
  }
}

pub(crate) mod kind {
  pub const HELLO: u8 = 0x01;
  pub const PING: u8 = 0x02;
  pub const PONG: u8 = 0x03;
  pub const RECEIVED: u8 = 0x04;
  pub const SET_TIME: u8 = 0x05;
  pub const EXEC: u8 = 0x10;
  pub const CONNECT: u8 = 0x11;
  pub const LISTEN: u8 = 0x12;
  pub const ACCEPTED: u8 = 0x13;
  pub const CALL: u8 = 0x14;
  pub const OPENED: u8 = 0x20;
  pub const DATA: u8 = 0x21;
  pub const STDERR: u8 = 0x22;
  pub const EOF: u8 = 0x23;
  pub const RESIZE: u8 = 0x24;
  pub const SIGNAL: u8 = 0x25;
  pub const EXITED: u8 = 0x26;
  pub const ERROR: u8 = 0x27;
  pub const RETURN: u8 = 0x28;
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
      Self::Call(_) => "call",
      Self::Return(_) => "return",
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

  /// The message as a frame on `channel`. Data, Stderr, and Error become the
  /// payload as they are, without a copy.
  pub fn frame(self, channel: u32) -> Frame {
    let (kind, payload) = match self {
      Self::Hello { version, answer } => (kind::HELLO, encode(&(version, answer))),
      Self::Ping(number) => (kind::PING, encode(&number)),
      Self::Pong(number) => (kind::PONG, encode(&number)),
      Self::Received(bytes) => (kind::RECEIVED, encode(&bytes)),
      Self::SetTime { seconds, nanoseconds } => (kind::SET_TIME, encode(&(seconds, nanoseconds))),
      Self::Exec(exec) => (kind::EXEC, encode(&exec)),
      Self::Connect(connect) => (kind::CONNECT, encode(&connect)),
      Self::Listen(listen) => (kind::LISTEN, encode(&listen)),
      Self::Accepted { listener } => (kind::ACCEPTED, encode(&listener)),
      Self::Call(call) => (kind::CALL, encode(&call)),
      Self::Return(value) => (kind::RETURN, encode(&value)),
      Self::Opened => (kind::OPENED, Vec::new()),
      Self::Data(bytes) => (kind::DATA, bytes),
      Self::Stderr(bytes) => (kind::STDERR, bytes),
      Self::Eof => (kind::EOF, Vec::new()),
      Self::Resize(size) => (kind::RESIZE, encode(&size)),
      Self::Signal(signal) => (kind::SIGNAL, encode(&signal)),
      Self::Exited(exit) => (kind::EXITED, encode(&exit)),
      Self::Error(message) => (kind::ERROR, message.into_bytes()),
    };

    Frame { channel, kind, payload }
  }

  pub fn from_frame(frame: Frame) -> Result<Self, DecodeError> {
    let Frame { kind, payload, .. } = frame;

    match kind {
      kind::DATA => Ok(Self::Data(payload)),
      kind::STDERR => Ok(Self::Stderr(payload)),
      kind::ERROR => String::from_utf8(payload)
        .map(Self::Error)
        .map_err(|_| DecodeError::NotUtf8),
      kind => Self::decode(kind, &payload),
    }
  }

  /// Decodes `frame` without taking its payload, which only Data, Stderr,
  /// and Error copy.
  pub fn peek(frame: &Frame) -> Result<Self, DecodeError> {
    match frame.kind {
      kind::DATA | kind::STDERR | kind::ERROR => Self::from_frame(frame.clone()),
      kind => Self::decode(kind, &frame.payload),
    }
  }

  /// Decodes the fields of a message of `kind` that is not Data, Stderr, or
  /// Error.
  fn decode(kind: u8, payload: &[u8]) -> Result<Self, DecodeError> {
    let mut reader = Reader::new(payload);
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
      kind::CALL => Self::Call(reader.get()?),
      kind::RETURN => Self::Return(reader.get()?),
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

record!(Exec {
  argv,
  env,
  cwd,
  pty,
  jail,
  user,
  umask,
  limits,
  rescue,
});
record!(User { name, group, groups });
record!(Limit { resource, soft, hard });
record!(Connect { to, jail });
record!(Listen { path, jail, mode });
record!(GuestPath { path, jail });
record!(Mount {
  kind,
  source,
  destination,
  options,
});
record!(FileCopy { from, to });
record!(Disk { device, ident });
record!(WindowSize { rows, columns });
tagged!(Address {
  0 => Port(port),
  1 => Unix(path),
});
tagged!(Exit {
  0 => Code(code),
  1 => Signal(signal),
});
tagged!(Call {
  0 => FileType(path),
  1 => Mount(mount),
  2 => Unmount(path),
  3 => Disks,
  4 => CopyFile(copy),
  5 => RemoveCopy(copy),
  6 => MountDataset(dataset),
});
tagged!(Return {
  0 => FileType(found),
  1 => Done,
  2 => Disks(disks),
  3 => Path(path),
});

/// A file type is a u8 tag.
impl Encode for FileType {
  fn encode(&self, out: &mut Writer) {
    let tag: u8 = match self {
      Self::Missing => 0,
      Self::Directory => 1,
      Self::File => 2,
      Self::Other => 3,
    };
    out.put(&tag);
  }
}

impl Decode for FileType {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    match reader.get::<u8>()? {
      0 => Ok(Self::Missing),
      1 => Ok(Self::Directory),
      2 => Ok(Self::File),
      3 => Ok(Self::Other),
      tag => Err(DecodeError::UnknownTag(tag)),
    }
  }
}

/// A resource is its number on the wire.
impl Encode for Resource {
  fn encode(&self, out: &mut Writer) {
    out.put(&self.0);
  }
}

impl Decode for Resource {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    reader.get().map(Self)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn names_what_a_relay_or_listener_reaches() {
    let web = Some("web".to_string());

    assert_eq!(
      Connect {
        to: Address::Port(80),
        jail: None,
      }
      .to_string(),
      "port 80"
    );
    assert_eq!(
      Connect {
        to: Address::Unix("/var/run/a.sock".into()),
        jail: web.clone(),
      }
      .to_string(),
      r#""/var/run/a.sock" in jail "web""#
    );
    assert_eq!(
      Listen {
        path: "/var/run/b.sock".into(),
        jail: web,
        mode: None,
      }
      .to_string(),
      r#""/var/run/b.sock" in jail "web""#
    );
  }

  #[test]
  fn says_how_a_process_exited() {
    assert!(Exit::Code(0).success());
    assert!(!Exit::Code(1).success() && !Exit::Signal(15).success());
    assert_eq!(
      [Exit::Code(1).to_string(), Exit::Signal(15).to_string()],
      ["status 1", "signal 15"]
    );
  }

  #[test]
  fn makes_an_exec_from_borrowed_or_owned_strings() {
    let owned = vec!["sh".to_string(), "-c".to_string()];
    let borrowed: &[&str] = &["sh", "-c"];

    assert_eq!(
      Exec::new(["sh", "-c"]),
      Exec {
        argv: owned.clone(),
        ..Exec::default()
      }
    );
    assert_eq!(Exec::new(&owned), Exec::new(borrowed));
  }

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
      Message::Call(Call::FileType(GuestPath {
        path: "/etc/rc.conf".into(),
        jail: Some("web".into()),
      })),
      Message::Call(Call::FileType(GuestPath::default())),
      Message::Call(Call::Mount(Mount {
        kind: "tmpfs".into(),
        source: "tmpfs".into(),
        destination: GuestPath {
          path: "/tmp".into(),
          jail: Some("web".into()),
        },
        options: vec!["ro".into(), "size=64m".into()],
      })),
      Message::Call(Call::Unmount("/jails/web".into())),
      Message::Call(Call::Disks),
      Message::Call(Call::CopyFile(FileCopy {
        from: GuestPath {
          path: "/etc/resolv.conf".into(),
          jail: None,
        },
        to: GuestPath {
          path: "/etc/resolv.conf".into(),
          jail: Some("web".into()),
        },
      })),
      Message::Call(Call::RemoveCopy(FileCopy::default())),
      Message::Call(Call::MountDataset("zroot/cfbsd".into())),
      Message::Return(Return::FileType(FileType::Missing)),
      Message::Return(Return::FileType(FileType::Directory)),
      Message::Return(Return::FileType(FileType::File)),
      Message::Return(Return::FileType(FileType::Other)),
      Message::Return(Return::Done),
      Message::Return(Return::Disks(vec![
        Disk {
          device: "/dev/vtbd0".into(),
          ident: None,
        },
        Disk {
          device: "/dev/vtbd1".into(),
          ident: Some("images".into()),
        },
      ])),
      Message::Return(Return::Path("/cfbsd".into())),
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
      assert_eq!(Message::from_frame(message.clone().frame(5)), Ok(message));
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
    assert_eq!(
      Message::Return(Return::FileType(FileType::Other))
        .frame(0)
        .payload,
      [0, 3]
    );
    assert_eq!(Message::Call(Call::Disks).frame(0).payload, [3]);
  }

  #[test]
  fn peeks_at_a_frame_as_it_decodes_one() {
    for message in [
      Message::Received(4096),
      Message::Hello {
        version: 4,
        answer: false,
      },
      Message::Data(b"stdout".to_vec()),
      Message::Error("refused".into()),
    ] {
      let frame = message.clone().frame(3);
      assert_eq!(Message::peek(&frame), Ok(message));
    }
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
