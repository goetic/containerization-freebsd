//! Drives the agent as the host does, with a host-side Mux over a socket pair
//! that stands in for the console.

use containerization_freebsd_protocol::{frame, message, mux};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// Far longer than any of these tests' commands take.
const TIMEOUT: Duration = Duration::from_secs(10);
const TERMINAL: message::WindowSize = message::WindowSize { rows: 24, columns: 80 };
/// SIGTERM has the same number on FreeBSD and macOS.
const SIGTERM: i32 = 15;

struct Host {
  mux: mux::Mux,
  console: UnixStream,
  frames: Receiver<frame::Frame>,
  /// Bytes written to the console.
  written: usize,
  /// Bytes the agent has acknowledged with Received.
  received: usize,
}

#[derive(Debug, Default)]
struct Finished {
  output: String,
  errors: String,
  eof: bool,
  exit: Option<message::Exit>,
}

impl Host {
  /// Starts an agent on the other end of the console and opens a session
  /// with it.
  fn start() -> Self {
    Self::start_with(|agent| agent)
  }

  /// Like `start`, but the agent writes to the console through `output`.
  fn start_with<W: Write + Send + 'static>(output: impl FnOnce(UnixStream) -> W) -> Self {
    let (console, agent) = UnixStream::pair().unwrap();
    let agent_input = agent.try_clone().unwrap();
    let agent_output = output(agent);
    std::thread::spawn(move || containerization_freebsd_agent::session::serve(agent_input, agent_output));

    let mut reader = console.try_clone().unwrap();
    let (sender, frames) = mpsc::channel();
    std::thread::spawn(move || {
      let mut decoder = frame::Decoder::new();
      let mut buffer = vec![0; 1 << 16];

      while let Ok(read @ 1..) = reader.read(&mut buffer) {
        decoder.push(&buffer[..read]);
        while let Some(frame) = decoder.decode() {
          if sender
            .send(frame.expect("the agent's frames arrive whole"))
            .is_err()
          {
            return;
          }
        }
      }
    });

    let mut host = Self {
      mux: mux::Mux::new(mux::Side::Host),
      console,
      frames,
      written: 0,
      received: 0,
    };
    assert_eq!(host.next(), (mux::CONTROL, announcement()));
    host.hello();
    host
  }

  /// Starts a session and asserts that the agent answers.
  fn hello(&mut self) {
    let hello = self.mux.hello();
    self.write(&hello);

    assert_eq!(
      self.next(),
      (
        mux::CONTROL,
        message::Message::Hello {
          version: mux::VERSION,
          answer: true
        }
      )
    );
    assert!(self.mux.in_session());
  }

  fn write(&mut self, frame: &frame::Frame) {
    let bytes = frame.to_bytes();
    self.console.write_all(&bytes).unwrap();
    self.written += bytes.len();
  }

  /// The agent's next message, skipping (and counting) Received messages.
  fn next(&mut self) -> (u32, message::Message) {
    loop {
      let frame = self
        .frames
        .recv_timeout(TIMEOUT)
        .expect("the agent sends a frame");
      match self
        .mux
        .receive(frame)
        .expect("the agent sends only what it may")
      {
        (mux::CONTROL, message::Message::Received(bytes)) => self.received += bytes as usize,
        next => return next,
      }
    }
  }

  fn open(&mut self, message: message::Message) -> u32 {
    let (channel, frame) = self.mux.open(message).unwrap();
    self.write(&frame);
    channel
  }

  fn send(&mut self, channel: u32, message: message::Message) {
    let frame = self.mux.send(channel, message).unwrap();
    self.write(&frame);
  }

  fn exec(&mut self, exec: message::Exec) -> u32 {
    let channel = self.open(message::Message::Exec(exec));
    assert_eq!(self.next(), (channel, message::Message::Opened));
    channel
  }

  /// Collects what the channel sends until it closes.
  fn finish(&mut self, channel: u32) -> Finished {
    let mut finished = Finished::default();

    while self.mux.is_open(channel) {
      let (from, message) = self.next();
      assert_eq!(from, channel);
      match message {
        message::Message::Data(bytes) => finished.output.push_str(&String::from_utf8_lossy(&bytes)),
        message::Message::Stderr(bytes) => finished.errors.push_str(&String::from_utf8_lossy(&bytes)),
        message::Message::Eof => finished.eof = true,
        message::Message::Exited(exit) => finished.exit = Some(exit),
        other => panic!("unexpected {other:?}"),
      }
    }
    finished
  }

  /// The channel's Data until its Eof.
  fn read_to_eof(&mut self, channel: u32) -> String {
    let mut output = String::new();

    loop {
      match self.next() {
        (from, message::Message::Data(bytes)) if from == channel => output.push_str(&String::from_utf8_lossy(&bytes)),
        (from, message::Message::Eof) if from == channel => return output,
        other => panic!("unexpected {other:?} after {output:?}"),
      }
    }
  }

  /// The channel's Data until it contains `text`.
  fn read_until(&mut self, channel: u32, text: &str) -> String {
    let mut output = String::new();

    while !output.contains(text) {
      match self.next() {
        (from, message::Message::Data(bytes)) if from == channel => output.push_str(&String::from_utf8_lossy(&bytes)),
        other => panic!("unexpected {other:?} before {text:?}, after {output:?}"),
      }
    }
    output
  }
}

fn announcement() -> message::Message {
  message::Message::Hello {
    version: mux::VERSION,
    answer: false,
  }
}

fn in_terminal(argv: &[&str]) -> message::Exec {
  message::Exec {
    pty: Some(TERMINAL),
    ..message::Exec::new(argv)
  }
}

fn connect(to: message::Address) -> message::Message {
  message::Message::Connect(message::Connect { to, jail: None })
}

/// A fresh temporary path for a test's socket.
fn socket_path(name: &str) -> PathBuf {
  let path = std::env::temp_dir().join(format!("cfbsd-agent-{}-{name}.sock", std::process::id()));
  let _ = std::fs::remove_file(&path);
  path
}

/// Reads a connection to its end, then writes back what it read in capitals.
fn answer_in_capitals(mut stream: impl Read + Write) {
  let mut received = Vec::new();
  stream.read_to_end(&mut received).unwrap();
  stream.write_all(&received.to_ascii_uppercase()).unwrap();
}

fn running(pid: &str) -> bool {
  std::process::Command::new("kill")
    .args(["-0", pid])
    .stderr(std::process::Stdio::null())
    .status()
    .unwrap()
    .success()
}

#[test]
fn announces_itself_and_answers_pings() {
  let mut host = Host::start();

  host.send(mux::CONTROL, message::Message::Ping(7));
  assert_eq!(host.next(), (mux::CONTROL, message::Message::Pong(7)));
}

#[test]
fn runs_a_process_on_pipes() {
  let mut host = Host::start();

  let channel = host.exec(message::Exec::new(["sh", "-c", "printf out; printf err >&2; exit 3"]));
  let finished = host.finish(channel);

  assert_eq!(finished.output, "out");
  assert_eq!(finished.errors, "err");
  assert!(finished.eof);
  assert_eq!(finished.exit, Some(message::Exit::Code(3)));
}

#[test]
fn passes_the_environment_and_working_directory() {
  let mut host = Host::start();

  let channel = host.exec(message::Exec {
    env: vec![("GREETING".into(), "hello".into())],
    cwd: Some("/".into()),
    ..message::Exec::new(["sh", "-c", "echo \"$GREETING\"; pwd"])
  });

  assert_eq!(host.finish(channel).output, "hello\n/\n");
}

#[test]
fn sets_the_umask_and_resource_limits() {
  let mut host = Host::start();

  let channel = host.exec(message::Exec {
    umask: Some(0o027),
    limits: vec![
      message::Limit {
        resource: message::Resource::OPEN_FILES,
        soft: 64,
        hard: 128,
      },
      message::Limit {
        resource: message::Resource::CORE,
        soft: 0,
        hard: u64::MAX,
      },
    ],
    cwd: Some("/".into()),
    ..message::Exec::new(["sh", "-c", "umask; ulimit -Sn; ulimit -Hn; ulimit -Sc; ulimit -Hc; pwd"])
  });
  let finished = host.finish(channel);

  assert_eq!(finished.output, "0027\n64\n128\n0\nunlimited\n/\n", "{finished:?}");
  assert_eq!(finished.exit, Some(message::Exit::Code(0)));
}

#[test]
fn refuses_a_user_its_root_does_not_list() {
  let mut host = Host::start();

  let channel = host.open(message::Message::Exec(message::Exec {
    user: Some(message::User {
      name: "cfbsd-nobody-at-all".into(),
      ..message::User::default()
    }),
    ..message::Exec::new(["true"])
  }));

  assert!(
    matches!(host.next(), (from, message::Message::Error(reason)) if from == channel && reason.contains("cfbsd-nobody-at-all")),
  );
}

#[test]
fn refuses_a_jail_it_cannot_find() {
  let mut host = Host::start();

  let channel = host.open(message::Message::Exec(message::Exec {
    jail: Some("cfbsd-no-such-jail".into()),
    ..message::Exec::new(["true"])
  }));

  assert!(
    matches!(host.next(), (from, message::Message::Error(reason)) if from == channel && reason.contains("cfbsd-no-such-jail")),
  );
}

#[test]
fn feeds_stdin_until_eof() {
  let mut host = Host::start();

  let channel = host.exec(message::Exec::new(["cat"]));
  host.send(channel, message::Message::Data(b"one\n".to_vec()));
  host.send(channel, message::Message::Data(b"two\n".to_vec()));
  host.send(channel, message::Message::Eof);
  let finished = host.finish(channel);

  assert_eq!(finished.output, "one\ntwo\n");
  assert_eq!(finished.exit, Some(message::Exit::Code(0)));
}

#[test]
fn says_it_received_every_byte_it_read() {
  let mut host = Host::start();

  let channel = host.exec(message::Exec::new(["cat"]));
  host.send(channel, message::Message::Data(vec![b'x'; 100_000]));
  host.send(channel, message::Message::Eof);
  host.finish(channel);

  // The agent sends Received before acting on what it read, so every byte is
  // acknowledged before the process exits.
  assert_eq!(host.received, host.written);
}

#[test]
fn signals_a_process() {
  let mut host = Host::start();

  let channel = host.exec(message::Exec::new(["sleep", "30"]));
  host.send(channel, message::Message::Signal(SIGTERM));

  assert_eq!(host.finish(channel).exit, Some(message::Exit::Signal(SIGTERM)));
}

#[test]
fn refuses_a_command_that_does_not_exist() {
  let mut host = Host::start();

  let channel = host.open(message::Message::Exec(message::Exec::new(["/nonexistent/command"])));
  let (from, message) = host.next();

  assert_eq!(from, channel);
  assert!(
    matches!(&message, message::Message::Error(reason) if reason.contains("running \"/nonexistent/command\"")),
    "{message:?}"
  );
  assert!(!host.mux.is_open(channel));
}

#[test]
fn says_a_missing_working_directory_failed_not_the_command() {
  let mut host = Host::start();

  let channel = host.open(message::Message::Exec(message::Exec {
    cwd: Some("/nonexistent/directory".into()),
    ..message::Exec::new(["true"])
  }));
  let (from, message) = host.next();

  assert_eq!(from, channel);
  assert!(
    matches!(&message, message::Message::Error(reason) if reason.starts_with("changing to \"/nonexistent/directory\": ")),
    "{message:?}"
  );
}

#[test]
fn says_a_user_it_cannot_become_failed_not_the_command() {
  // Only root may setuid to another user.
  if is_root() {
    return;
  }
  let mut host = Host::start();

  let channel = host.open(message::Message::Exec(message::Exec {
    user: Some(message::User {
      name: "0".into(),
      ..message::User::default()
    }),
    ..message::Exec::new(["true"])
  }));
  let (from, message) = host.next();

  assert_eq!(from, channel);
  assert!(
    matches!(&message, message::Message::Error(reason) if reason.starts_with("becoming \"0\": ")),
    "{message:?}"
  );
}

/// Whether the tests run as root, according to `id -u`.
fn is_root() -> bool {
  let output = std::process::Command::new("id").arg("-u").output().unwrap();
  output.stdout == b"0\n"
}

#[test]
fn runs_a_process_in_a_terminal() {
  let mut host = Host::start();

  let channel = host.exec(in_terminal(&["sh", "-c", "test -t 0 && test -t 2 && stty size"]));
  let finished = host.finish(channel);

  assert!(finished.output.contains("24 80"), "{finished:?}");
  assert_eq!(finished.exit, Some(message::Exit::Code(0)));
}

#[test]
fn resizes_a_terminal() {
  let mut host = Host::start();

  let channel = host.exec(in_terminal(&["sh", "-c", "echo ready; read line; stty size"]));
  host.read_until(channel, "ready");
  host.send(
    channel,
    message::Message::Resize(message::WindowSize { rows: 40, columns: 100 }),
  );
  host.send(channel, message::Message::Data(b"\n".to_vec()));
  let finished = host.finish(channel);

  assert!(finished.output.contains("40 100"), "{finished:?}");
}

#[test]
fn relays_to_a_local_port() {
  let mut host = Host::start();
  let listener = TcpListener::bind("127.0.0.1:0").unwrap();
  let port = listener.local_addr().unwrap().port();
  let server = std::thread::spawn(move || answer_in_capitals(listener.accept().unwrap().0));

  let channel = host.open(connect(message::Address::Port(port)));
  assert_eq!(host.next(), (channel, message::Message::Opened));
  host.send(channel, message::Message::Data(b"relayed".to_vec()));
  host.send(channel, message::Message::Eof);
  let finished = host.finish(channel);
  server.join().unwrap();

  assert_eq!(finished.output, "RELAYED");
  assert!(finished.eof);
}

#[test]
fn refuses_a_port_nothing_listens_on() {
  let mut host = Host::start();
  let port = TcpListener::bind("127.0.0.1:0")
    .unwrap()
    .local_addr()
    .unwrap()
    .port();

  let channel = host.open(connect(message::Address::Port(port)));

  assert!(matches!(host.next(), (from, message::Message::Error(_)) if from == channel));
}

#[test]
fn writes_all_the_host_sent_before_its_eof_closes_a_relay() {
  let mut host = Host::start();
  let listener = TcpListener::bind("127.0.0.1:0").unwrap();
  let port = listener.local_addr().unwrap().port();
  let (eof_sent, wait_for_eof) = mpsc::channel();
  // The server half-closes at once, so the host's Eof closes the relay. It
  // reads nothing until then, so the host's Data backs up in the agent.
  let server = std::thread::spawn(move || {
    let (mut stream, _) = listener.accept().unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    wait_for_eof.recv().unwrap();
    let mut received = Vec::new();
    stream.read_to_end(&mut received).unwrap();
    received.len()
  });
  let input = vec![b'x'; 16 << 20];

  let channel = host.open(connect(message::Address::Port(port)));
  assert_eq!(host.next(), (channel, message::Message::Opened));
  assert_eq!(host.next(), (channel, message::Message::Eof));
  for chunk in input.chunks(16 << 10) {
    host.send(channel, message::Message::Data(chunk.to_vec()));
  }
  host.send(channel, message::Message::Eof);
  // Give the agent time to act on the Eof.
  std::thread::sleep(Duration::from_millis(200));
  eof_sent.send(()).unwrap();

  assert_eq!(server.join().unwrap(), input.len());
}

#[test]
fn relays_to_a_unix_socket() {
  let mut host = Host::start();
  let path = socket_path("connect");
  let listener = UnixListener::bind(&path).unwrap();
  let server = std::thread::spawn(move || answer_in_capitals(listener.accept().unwrap().0));

  let channel = host.open(connect(message::Address::Unix(path.to_str().unwrap().into())));
  assert_eq!(host.next(), (channel, message::Message::Opened));
  host.send(channel, message::Message::Data(b"relayed".to_vec()));
  host.send(channel, message::Message::Eof);
  let finished = host.finish(channel);
  server.join().unwrap();
  std::fs::remove_file(&path).unwrap();

  assert_eq!(finished.output, "RELAYED");
}

#[test]
fn listens_on_a_unix_socket_and_relays_each_connection() {
  let mut host = Host::start();
  let path = socket_path("listen");
  // Leave a stale socket behind for Listen to replace.
  drop(UnixListener::bind(&path).unwrap());

  let listener = host.open(message::Message::Listen(message::Listen {
    path: path.to_str().unwrap().into(),
    jail: None,
    mode: Some(0o640),
  }));
  assert_eq!(host.next(), (listener, message::Message::Opened));
  let mode = std::fs::metadata(&path).unwrap().permissions().mode();
  assert_eq!(mode & 0o777, 0o640);

  let client = {
    let path = path.clone();
    std::thread::spawn(move || {
      let mut stream = UnixStream::connect(path).unwrap();
      stream.write_all(b"hello").unwrap();
      stream.shutdown(Shutdown::Write).unwrap();
      let mut answer = String::new();
      stream.read_to_string(&mut answer).unwrap();
      answer
    })
  };
  let (channel, accepted) = host.next();
  assert_eq!(accepted, message::Message::Accepted { listener });
  host.send(channel, message::Message::Opened);
  assert_eq!(host.read_to_eof(channel), "hello");
  host.send(channel, message::Message::Data(b"HELLO".to_vec()));
  host.send(channel, message::Message::Eof);
  assert_eq!(client.join().unwrap(), "HELLO");

  // The agent answers the host's Eof once it has removed the socket.
  host.send(listener, message::Message::Eof);
  assert_eq!(host.next(), (listener, message::Message::Eof));
  assert!(!path.exists());
}

#[test]
fn a_new_session_kills_the_old_ones_processes() {
  let mut host = Host::start();
  let channel = host.exec(message::Exec::new(["sh", "-c", "echo $$; exec sleep 30"]));
  let pid = host.read_until(channel, "\n").trim().to_string();
  assert!(running(&pid));

  host.hello();

  let started = Instant::now();
  while running(&pid) {
    assert!(started.elapsed() < TIMEOUT, "process {pid} outlived its session");
    std::thread::sleep(Duration::from_millis(20));
  }
  // Nothing from the old channel arrives in the new session.
  host.send(mux::CONTROL, message::Message::Ping(1));
  assert_eq!(host.next(), (mux::CONTROL, message::Message::Pong(1)));
}

#[test]
fn says_what_type_of_file_is_at_a_path() {
  let mut host = Host::start();
  let root = std::env::temp_dir().join(format!("cfbsd-agent-file-type-{}", std::process::id()));
  std::fs::create_dir_all(&root).unwrap();
  std::fs::write(root.join("file"), "").unwrap();
  std::os::unix::fs::symlink("missing", root.join("dangling")).unwrap();
  let mut file_type = |path: &Path, jail: Option<&str>| {
    let channel = host.open(message::Message::Call(message::Call::FileType(message::GuestPath {
      path: path.to_str().unwrap().into(),
      jail: jail.map(str::to_string),
    })));
    let (answered, answer) = host.next();
    assert_eq!(answered, channel);
    assert!(!host.mux.is_open(channel));
    answer
  };

  let answers = [
    file_type(&root, None),
    file_type(&root.join("file"), None),
    file_type(Path::new("/dev/null"), None),
    file_type(&root.join("missing"), None),
    file_type(&root.join("dangling"), None),
    file_type(&root, Some("cfbsd-no-such-jail")),
  ];
  std::fs::remove_dir_all(&root).unwrap();

  let returned = |found| message::Message::Return(message::Return::FileType(found));
  assert_eq!(
    answers[..5],
    [
      returned(message::FileType::Directory),
      returned(message::FileType::File),
      returned(message::FileType::Other),
      returned(message::FileType::Missing),
      returned(message::FileType::Missing),
    ]
  );
  assert!(
    matches!(&answers[5], message::Message::Error(reason) if reason.contains("cfbsd-no-such-jail")),
    "{:?}",
    answers[5]
  );
}

#[test]
fn copies_a_file_and_removes_the_copy_unless_it_changed() {
  let mut host = Host::start();
  let directory = tempfile::tempdir().unwrap();
  let file = |name: &str| directory.path().join(name);
  let copy = |from: &str, to: &str| message::FileCopy {
    from: message::GuestPath {
      path: file(from).to_str().unwrap().into(),
      jail: None,
    },
    to: message::GuestPath {
      path: file(to).to_str().unwrap().into(),
      jail: None,
    },
  };
  let original = "nameserver 192.0.2.1\n";
  std::fs::write(file("original"), original).unwrap();
  std::fs::set_permissions(file("original"), std::fs::Permissions::from_mode(0o640)).unwrap();
  std::fs::write(file("taken"), "mine\n").unwrap();
  std::fs::write(file("longer"), format!("{original}options edns0\n")).unwrap();
  let mut call = |call: message::Call| {
    let channel = host.open(message::Message::Call(call));
    let (answered, answer) = host.next();
    assert_eq!(answered, channel);
    answer
  };
  let done = message::Message::Return(message::Return::Done);

  assert_eq!(call(message::Call::CopyFile(copy("original", "copy"))), done);
  assert_eq!(call(message::Call::CopyFile(copy("original", "taken"))), done);
  assert_eq!(call(message::Call::CopyFile(copy("missing", "nothing"))), done);
  assert_eq!(std::fs::read_to_string(file("copy")).unwrap(), original);
  assert_eq!(
    std::fs::metadata(file("copy"))
      .unwrap()
      .permissions()
      .mode()
      & 0o777,
    0o640
  );
  assert_eq!(std::fs::read_to_string(file("taken")).unwrap(), "mine\n");
  assert!(!file("nothing").exists());

  for changed in ["taken", "longer", "copy"] {
    assert_eq!(call(message::Call::RemoveCopy(copy("original", changed))), done);
  }
  assert!(file("taken").exists() && file("longer").exists());
  assert!(!file("copy").exists());
}

/// The agent's end of the console, counting the agent's writes to it.
struct Counting {
  console: UnixStream,
  writes: Arc<AtomicUsize>,
}

impl Write for Counting {
  fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
    self.writes.fetch_add(1, Ordering::Relaxed);
    self.console.write(bytes)
  }

  fn flush(&mut self) -> std::io::Result<()> {
    self.console.flush()
  }
}

#[test]
fn writes_the_answers_to_one_read_at_once() {
  let writes = Arc::new(AtomicUsize::new(0));
  let counted = writes.clone();
  let mut host = Host::start_with(move |console| Counting {
    console,
    writes: counted,
  });
  let before = writes.load(Ordering::Relaxed);

  let mut pings = Vec::new();
  for number in 0..50 {
    let ping = host
      .mux
      .send(mux::CONTROL, message::Message::Ping(number))
      .unwrap();
    pings.extend(ping.to_bytes());
  }
  host.console.write_all(&pings).unwrap();
  for number in 0..50 {
    assert_eq!(host.next(), (mux::CONTROL, message::Message::Pong(number)));
  }

  let writes = writes.load(Ordering::Relaxed) - before;
  assert!(writes <= 5, "the agent wrote 50 Pongs in {writes} writes");
}

#[test]
fn announces_itself_after_losing_frames() {
  let mut host = Host::start();

  host.console.write_all(b"noise").unwrap();
  host.send(mux::CONTROL, message::Message::Ping(2));

  assert_eq!(host.next(), (mux::CONTROL, announcement()));
  assert!(!host.mux.in_session());
  assert_eq!(host.next(), (mux::CONTROL, message::Message::Pong(2)));
  host.hello();
}

/// A host that reads the console only when it asks for the agent's next
/// message, so the agent's output can back up behind it.
struct SlowHost {
  mux: mux::Mux,
  console: UnixStream,
  decoder: frame::Decoder,
}

impl SlowHost {
  fn start() -> Self {
    let (console, agent) = UnixStream::pair().unwrap();
    let agent_input = agent.try_clone().unwrap();
    std::thread::spawn(move || containerization_freebsd_agent::session::serve(agent_input, agent));
    let mut host = Self {
      mux: mux::Mux::new(mux::Side::Host),
      console,
      decoder: frame::Decoder::new(),
    };

    assert_eq!(host.next(), (mux::CONTROL, announcement()));
    let hello = host.mux.hello();
    host.write(&hello);
    assert!(matches!(
      host.next(),
      (mux::CONTROL, message::Message::Hello { answer: true, .. })
    ));
    host
  }

  fn write(&mut self, frame: &frame::Frame) {
    self.console.write_all(&frame.to_bytes()).unwrap();
  }

  fn send(&mut self, channel: u32, message: message::Message) {
    let frame = self.mux.send(channel, message).unwrap();
    self.write(&frame);
  }

  /// The agent's next message, skipping Received messages.
  fn next(&mut self) -> (u32, message::Message) {
    loop {
      if let Some(decoded) = self.decoder.decode() {
        match self.mux.receive(decoded.unwrap()).unwrap() {
          (mux::CONTROL, message::Message::Received(_)) => continue,
          next => return next,
        }
      }
      let mut buffer = vec![0; 1 << 16];
      let read = self.console.read(&mut buffer).unwrap();
      assert!(read > 0, "the agent closed the console");
      self.decoder.push(&buffer[..read]);
    }
  }
}

#[test]
fn answers_the_host_ahead_of_output_waiting_for_the_console() {
  let mut host = SlowHost::start();
  let (channel, frame) = host
    .mux
    .open(message::Message::Exec(message::Exec::new(["yes"])))
    .unwrap();
  host.write(&frame);
  assert_eq!(host.next(), (channel, message::Message::Opened));
  // While the host reads nothing, yes's output fills the agent's queue.
  std::thread::sleep(Duration::from_millis(300));

  host.send(mux::CONTROL, message::Message::Ping(3));
  let mut output = 0;
  loop {
    match host.next() {
      (mux::CONTROL, message::Message::Pong(3)) => break,
      (_, message::Message::Data(_)) => output += 1,
      other => panic!("unexpected {other:?}"),
    }
  }

  assert!(output < 16, "the Pong followed {output} frames of output");
  host.send(channel, message::Message::Error("done".into()));
}
