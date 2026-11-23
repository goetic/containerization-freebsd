//! Drives the agent as the host does, with a host-side Mux over a socket pair
//! that stands in for the console.

use containerization_freebsd_protocol::{
  Address, CONTROL, Connect, Decoder, Exec, Exit, Frame, Limit, Listen, Message, Mux, Resource, Side, User, VERSION,
  WindowSize,
};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// Far longer than any of these tests' commands take.
const TIMEOUT: Duration = Duration::from_secs(10);
const TERMINAL: WindowSize = WindowSize { rows: 24, columns: 80 };
/// SIGTERM has the same number on FreeBSD and macOS.
const SIGTERM: i32 = 15;

struct Host {
  mux: Mux,
  console: UnixStream,
  frames: Receiver<Frame>,
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
  exit: Option<Exit>,
}

impl Host {
  /// Starts an agent on the other end of the console and opens a session
  /// with it.
  fn start() -> Self {
    let (console, agent) = UnixStream::pair().unwrap();
    let agent_input = agent.try_clone().unwrap();
    std::thread::spawn(move || containerization_freebsd_agent::serve(agent_input, agent));

    let mut reader = console.try_clone().unwrap();
    let (sender, frames) = mpsc::channel();
    std::thread::spawn(move || {
      let mut decoder = Decoder::new();
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
      mux: Mux::new(Side::Host),
      console,
      frames,
      written: 0,
      received: 0,
    };
    assert_eq!(host.next(), (CONTROL, announcement()));
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
        CONTROL,
        Message::Hello {
          version: VERSION,
          answer: true
        }
      )
    );
    assert!(self.mux.in_session());
  }

  fn write(&mut self, frame: &Frame) {
    let bytes = frame.to_bytes();
    self.console.write_all(&bytes).unwrap();
    self.written += bytes.len();
  }

  /// The agent's next message, skipping (and counting) Received messages.
  fn next(&mut self) -> (u32, Message) {
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
        (CONTROL, Message::Received(bytes)) => self.received += bytes as usize,
        next => return next,
      }
    }
  }

  fn open(&mut self, message: Message) -> u32 {
    let (channel, frame) = self.mux.open(message).unwrap();
    self.write(&frame);
    channel
  }

  fn send(&mut self, channel: u32, message: Message) {
    let frame = self.mux.send(channel, message).unwrap();
    self.write(&frame);
  }

  fn exec(&mut self, exec: Exec) -> u32 {
    let channel = self.open(Message::Exec(exec));
    assert_eq!(self.next(), (channel, Message::Opened));
    channel
  }

  /// Collects what the channel sends until it closes.
  fn finish(&mut self, channel: u32) -> Finished {
    let mut finished = Finished::default();

    while self.mux.is_open(channel) {
      let (from, message) = self.next();
      assert_eq!(from, channel);
      match message {
        Message::Data(bytes) => finished.output.push_str(&String::from_utf8_lossy(&bytes)),
        Message::Stderr(bytes) => finished.errors.push_str(&String::from_utf8_lossy(&bytes)),
        Message::Eof => finished.eof = true,
        Message::Exited(exit) => finished.exit = Some(exit),
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
        (from, Message::Data(bytes)) if from == channel => output.push_str(&String::from_utf8_lossy(&bytes)),
        (from, Message::Eof) if from == channel => return output,
        other => panic!("unexpected {other:?} after {output:?}"),
      }
    }
  }

  /// The channel's Data until it contains `text`.
  fn read_until(&mut self, channel: u32, text: &str) -> String {
    let mut output = String::new();

    while !output.contains(text) {
      match self.next() {
        (from, Message::Data(bytes)) if from == channel => output.push_str(&String::from_utf8_lossy(&bytes)),
        other => panic!("unexpected {other:?} before {text:?}, after {output:?}"),
      }
    }
    output
  }
}

fn announcement() -> Message {
  Message::Hello {
    version: VERSION,
    answer: false,
  }
}

fn in_terminal(argv: &[&str]) -> Exec {
  Exec {
    pty: Some(TERMINAL),
    ..Exec::new(argv)
  }
}

fn connect(to: Address) -> Message {
  Message::Connect(Connect { to, jail: None })
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

  host.send(CONTROL, Message::Ping(7));
  assert_eq!(host.next(), (CONTROL, Message::Pong(7)));
}

#[test]
fn runs_a_process_on_pipes() {
  let mut host = Host::start();

  let channel = host.exec(Exec::new(["sh", "-c", "printf out; printf err >&2; exit 3"]));
  let finished = host.finish(channel);

  assert_eq!(finished.output, "out");
  assert_eq!(finished.errors, "err");
  assert!(finished.eof);
  assert_eq!(finished.exit, Some(Exit::Code(3)));
}

#[test]
fn passes_the_environment_and_working_directory() {
  let mut host = Host::start();

  let channel = host.exec(Exec {
    env: vec![("GREETING".into(), "hello".into())],
    cwd: Some("/".into()),
    ..Exec::new(["sh", "-c", "echo \"$GREETING\"; pwd"])
  });

  assert_eq!(host.finish(channel).output, "hello\n/\n");
}

#[test]
fn sets_the_umask_and_resource_limits() {
  let mut host = Host::start();

  let channel = host.exec(Exec {
    umask: Some(0o027),
    limits: vec![
      Limit {
        resource: Resource::OPEN_FILES,
        soft: 64,
        hard: 128,
      },
      Limit {
        resource: Resource::CORE,
        soft: 0,
        hard: u64::MAX,
      },
    ],
    cwd: Some("/".into()),
    ..Exec::new(["sh", "-c", "umask; ulimit -Sn; ulimit -Hn; ulimit -Sc; ulimit -Hc; pwd"])
  });
  let finished = host.finish(channel);

  assert_eq!(finished.output, "0027\n64\n128\n0\nunlimited\n/\n", "{finished:?}");
  assert_eq!(finished.exit, Some(Exit::Code(0)));
}

#[test]
fn refuses_a_user_its_root_does_not_list() {
  let mut host = Host::start();

  let channel = host.open(Message::Exec(Exec {
    user: Some(User {
      name: "cfbsd-nobody-at-all".into(),
      ..User::default()
    }),
    ..Exec::new(["true"])
  }));

  assert!(
    matches!(host.next(), (from, Message::Error(reason)) if from == channel && reason.contains("cfbsd-nobody-at-all")),
  );
}

#[test]
fn refuses_a_jail_it_cannot_find() {
  let mut host = Host::start();

  let channel = host.open(Message::Exec(Exec {
    jail: Some("cfbsd-no-such-jail".into()),
    ..Exec::new(["true"])
  }));

  assert!(
    matches!(host.next(), (from, Message::Error(reason)) if from == channel && reason.contains("cfbsd-no-such-jail")),
  );
}

#[test]
fn feeds_stdin_until_eof() {
  let mut host = Host::start();

  let channel = host.exec(Exec::new(["cat"]));
  host.send(channel, Message::Data(b"one\n".to_vec()));
  host.send(channel, Message::Data(b"two\n".to_vec()));
  host.send(channel, Message::Eof);
  let finished = host.finish(channel);

  assert_eq!(finished.output, "one\ntwo\n");
  assert_eq!(finished.exit, Some(Exit::Code(0)));
}

#[test]
fn says_it_received_every_byte_it_read() {
  let mut host = Host::start();

  let channel = host.exec(Exec::new(["cat"]));
  host.send(channel, Message::Data(vec![b'x'; 100_000]));
  host.send(channel, Message::Eof);
  host.finish(channel);

  // The agent sends Received before acting on what it read, so every byte is
  // acknowledged before the process exits.
  assert_eq!(host.received, host.written);
}

#[test]
fn signals_a_process() {
  let mut host = Host::start();

  let channel = host.exec(Exec::new(["sleep", "30"]));
  host.send(channel, Message::Signal(SIGTERM));

  assert_eq!(host.finish(channel).exit, Some(Exit::Signal(SIGTERM)));
}

#[test]
fn refuses_a_command_that_does_not_exist() {
  let mut host = Host::start();

  let channel = host.open(Message::Exec(Exec::new(["/nonexistent/command"])));
  let (from, message) = host.next();

  assert_eq!(from, channel);
  assert!(
    matches!(&message, Message::Error(reason) if reason.contains("running \"/nonexistent/command\"")),
    "{message:?}"
  );
  assert!(!host.mux.is_open(channel));
}

#[test]
fn says_a_missing_working_directory_failed_not_the_command() {
  let mut host = Host::start();

  let channel = host.open(Message::Exec(Exec {
    cwd: Some("/nonexistent/directory".into()),
    ..Exec::new(["true"])
  }));
  let (from, message) = host.next();

  assert_eq!(from, channel);
  assert!(
    matches!(&message, Message::Error(reason) if reason.starts_with("changing to \"/nonexistent/directory\": ")),
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

  let channel = host.open(Message::Exec(Exec {
    user: Some(User {
      name: "0".into(),
      ..User::default()
    }),
    ..Exec::new(["true"])
  }));
  let (from, message) = host.next();

  assert_eq!(from, channel);
  assert!(
    matches!(&message, Message::Error(reason) if reason.starts_with("becoming \"0\": ")),
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
  assert_eq!(finished.exit, Some(Exit::Code(0)));
}

#[test]
fn resizes_a_terminal() {
  let mut host = Host::start();

  let channel = host.exec(in_terminal(&["sh", "-c", "echo ready; read line; stty size"]));
  host.read_until(channel, "ready");
  host.send(channel, Message::Resize(WindowSize { rows: 40, columns: 100 }));
  host.send(channel, Message::Data(b"\n".to_vec()));
  let finished = host.finish(channel);

  assert!(finished.output.contains("40 100"), "{finished:?}");
}

#[test]
fn relays_to_a_local_port() {
  let mut host = Host::start();
  let listener = TcpListener::bind("127.0.0.1:0").unwrap();
  let port = listener.local_addr().unwrap().port();
  let server = std::thread::spawn(move || answer_in_capitals(listener.accept().unwrap().0));

  let channel = host.open(connect(Address::Port(port)));
  assert_eq!(host.next(), (channel, Message::Opened));
  host.send(channel, Message::Data(b"relayed".to_vec()));
  host.send(channel, Message::Eof);
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

  let channel = host.open(connect(Address::Port(port)));

  assert!(matches!(host.next(), (from, Message::Error(_)) if from == channel));
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

  let channel = host.open(connect(Address::Port(port)));
  assert_eq!(host.next(), (channel, Message::Opened));
  assert_eq!(host.next(), (channel, Message::Eof));
  for chunk in input.chunks(16 << 10) {
    host.send(channel, Message::Data(chunk.to_vec()));
  }
  host.send(channel, Message::Eof);
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

  let channel = host.open(connect(Address::Unix(path.to_str().unwrap().into())));
  assert_eq!(host.next(), (channel, Message::Opened));
  host.send(channel, Message::Data(b"relayed".to_vec()));
  host.send(channel, Message::Eof);
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

  let listener = host.open(Message::Listen(Listen {
    path: path.to_str().unwrap().into(),
    jail: None,
    mode: Some(0o640),
  }));
  assert_eq!(host.next(), (listener, Message::Opened));
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
  assert_eq!(accepted, Message::Accepted { listener });
  host.send(channel, Message::Opened);
  assert_eq!(host.read_to_eof(channel), "hello");
  host.send(channel, Message::Data(b"HELLO".to_vec()));
  host.send(channel, Message::Eof);
  assert_eq!(client.join().unwrap(), "HELLO");

  // The agent answers the host's Eof once it has removed the socket.
  host.send(listener, Message::Eof);
  assert_eq!(host.next(), (listener, Message::Eof));
  assert!(!path.exists());
}

#[test]
fn a_new_session_kills_the_old_ones_processes() {
  let mut host = Host::start();
  let channel = host.exec(Exec::new(["sh", "-c", "echo $$; exec sleep 30"]));
  let pid = host.read_until(channel, "\n").trim().to_string();
  assert!(running(&pid));

  host.hello();

  let started = Instant::now();
  while running(&pid) {
    assert!(started.elapsed() < TIMEOUT, "process {pid} outlived its session");
    std::thread::sleep(Duration::from_millis(20));
  }
  // Nothing from the old channel arrives in the new session.
  host.send(CONTROL, Message::Ping(1));
  assert_eq!(host.next(), (CONTROL, Message::Pong(1)));
}

#[test]
fn announces_itself_after_losing_frames() {
  let mut host = Host::start();

  host.console.write_all(b"noise").unwrap();
  host.send(CONTROL, Message::Ping(2));

  assert_eq!(host.next(), (CONTROL, announcement()));
  assert!(!host.mux.in_session());
  assert_eq!(host.next(), (CONTROL, Message::Pong(2)));
  host.hello();
}

/// A host that reads the console only when it asks for the agent's next
/// message, so the agent's output can back up behind it.
struct SlowHost {
  mux: Mux,
  console: UnixStream,
  decoder: Decoder,
}

impl SlowHost {
  fn start() -> Self {
    let (console, agent) = UnixStream::pair().unwrap();
    let agent_input = agent.try_clone().unwrap();
    std::thread::spawn(move || containerization_freebsd_agent::serve(agent_input, agent));
    let mut host = Self {
      mux: Mux::new(Side::Host),
      console,
      decoder: Decoder::new(),
    };

    assert_eq!(host.next(), (CONTROL, announcement()));
    let hello = host.mux.hello();
    host.write(&hello);
    assert!(matches!(host.next(), (CONTROL, Message::Hello { answer: true, .. })));
    host
  }

  fn write(&mut self, frame: &Frame) {
    self.console.write_all(&frame.to_bytes()).unwrap();
  }

  fn send(&mut self, channel: u32, message: Message) {
    let frame = self.mux.send(channel, message).unwrap();
    self.write(&frame);
  }

  /// The agent's next message, skipping Received messages.
  fn next(&mut self) -> (u32, Message) {
    loop {
      if let Some(decoded) = self.decoder.decode() {
        match self.mux.receive(decoded.unwrap()).unwrap() {
          (CONTROL, Message::Received(_)) => continue,
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
  let (channel, frame) = host.mux.open(Message::Exec(Exec::new(["yes"]))).unwrap();
  host.write(&frame);
  assert_eq!(host.next(), (channel, Message::Opened));
  // While the host reads nothing, yes's output fills the agent's queue.
  std::thread::sleep(Duration::from_millis(300));

  host.send(CONTROL, Message::Ping(3));
  let mut output = 0;
  loop {
    match host.next() {
      (CONTROL, Message::Pong(3)) => break,
      (_, Message::Data(_)) => output += 1,
      other => panic!("unexpected {other:?}"),
    }
  }

  assert!(output < 16, "the Pong followed {output} frames of output");
  host.send(channel, Message::Error("done".into()));
}
