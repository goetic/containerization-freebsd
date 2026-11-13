//! Drives the agent the way the host does: a host-side Mux, over a socket pair
//! standing in for the console.

use containerization_freebsd_protocol::{CONTROL, Decoder, Exec, Exit, Frame, Message, Mux, Side, VERSION, WindowSize};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const PATIENCE: Duration = Duration::from_secs(10);
const TERMINAL: WindowSize = WindowSize { rows: 24, columns: 80 };
/// FreeBSD and macOS number it alike.
const SIGTERM: i32 = 15;

struct Host {
  mux: Mux,
  console: UnixStream,
  frames: Receiver<Frame>,
}

#[derive(Debug, Default)]
struct Finished {
  output: String,
  errors: String,
  eof: bool,
  exit: Option<Exit>,
}

impl Host {
  /// An agent serving the other end of the console, and a session with it.
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
    };
    assert_eq!(host.next(), (CONTROL, announcement()));
    host.hello();
    host
  }

  /// Starts a session, which the agent must answer.
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
    self.console.write_all(&frame.to_bytes()).unwrap();
  }

  /// The agent's next message.
  fn next(&mut self) -> (u32, Message) {
    let frame = self
      .frames
      .recv_timeout(PATIENCE)
      .expect("the agent sends a frame");
    self
      .mux
      .receive(frame)
      .expect("the agent sends only what it may")
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

  /// What the channel sends until it closes.
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

  /// The channel's Data until it holds `text`.
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

fn command(argv: &[&str]) -> Exec {
  Exec {
    argv: argv.iter().map(|arg| arg.to_string()).collect(),
    ..Exec::default()
  }
}

fn in_terminal(argv: &[&str]) -> Exec {
  Exec {
    pty: Some(TERMINAL),
    ..command(argv)
  }
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

  let channel = host.exec(command(&["sh", "-c", "printf out; printf err >&2; exit 3"]));
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
    ..command(&["sh", "-c", "echo \"$GREETING\"; pwd"])
  });

  assert_eq!(host.finish(channel).output, "hello\n/\n");
}

#[test]
fn feeds_stdin_until_eof() {
  let mut host = Host::start();

  let channel = host.exec(command(&["cat"]));
  host.send(channel, Message::Data(b"one\n".to_vec()));
  host.send(channel, Message::Data(b"two\n".to_vec()));
  host.send(channel, Message::Eof);
  let finished = host.finish(channel);

  assert_eq!(finished.output, "one\ntwo\n");
  assert_eq!(finished.exit, Some(Exit::Code(0)));
}

#[test]
fn signals_a_process() {
  let mut host = Host::start();

  let channel = host.exec(command(&["sleep", "30"]));
  host.send(channel, Message::Signal(SIGTERM));

  assert_eq!(host.finish(channel).exit, Some(Exit::Signal(SIGTERM)));
}

#[test]
fn refuses_a_command_that_does_not_exist() {
  let mut host = Host::start();

  let channel = host.open(Message::Exec(command(&["/nonexistent/command"])));
  let (from, message) = host.next();

  assert_eq!(from, channel);
  assert!(
    matches!(&message, Message::Error(reason) if reason.contains("/nonexistent/command")),
    "{message:?}"
  );
  assert!(!host.mux.is_open(channel));
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
  let server = std::thread::spawn(move || {
    let (mut stream, _) = listener.accept().unwrap();
    let mut received = Vec::new();
    stream.read_to_end(&mut received).unwrap();
    stream.write_all(&received.to_ascii_uppercase()).unwrap();
  });

  let channel = host.open(Message::Connect { port });
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

  let channel = host.open(Message::Connect { port });

  assert!(matches!(host.next(), (from, Message::Error(_)) if from == channel));
}

#[test]
fn a_new_session_kills_the_old_ones_processes() {
  let mut host = Host::start();
  let channel = host.exec(command(&["sh", "-c", "echo $$; exec sleep 30"]));
  let pid = host.read_until(channel, "\n").trim().to_string();
  assert!(running(&pid));

  host.hello();

  let started = Instant::now();
  while running(&pid) {
    assert!(started.elapsed() < PATIENCE, "process {pid} outlived its session");
    std::thread::sleep(Duration::from_millis(20));
  }
  // Nothing of the old channel follows.
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
