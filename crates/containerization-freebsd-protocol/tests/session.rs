//! Both sides of a session, in memory, their frames crossing one byte stream
//! as the console carries them.

use containerization_freebsd_protocol::{
  CONTROL, Decoder, Error, Exec, Exit, Frame, MAX_PAYLOAD, Message, Mux, Side, VersionMismatch, WindowSize,
};

const TERMINAL: WindowSize = WindowSize { rows: 24, columns: 80 };

/// Frames through the byte stream and out of a decoder.
fn carry(frames: impl IntoIterator<Item = Frame>) -> Vec<Frame> {
  let mut bytes = Vec::new();
  for frame in frames {
    frame.encode(&mut bytes);
  }
  let mut decoder = Decoder::new();
  decoder.push(&bytes);

  std::iter::from_fn(|| decoder.decode())
    .map(|frame| frame.expect("nothing skipped"))
    .collect()
}

/// What `to` receives of `frames`.
fn deliver(to: &mut Mux, frames: impl IntoIterator<Item = Frame>) -> Vec<(u32, Message)> {
  carry(frames)
    .into_iter()
    .map(|frame| to.receive(frame).expect("receives"))
    .collect()
}

fn session() -> (Mux, Mux) {
  let mut host = Mux::new(Side::Host);
  let mut guest = Mux::new(Side::Guest);

  deliver(&mut guest, [host.hello()]);
  deliver(&mut host, [guest.hello()]);
  (host, guest)
}

fn exec(argv: &[&str], pty: Option<WindowSize>) -> Message {
  Message::Exec(Exec {
    argv: argv.iter().map(|arg| arg.to_string()).collect(),
    pty,
    ..Exec::default()
  })
}

fn not_allowed(channel: u32, message: &'static str) -> Error {
  Error::NotAllowed { channel, message }
}

#[test]
fn agrees_on_the_newest_version_both_support() {
  let mut host = Mux::with_versions(Side::Host, (1, 3));
  let mut guest = Mux::with_versions(Side::Guest, (2, 5));

  deliver(&mut guest, [host.hello()]);
  deliver(&mut host, [guest.hello()]);

  assert_eq!((host.version(), guest.version()), (Some(3), Some(3)));
}

#[test]
fn opens_nothing_when_no_version_is_common() {
  let mut host = Mux::with_versions(Side::Host, (1, 1));
  let mut guest = Mux::with_versions(Side::Guest, (2, 2));

  let hello = carry([host.hello()]).remove(0);
  assert_eq!(
    guest.receive(hello),
    Err(Error::Version(VersionMismatch {
      ours: (2, 2),
      theirs: (1, 1)
    }))
  );
  let hello = carry([guest.hello()]).remove(0);
  assert_eq!(
    host.receive(hello),
    Err(Error::Version(VersionMismatch {
      ours: (1, 1),
      theirs: (2, 2)
    }))
  );

  assert_eq!(host.open(exec(&["true"], None)).unwrap_err(), Error::NotNegotiated);
  let request = Message::HostCommand {
    name: "test".into(),
    args: Vec::new(),
  };
  assert_eq!(guest.open(request).unwrap_err(), Error::NotNegotiated);
}

#[test]
fn passes_only_control_messages_before_the_hellos() {
  let mut host = Mux::new(Side::Host);
  let mut guest = Mux::new(Side::Guest);

  assert_eq!(host.open(exec(&["true"], None)).unwrap_err(), Error::NotNegotiated);
  assert_eq!(
    guest.receive(exec(&["true"], None).frame(2)).unwrap_err(),
    Error::NotNegotiated
  );
  // A ping finds out whether the agent is there at all.
  let ping = host.send(CONTROL, Message::Ping(1)).unwrap();
  assert_eq!(deliver(&mut guest, [ping]), [(CONTROL, Message::Ping(1))]);
}

#[test]
fn keeps_interleaved_channels_apart() {
  let (mut host, mut guest) = session();
  let (plain, open_plain) = host.open(exec(&["make"], None)).unwrap();
  let (pty, open_pty) = host.open(exec(&["sh"], Some(TERMINAL))).unwrap();
  let (relay, open_relay) = host.open(Message::Connect { port: 80 }).unwrap();
  assert_eq!([plain, pty, relay], [2, 4, 6]);
  deliver(&mut guest, [open_plain, open_pty, open_relay]);

  let mut send = |channel, message| guest.send(channel, message).unwrap();
  let frames = [
    send(relay, Message::Opened),
    send(plain, Message::Opened),
    send(plain, Message::Data(b"cc -c a.c\n".to_vec())),
    send(pty, Message::Opened),
    send(relay, Message::Data(b"HTTP/1.1 200 OK\r\n".to_vec())),
    send(plain, Message::Stderr(b"warning\n".to_vec())),
    send(pty, Message::Data(b"$ ".to_vec())),
    send(plain, Message::Exited(Exit::Code(0))),
  ];
  let received = deliver(&mut host, frames);
  let on = |channel| -> Vec<Message> {
    received
      .iter()
      .filter(|(on, _)| *on == channel)
      .map(|(_, message)| message.clone())
      .collect()
  };

  assert_eq!(
    on(plain),
    [
      Message::Opened,
      Message::Data(b"cc -c a.c\n".to_vec()),
      Message::Stderr(b"warning\n".to_vec()),
      Message::Exited(Exit::Code(0)),
    ]
  );
  assert_eq!(on(pty), [Message::Opened, Message::Data(b"$ ".to_vec())]);
  assert_eq!(
    on(relay),
    [Message::Opened, Message::Data(b"HTTP/1.1 200 OK\r\n".to_vec())]
  );
  assert_eq!(
    [plain, pty, relay].map(|channel| (host.is_open(channel), guest.is_open(channel))),
    [(false, false), (true, true), (true, true)]
  );
}

#[test]
fn resizes_only_a_terminal_and_only_from_its_opener() {
  let (mut host, mut guest) = session();
  let (pty, open_pty) = host.open(exec(&["sh"], Some(TERMINAL))).unwrap();
  let (plain, open_plain) = host.open(exec(&["make"], None)).unwrap();
  deliver(&mut guest, [open_pty, open_plain]);
  let bigger = WindowSize { rows: 50, columns: 132 };

  let resize = host.send(pty, Message::Resize(bigger)).unwrap();
  assert_eq!(deliver(&mut guest, [resize]), [(pty, Message::Resize(bigger))]);

  assert_eq!(
    host.send(plain, Message::Resize(bigger)).unwrap_err(),
    not_allowed(plain, "resize")
  );
  assert_eq!(
    guest.send(pty, Message::Resize(bigger)).unwrap_err(),
    not_allowed(pty, "resize")
  );
  assert_eq!(
    host
      .receive(Message::Resize(bigger).frame(pty))
      .unwrap_err(),
    not_allowed(pty, "resize")
  );
}

#[test]
fn closes_a_relay_once_both_ends_have_finished() {
  let (mut host, mut guest) = session();
  let (relay, open) = host.open(Message::Connect { port: 5432 }).unwrap();
  deliver(&mut guest, [open]);
  deliver(&mut host, [guest.send(relay, Message::Opened).unwrap()]);

  // The host's end is done writing; the guest's can still answer.
  deliver(&mut guest, [host.send(relay, Message::Eof).unwrap()]);
  assert_eq!(
    host
      .send(relay, Message::Data(b"late".to_vec()))
      .unwrap_err(),
    not_allowed(relay, "data")
  );
  let answer = guest
    .send(relay, Message::Data(b"answer".to_vec()))
    .unwrap();
  assert_eq!(
    deliver(&mut host, [answer]),
    [(relay, Message::Data(b"answer".to_vec()))]
  );
  assert!(host.is_open(relay) && guest.is_open(relay));

  deliver(&mut host, [guest.send(relay, Message::Eof).unwrap()]);
  assert!(!host.is_open(relay) && !guest.is_open(relay));
  assert_eq!(
    host.send(relay, Message::Eof).unwrap_err(),
    Error::UnknownChannel(relay)
  );
}

#[test]
fn closes_a_refused_relay() {
  let (mut host, mut guest) = session();
  let (relay, open) = host.open(Message::Connect { port: 1 }).unwrap();
  deliver(&mut guest, [open]);

  let refused = guest
    .send(relay, Message::Error("connection refused".into()))
    .unwrap();
  assert_eq!(
    deliver(&mut host, [refused]),
    [(relay, Message::Error("connection refused".into()))]
  );
  assert!(!host.is_open(relay) && !guest.is_open(relay));
}

#[test]
fn closes_a_process_when_it_exits_not_when_its_output_ends() {
  let (mut host, mut guest) = session();
  let (channel, open) = host.open(exec(&["false"], None)).unwrap();
  deliver(&mut guest, [open]);

  deliver(
    &mut host,
    [
      guest.send(channel, Message::Opened).unwrap(),
      guest.send(channel, Message::Eof).unwrap(),
    ],
  );
  assert!(host.is_open(channel));

  deliver(
    &mut host,
    [guest.send(channel, Message::Exited(Exit::Code(1))).unwrap()],
  );
  assert!(!host.is_open(channel) && !guest.is_open(channel));
  assert_eq!(
    host.send(channel, Message::Signal(15)).unwrap_err(),
    Error::UnknownChannel(channel)
  );
}

#[test]
fn lets_only_the_guest_ask_for_host_commands() {
  let (mut host, mut guest) = session();
  let request = Message::HostCommand {
    name: "test".into(),
    args: vec!["-q".into()],
  };

  let (channel, open) = guest.open(request.clone()).unwrap();
  assert_eq!(channel, 1);
  assert_eq!(deliver(&mut host, [open]), [(channel, request.clone())]);
  let mut send = |message| host.send(channel, message).unwrap();
  let frames = [
    send(Message::Opened),
    send(Message::Data(b"ok\n".to_vec())),
    send(Message::Exited(Exit::Code(0))),
  ];
  deliver(&mut guest, frames);
  assert!(!guest.is_open(channel) && !host.is_open(channel));

  assert_eq!(host.open(request).unwrap_err(), not_allowed(2, "host command"));
  assert_eq!(guest.open(exec(&["true"], None)).unwrap_err(), not_allowed(3, "exec"));
  // Nor can either pass off its own opening as the other's.
  assert_eq!(
    host.receive(exec(&["true"], None).frame(3)).unwrap_err(),
    not_allowed(3, "exec")
  );
  assert_eq!(
    guest.receive(exec(&["true"], None).frame(3)).unwrap_err(),
    Error::BadChannel(3)
  );
}

#[test]
fn forgets_the_old_session_at_a_new_hello() {
  // As after a restore: the host starts over, and the guest drops what it had.
  let (mut host, mut guest) = session();
  let (channel, open) = host.open(exec(&["sleep", "60"], None)).unwrap();
  deliver(&mut guest, [open]);

  let hello = host.hello();
  assert!(!host.is_open(channel));
  assert_eq!(host.open(exec(&["true"], None)).unwrap_err(), Error::NotNegotiated);
  deliver(&mut guest, [hello]);
  assert!(!guest.is_open(channel));
  deliver(&mut host, [guest.hello()]);

  assert_eq!(host.version(), Some(1));
  assert_eq!(
    host
      .receive(Message::Data(b"late".to_vec()).frame(channel))
      .unwrap_err(),
    Error::UnknownChannel(channel)
  );
}

#[test]
fn refuses_a_payload_over_the_limit() {
  let (mut host, mut guest) = session();
  let (channel, open) = host.open(exec(&["cat"], None)).unwrap();
  deliver(&mut guest, [open]);

  assert_eq!(
    host
      .send(channel, Message::Data(vec![0; MAX_PAYLOAD + 1]))
      .unwrap_err(),
    Error::TooLarge(MAX_PAYLOAD + 1)
  );
  assert!(
    host
      .send(channel, Message::Data(vec![0; MAX_PAYLOAD]))
      .is_ok()
  );
}
