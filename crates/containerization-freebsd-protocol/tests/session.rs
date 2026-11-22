//! Runs both sides of a session in memory, passing their frames through an
//! encoded byte stream as the console would.

use containerization_freebsd_protocol::{
  Address, CONTROL, Connect, Decoder, Error, Exec, Exit, Frame, Listen, MAX_PAYLOAD, Message, Mux, Side, VERSION,
  VersionMismatch, WindowSize,
};

const TERMINAL: WindowSize = WindowSize { rows: 24, columns: 80 };

/// Encodes `frames` into one byte stream and decodes them again.
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

/// Carries `frames` to `to` and returns what it receives.
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
  Message::Exec(Exec { pty, ..Exec::new(argv) })
}

fn connect(port: u16) -> Message {
  Message::Connect(Connect {
    to: Address::Port(port),
    jail: None,
  })
}

fn listen(path: &str) -> Message {
  Message::Listen(Listen {
    path: path.into(),
    ..Listen::default()
  })
}

fn not_allowed(channel: u32, message: &'static str) -> Error {
  Error::NotAllowed { channel, message }
}

#[test]
fn opens_nothing_when_the_versions_differ() {
  let mut host = Mux::new(Side::Host);
  let mut guest = Mux::new(Side::Guest);
  let newer = |answer| {
    Message::Hello {
      version: VERSION + 1,
      answer,
    }
    .frame(CONTROL)
  };
  let mismatch = Error::Version(VersionMismatch {
    ours: VERSION,
    theirs: VERSION + 1,
  });

  host.hello();
  assert_eq!(host.receive(newer(true)).unwrap_err(), mismatch);
  assert_eq!(guest.receive(newer(false)).unwrap_err(), mismatch);

  assert_eq!(host.open(exec(&["true"], None)).unwrap_err(), Error::NoSession);
}

#[test]
fn passes_only_control_messages_before_the_hellos() {
  let mut host = Mux::new(Side::Host);
  let mut guest = Mux::new(Side::Guest);

  assert_eq!(host.open(exec(&["true"], None)).unwrap_err(), Error::NoSession);
  assert_eq!(
    guest.receive(exec(&["true"], None).frame(2)).unwrap_err(),
    Error::NoSession
  );
  // A ping checks whether the agent is running at all.
  let ping = host.send(CONTROL, Message::Ping(1)).unwrap();
  assert_eq!(deliver(&mut guest, [ping]), [(CONTROL, Message::Ping(1))]);
  // The agent reads the console whether or not there is a session.
  let received = guest.send(CONTROL, Message::Received(64)).unwrap();
  assert_eq!(deliver(&mut host, [received]), [(CONTROL, Message::Received(64))]);
}

#[test]
fn lets_only_the_guest_say_what_it_received() {
  let (mut host, mut guest) = session();

  assert_eq!(
    host.send(CONTROL, Message::Received(1)).unwrap_err(),
    not_allowed(CONTROL, "received")
  );
  assert_eq!(
    guest
      .receive(Message::Received(1).frame(CONTROL))
      .unwrap_err(),
    not_allowed(CONTROL, "received")
  );
  assert_eq!(
    guest.send(2, Message::Received(1)).unwrap_err(),
    Error::UnknownChannel(2)
  );
}

#[test]
fn lets_only_the_host_set_the_time() {
  let (mut host, mut guest) = session();
  let time = Message::SetTime {
    seconds: 1,
    nanoseconds: 2,
  };

  let frame = host.send(CONTROL, time.clone()).unwrap();
  assert_eq!(deliver(&mut guest, [frame]), [(CONTROL, time.clone())]);
  assert_eq!(
    guest.send(CONTROL, time.clone()).unwrap_err(),
    not_allowed(CONTROL, "set time")
  );
  assert_eq!(
    host.receive(time.frame(CONTROL)).unwrap_err(),
    not_allowed(CONTROL, "set time")
  );
}

#[test]
fn keeps_interleaved_channels_apart() {
  let (mut host, mut guest) = session();
  let (plain, open_plain) = host.open(exec(&["make"], None)).unwrap();
  let (pty, open_pty) = host.open(exec(&["sh"], Some(TERMINAL))).unwrap();
  let (relay, open_relay) = host.open(connect(80)).unwrap();
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
  let (relay, open) = host.open(connect(5432)).unwrap();
  deliver(&mut guest, [open]);
  deliver(&mut host, [guest.send(relay, Message::Opened).unwrap()]);

  // The host has finished writing, but the guest can still answer.
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
  let (relay, open) = host.open(connect(1)).unwrap();
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
fn relays_each_connection_to_a_listener_on_a_channel_the_guest_opens() {
  let (mut host, mut guest) = session();
  let (listener, open) = host.open(listen("/var/run/host.sock")).unwrap();
  deliver(&mut guest, [open]);
  deliver(&mut host, [guest.send(listener, Message::Opened).unwrap()]);

  let (first, accepted) = guest.open(Message::Accepted { listener }).unwrap();
  let (second, also_accepted) = guest.open(Message::Accepted { listener }).unwrap();
  assert_eq!([first, second], [1, 3]);
  // The guest may send data before the host has connected its end.
  let early = guest.send(first, Message::Data(b"hello".to_vec())).unwrap();
  assert_eq!(
    deliver(&mut host, [accepted, also_accepted, early]),
    [
      (first, Message::Accepted { listener }),
      (second, Message::Accepted { listener }),
      (first, Message::Data(b"hello".to_vec())),
    ]
  );
  assert_eq!(
    host
      .send(first, Message::Data(b"early".to_vec()))
      .unwrap_err(),
    not_allowed(first, "data")
  );

  deliver(
    &mut guest,
    [
      host.send(first, Message::Opened).unwrap(),
      host.send(first, Message::Data(b"HELLO".to_vec())).unwrap(),
      host.send(first, Message::Eof).unwrap(),
    ],
  );
  deliver(&mut host, [guest.send(first, Message::Eof).unwrap()]);
  assert!(!host.is_open(first) && !guest.is_open(first));
  // The host could not connect the second connection.
  deliver(
    &mut guest,
    [host.send(second, Message::Error("refused".into())).unwrap()],
  );
  assert!(!host.is_open(second) && !guest.is_open(second));
  assert!(host.is_open(listener) && guest.is_open(listener));
}

#[test]
fn closes_a_listener_once_both_sides_have_sent_eof() {
  let (mut host, mut guest) = session();
  let (listener, open) = host.open(listen("/var/run/host.sock")).unwrap();
  deliver(&mut guest, [open]);
  deliver(&mut host, [guest.send(listener, Message::Opened).unwrap()]);
  assert_eq!(
    host
      .send(listener, Message::Data(b"x".to_vec()))
      .unwrap_err(),
    not_allowed(listener, "data")
  );

  deliver(&mut guest, [host.send(listener, Message::Eof).unwrap()]);
  // A connection accepted before the listener stopped can still open.
  let (_, accepted) = guest.open(Message::Accepted { listener }).unwrap();
  deliver(&mut host, [accepted]);
  assert!(host.is_open(listener) && guest.is_open(listener));

  deliver(&mut host, [guest.send(listener, Message::Eof).unwrap()]);
  assert!(!host.is_open(listener) && !guest.is_open(listener));
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
fn lets_each_side_open_only_its_own_channels() {
  let (mut host, mut guest) = session();
  let accepted = Message::Accepted { listener: 2 };

  assert_eq!(guest.open(exec(&["true"], None)).unwrap_err(), not_allowed(1, "exec"));
  assert_eq!(guest.open(connect(22)).unwrap_err(), not_allowed(1, "connect"));
  assert_eq!(guest.open(listen("/s")).unwrap_err(), not_allowed(1, "listen"));
  assert_eq!(host.open(accepted.clone()).unwrap_err(), not_allowed(2, "accepted"));
  // Neither side can send an opening message that belongs to the other.
  assert_eq!(
    host.receive(exec(&["true"], None).frame(3)).unwrap_err(),
    not_allowed(3, "exec")
  );
  assert_eq!(
    guest.receive(exec(&["true"], None).frame(3)).unwrap_err(),
    Error::BadChannel(3)
  );
  assert_eq!(
    guest.receive(accepted.frame(1)).unwrap_err(),
    not_allowed(1, "accepted")
  );
  assert_eq!(host.receive(accepted.frame(2)).unwrap_err(), Error::BadChannel(2));
}

#[test]
fn forgets_the_old_session_at_a_new_hello() {
  // Simulates a restore: the host starts over, and the guest drops its
  // channels.
  let (mut host, mut guest) = session();
  let (channel, open) = host.open(exec(&["sleep", "60"], None)).unwrap();
  deliver(&mut guest, [open]);

  let hello = host.hello();
  assert!(!host.is_open(channel));
  assert_eq!(host.open(exec(&["true"], None)).unwrap_err(), Error::NoSession);
  deliver(&mut guest, [hello]);
  assert!(!guest.is_open(channel));
  deliver(&mut host, [guest.hello()]);

  assert!(host.in_session());
  assert_eq!(
    host
      .receive(Message::Data(b"late".to_vec()).frame(channel))
      .unwrap_err(),
    Error::UnknownChannel(channel)
  );
}

#[test]
fn starts_over_when_the_agent_announces_it_has_no_session() {
  let (mut host, mut guest) = session();
  let (channel, open) = host.open(exec(&["sleep", "60"], None)).unwrap();
  deliver(&mut guest, [open]);

  // The agent restarts.
  let mut agent = Mux::new(Side::Guest);
  let received = deliver(&mut host, [agent.hello()]);
  assert!(matches!(
    received[..],
    [(CONTROL, Message::Hello { answer: false, .. })]
  ));
  assert!(!host.is_open(channel) && !host.in_session());

  deliver(&mut agent, [host.hello()]);
  deliver(&mut host, [agent.hello()]);
  assert!(host.in_session());
}

#[test]
fn settles_when_the_agent_starts_as_the_host_says_hello() {
  let mut host = Mux::new(Side::Host);
  let mut guest = Mux::new(Side::Guest);
  let first = host.hello();
  let announcement = guest.hello();
  deliver(&mut guest, [first]);
  let answer = guest.hello();

  // The host answers the announcement before the answer to its first Hello
  // arrives, and opens a channel on that answer.
  deliver(&mut host, [announcement]);
  let second = host.hello();
  deliver(&mut host, [answer]);
  let (channel, open) = host.open(exec(&["true"], None)).unwrap();
  deliver(&mut guest, [second]);
  let answer = guest.hello();
  deliver(&mut guest, [open]);
  deliver(&mut host, [answer]);

  assert!(host.is_open(channel) && guest.is_open(channel));
}

#[test]
fn refuses_an_answer_to_another_hosts_hello() {
  // Simulates a restore: the guest answers the Hello of the host that saved
  // the VM.
  let mut saved = Mux::new(Side::Host);
  let mut guest = Mux::new(Side::Guest);
  deliver(&mut guest, [saved.hello()]);
  let answer = carry([guest.hello()]).remove(0);
  let mut host = Mux::new(Side::Host);

  assert_eq!(host.receive(answer).unwrap_err(), not_allowed(CONTROL, "hello"));
  assert!(!host.in_session());
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
