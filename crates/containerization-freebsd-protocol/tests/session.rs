//! Runs both sides of a session in memory, passing their frames through an
//! encoded byte stream as the console would.

use containerization_freebsd_protocol::{frame, message, mux};

const TERMINAL: message::WindowSize = message::WindowSize { rows: 24, columns: 80 };

/// Encodes `frames` into one byte stream and decodes them again.
fn carry(frames: impl IntoIterator<Item = frame::Frame>) -> Vec<frame::Frame> {
  let mut bytes = Vec::new();
  for frame in frames {
    frame.encode(&mut bytes);
  }
  let mut decoder = frame::Decoder::new();
  decoder.push(&bytes);

  std::iter::from_fn(|| decoder.decode())
    .map(|frame| frame.expect("nothing skipped"))
    .collect()
}

/// Carries `frames` to `to` and returns what it receives.
fn deliver(to: &mut mux::Mux, frames: impl IntoIterator<Item = frame::Frame>) -> Vec<(u32, message::Message)> {
  carry(frames)
    .into_iter()
    .map(|frame| to.receive(frame).expect("receives"))
    .collect()
}

fn session() -> (mux::Mux, mux::Mux) {
  let mut host = mux::Mux::new(mux::Side::Host);
  let mut guest = mux::Mux::new(mux::Side::Guest);

  deliver(&mut guest, [host.hello()]);
  deliver(&mut host, [guest.hello()]);
  (host, guest)
}

fn exec(argv: &[&str], pty: Option<message::WindowSize>) -> message::Message {
  message::Message::Exec(message::Exec {
    pty,
    ..message::Exec::new(argv)
  })
}

fn connect(port: u16) -> message::Message {
  message::Message::Connect(message::Connect {
    to: message::Address::Port(port),
    jail: None,
  })
}

fn listen(path: &str) -> message::Message {
  message::Message::Listen(message::Listen {
    path: path.into(),
    ..message::Listen::default()
  })
}

fn not_allowed(channel: u32, message: &'static str) -> mux::Error {
  mux::Error::NotAllowed { channel, message }
}

#[test]
fn opens_nothing_when_the_versions_differ() {
  let mut host = mux::Mux::new(mux::Side::Host);
  let mut guest = mux::Mux::new(mux::Side::Guest);
  let newer = |answer| {
    message::Message::Hello {
      version: mux::VERSION + 1,
      answer,
    }
    .frame(mux::CONTROL)
  };
  let mismatch = mux::Error::Version(mux::VersionMismatch {
    ours: mux::VERSION,
    theirs: mux::VERSION + 1,
  });

  host.hello();
  assert_eq!(host.receive(newer(true)).unwrap_err(), mismatch);
  assert_eq!(guest.receive(newer(false)).unwrap_err(), mismatch);

  assert_eq!(host.open(exec(&["true"], None)).unwrap_err(), mux::Error::NoSession);
}

#[test]
fn passes_only_control_messages_before_the_hellos() {
  let mut host = mux::Mux::new(mux::Side::Host);
  let mut guest = mux::Mux::new(mux::Side::Guest);

  assert_eq!(host.open(exec(&["true"], None)).unwrap_err(), mux::Error::NoSession);
  assert_eq!(
    guest.receive(exec(&["true"], None).frame(2)).unwrap_err(),
    mux::Error::NoSession
  );
  // A ping checks whether the agent is running at all.
  let ping = host.send(mux::CONTROL, message::Message::Ping(1)).unwrap();
  assert_eq!(deliver(&mut guest, [ping]), [(mux::CONTROL, message::Message::Ping(1))]);
  // The agent reads the console whether or not there is a session.
  let received = guest
    .send(mux::CONTROL, message::Message::Received(64))
    .unwrap();
  assert_eq!(
    deliver(&mut host, [received]),
    [(mux::CONTROL, message::Message::Received(64))]
  );
}

#[test]
fn lets_only_the_guest_say_what_it_received() {
  let (mut host, mut guest) = session();

  assert_eq!(
    host
      .send(mux::CONTROL, message::Message::Received(1))
      .unwrap_err(),
    not_allowed(mux::CONTROL, "received")
  );
  assert_eq!(
    guest
      .receive(message::Message::Received(1).frame(mux::CONTROL))
      .unwrap_err(),
    not_allowed(mux::CONTROL, "received")
  );
  assert_eq!(
    guest.send(2, message::Message::Received(1)).unwrap_err(),
    mux::Error::UnknownChannel(2)
  );
}

#[test]
fn lets_only_the_host_set_the_time() {
  let (mut host, mut guest) = session();
  let time = message::Message::SetTime {
    seconds: 1,
    nanoseconds: 2,
  };

  let frame = host.send(mux::CONTROL, time.clone()).unwrap();
  assert_eq!(deliver(&mut guest, [frame]), [(mux::CONTROL, time.clone())]);
  assert_eq!(
    guest.send(mux::CONTROL, time.clone()).unwrap_err(),
    not_allowed(mux::CONTROL, "set time")
  );
  assert_eq!(
    host.receive(time.frame(mux::CONTROL)).unwrap_err(),
    not_allowed(mux::CONTROL, "set time")
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
    send(relay, message::Message::Opened),
    send(plain, message::Message::Opened),
    send(plain, message::Message::Data(b"cc -c a.c\n".to_vec())),
    send(pty, message::Message::Opened),
    send(relay, message::Message::Data(b"HTTP/1.1 200 OK\r\n".to_vec())),
    send(plain, message::Message::Stderr(b"warning\n".to_vec())),
    send(pty, message::Message::Data(b"$ ".to_vec())),
    send(plain, message::Message::Exited(message::Exit::Code(0))),
  ];
  let received = deliver(&mut host, frames);
  let on = |channel| -> Vec<message::Message> {
    received
      .iter()
      .filter(|(on, _)| *on == channel)
      .map(|(_, message)| message.clone())
      .collect()
  };

  assert_eq!(
    on(plain),
    [
      message::Message::Opened,
      message::Message::Data(b"cc -c a.c\n".to_vec()),
      message::Message::Stderr(b"warning\n".to_vec()),
      message::Message::Exited(message::Exit::Code(0)),
    ]
  );
  assert_eq!(
    on(pty),
    [message::Message::Opened, message::Message::Data(b"$ ".to_vec())]
  );
  assert_eq!(
    on(relay),
    [
      message::Message::Opened,
      message::Message::Data(b"HTTP/1.1 200 OK\r\n".to_vec())
    ]
  );
  assert_eq!(
    [plain, pty, relay].map(|channel| (host.is_open(channel), guest.is_open(channel))),
    [(false, false), (true, true), (true, true)]
  );
}

#[test]
fn resizes_only_a_terminal_and_only_from_its_initiator() {
  let (mut host, mut guest) = session();
  let (pty, open_pty) = host.open(exec(&["sh"], Some(TERMINAL))).unwrap();
  let (plain, open_plain) = host.open(exec(&["make"], None)).unwrap();
  deliver(&mut guest, [open_pty, open_plain]);
  let bigger = message::WindowSize { rows: 50, columns: 132 };

  let resize = host.send(pty, message::Message::Resize(bigger)).unwrap();
  assert_eq!(deliver(&mut guest, [resize]), [(pty, message::Message::Resize(bigger))]);

  assert_eq!(
    host
      .send(plain, message::Message::Resize(bigger))
      .unwrap_err(),
    not_allowed(plain, "resize")
  );
  assert_eq!(
    guest
      .send(pty, message::Message::Resize(bigger))
      .unwrap_err(),
    not_allowed(pty, "resize")
  );
  assert_eq!(
    host
      .receive(message::Message::Resize(bigger).frame(pty))
      .unwrap_err(),
    not_allowed(pty, "resize")
  );
}

#[test]
fn closes_a_relay_once_both_ends_have_finished() {
  let (mut host, mut guest) = session();
  let (relay, open) = host.open(connect(5432)).unwrap();
  deliver(&mut guest, [open]);
  deliver(&mut host, [guest.send(relay, message::Message::Opened).unwrap()]);

  // The host has finished writing, but the guest can still answer.
  deliver(&mut guest, [host.send(relay, message::Message::Eof).unwrap()]);
  assert_eq!(
    host
      .send(relay, message::Message::Data(b"late".to_vec()))
      .unwrap_err(),
    not_allowed(relay, "data")
  );
  let answer = guest
    .send(relay, message::Message::Data(b"answer".to_vec()))
    .unwrap();
  assert_eq!(
    deliver(&mut host, [answer]),
    [(relay, message::Message::Data(b"answer".to_vec()))]
  );
  assert!(host.is_open(relay) && guest.is_open(relay));

  deliver(&mut host, [guest.send(relay, message::Message::Eof).unwrap()]);
  assert!(!host.is_open(relay) && !guest.is_open(relay));
  assert_eq!(
    host.send(relay, message::Message::Eof).unwrap_err(),
    mux::Error::UnknownChannel(relay)
  );
}

#[test]
fn closes_a_refused_relay() {
  let (mut host, mut guest) = session();
  let (relay, open) = host.open(connect(1)).unwrap();
  deliver(&mut guest, [open]);

  let refused = guest
    .send(relay, message::Message::Error("connection refused".into()))
    .unwrap();
  assert_eq!(
    deliver(&mut host, [refused]),
    [(relay, message::Message::Error("connection refused".into()))]
  );
  assert!(!host.is_open(relay) && !guest.is_open(relay));
}

#[test]
fn sends_data_from_borrowed_bytes_as_send_does() {
  let (mut host, mut guest) = session();
  let (channel, open) = host.open(exec(&["cat"], None)).unwrap();
  deliver(&mut guest, [open]);
  let mut encoded = Vec::new();

  host.send_data(channel, b"stdin", &mut encoded).unwrap();
  let mut decoder = frame::Decoder::new();
  decoder.push(&encoded);
  let frame = decoder.decode().unwrap().unwrap();
  assert_eq!(
    guest.receive(frame).unwrap(),
    (channel, message::Message::Data(b"stdin".to_vec()))
  );

  deliver(&mut guest, [host.send(channel, message::Message::Eof).unwrap()]);
  assert_eq!(
    host.send_data(channel, b"late", &mut encoded).unwrap_err(),
    not_allowed(channel, "data")
  );
  assert_eq!(
    host
      .send_data(mux::CONTROL, b"x", &mut encoded)
      .unwrap_err(),
    not_allowed(mux::CONTROL, "data")
  );
}

#[test]
fn closes_a_call_channel_with_its_answer() {
  let (mut host, mut guest) = session();
  let call = || {
    message::Message::Call(message::Call::FileType(message::GuestPath {
      path: "/etc".into(),
      jail: None,
    }))
  };
  let (answered, open) = host.open(call()).unwrap();
  let (refused, also_open) = host.open(call()).unwrap();
  deliver(&mut guest, [open, also_open]);
  assert_eq!(
    host
      .send(answered, message::Message::Data(b"x".to_vec()))
      .unwrap_err(),
    not_allowed(answered, "data")
  );
  assert_eq!(
    guest.send(answered, message::Message::Opened).unwrap_err(),
    not_allowed(answered, "opened")
  );

  let answer = guest
    .send(
      answered,
      message::Message::Return(message::Return::FileType(message::FileType::Directory)),
    )
    .unwrap();
  let refusal = guest
    .send(refused, message::Message::Error("no jail is named \"web\"".into()))
    .unwrap();
  deliver(&mut host, [answer, refusal]);
  assert!(!host.is_open(answered) && !guest.is_open(answered));
  assert!(!host.is_open(refused) && !guest.is_open(refused));
}

#[test]
fn relays_each_connection_to_a_listener_on_a_channel_the_guest_opens() {
  let (mut host, mut guest) = session();
  let (listener, open) = host.open(listen("/var/run/host.sock")).unwrap();
  deliver(&mut guest, [open]);
  deliver(&mut host, [guest.send(listener, message::Message::Opened).unwrap()]);

  let (first, accepted) = guest.open(message::Message::Accepted { listener }).unwrap();
  let (second, also_accepted) = guest.open(message::Message::Accepted { listener }).unwrap();
  assert_eq!([first, second], [1, 3]);
  // The guest may send data before the host has connected its end.
  let early = guest
    .send(first, message::Message::Data(b"hello".to_vec()))
    .unwrap();
  assert_eq!(
    deliver(&mut host, [accepted, also_accepted, early]),
    [
      (first, message::Message::Accepted { listener }),
      (second, message::Message::Accepted { listener }),
      (first, message::Message::Data(b"hello".to_vec())),
    ]
  );
  assert_eq!(
    host
      .send(first, message::Message::Data(b"early".to_vec()))
      .unwrap_err(),
    not_allowed(first, "data")
  );

  deliver(
    &mut guest,
    [
      host.send(first, message::Message::Opened).unwrap(),
      host
        .send(first, message::Message::Data(b"HELLO".to_vec()))
        .unwrap(),
      host.send(first, message::Message::Eof).unwrap(),
    ],
  );
  deliver(&mut host, [guest.send(first, message::Message::Eof).unwrap()]);
  assert!(!host.is_open(first) && !guest.is_open(first));
  // The host could not connect the second connection.
  deliver(
    &mut guest,
    [host
      .send(second, message::Message::Error("refused".into()))
      .unwrap()],
  );
  assert!(!host.is_open(second) && !guest.is_open(second));
  assert!(host.is_open(listener) && guest.is_open(listener));
}

#[test]
fn closes_a_listener_once_both_sides_have_sent_eof() {
  let (mut host, mut guest) = session();
  let (listener, open) = host.open(listen("/var/run/host.sock")).unwrap();
  deliver(&mut guest, [open]);
  deliver(&mut host, [guest.send(listener, message::Message::Opened).unwrap()]);
  assert_eq!(
    host
      .send(listener, message::Message::Data(b"x".to_vec()))
      .unwrap_err(),
    not_allowed(listener, "data")
  );

  deliver(&mut guest, [host.send(listener, message::Message::Eof).unwrap()]);
  // A connection accepted before the listener stopped can still open.
  let (_, accepted) = guest.open(message::Message::Accepted { listener }).unwrap();
  deliver(&mut host, [accepted]);
  assert!(host.is_open(listener) && guest.is_open(listener));

  deliver(&mut host, [guest.send(listener, message::Message::Eof).unwrap()]);
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
      guest.send(channel, message::Message::Opened).unwrap(),
      guest.send(channel, message::Message::Eof).unwrap(),
    ],
  );
  assert!(host.is_open(channel));

  deliver(
    &mut host,
    [guest
      .send(channel, message::Message::Exited(message::Exit::Code(1)))
      .unwrap()],
  );
  assert!(!host.is_open(channel) && !guest.is_open(channel));
  assert_eq!(
    host
      .send(channel, message::Message::Signal(15))
      .unwrap_err(),
    mux::Error::UnknownChannel(channel)
  );
}

#[test]
fn lets_each_side_open_only_its_own_channels() {
  let (mut host, mut guest) = session();
  let accepted = message::Message::Accepted { listener: 2 };

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
    mux::Error::BadChannel(3)
  );
  assert_eq!(
    guest.receive(accepted.clone().frame(1)).unwrap_err(),
    not_allowed(1, "accepted")
  );
  assert_eq!(host.receive(accepted.frame(2)).unwrap_err(), mux::Error::BadChannel(2));
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
  assert_eq!(host.open(exec(&["true"], None)).unwrap_err(), mux::Error::NoSession);
  deliver(&mut guest, [hello]);
  assert!(!guest.is_open(channel));
  deliver(&mut host, [guest.hello()]);

  assert!(host.in_session());
  assert_eq!(
    host
      .receive(message::Message::Data(b"late".to_vec()).frame(channel))
      .unwrap_err(),
    mux::Error::UnknownChannel(channel)
  );
}

#[test]
fn starts_over_when_the_agent_announces_it_has_no_session() {
  let (mut host, mut guest) = session();
  let (channel, open) = host.open(exec(&["sleep", "60"], None)).unwrap();
  deliver(&mut guest, [open]);

  // The agent restarts.
  let mut agent = mux::Mux::new(mux::Side::Guest);
  let received = deliver(&mut host, [agent.hello()]);
  assert!(matches!(
    received[..],
    [(mux::CONTROL, message::Message::Hello { answer: false, .. })]
  ));
  assert!(!host.is_open(channel) && !host.in_session());

  deliver(&mut agent, [host.hello()]);
  deliver(&mut host, [agent.hello()]);
  assert!(host.in_session());
}

#[test]
fn settles_when_the_agent_starts_as_the_host_says_hello() {
  let mut host = mux::Mux::new(mux::Side::Host);
  let mut guest = mux::Mux::new(mux::Side::Guest);
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
  let mut saved = mux::Mux::new(mux::Side::Host);
  let mut guest = mux::Mux::new(mux::Side::Guest);
  deliver(&mut guest, [saved.hello()]);
  let answer = carry([guest.hello()]).remove(0);
  let mut host = mux::Mux::new(mux::Side::Host);

  assert_eq!(host.receive(answer).unwrap_err(), not_allowed(mux::CONTROL, "hello"));
  assert!(!host.in_session());
}

#[test]
fn refuses_a_payload_over_the_limit() {
  let (mut host, mut guest) = session();
  let (channel, open) = host.open(exec(&["cat"], None)).unwrap();
  deliver(&mut guest, [open]);

  assert_eq!(
    host
      .send(channel, message::Message::Data(vec![0; frame::MAX_PAYLOAD + 1]))
      .unwrap_err(),
    mux::Error::TooLarge(frame::MAX_PAYLOAD + 1)
  );
  assert!(
    host
      .send(channel, message::Message::Data(vec![0; frame::MAX_PAYLOAD]))
      .is_ok()
  );
}
