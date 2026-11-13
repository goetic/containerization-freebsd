//! Relays the host opens with Connect, to a TCP port on the guest's loopback.

use crate::session::{Handle, Input, Outbox, READ, Running};
use containerization_freebsd_protocol::Message;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread;

/// Connects to `port` on 127.0.0.1, or failing that on ::1.
pub(crate) fn connect(port: u16, outbox: Outbox) -> io::Result<Handle> {
  let addresses = [
    SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
    SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
  ];
  let stream = TcpStream::connect(&addresses[..])?;
  let (reader, writer) = (stream.try_clone()?, stream.try_clone()?);

  let (input, inputs) = mpsc::channel();
  thread::spawn(move || forward(writer, &inputs));
  thread::spawn(move || back(reader, &outbox));

  Ok(Handle {
    input,
    running: Running::Relay(stream),
  })
}

/// Writes the host's Data to the connection, and at its Eof shuts the
/// connection's write side.
fn forward(mut stream: TcpStream, inputs: &Receiver<Input>) {
  for input in inputs {
    match input {
      Input::Data(bytes) => {
        // Reading fails too, and tells the host.
        if stream.write_all(&bytes).is_err() {
          return;
        }
      }
      Input::Eof => {
        let _ = stream.shutdown(Shutdown::Write);
        return;
      }
    }
  }
}

/// Sends what the connection reads as Data, then Eof; or Error, if reading
/// fails.
fn back(mut stream: TcpStream, outbox: &Outbox) {
  let mut buffer = vec![0; READ];

  loop {
    match stream.read(&mut buffer) {
      Ok(0) => {
        outbox.send(Message::Eof);
        return;
      }
      Ok(read) => {
        if !outbox.send(Message::Data(buffer[..read].to_vec())) {
          return;
        }
      }
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      Err(error) => {
        outbox.send(Message::Error(format!("reading from the connection: {error}")));
        return;
      }
    }
  }
}
