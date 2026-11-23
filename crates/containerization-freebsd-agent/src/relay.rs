//! Relays between a channel and a connection. The host opens a relay to a
//! guest socket with Connect; the agent opens one with Accepted for each
//! connection to a socket it listens on.

use crate::pipe::{Stopped, read_chunks, write_until_eof};
use crate::session::{Handle, Input, Outbox};
use crate::sys::{self, SocketAddress};
use containerization_freebsd_protocol::{Address, Connect, Message};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;

pub(crate) enum Connection {
  Tcp(TcpStream),
  Unix(UnixStream),
}

/// Connects as `connect` describes, from inside its jail if it names one.
pub(crate) fn connect(connect: &Connect, outbox: Outbox) -> io::Result<Handle> {
  let jail = sys::jail_id(connect.jail.as_deref())?;
  let connection = match (&connect.to, jail) {
    (Address::Port(port), None) => Connection::Tcp(TcpStream::connect(
      &[
        SocketAddr::from((Ipv4Addr::LOCALHOST, *port)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, *port)),
      ][..],
    )?),
    (Address::Port(port), Some(jid)) => Connection::Tcp(sys::connect_in(jid, &SocketAddress::loopback(*port))?.into()),
    (Address::Unix(path), None) => Connection::Unix(UnixStream::connect(path)?),
    (Address::Unix(path), Some(jid)) => {
      let address = SocketAddress::unix(&sys::path(path)?)?;
      Connection::Unix(sys::connect_in(jid, &[address])?.into())
    }
  };

  Ok(start(connection, outbox))
}

/// Relays `connection` on the channel `outbox` sends on. The two threads and
/// the handle share the connection, as std's streams allow.
pub(crate) fn start(connection: Connection, outbox: Outbox) -> Handle {
  let connection = Arc::new(connection);
  let (input, inputs) = mpsc::channel();
  let (writer, reader) = (connection.clone(), connection.clone());
  thread::spawn(move || forward(&writer, &inputs));
  thread::spawn(move || back(&reader, &outbox));

  Handle::Relay { input, connection }
}

/// Writes the host's Data to the connection, and at its Eof half-closes the
/// connection.
fn forward(connection: &Connection, inputs: &Receiver<Input>) {
  let mut writer = connection;
  if write_until_eof(&mut writer, inputs) {
    let _ = connection.shutdown(Shutdown::Write);
  }
}

/// Sends what the connection reads as Data, then Eof. Sends Error instead if
/// reading fails.
fn back(connection: &Connection, outbox: &Outbox) {
  match read_chunks(connection, |bytes| outbox.send(Message::Data(bytes))) {
    Stopped::Eof => {
      outbox.send(Message::Eof);
    }
    // The session loop has stopped.
    Stopped::Refused => {}
    Stopped::Failed(error) => {
      outbox.send(Message::Error(format!("reading from the connection: {error}")));
    }
  }
}

impl Connection {
  pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
    match self {
      Self::Tcp(stream) => stream.shutdown(how),
      Self::Unix(stream) => stream.shutdown(how),
    }
  }
}

impl Read for &Connection {
  fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
    match self {
      Connection::Tcp(stream) => {
        let mut stream: &TcpStream = stream;
        stream.read(buffer)
      }
      Connection::Unix(stream) => {
        let mut stream: &UnixStream = stream;
        stream.read(buffer)
      }
    }
  }
}

impl Write for &Connection {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    match self {
      Connection::Tcp(stream) => {
        let mut stream: &TcpStream = stream;
        stream.write(bytes)
      }
      Connection::Unix(stream) => {
        let mut stream: &UnixStream = stream;
        stream.write(bytes)
      }
    }
  }

  fn flush(&mut self) -> io::Result<()> {
    Ok(())
  }
}
