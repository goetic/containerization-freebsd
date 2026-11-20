//! Relays between a channel and a connection. The host opens a relay to a
//! guest socket with Connect; the agent opens one with Accepted for each
//! connection to a socket it listens on.

use crate::session::{Handle, Input, Outbox, READ};
use crate::sys::{self, SocketAddress};
use containerization_freebsd_protocol::{Address, Connect, Message};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
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

  start(connection, outbox)
}

/// Relays `connection` on the channel `outbox` sends on.
pub(crate) fn start(connection: Connection, outbox: Outbox) -> io::Result<Handle> {
  let (reader, writer) = (connection.try_clone()?, connection.try_clone()?);

  let (input, inputs) = mpsc::channel();
  thread::spawn(move || forward(writer, &inputs));
  thread::spawn(move || back(reader, &outbox));

  Ok(Handle::Relay { input, connection })
}

/// Writes the host's Data to the connection, and at its Eof half-closes the
/// connection.
fn forward(mut connection: Connection, inputs: &Receiver<Input>) {
  for input in inputs {
    match input {
      Input::Data(bytes) => {
        // The peer closed or reset the connection: the rest of the Data has
        // nowhere to go.
        if connection.write_all(&bytes).is_err() {
          return;
        }
      }
      Input::Eof => {
        let _ = connection.shutdown(Shutdown::Write);
        return;
      }
    }
  }
}

/// Sends what the connection reads as Data, then Eof. Sends Error instead if
/// reading fails.
fn back(mut connection: Connection, outbox: &Outbox) {
  let mut buffer = vec![0; READ];

  loop {
    match connection.read(&mut buffer) {
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

impl Connection {
  fn try_clone(&self) -> io::Result<Self> {
    Ok(match self {
      Self::Tcp(stream) => Self::Tcp(stream.try_clone()?),
      Self::Unix(stream) => Self::Unix(stream.try_clone()?),
    })
  }

  pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
    match self {
      Self::Tcp(stream) => stream.shutdown(how),
      Self::Unix(stream) => stream.shutdown(how),
    }
  }
}

impl Read for Connection {
  fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
    match self {
      Self::Tcp(stream) => stream.read(buffer),
      Self::Unix(stream) => stream.read(buffer),
    }
  }
}

impl Write for Connection {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    match self {
      Self::Tcp(stream) => stream.write(bytes),
      Self::Unix(stream) => stream.write(bytes),
    }
  }

  fn flush(&mut self) -> io::Result<()> {
    match self {
      Self::Tcp(stream) => stream.flush(),
      Self::Unix(stream) => stream.flush(),
    }
  }
}
