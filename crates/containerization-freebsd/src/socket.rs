//! Relays Unix sockets between the host and the guest or a jail, like
//! Containerization's `UnixSocketConfiguration`.

use crate::{agent, error};
use containerization_freebsd_protocol::message;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

/// A Unix socket relayed between the host and the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnixSocket {
  /// The socket's path on the host.
  pub host: PathBuf,
  /// The socket's path in the guest, or in the jail.
  pub guest: String,
  pub direction: Direction,
  /// The mode of the socket the relay creates: in the guest for `Into`, on
  /// the host for `OutOf`. `None` leaves it to the umask.
  pub mode: Option<u16>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Direction {
  /// The host's socket appears in the guest: the agent listens at `guest`,
  /// and relays each connection to `host`.
  #[default]
  Into,
  /// The guest's socket appears on the host: the host listens at `host`,
  /// and relays each connection to `guest`.
  OutOf,
}

/// A socket relay started by `Agent::relay_socket`. Connections already
/// relayed outlive it. Dropping it stops the relay but, for `Into`, leaves the
/// socket in the guest; `close` also removes it.
pub struct SocketRelay {
  relaying: Relaying,
}

enum Relaying {
  Into(agent::channel::Listener),
  OutOf(HostListener),
}

/// The host side of an `OutOf` relay.
struct HostListener {
  path: PathBuf,
  stopped: Arc<AtomicBool>,
}

impl agent::Agent {
  /// Relays `socket` between the host and the guest, replacing any socket
  /// already at the listening path. For `Into`, the socket's guest directory
  /// must exist.
  pub fn relay_socket(&self, socket: &UnixSocket) -> error::Result<SocketRelay> {
    self.relay_socket_in(socket, None)
  }

  /// Like `relay_socket`, with the socket's guest path in `jail`, if given.
  pub(crate) fn relay_socket_in(&self, socket: &UnixSocket, jail: Option<&str>) -> error::Result<SocketRelay> {
    let jail = jail.map(str::to_string);
    let relaying = match socket.direction {
      Direction::Into => {
        let listen = message::Listen {
          path: socket.guest.clone(),
          jail,
          mode: socket.mode,
        };
        Relaying::Into(self.listen(listen, socket.host.clone())?)
      }
      Direction::OutOf => {
        let connect = message::Connect {
          to: message::Address::Unix(socket.guest.clone()),
          jail,
        };
        Relaying::OutOf(
          HostListener::start(self.share(), socket, connect)
            .map_err(error::Error::io(format!("listening on {}", socket.host.display())))?,
        )
      }
    };

    Ok(SocketRelay { relaying })
  }
}

impl SocketRelay {
  /// Stops the relay and removes its socket. For `Into`, waits for the agent
  /// to close the listener and unlink the socket, so the listener no longer
  /// holds the socket's file system busy.
  pub fn close(self) -> error::Result<()> {
    match self.relaying {
      Relaying::Into(listener) => listener.close(),
      Relaying::OutOf(listener) => {
        drop(listener);
        Ok(())
      }
    }
  }
}

impl HostListener {
  /// Listens at `socket.host` and relays each connection to the guest
  /// address in `connect`.
  fn start(agent: agent::Agent, socket: &UnixSocket, connect: message::Connect) -> io::Result<Self> {
    let path = socket.host.clone();
    remove_socket(&path)?;
    let listener = UnixListener::bind(&path)?;
    if let Some(mode) = socket.mode {
      fs::set_permissions(&path, fs::Permissions::from_mode(mode.into()))?;
    }
    let stopped = Arc::new(AtomicBool::new(false));
    let stopping = stopped.clone();

    thread::spawn(move || {
      for local in listener.incoming() {
        if stopping.load(Ordering::Relaxed) {
          return;
        }
        let Ok(local) = local else { continue };
        let (agent, connect) = (agent.share(), connect.clone());
        // If the guest refuses the connection, dropping `local` closes it.
        thread::spawn(move || {
          if let Ok(relay) = agent.relay(connect) {
            relay.splice(local);
          }
        });
      }
    });
    Ok(Self { path, stopped })
  }
}

impl Drop for HostListener {
  /// Stops accepting and removes the socket. A self-connection wakes the
  /// blocked accept(2) so the thread sees the stop flag.
  fn drop(&mut self) {
    self.stopped.store(true, Ordering::Relaxed);
    let _ = UnixStream::connect(&self.path);
    let _ = fs::remove_file(&self.path);
  }
}

/// Removes the socket at `path`, if there is one.
fn remove_socket(path: &Path) -> io::Result<()> {
  match fs::symlink_metadata(path) {
    Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path),
    Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
    // Any other file there is left alone, so binding fails on it.
    _ => Ok(()),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::{Read, Write};
  use std::net::Shutdown;

  fn socket(host: PathBuf, guest: &Path, direction: Direction, mode: Option<u16>) -> UnixSocket {
    UnixSocket {
      host,
      guest: guest.to_str().unwrap().to_string(),
      direction,
      mode,
    }
  }

  /// Answers each connection to `listener`, once the client finishes
  /// sending, with what it sent in capitals.
  fn answer_in_capitals(listener: UnixListener) {
    thread::spawn(move || {
      for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        stream.write_all(&received.to_ascii_uppercase()).unwrap();
      }
    });
  }

  /// Sends `text` over a connection to `path` and returns the answer, which
  /// is empty if the connection closes first.
  fn ask(path: &Path, text: &str) -> String {
    let mut stream = UnixStream::connect(path).unwrap();
    let _ = stream.write_all(text.as_bytes());
    let _ = stream.shutdown(Shutdown::Write);
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
  }

  fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
  }

  #[test]
  fn relays_a_host_socket_into_the_guest() {
    let agent = agent::tests::started();
    let directory = tempfile::tempdir().unwrap();
    let (host, guest) = (directory.path().join("host.sock"), directory.path().join("guest.sock"));
    answer_in_capitals(UnixListener::bind(&host).unwrap());
    let into = socket(host, &guest, Direction::Into, Some(0o600));

    let relay = agent.relay_socket(&into).unwrap();
    assert_eq!(mode(&guest), 0o600);
    assert_eq!(ask(&guest, "into"), "INTO");
    // A dropped relay leaves its socket for the next relay to replace.
    drop(relay);
    let relay = agent.relay_socket(&into).unwrap();
    assert_eq!(ask(&guest, "again"), "AGAIN");

    relay.close().unwrap();
    assert!(!guest.exists());
  }

  #[test]
  fn relays_a_guest_socket_out_to_the_host() {
    let agent = agent::tests::started();
    let directory = tempfile::tempdir().unwrap();
    let (host, guest) = (directory.path().join("host.sock"), directory.path().join("guest.sock"));
    answer_in_capitals(UnixListener::bind(&guest).unwrap());

    let relay = agent
      .relay_socket(&socket(host.clone(), &guest, Direction::OutOf, Some(0o600)))
      .unwrap();
    assert_eq!(mode(&host), 0o600);
    assert_eq!(ask(&host, "out"), "OUT");
    assert_eq!(ask(&host, "again"), "AGAIN");

    relay.close().unwrap();
    assert!(!host.exists());
  }

  #[test]
  fn closes_connections_it_cannot_relay() {
    let agent = agent::tests::started();
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name);

    // Nothing listens at the far end of either relay.
    let _into = agent
      .relay_socket(&socket(path("absent.sock"), &path("into.sock"), Direction::Into, None))
      .unwrap();
    let _out_of = agent
      .relay_socket(&socket(path("out.sock"), &path("absent.sock"), Direction::OutOf, None))
      .unwrap();

    assert_eq!(ask(&path("into.sock"), "anyone?"), "");
    assert_eq!(ask(&path("out.sock"), "anyone?"), "");
  }
}
