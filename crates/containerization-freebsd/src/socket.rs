//! Unix sockets relayed between the host and the guest, or a jail, as
//! Containerization's `UnixSocketConfiguration`s are.

use crate::agent::{Agent, Listener, Relay};
use crate::error::{Error, Result};
use containerization_freebsd_protocol::{Address, Connect, Listen};
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

/// The most a relay reads from the host at once.
const READ: usize = 64 << 10;

/// A Unix socket relayed between the host and the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnixSocket {
  /// Its path on the host.
  pub host: PathBuf,
  /// Its path in the guest, or in the jail.
  pub guest: String,
  pub direction: Direction,
  /// The permissions of the socket the relay makes: in the guest, going
  /// into it; on the host, coming out. Or those the umask leaves.
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

/// A socket relayed, as `Agent::relay_socket` started it. Connections it
/// relayed carry on after it stops. Dropping it stops it; going into the
/// guest, that leaves the socket's file there, which `close` removes.
pub struct SocketRelay {
  relaying: Relaying,
}

enum Relaying {
  Into(Listener),
  OutOf(HostListener),
}

/// The host's end of a relay out of the guest: its socket, and the thread
/// accepting connections to it.
struct HostListener {
  path: PathBuf,
  stopped: Arc<AtomicBool>,
}

impl Agent {
  /// Relays `socket` between the host and the guest. A socket already
  /// where the relay listens is replaced; going into the guest, its
  /// directory must exist.
  pub fn relay_socket(&self, socket: &UnixSocket) -> Result<SocketRelay> {
    self.relay_socket_in(socket, None)
  }

  /// As `relay_socket`, with the socket's guest path in `jail`, if given.
  pub(crate) fn relay_socket_in(&self, socket: &UnixSocket, jail: Option<&str>) -> Result<SocketRelay> {
    let jail = jail.map(str::to_string);
    let relaying = match socket.direction {
      Direction::Into => {
        let listen = Listen {
          path: socket.guest.clone(),
          jail,
          mode: socket.mode,
        };
        Relaying::Into(self.listen(listen, socket.host.clone())?)
      }
      Direction::OutOf => {
        let connect = Connect {
          to: Address::Unix(socket.guest.clone()),
          jail,
        };
        Relaying::OutOf(
          HostListener::start(self.share(), socket, connect)
            .map_err(Error::io(format!("listening on {}", socket.host.display())))?,
        )
      }
    };

    Ok(SocketRelay { relaying })
  }
}

impl SocketRelay {
  /// Stops it, and removes its socket: going into the guest, once the
  /// agent has closed it, so it no longer holds the file system it is on.
  pub fn close(self) -> Result<()> {
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
  /// Listens at `socket.host`, and relays each connection as `connect`
  /// says.
  fn start(agent: Agent, socket: &UnixSocket, connect: Connect) -> io::Result<Self> {
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
        // One the guest refuses is closed.
        thread::spawn(move || {
          if let Ok(relay) = agent.relay(connect) {
            pump(relay, local);
          }
        });
      }
    });
    Ok(Self { path, stopped })
  }
}

impl Drop for HostListener {
  /// Stops accepting, waking the thread with a connection of its own, and
  /// removes the socket.
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
    // Binding fails on anything else there.
    _ => Ok(()),
  }
}

/// Relays between `relay` and `local`, a connection on the host, until
/// both have finished.
pub(crate) fn pump(relay: Relay, local: UnixStream) {
  let Ok(mut to_local) = local.try_clone() else {
    return;
  };
  let relay = Arc::new(relay);
  let back = {
    let relay = relay.clone();
    thread::spawn(move || {
      loop {
        match relay.read() {
          Ok(Some(bytes)) if to_local.write_all(&bytes).is_ok() => {}
          Ok(None) => {
            let _ = to_local.shutdown(Shutdown::Write);
            return;
          }
          // Either end failed: so does the other.
          _ => {
            let _ = to_local.shutdown(Shutdown::Both);
            return;
          }
        }
      }
    })
  };

  let mut from_local = local;
  let mut buffer = vec![0; READ];
  loop {
    match from_local.read(&mut buffer) {
      Ok(0) => break,
      Ok(read) => {
        if relay.write(&buffer[..read]).is_err() {
          break;
        }
      }
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      Err(_) => break,
    }
  }
  let _ = relay.close_write();
  let _ = back.join();
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::agent::tests::started;

  fn socket(host: PathBuf, guest: &Path, direction: Direction, mode: Option<u16>) -> UnixSocket {
    UnixSocket {
      host,
      guest: guest.to_str().unwrap().to_string(),
      direction,
      mode,
    }
  }

  /// Answers each connection to `listener`, once it ends, with what it
  /// sent in capitals.
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

  /// What a connection to `path` answers `text` with: nothing, if it closes
  /// first.
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
    let agent = started();
    let directory = tempfile::tempdir().unwrap();
    let (host, guest) = (directory.path().join("host.sock"), directory.path().join("guest.sock"));
    answer_in_capitals(UnixListener::bind(&host).unwrap());
    let into = socket(host, &guest, Direction::Into, Some(0o600));

    let relay = agent.relay_socket(&into).unwrap();
    assert_eq!(mode(&guest), 0o600);
    assert_eq!(ask(&guest, "into"), "INTO");
    // Dropped, it leaves its socket for the next relay to replace.
    drop(relay);
    let relay = agent.relay_socket(&into).unwrap();
    assert_eq!(ask(&guest, "again"), "AGAIN");

    relay.close().unwrap();
    assert!(!guest.exists());
  }

  #[test]
  fn relays_a_guest_socket_out_to_the_host() {
    let agent = started();
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
    let agent = started();
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name);

    // Nothing listens at the far end of either.
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
