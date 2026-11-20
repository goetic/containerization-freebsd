//! Unix sockets the host has the agent listen on with Listen. The session
//! loop relays each connection on a channel it opens with Accepted.

use crate::session::{Handle, Outbox};
use crate::sys;
use containerization_freebsd_protocol::{Listen, Message};
use std::fs;
use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::thread;

/// The session loop's hold on a listening socket, whose thread accepts its
/// connections. Dropping it closes the socket, leaving its file for a later
/// Listen to replace.
pub(crate) struct Listening {
  stop: PipeWriter,
  jail: Option<libc::c_int>,
  path: String,
}

impl Listening {
  /// Removes the socket's file, then has its thread close it and send Eof.
  /// The session loop removes it, not the thread: removing it from inside a
  /// jail forks, which only the session loop may.
  pub(crate) fn remove(&mut self) -> io::Result<()> {
    let removed =
      remove(self.jail, &self.path).map_err(|error| io::Error::other(format!("removing {:?}: {error}", self.path)));
    self.stop.write_all(&[1])?;
    removed
  }
}

/// Listens as `listen` says: from inside its jail, if it has one.
pub(crate) fn listen(listen: &Listen, outbox: Outbox) -> io::Result<Handle> {
  let jail = sys::jail_id(listen.jail.as_deref())?;
  let path = listen.path.clone();
  let listener = bind(jail, &path, listen.mode)?;
  // So a connection gone before it is accepted can't hold up the thread.
  listener.set_nonblocking(true)?;
  let (stopped, stop) = io::pipe()?;

  thread::spawn(move || {
    let removed = accept(&listener, stopped, &outbox);
    drop(listener);

    if removed {
      outbox.send(Message::Eof);
    }
  });
  Ok(Handle::Listener(Listening { stop, jail, path }))
}

/// A socket listening at `path`, in place of any socket there.
fn bind(jail: Option<libc::c_int>, path: &str, mode: Option<u16>) -> io::Result<UnixListener> {
  if let Some(jid) = jail {
    return Ok(sys::listen_in(jid, &sys::path(path)?, mode)?.into());
  }
  remove(None, path)?;
  let listener = UnixListener::bind(path)?;
  if let Some(mode) = mode {
    fs::set_permissions(path, fs::Permissions::from_mode(mode.into()))?;
  }
  Ok(listener)
}

/// Removes the socket at `path`, if there is one.
fn remove(jail: Option<libc::c_int>, path: &str) -> io::Result<()> {
  if let Some(jid) = jail {
    return sys::remove_socket_in(jid, &sys::path(path)?);
  }
  match fs::symlink_metadata(path) {
    Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path),
    Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
    // Binding fails on anything else there.
    _ => Ok(()),
  }
}

/// Hands the session loop each connection until `stopped` is readable:
/// whether something was written to it, the socket's file having been
/// removed, rather than it closing.
fn accept(listener: &UnixListener, mut stopped: PipeReader, outbox: &Outbox) -> bool {
  loop {
    match sys::wait_for_connection(listener.as_fd(), stopped.as_fd()) {
      Ok(true) => {}
      Ok(false) => return stopped.read(&mut [0]).is_ok_and(|read| read == 1),
      Err(error) => {
        outbox.send(Message::Error(format!("waiting for a connection: {error}")));
        return false;
      }
    }

    match listener.accept() {
      // On FreeBSD, a connection takes on its listener's O_NONBLOCK.
      Ok((stream, _)) => {
        if stream.set_nonblocking(false).is_ok() && !outbox.accepted(stream) {
          return false;
        }
      }
      Err(error)
        if matches!(
          error.kind(),
          io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
        ) => {}
      Err(error) => {
        outbox.send(Message::Error(format!("accepting a connection: {error}")));
        return false;
      }
    }
  }
}
