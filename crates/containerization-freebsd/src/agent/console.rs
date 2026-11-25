//! The console's window, the thread that reads the console and reopens the
//! window as the agent reports what it has read, and the thread that writes
//! to the console as the window allows.

use super::session;
use crate::error;
use containerization_freebsd_protocol::{frame, message, mux};
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Condvar, Mutex, PoisonError};

/// Tracks the console bytes the host has written that the agent has not yet
/// reported with Received.
#[derive(Default)]
pub(super) struct Credit {
  window: Mutex<Window>,
  changed: Condvar,
}

#[derive(Default)]
struct Window {
  unreceived: usize,
  closed: bool,
}

impl Credit {
  /// Waits until the window has room, then reserves and returns up to
  /// `wanted` bytes of it.
  pub(super) fn take(&self, wanted: usize) -> error::Result<usize> {
    let window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
    let mut window = self
      .changed
      .wait_timeout_while(window, super::AGENT_TIMEOUT, |window| {
        !window.closed && window.unreceived >= mux::WINDOW
      })
      .unwrap_or_else(PoisonError::into_inner)
      .0;

    if window.closed {
      return Err(error::Error::Guest("the console closed".to_string()));
    }
    if window.unreceived >= mux::WINDOW {
      return Err(error::Error::Timeout(format!(
        "the guest agent read none of the console's last {} bytes within {}s",
        window.unreceived,
        super::AGENT_TIMEOUT.as_secs()
      )));
    }
    let room = (mux::WINDOW - window.unreceived).min(wanted);
    window.unreceived += room;
    Ok(room)
  }

  /// Updates the window from a frame the agent sent.
  fn hear(&self, frame: &frame::Frame) {
    if frame.channel != mux::CONTROL {
      return;
    }
    let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);

    match message::Message::peek(frame) {
      Ok(message::Message::Received(bytes)) => {
        window.unreceived = window.unreceived.saturating_sub(bytes as usize);
      }
      // The agent is new or starting over. Bytes the old agent never read
      // are lost, or the agent has already read past them.
      Ok(message::Message::Hello { .. }) => window.unreceived = 0,
      _ => return,
    }
    self.changed.notify_all();
  }

  fn close(&self) {
    self
      .window
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .closed = true;
    self.changed.notify_all();
  }
}

/// An encoded frame for the writer thread, and where to report how writing
/// it went.
pub(super) struct Outgoing {
  pub(super) bytes: Vec<u8>,
  pub(super) done: SyncSender<error::Result<()>>,
}

/// Writes each frame from `queue` to the console in order, in slices as the
/// window makes room for them, and reports how each went.
pub(super) fn write(queue: &Receiver<Outgoing>, mut input: PipeWriter, credit: &Credit) {
  for Outgoing { bytes, done } in queue {
    let _ = done.send(write_frame(&mut input, credit, &bytes));
  }
}

fn write_frame(input: &mut PipeWriter, credit: &Credit, bytes: &[u8]) -> error::Result<()> {
  let mut rest = bytes;

  while !rest.is_empty() {
    let (now, later) = rest.split_at(credit.take(rest.len())?);
    input
      .write_all(now)
      .map_err(error::Error::io("writing to the guest agent"))?;
    rest = later;
  }
  Ok(())
}

/// Reads the console, counts the agent's Received reports, and passes
/// everything to the handler thread. Counting them here, rather than in the
/// handler thread, reopens the window however busy that thread is. The raw
/// bytes are passed only while `session` is false, since the handler shows
/// console text only before a session starts.
pub(super) fn read(
  mut output: PipeReader,
  credit: &Credit,
  session: &AtomicBool,
  events: &mpsc::Sender<session::Event>,
) {
  let mut decoder = frame::Decoder::new();
  let mut buffer = vec![0; 64 << 10];

  while let Ok(read @ 1..) = output.read(&mut buffer) {
    if !session.load(Ordering::Relaxed) {
      let _ = events.send(session::Event::Read(buffer[..read].to_vec()));
    }
    decoder.push(&buffer[..read]);

    while let Some(decoded) = decoder.decode() {
      let event = match decoded {
        Ok(frame) => {
          credit.hear(&frame);
          session::Event::Frame(frame)
        }
        Err(frame::Skipped(_)) => session::Event::Skipped,
      };
      let _ = events.send(event);
    }
  }
  credit.close();
}
