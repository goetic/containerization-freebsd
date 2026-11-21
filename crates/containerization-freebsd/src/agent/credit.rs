//! The console's window, and the thread that reads the console and reopens
//! the window as the agent reports what it has read.

use super::AGENT_TIMEOUT;
use super::session::Event;
use crate::error::{Error, Result};
use containerization_freebsd_protocol::{CONTROL, Decoder, Frame, Message, Skipped, WINDOW};
use std::io::{PipeReader, Read};
use std::sync::mpsc;
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
  pub(super) fn take(&self, wanted: usize) -> Result<usize> {
    let window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
    let mut window = self
      .changed
      .wait_timeout_while(window, AGENT_TIMEOUT, |window| {
        !window.closed && window.unreceived >= WINDOW
      })
      .unwrap_or_else(PoisonError::into_inner)
      .0;

    if window.closed {
      return Err(Error::Guest("the console closed".to_string()));
    }
    if window.unreceived >= WINDOW {
      return Err(Error::Timeout(format!(
        "the guest agent read none of the console's last {} bytes within {}s",
        window.unreceived,
        AGENT_TIMEOUT.as_secs()
      )));
    }
    let room = (WINDOW - window.unreceived).min(wanted);
    window.unreceived += room;
    Ok(room)
  }

  /// Updates the window from a frame the agent sent.
  fn hear(&self, frame: &Frame) {
    if frame.channel != CONTROL {
      return;
    }
    let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);

    match Message::from_frame(frame.clone()) {
      Ok(Message::Received(bytes)) => {
        window.unreceived = window.unreceived.saturating_sub(bytes as usize);
      }
      // The agent is new or starting over. Bytes the old agent never read
      // are lost, or the agent has already read past them.
      Ok(Message::Hello { .. }) => window.unreceived = 0,
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

/// Reads the console, counts the agent's Received reports, and passes
/// everything to the handler thread. This thread must never lock the
/// session's state, because a writer holds that lock while it waits for room.
pub(super) fn read(mut output: PipeReader, credit: &Credit, events: &mpsc::Sender<Event>) {
  let mut decoder = Decoder::new();
  let mut buffer = vec![0; 64 << 10];

  while let Ok(read @ 1..) = output.read(&mut buffer) {
    let _ = events.send(Event::Read(buffer[..read].to_vec()));
    decoder.push(&buffer[..read]);

    while let Some(decoded) = decoder.decode() {
      let event = match decoded {
        Ok(frame) => {
          credit.hear(&frame);
          Event::Frame(frame)
        }
        Err(Skipped(_)) => Event::Skipped,
      };
      let _ = events.send(event);
    }
  }
  credit.close();
}
