//! Moving bytes between the agent's descriptors and its channels: reading a
//! descriptor in chunks for the host, and writing the host's Data to one.

use crate::session::Input;
use std::io::{self, Read, Write};
use std::sync::mpsc::Receiver;

/// The most bytes read from a descriptor at once, under MAX_PAYLOAD so every
/// read fits in one frame.
pub(crate) const READ: usize = 64 << 10;

/// Why `read_chunks` stopped reading.
pub(crate) enum Stopped {
  Eof,
  /// The consumer returned false.
  Refused,
  Failed(io::Error),
}

/// Reads `source` in chunks of up to `READ` bytes and passes each to
/// `consume`, until the source ends or fails or `consume` returns false.
/// Interrupted reads are retried.
pub(crate) fn read_chunks(mut source: impl Read, mut consume: impl FnMut(Vec<u8>) -> bool) -> Stopped {
  let mut buffer = vec![0; READ];

  loop {
    match source.read(&mut buffer) {
      Ok(0) => return Stopped::Eof,
      Ok(read) => {
        if !consume(buffer[..read].to_vec()) {
          return Stopped::Refused;
        }
      }
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      Err(error) => return Stopped::Failed(error),
    }
  }
}

/// Writes the host's Data to `sink` until the host's Eof, a failed write, or
/// the end of `inputs`. Returns whether the host sent Eof; Data that follows
/// it is left for a later call.
pub(crate) fn write_until_eof(sink: &mut impl Write, inputs: &Receiver<Input>) -> bool {
  for input in inputs {
    match input {
      Input::Data(bytes) => {
        // The other end stopped reading, so the rest has nowhere to go.
        if sink.write_all(&bytes).is_err() {
          return false;
        }
      }
      Input::Eof => return true,
    }
  }
  false
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::mpsc;

  #[test]
  fn reads_until_the_consumer_refuses() {
    let mut chunks = 0;

    let stopped = read_chunks(io::repeat(0), |chunk| {
      chunks += 1;
      chunk.len() == READ && chunks < 3
    });

    assert!(matches!(stopped, Stopped::Refused));
    assert_eq!(chunks, 3);
    assert!(matches!(read_chunks(io::empty(), |_| true), Stopped::Eof));
  }

  #[test]
  fn writes_up_to_the_hosts_eof() {
    let (input, inputs) = mpsc::channel();
    for message in [Input::Data(b"one".to_vec()), Input::Eof, Input::Data(b"two".to_vec())] {
      input.send(message).unwrap();
    }
    drop(input);
    let mut written = Vec::new();

    assert!(write_until_eof(&mut written, &inputs));
    assert_eq!(written, b"one");
    assert!(!write_until_eof(&mut written, &inputs));
    assert_eq!(written, b"onetwo");
  }
}
