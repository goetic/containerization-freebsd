//! Frames on one byte stream:
//!
//! ```text
//! magic        4 bytes  F5 C0 FB 5D
//! channel      u32 LE
//! kind         u8
//! length       u32 LE   of the payload, at most MAX_PAYLOAD
//! header crc   u32 LE   CRC-32 of channel, kind and length
//! payload      length bytes
//! payload crc  u32 LE   CRC-32 of the payload
//! ```
//!
//! After the magic, every F5 is sent as F5 00; lengths and checksums count
//! the bytes before. So a magic starts a frame and nothing else does: not
//! text the guest printed before the agent started, as F5 never occurs in
//! UTF-8, and not a payload, whatever it holds.
//!
//! The console has no framing of its own, and a restore or a restarted host
//! can join it mid-frame, so the decoder drops bytes until a magic, and drops
//! a frame the next magic cuts short. The header has its own checksum so a
//! corrupt length fails at once, not when the next frame arrives.

use std::collections::VecDeque;
use std::mem;

pub const MAGIC: [u8; 4] = [0xF5, 0xC0, 0xFB, 0x5D];
pub const MAX_PAYLOAD: usize = 1 << 20;

/// Follows an F5 that doesn't start a magic.
const ESCAPED: u8 = 0x00;
/// Channel, kind, length and the header's checksum.
const HEADER: usize = 13;
const TRAILER: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
  pub channel: u32,
  pub kind: u8,
  pub payload: Vec<u8>,
}

impl Frame {
  /// Appends the frame's bytes to `out`.
  ///
  /// # Panics
  ///
  /// If the payload is over [`MAX_PAYLOAD`].
  pub fn encode(&self, out: &mut Vec<u8>) {
    assert!(
      self.payload.len() <= MAX_PAYLOAD,
      "a {}-byte payload is over MAX_PAYLOAD",
      self.payload.len()
    );
    let mut header = [0; HEADER];
    header[..4].copy_from_slice(&self.channel.to_le_bytes());
    header[4] = self.kind;
    header[5..9].copy_from_slice(&(self.payload.len() as u32).to_le_bytes());
    let crc = crc32(&header[..9]);
    header[9..].copy_from_slice(&crc.to_le_bytes());

    out.extend_from_slice(&MAGIC);
    escape(&header, out);
    escape(&self.payload, out);
    escape(&crc32(&self.payload).to_le_bytes(), out);
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + HEADER + self.payload.len() + TRAILER);

    self.encode(&mut out);
    out
  }
}

fn escape(bytes: &[u8], out: &mut Vec<u8>) {
  for run in bytes.split_inclusive(|&byte| byte == MAGIC[0]) {
    out.extend_from_slice(run);
    if run.last() == Some(&MAGIC[0]) {
      out.push(ESCAPED);
    }
  }
}

/// Bytes the decoder dropped to find the next frame. Mid-session, that means
/// frames were lost: the host should start the session over, or the agent
/// announce itself so that the host does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Skipped(pub usize);

#[derive(Debug, Default)]
pub struct Decoder {
  state: State,
  /// The frame after its magic, unescaped, so far.
  body: Vec<u8>,
  /// The bytes the frame took on the stream, its magic and escapes included.
  taken: usize,
  skipped: usize,
  decoded: VecDeque<Result<Frame, Skipped>>,
}

#[derive(Clone, Copy, Debug)]
enum State {
  /// How much of a magic has arrived.
  Magic(usize),
  /// Inside a frame, perhaps just after an F5.
  Frame { escaping: bool },
}

impl Default for State {
  fn default() -> Self {
    Self::Magic(0)
  }
}

impl Decoder {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn push(&mut self, bytes: &[u8]) {
    for &byte in bytes {
      self.byte(byte);
    }
    self.report_skipped();
  }

  /// The next frame or run of dropped bytes, in stream order; or `None`
  /// until more bytes arrive.
  pub fn decode(&mut self) -> Option<Result<Frame, Skipped>> {
    self.decoded.pop_front()
  }

  fn byte(&mut self, byte: u8) {
    match self.state {
      State::Magic(matched) if byte == MAGIC[matched] => {
        if matched + 1 == MAGIC.len() {
          self.state = State::Frame { escaping: false };
          self.body.clear();
          self.taken = MAGIC.len();
        } else {
          self.state = State::Magic(matched + 1);
        }
      }
      State::Magic(0) => self.skipped += 1,
      State::Magic(matched) => {
        // No later byte of a magic is F5, so only this one can start another.
        self.skipped += matched;
        self.state = State::Magic(0);
        self.byte(byte);
      }
      State::Frame { escaping: true } if byte == ESCAPED => {
        self.taken += 1;
        self.state = State::Frame { escaping: false };
        self.take(MAGIC[0]);
      }
      State::Frame { escaping: true } => {
        // That F5 started a magic, cutting this frame short.
        self.skipped += self.taken - 1;
        self.state = State::Magic(1);
        self.byte(byte);
      }
      State::Frame { escaping: false } => {
        self.taken += 1;
        if byte == MAGIC[0] {
          self.state = State::Frame { escaping: true };
        } else {
          self.take(byte);
        }
      }
    }
  }

  /// Adds an unescaped byte to the frame, which ends at a header that fails,
  /// or at its last byte.
  fn take(&mut self, byte: u8) {
    self.body.push(byte);
    if self.body.len() < HEADER {
      return;
    }
    let length = u32_at(&self.body, 5) as usize;

    if self.body.len() == HEADER {
      if crc32(&self.body[..9]) != u32_at(&self.body, 9) || length > MAX_PAYLOAD {
        self.drop_frame();
      }
    } else if self.body.len() == HEADER + length + TRAILER {
      self.finish(length);
    }
  }

  fn finish(&mut self, length: usize) {
    let payload = &self.body[HEADER..HEADER + length];

    if crc32(payload) == u32_at(&self.body, HEADER + length) {
      let frame = Frame {
        channel: u32_at(&self.body, 0),
        kind: self.body[4],
        payload: payload.to_vec(),
      };
      self.state = State::Magic(0);
      self.report_skipped();
      self.decoded.push_back(Ok(frame));
    } else {
      self.drop_frame();
    }
  }

  fn drop_frame(&mut self) {
    self.skipped += self.taken;
    self.state = State::Magic(0);
  }

  fn report_skipped(&mut self) {
    if self.skipped > 0 {
      self
        .decoded
        .push_back(Err(Skipped(mem::take(&mut self.skipped))));
    }
  }
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
  u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// CRC-32 (IEEE 802.3), as zlib computes it.
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
  const TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut index = 0;

    while index < 256 {
      let mut crc = index as u32;
      let mut bit = 0;

      while bit < 8 {
        crc = if crc & 1 == 1 {
          (crc >> 1) ^ 0xEDB8_8320
        } else {
          crc >> 1
        };
        bit += 1;
      }
      table[index] = crc;
      index += 1;
    }
    table
  };

  !bytes.iter().fold(!0, |crc, &byte| {
    TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize] ^ (crc >> 8)
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  fn frame(channel: u32, payload: &[u8]) -> Frame {
    Frame {
      channel,
      kind: 0x21,
      payload: payload.to_vec(),
    }
  }

  fn decode_all(decoder: &mut Decoder) -> Vec<Result<Frame, Skipped>> {
    std::iter::from_fn(|| decoder.decode()).collect()
  }

  #[test]
  fn computes_the_ieee_crc32() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
  }

  #[test]
  fn decodes_what_it_encodes_even_a_byte_at_a_time() {
    let frames = [frame(0, b""), frame(7, b"hello"), frame(u32::MAX, &[0xF5; 300])];
    let bytes: Vec<u8> = frames.iter().flat_map(Frame::to_bytes).collect();
    let mut decoder = Decoder::new();
    let mut decoded = Vec::new();

    for byte in bytes {
      decoder.push(&[byte]);
      decoded.extend(decode_all(&mut decoder));
    }

    assert_eq!(decoded, frames.map(Ok::<_, Skipped>));
  }

  #[test]
  fn skips_text_before_the_first_frame() {
    let mut decoder = Decoder::new();
    decoder.push(b"console-ready 3\n");
    decoder.push(&frame(1, b"x").to_bytes());

    assert_eq!(decode_all(&mut decoder), [Err(Skipped(16)), Ok(frame(1, b"x"))]);
  }

  #[test]
  fn finds_the_next_frame_after_a_corrupt_one() {
    let mut bytes = frame(1, b"lost").to_bytes();
    let lost = bytes.len();
    bytes[MAGIC.len() + HEADER + 1] ^= 0xFF;
    bytes.extend(frame(3, b"kept").to_bytes());
    let mut decoder = Decoder::new();
    decoder.push(&bytes);

    assert_eq!(decode_all(&mut decoder), [Err(Skipped(lost)), Ok(frame(3, b"kept"))]);
  }

  #[test]
  fn rejects_a_corrupt_header_without_waiting_for_the_length_it_claims() {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&[0, 0, 0, 0, 0x21]);
    bytes.extend_from_slice(&1000u32.to_le_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes.extend(frame(5, b"real").to_bytes());
    let mut decoder = Decoder::new();
    decoder.push(&bytes);

    assert_eq!(
      decode_all(&mut decoder),
      [Err(Skipped(MAGIC.len() + HEADER)), Ok(frame(5, b"real"))]
    );
  }

  #[test]
  fn finds_a_magic_split_across_pushes() {
    let bytes = frame(9, b"split").to_bytes();
    let mut decoder = Decoder::new();
    decoder.push(b"noise");
    decoder.push(&bytes[..2]);
    let mut decoded = decode_all(&mut decoder);
    decoder.push(&bytes[2..]);
    decoded.extend(decode_all(&mut decoder));

    let skipped: usize = decoded
      .iter()
      .filter_map(|decoded| decoded.as_ref().err())
      .map(|skipped| skipped.0)
      .sum();
    let frames: Vec<_> = decoded.into_iter().filter_map(Result::ok).collect();
    assert_eq!((skipped, frames), (5, vec![frame(9, b"split")]));
  }

  #[test]
  fn never_takes_a_payload_for_a_frame() {
    // As after a restore: a frame cut short whose payload holds a frame's
    // bytes, then the next host's first frame.
    let hidden = frame(2, b"forged").to_bytes();
    let cut = frame(4, &hidden).to_bytes();
    let cut = &cut[..cut.len() - 1];
    let mut decoder = Decoder::new();
    decoder.push(cut);
    decoder.push(&frame(0, b"hello").to_bytes());

    assert_eq!(
      decode_all(&mut decoder),
      [Err(Skipped(cut.len())), Ok(frame(0, b"hello"))]
    );
  }

  #[test]
  fn drops_a_frame_the_next_magic_cuts_short() {
    // Waiting out the length it claims would swallow the next host's Hello.
    let long = frame(2, &[b'x'; 100_000]).to_bytes();
    let mut decoder = Decoder::new();
    decoder.push(&long[..1000]);
    decoder.push(&frame(0, b"hello").to_bytes());

    assert_eq!(decode_all(&mut decoder), [Err(Skipped(1000)), Ok(frame(0, b"hello"))]);
  }
}
