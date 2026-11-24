//! The frame format on the console's byte stream:
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
//! After the magic, every F5 byte is escaped as F5 00. Lengths and checksums
//! cover the unescaped bytes. So the magic appears only at the start of a
//! frame: never in a payload, whatever it holds, nor in text the guest
//! printed before the agent started, because F5 never occurs in UTF-8.
//!
//! The console has no framing of its own, and a restore or a restarted host
//! can join the stream mid-frame. So the decoder drops bytes until it finds a
//! magic, and drops any frame that the next magic cuts short. The header has
//! its own checksum so that a corrupt length is rejected at once, instead of
//! swallowing the bytes of the frames that follow.

use std::collections::VecDeque;
use std::mem;

pub const MAGIC: [u8; 4] = [0xF5, 0xC0, 0xFB, 0x5D];
pub const MAX_PAYLOAD: usize = 1 << 20;

/// Stuffed after each F5 that does not start a magic.
const ESCAPED: u8 = 0x00;
/// The size of the channel, kind, length and header CRC.
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
  /// Panics if the payload is larger than [`MAX_PAYLOAD`].
  pub fn encode(&self, out: &mut Vec<u8>) {
    encode_frame(self.channel, self.kind, &self.payload, out);
  }

  /// The frame's bytes, in a buffer with room for every escape.
  pub fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::with_capacity(encoded_len(&self.payload));

    self.encode(&mut out);
    out
  }
}

/// The most bytes a frame with `payload` can take on the stream: its
/// unescaped bytes, an escape for each F5 in the payload, and room for an
/// escape after each byte of the header and trailer, which can hold F5s too.
pub(crate) fn encoded_len(payload: &[u8]) -> usize {
  let escapes = payload.iter().filter(|&&byte| byte == MAGIC[0]).count();

  MAGIC.len() + 2 * (HEADER + TRAILER) + payload.len() + escapes
}

/// Appends the bytes of the frame with these parts to `out`.
///
/// # Panics
///
/// Panics if `payload` is larger than [`MAX_PAYLOAD`].
pub(crate) fn encode_frame(channel: u32, kind: u8, payload: &[u8], out: &mut Vec<u8>) {
  assert!(
    payload.len() <= MAX_PAYLOAD,
    "a {}-byte payload is over MAX_PAYLOAD",
    payload.len()
  );
  let mut header = [0; HEADER];
  header[..4].copy_from_slice(&channel.to_le_bytes());
  header[4] = kind;
  header[5..9].copy_from_slice(&(payload.len() as u32).to_le_bytes());
  let crc = crc32(&header[..9]);
  header[9..].copy_from_slice(&crc.to_le_bytes());

  out.extend_from_slice(&MAGIC);
  escape(&header, out);
  escape(payload, out);
  escape(&crc32(payload).to_le_bytes(), out);
}

fn escape(bytes: &[u8], out: &mut Vec<u8>) {
  for run in bytes.split_inclusive(|&byte| byte == MAGIC[0]) {
    out.extend_from_slice(run);
    if run.last() == Some(&MAGIC[0]) {
      out.push(ESCAPED);
    }
  }
}

/// The number of bytes the decoder dropped to find the next frame. During a
/// session this means frames were lost: the host should start a new session,
/// or the agent should announce itself so that the host does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Skipped(pub usize);

#[derive(Debug, Default)]
pub struct Decoder {
  state: State,
  /// The current frame's header, unescaped.
  header: [u8; HEADER],
  /// The current frame's payload, unescaped, so far. It becomes the frame's
  /// payload without a copy.
  payload: Vec<u8>,
  /// The payload's length, once the header has arrived and checked out.
  length: usize,
  /// The current frame's payload CRC.
  trailer: [u8; TRAILER],
  /// How many of the current frame's unescaped bytes after its magic have
  /// arrived: the header's, then the payload's, then the trailer's.
  received: usize,
  /// The current frame's length on the stream, including magic and escapes.
  taken: usize,
  skipped: usize,
  decoded: VecDeque<Result<Frame, Skipped>>,
}

#[derive(Clone, Copy, Debug)]
enum State {
  /// Searching for a magic, with this many of its bytes matched.
  Magic(usize),
  /// Inside a frame. `escaping` is set just after an F5.
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

  pub fn push(&mut self, mut bytes: &[u8]) {
    while let Some(&first) = bytes.first() {
      // Between frames and inside one, the bytes up to the next F5 are taken
      // as a run. Each F5 goes through the state machine on its own.
      let run = match self.state {
        State::Magic(0) => {
          let run = until_magic(bytes, bytes.len());
          self.skipped += run;
          run
        }
        State::Frame { escaping: false } => {
          let run = until_magic(bytes, self.wanted());
          self.taken += run;
          self.take(&bytes[..run]);
          run
        }
        _ => 0,
      };
      if run == 0 {
        self.byte(first);
        bytes = &bytes[1..];
      } else {
        bytes = &bytes[run..];
      }
    }
    self.report_skipped();
  }

  /// Returns the next frame or run of dropped bytes, in stream order, or
  /// `None` if more bytes are needed.
  pub fn decode(&mut self) -> Option<Result<Frame, Skipped>> {
    self.decoded.pop_front()
  }

  fn byte(&mut self, byte: u8) {
    match self.state {
      State::Magic(matched) if byte == MAGIC[matched] => {
        if matched + 1 == MAGIC.len() {
          self.state = State::Frame { escaping: false };
          self.received = 0;
          self.length = 0;
          self.payload.clear();
          self.taken = MAGIC.len();
        } else {
          self.state = State::Magic(matched + 1);
        }
      }
      State::Magic(0) => self.skipped += 1,
      State::Magic(matched) => {
        // Only the magic's first byte is F5, so a new magic can start at this
        // byte but not at any byte already matched.
        self.skipped += matched;
        self.state = State::Magic(0);
        self.byte(byte);
      }
      State::Frame { escaping: true } if byte == ESCAPED => {
        self.taken += 1;
        self.state = State::Frame { escaping: false };
        self.take(&[MAGIC[0]]);
      }
      State::Frame { escaping: true } => {
        // The previous F5 started a magic, which cuts this frame short.
        self.skipped += self.taken - 1;
        self.state = State::Magic(1);
        self.byte(byte);
      }
      State::Frame { escaping: false } => {
        self.taken += 1;
        if byte == MAGIC[0] {
          self.state = State::Frame { escaping: true };
        } else {
          self.take(&[byte]);
        }
      }
    }
  }

  /// How many more unescaped bytes the part of the frame being read needs:
  /// the header, the payload, or the trailer. Always at least one.
  fn wanted(&self) -> usize {
    let (header, payload) = (HEADER, HEADER + self.length);

    if self.received < header {
      header - self.received
    } else if self.received < payload {
      payload - self.received
    } else {
      payload + TRAILER - self.received
    }
  }

  /// Adds unescaped bytes to the frame, no more than `wanted`. The frame ends
  /// early if its header is invalid, and otherwise at its last byte.
  fn take(&mut self, bytes: &[u8]) {
    let start = self.received;
    self.received += bytes.len();

    if start < HEADER {
      self.header[start..self.received].copy_from_slice(bytes);
      if self.received < HEADER {
        return;
      }
      let length = u32_at(&self.header, 5) as usize;
      if crc32(&self.header[..9]) != u32_at(&self.header, 9) || length > MAX_PAYLOAD {
        self.drop_frame();
        return;
      }
      self.length = length;
      self.payload.reserve(length);
    } else if start < HEADER + self.length {
      self.payload.extend_from_slice(bytes);
    } else {
      let at = start - HEADER - self.length;
      self.trailer[at..at + bytes.len()].copy_from_slice(bytes);
    }

    if self.received == HEADER + self.length + TRAILER {
      self.finish();
    }
  }

  fn finish(&mut self) {
    if crc32(&self.payload) == u32::from_le_bytes(self.trailer) {
      let frame = Frame {
        channel: u32_at(&self.header, 0),
        kind: self.header[4],
        payload: mem::take(&mut self.payload),
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

/// How many of the first `limit` bytes come before the next F5.
fn until_magic(bytes: &[u8], limit: usize) -> usize {
  let limit = limit.min(bytes.len());

  bytes[..limit]
    .iter()
    .position(|&byte| byte == MAGIC[0])
    .unwrap_or(limit)
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
  u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// CRC-32 (IEEE 802.3), as zlib computes it.
fn crc32(bytes: &[u8]) -> u32 {
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
  fn decodes_frames_pushed_in_pieces_of_every_size() {
    let payload: Vec<u8> = (0..1000u32).map(|index| (index * 37 % 256) as u8).collect();
    let frames = [frame(0xF5F5_F5F5, &payload), frame(2, b""), frame(4, &[0xF5, 0, 0xF5])];
    let bytes: Vec<u8> = frames.iter().flat_map(Frame::to_bytes).collect();

    for size in 1..=40 {
      let mut decoder = Decoder::new();
      let mut decoded = Vec::new();
      for piece in bytes.chunks(size) {
        decoder.push(piece);
        decoded.extend(decode_all(&mut decoder));
      }

      assert_eq!(decoded, frames.clone().map(Ok::<_, Skipped>), "pieces of {size}");
    }
  }

  #[test]
  fn makes_room_for_every_escape() {
    let frames = [frame(0xF5F5_F5F5, &[0xF5; 100]), frame(1, b"plain")];

    for frame in frames {
      let bytes = frame.to_bytes();
      assert!(bytes.len() <= encoded_len(&frame.payload));
    }
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
    // Simulates a restore: a frame cut short, whose payload holds an encoded
    // frame, followed by the new host's first frame.
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
    // Waiting for the claimed length would swallow the new host's Hello.
    let long = frame(2, &[b'x'; 100_000]).to_bytes();
    let mut decoder = Decoder::new();
    decoder.push(&long[..1000]);
    decoder.push(&frame(0, b"hello").to_bytes());

    assert_eq!(decode_all(&mut decoder), [Err(Skipped(1000)), Ok(frame(0, b"hello"))]);
  }
}
