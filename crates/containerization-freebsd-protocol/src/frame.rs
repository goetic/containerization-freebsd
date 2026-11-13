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
//! The console has no framing of its own, and a restore or a restarted host
//! can join it mid-frame, so the decoder drops bytes until a magic whose
//! header checksum holds. 0xF5 and 0xC0 never occur in UTF-8, so text the
//! guest printed before the agent started can't pass for a frame. The header
//! has its own checksum so a false magic fails at once, not after the decoder
//! waits for the length it claims.

pub const MAGIC: [u8; 4] = [0xF5, 0xC0, 0xFB, 0x5D];
pub const MAX_PAYLOAD: usize = 1 << 20;

const HEADER: usize = 17;
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
    let start = out.len();

    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&self.channel.to_le_bytes());
    out.push(self.kind);
    out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
    let header = crc32(&out[start + MAGIC.len()..]);
    out.extend_from_slice(&header.to_le_bytes());
    out.extend_from_slice(&self.payload);
    out.extend_from_slice(&crc32(&self.payload).to_le_bytes());
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + self.payload.len() + TRAILER);

    self.encode(&mut out);
    out
  }
}

/// Bytes the decoder dropped to find the next frame. Mid-session, that means
/// frames were lost, and the host should start the session over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Skipped(pub usize);

#[derive(Debug, Default)]
pub struct Decoder {
  buffer: Vec<u8>,
}

enum Parsed {
  Incomplete,
  Corrupt,
  Frame(Frame, usize),
}

impl Decoder {
  pub fn new() -> Self {
    Self::default()
  }

  pub fn push(&mut self, bytes: &[u8]) {
    self.buffer.extend_from_slice(bytes);
  }

  /// The next frame; or the bytes dropped before it, then the frame on the
  /// next call; or `None` until more bytes arrive.
  pub fn decode(&mut self) -> Option<Result<Frame, Skipped>> {
    let mut skip = 0;
    let found = loop {
      let Some(at) = find_magic(&self.buffer[skip..]) else {
        // Keep what may be the start of a magic the next push completes.
        skip = skip.max(self.buffer.len().saturating_sub(MAGIC.len() - 1));
        break None;
      };
      skip += at;

      match parse(&self.buffer[skip..]) {
        Parsed::Incomplete => break None,
        Parsed::Corrupt => skip += 1,
        Parsed::Frame(frame, length) => break Some((frame, length)),
      }
    };

    if skip > 0 {
      self.buffer.drain(..skip);
      return Some(Err(Skipped(skip)));
    }

    let (frame, length) = found?;
    self.buffer.drain(..length);
    Some(Ok(frame))
  }
}

fn find_magic(bytes: &[u8]) -> Option<usize> {
  bytes
    .windows(MAGIC.len())
    .position(|window| window == MAGIC.as_slice())
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
  u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// The frame `bytes` starts with, which starts with a magic.
fn parse(bytes: &[u8]) -> Parsed {
  if bytes.len() < HEADER {
    return Parsed::Incomplete;
  }
  if crc32(&bytes[4..13]) != u32_at(bytes, 13) {
    return Parsed::Corrupt;
  }

  let length = u32_at(bytes, 9) as usize;
  if length > MAX_PAYLOAD {
    return Parsed::Corrupt;
  }
  let total = HEADER + length + TRAILER;
  if bytes.len() < total {
    return Parsed::Incomplete;
  }

  let payload = &bytes[HEADER..HEADER + length];
  if crc32(payload) != u32_at(bytes, HEADER + length) {
    return Parsed::Corrupt;
  }

  Parsed::Frame(
    Frame {
      channel: u32_at(bytes, 4),
      kind: bytes[8],
      payload: payload.to_vec(),
    },
    total,
  )
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
    bytes[HEADER + 1] ^= 0xFF;
    bytes.extend(frame(3, b"kept").to_bytes());
    let mut decoder = Decoder::new();
    decoder.push(&bytes);

    assert_eq!(decode_all(&mut decoder), [Err(Skipped(lost)), Ok(frame(3, b"kept"))]);
  }

  #[test]
  fn rejects_a_false_magic_without_waiting_for_the_length_it_claims() {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&[0, 0, 0, 0, 0x21]);
    bytes.extend_from_slice(&1000u32.to_le_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes.extend(frame(5, b"real").to_bytes());
    let mut decoder = Decoder::new();
    decoder.push(&bytes);

    assert_eq!(decode_all(&mut decoder), [Err(Skipped(HEADER)), Ok(frame(5, b"real"))]);
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
}
