//! How a payload encodes values: integers little-endian, a bool as a u8 of
//! 0 or 1, a string or list as a u32 length followed by its bytes or items,
//! and an option as a bool followed by the value, if any.

use std::fmt;

/// Why a frame's payload isn't a valid message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
  UnknownKind(u8),
  Truncated,
  /// The payload has bytes after the message's last field.
  TooLong,
  NotUtf8,
  UnknownTag(u8),
}

impl fmt::Display for DecodeError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::UnknownKind(kind) => write!(formatter, "unknown message kind {kind:#04x}"),
      Self::Truncated => formatter.write_str("the payload ends early"),
      Self::TooLong => formatter.write_str("the payload goes on after the message"),
      Self::NotUtf8 => formatter.write_str("a string is not UTF-8"),
      Self::UnknownTag(tag) => write!(formatter, "unknown tag {tag}"),
    }
  }
}

impl std::error::Error for DecodeError {}

pub(crate) trait Encode {
  fn encode(&self, out: &mut Writer);
}

pub(crate) trait Decode: Sized {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError>;
}

/// `value` as a payload.
pub(crate) fn encode(value: &(impl Encode + ?Sized)) -> Vec<u8> {
  let mut out = Writer::default();
  out.put(value);
  out.0
}

#[derive(Default)]
pub(crate) struct Writer(Vec<u8>);

impl Writer {
  pub(crate) fn put(&mut self, value: &(impl Encode + ?Sized)) -> &mut Self {
    value.encode(self);
    self
  }
}

pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
  pub(crate) fn new(payload: &'a [u8]) -> Self {
    Self(payload)
  }

  pub(crate) fn get<T: Decode>(&mut self) -> Result<T, DecodeError> {
    T::decode(self)
  }

  /// Fails if the payload goes on after the message's last field.
  pub(crate) fn finish(self) -> Result<(), DecodeError> {
    if self.0.is_empty() {
      Ok(())
    } else {
      Err(DecodeError::TooLong)
    }
  }

  fn take<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
    let (taken, rest) = self.0.split_first_chunk().ok_or(DecodeError::Truncated)?;

    self.0 = rest;
    Ok(*taken)
  }

  fn bytes(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
    let (taken, rest) = self
      .0
      .split_at_checked(length)
      .ok_or(DecodeError::Truncated)?;

    self.0 = rest;
    Ok(taken)
  }

  /// A string's or list's length prefix.
  fn length(&mut self) -> Result<usize, DecodeError> {
    self.get::<u32>().map(|length| length as usize)
  }
}

/// Saturating is safe: a length over u32::MAX also exceeds MAX_PAYLOAD, so
/// the frame is refused before it is sent.
fn wire_length(length: usize) -> u32 {
  u32::try_from(length).unwrap_or(u32::MAX)
}

macro_rules! integers {
  ($($integer:ty),*) => {$(
    impl Encode for $integer {
      fn encode(&self, out: &mut Writer) {
        out.0.extend_from_slice(&self.to_le_bytes());
      }
    }

    impl Decode for $integer {
      fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        reader.take().map(Self::from_le_bytes)
      }
    }
  )*};
}

integers!(u8, u16, u32, u64, i32);

/// Encodes and decodes the struct `$record` as its fields in the order
/// listed, so that both directions follow one list.
macro_rules! record {
  ($record:ty { $($field:ident),+ $(,)? }) => {
    impl $crate::codec::Encode for $record {
      fn encode(&self, out: &mut $crate::codec::Writer) {
        $(out.put(&self.$field);)+
      }
    }

    impl $crate::codec::Decode for $record {
      fn decode(reader: &mut $crate::codec::Reader<'_>) -> Result<Self, $crate::codec::DecodeError> {
        Ok(Self {
          $($field: reader.get()?,)+
        })
      }
    }
  };
}

/// Encodes and decodes the enum `$tagged`, whose variants each hold one
/// value, as the variant's u8 tag followed by the value.
macro_rules! tagged {
  ($tagged:ty { $($tag:literal => $variant:ident),+ $(,)? }) => {
    impl $crate::codec::Encode for $tagged {
      fn encode(&self, out: &mut $crate::codec::Writer) {
        match self {
          $(Self::$variant(value) => out.put(&($tag as u8)).put(value),)+
        };
      }
    }

    impl $crate::codec::Decode for $tagged {
      fn decode(reader: &mut $crate::codec::Reader<'_>) -> Result<Self, $crate::codec::DecodeError> {
        match reader.get::<u8>()? {
          $($tag => Ok(Self::$variant(reader.get()?)),)+
          tag => Err($crate::codec::DecodeError::UnknownTag(tag)),
        }
      }
    }
  };
}

pub(crate) use {record, tagged};

impl Encode for bool {
  fn encode(&self, out: &mut Writer) {
    out.put(&u8::from(*self));
  }
}

impl Decode for bool {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    match reader.get()? {
      0u8 => Ok(false),
      1 => Ok(true),
      tag => Err(DecodeError::UnknownTag(tag)),
    }
  }
}

impl Encode for str {
  fn encode(&self, out: &mut Writer) {
    out.put(&wire_length(self.len()));
    out.0.extend_from_slice(self.as_bytes());
  }
}

impl Encode for String {
  fn encode(&self, out: &mut Writer) {
    out.put(self.as_str());
  }
}

impl Decode for String {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    let length = reader.length()?;

    String::from_utf8(reader.bytes(length)?.to_vec()).map_err(|_| DecodeError::NotUtf8)
  }
}

impl<T: Encode> Encode for Option<T> {
  fn encode(&self, out: &mut Writer) {
    match self {
      Some(value) => out.put(&true).put(value),
      None => out.put(&false),
    };
  }
}

impl<T: Decode> Decode for Option<T> {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    if reader.get()? {
      reader.get().map(Some)
    } else {
      Ok(None)
    }
  }
}

impl<T: Encode> Encode for Vec<T> {
  fn encode(&self, out: &mut Writer) {
    out.put(&wire_length(self.len()));
    for item in self {
      out.put(item);
    }
  }
}

impl<T: Decode> Decode for Vec<T> {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    (0..reader.length()?).map(|_| reader.get()).collect()
  }
}

impl<A: Encode, B: Encode> Encode for (A, B) {
  fn encode(&self, out: &mut Writer) {
    out.put(&self.0).put(&self.1);
  }
}

impl<A: Decode, B: Decode> Decode for (A, B) {
  fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
    Ok((reader.get()?, reader.get()?))
  }
}
