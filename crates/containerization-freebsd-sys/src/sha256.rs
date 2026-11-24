//! SHA-256 from the system's library: libmd on FreeBSD, and CommonCrypto on
//! macOS, where the agent's tests run.

/// The library's hashing context, which is smaller than this on both
/// systems.
#[repr(C, align(8))]
struct Context([u8; 256]);

#[cfg(target_os = "freebsd")]
#[link(name = "md")]
unsafe extern "C" {
  #[link_name = "_libmd_SHA256_Init"]
  fn init(context: *mut Context);
  #[link_name = "_libmd_SHA256_Update"]
  fn update(context: *mut Context, data: *const libc::c_void, length: libc::size_t);
  #[link_name = "_libmd_SHA256_Final"]
  fn finish(digest: *mut u8, context: *mut Context);
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
  #[link_name = "CC_SHA256_Init"]
  fn init(context: *mut Context) -> libc::c_int;
  #[link_name = "CC_SHA256_Update"]
  fn update(context: *mut Context, data: *const libc::c_void, length: u32) -> libc::c_int;
  #[link_name = "CC_SHA256_Final"]
  fn finish(digest: *mut u8, context: *mut Context) -> libc::c_int;
}

/// A SHA-256 hash in progress.
pub struct Sha256(Context);

impl Sha256 {
  pub fn new() -> Self {
    let mut hash = Self(Context([0; 256]));

    // SAFETY: init writes no more than the context holds.
    unsafe { init(&mut hash.0) };
    hash
  }

  /// Hashes `bytes`, after those hashed before.
  pub fn update(&mut self, bytes: &[u8]) {
    // CommonCrypto takes at most a u32's worth of bytes at a time.
    for chunk in bytes.chunks(u32::MAX as usize) {
      // SAFETY: update reads no more than the chunk holds, and writes no
      // more than the context holds.
      unsafe { update(&mut self.0, chunk.as_ptr().cast(), chunk.len() as _) };
    }
  }

  /// The hash of everything hashed.
  pub fn finish(mut self) -> [u8; 32] {
    let mut digest = [0; 32];

    // SAFETY: finish writes the 32-byte digest, and no more than the context
    // holds.
    unsafe { finish(digest.as_mut_ptr(), &mut self.0) };
    digest
  }
}

impl Default for Sha256 {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn hex(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
  }

  #[test]
  fn hashes_in_pieces_as_at_once() {
    let mut pieces = Sha256::new();
    pieces.update(b"a");
    pieces.update(b"");
    pieces.update(b"bc");

    assert_eq!(
      hex(pieces.finish()),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
      hex(Sha256::new().finish()),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  }
}
