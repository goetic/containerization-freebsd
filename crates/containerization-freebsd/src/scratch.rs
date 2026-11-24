//! Scratch files the host writes, such as downloads not yet verified.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The path of a scratch file, which is removed when this is dropped. Once
/// the file has been renamed into place, as a verified blob is, removing it
/// finds nothing, so a scratch file that was kept needs no special case.
#[derive(Debug)]
pub(crate) struct Scratch(PathBuf);

impl Scratch {
  /// A new path in `directory`, unique to this process, starting with
  /// `prefix`. Nothing is created there until the caller writes the file.
  pub(crate) fn new_in(directory: &Path, prefix: &str) -> Self {
    static NEXT: AtomicU64 = AtomicU64::new(0);

    Self(directory.join(format!(
      "{prefix}{}-{}",
      std::process::id(),
      NEXT.fetch_add(1, Ordering::Relaxed)
    )))
  }

  pub(crate) fn path(&self) -> &Path {
    &self.0
  }
}

impl Drop for Scratch {
  fn drop(&mut self) {
    let _ = std::fs::remove_file(&self.0);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn removes_its_file_unless_it_was_moved() {
    let directory = tempfile::tempdir().unwrap();
    let (removed, moved) = (
      Scratch::new_in(directory.path(), "a-"),
      Scratch::new_in(directory.path(), "a-"),
    );
    assert_ne!(removed.path(), moved.path());
    std::fs::write(removed.path(), b"").unwrap();
    std::fs::write(moved.path(), b"").unwrap();
    let (removed_path, kept) = (removed.path().to_path_buf(), directory.path().join("kept"));
    std::fs::rename(moved.path(), &kept).unwrap();

    drop((removed, moved));

    assert!(!removed_path.exists());
    assert!(kept.exists());
  }
}
