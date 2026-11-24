//! Mounting and unmounting file systems, and listing what is mounted.

use std::io;
use std::path::{Path, PathBuf};

/// A mounted file system, as getfsstat(2) describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mounted {
  /// The file system's type, such as `zfs` or `nullfs`.
  pub kind: String,
  /// What is mounted, such as a ZFS dataset's name.
  pub source: String,
  /// Where it is mounted.
  pub point: PathBuf,
}

/// Mounts the file system of type `kind` from `source` at `point` with
/// nmount(2), as mount(8) does for a type without a mount program of its
/// own. Each option is a `name` or a `name=value`, such as `ro` or
/// `size=64m`.
#[cfg(target_os = "freebsd")]
pub fn mount(kind: &str, source: &str, point: &Path, options: &[String]) -> io::Result<()> {
  use crate::{c_string, iovec};
  use std::ffi::{CStr, CString};

  let mut pairs: Vec<(CString, Option<CString>)> = vec![
    (c"fstype".into(), Some(c_string(kind)?)),
    (c"fspath".into(), Some(c_string(point)?)),
    (c"from".into(), Some(c_string(source)?)),
  ];
  for option in options {
    let (name, value) = match option.split_once('=') {
      Some((name, value)) => (name, Some(value)),
      None => (option.as_str(), None),
    };
    pairs.push((c_string(name)?, value.map(c_string).transpose()?));
  }
  // Where the kernel explains a failure, if it does.
  let mut message = [0u8; 256];
  let mut parameters: Vec<libc::iovec> = pairs
    .iter()
    .flat_map(|(name, value)| {
      [
        iovec(name.to_bytes_with_nul()),
        value
          .as_deref()
          .map_or(iovec(&[]), |value| iovec(value.to_bytes_with_nul())),
      ]
    })
    .collect();
  parameters.extend([
    iovec(c"errmsg".to_bytes_with_nul()),
    libc::iovec {
      iov_base: message.as_mut_ptr().cast(),
      iov_len: message.len(),
    },
  ]);

  // SAFETY: nmount reads the names and values, which outlive the call, and
  // writes no more than the message buffer holds.
  if unsafe { libc::nmount(parameters.as_mut_ptr(), parameters.len() as libc::c_uint, 0) } == -1 {
    let error = io::Error::last_os_error();
    let explained = CStr::from_bytes_until_nul(&message).map_or_else(|_| "".into(), CStr::to_string_lossy);
    return Err(if explained.is_empty() {
      error
    } else {
      io::Error::new(error.kind(), format!("{explained}: {error}"))
    });
  }
  Ok(())
}

#[cfg(not(target_os = "freebsd"))]
pub fn mount(kind: &str, _: &str, point: &Path, _: &[String]) -> io::Result<()> {
  crate::unsupported(format_args!("mounting {kind} at {}", point.display()))
}

/// Unmounts the file system mounted at `point`.
#[cfg(target_os = "freebsd")]
pub fn unmount(point: &Path) -> io::Result<()> {
  let point = crate::c_string(point)?;

  // SAFETY: unmount only reads the path, which outlives the call.
  crate::check(unsafe { libc::unmount(point.as_ptr(), 0) })?;
  Ok(())
}

#[cfg(not(target_os = "freebsd"))]
pub fn unmount(point: &Path) -> io::Result<()> {
  crate::unsupported(format_args!("unmounting {}", point.display()))
}

/// The mounted file systems, in the order they were mounted.
#[cfg(target_os = "freebsd")]
pub fn mounts() -> io::Result<Vec<Mounted>> {
  use std::ffi::OsString;
  use std::os::unix::ffi::OsStringExt;

  // c_char is u8 on aarch64, but i8 on x86_64.
  #[allow(clippy::unnecessary_cast)]
  fn bytes(chars: &[libc::c_char]) -> Vec<u8> {
    chars
      .iter()
      .take_while(|&&char| char != 0)
      .map(|&char| char as u8)
      .collect()
  }
  let text = |chars: &[libc::c_char]| String::from_utf8_lossy(&bytes(chars)).into_owned();

  loop {
    // SAFETY: with no buffer, getfsstat only counts the file systems.
    let count = crate::check(unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) })?;
    // Room for one more shows whether one was mounted between the calls.
    let mut buffer: Vec<libc::statfs> = Vec::with_capacity(count as usize + 1);
    let size = buffer.capacity() * size_of::<libc::statfs>();
    // SAFETY: getfsstat writes no more than `size` bytes, which the buffer has
    // room for, and returns how many file systems it wrote.
    let filled = crate::check(unsafe { libc::getfsstat(buffer.as_mut_ptr(), size as libc::c_long, libc::MNT_NOWAIT) })?;
    if filled as usize == buffer.capacity() {
      continue;
    }
    // SAFETY: getfsstat initialized the first `filled` entries.
    unsafe { buffer.set_len(filled as usize) };

    return Ok(
      buffer
        .iter()
        .map(|mounted| Mounted {
          kind: text(&mounted.f_fstypename),
          source: text(&mounted.f_mntfromname),
          point: PathBuf::from(OsString::from_vec(bytes(&mounted.f_mntonname))),
        })
        .collect(),
    );
  }
}

#[cfg(not(target_os = "freebsd"))]
pub fn mounts() -> io::Result<Vec<Mounted>> {
  crate::unsupported("listing the mounted file systems")
}
