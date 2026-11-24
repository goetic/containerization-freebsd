//! Reading sysctl(3) values, by name or by walking the tree of names.

use crate::{c_string, check};
use std::ffi::CStr;
use std::io;
use std::ptr;

/// Room for the most numbers a MIB has: FreeBSD's CTL_MAXNAME, which is
/// more than macOS's.
const LONGEST: usize = 24;

/// A sysctl MIB: the numbers that name a node or a leaf of the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mib(Vec<libc::c_int>);

impl Mib {
  /// The MIB of the node or leaf named `name`, such as `kern.disks`.
  pub fn named(name: &str) -> io::Result<Self> {
    let name = c_string(name)?;
    let mut mib = vec![0; LONGEST];
    let mut length = mib.len();

    // SAFETY: sysctlnametomib writes no more than `length` numbers to `mib`,
    // and sets `length` to how many it wrote.
    check(unsafe { libc::sysctlnametomib(name.as_ptr(), mib.as_mut_ptr(), &mut length) })?;
    mib.truncate(length);
    Ok(Self(mib))
  }

  /// The first leaf after this MIB in the tree's order, or `None` after the
  /// last. After a node, it is the node's first leaf.
  pub fn next(&self) -> io::Result<Option<Self>> {
    let mut next = vec![0; LONGEST];

    match read(
      &self.query(2),
      next.as_mut_ptr().cast(),
      LONGEST * size_of::<libc::c_int>(),
    ) {
      Ok(length) => {
        next.truncate(length / size_of::<libc::c_int>());
        Ok(Some(Self(next)))
      }
      Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
      Err(error) => Err(error),
    }
  }

  /// The name, such as `kern.disks`.
  pub fn name(&self) -> io::Result<String> {
    Ok(text(&value(&self.query(1))?))
  }

  /// The value, as the kernel lays it out. A string's ends with its NUL.
  pub fn value(&self) -> io::Result<Vec<u8>> {
    value(&self.0)
  }

  /// Whether `other` is this MIB or a MIB under it.
  pub fn contains(&self, other: &Self) -> bool {
    other.0.starts_with(&self.0)
  }

  /// The MIB of the sysctl tree's own function `function`, such as 1 (the
  /// name) or 2 (the next leaf), applied to this MIB.
  fn query(&self, function: libc::c_int) -> Vec<libc::c_int> {
    [&[0, function][..], &self.0].concat()
  }
}

/// The value of the sysctl named `name`, as `Mib::value` returns it.
pub fn sysctl(name: &str) -> io::Result<Vec<u8>> {
  Mib::named(name)?.value()
}

/// The text of a string value, up to its NUL.
pub fn text(value: &[u8]) -> String {
  CStr::from_bytes_until_nul(value).map_or_else(
    |_| String::from_utf8_lossy(value).into_owned(),
    |text| text.to_string_lossy().into_owned(),
  )
}

/// The whole value at `mib`, however long.
fn value(mib: &[libc::c_int]) -> io::Result<Vec<u8>> {
  loop {
    let wanted = read(mib, ptr::null_mut(), 0)?;
    // Room to spare, in case the value grows between the two reads.
    let mut value = vec![0u8; wanted + wanted / 8 + 64];
    match read(mib, value.as_mut_ptr().cast(), value.len()) {
      Ok(length) => {
        value.truncate(length);
        return Ok(value);
      }
      Err(error) if error.raw_os_error() == Some(libc::ENOMEM) => {}
      Err(error) => return Err(error),
    }
  }
}

/// Reads the value at `mib` into `buffer`, which has room for `room` bytes,
/// and returns how many it wrote or, with a null buffer, would write.
fn read(mib: &[libc::c_int], buffer: *mut libc::c_void, room: usize) -> io::Result<usize> {
  // macOS's sysctl takes the MIB as mutable.
  let mut mib = mib.to_vec();
  let mut length = room;

  // SAFETY: sysctl writes no more than `length` bytes to `buffer`, and sets
  // `length` to how many it wrote; with a null buffer, it writes only
  // `length`. It sets nothing, since the new value is null.
  check(unsafe {
    libc::sysctl(
      mib.as_mut_ptr(),
      mib.len() as libc::c_uint,
      buffer,
      &mut length,
      ptr::null_mut(),
      0,
    )
  })?;
  Ok(length)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reads_a_value_by_name() {
    let ostype = text(&sysctl("kern.ostype").unwrap());

    assert!(["Darwin", "FreeBSD"].contains(&ostype.as_str()), "{ostype}");
  }

  #[test]
  fn walks_the_leaves_under_a_node() {
    let kern = Mib::named("kern").unwrap();
    let first = kern.next().unwrap().unwrap();
    let second = first.next().unwrap().unwrap();

    assert!(kern.contains(&first) && kern.contains(&second));
    assert!(first.name().unwrap().starts_with("kern."));
    assert_ne!(first, second);
    assert_eq!(Mib::named(&first.name().unwrap()).unwrap(), first);
    assert!(!first.contains(&kern));
  }
}
