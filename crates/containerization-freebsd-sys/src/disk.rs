//! The guest's disks, and their idents.

use std::io;

/// The names of the guest's disks, such as `vtbd0`, from `kern.disks`.
#[cfg(target_os = "freebsd")]
pub fn disks() -> io::Result<Vec<String>> {
  use std::ffi::CStr;
  use std::ptr;

  let name = c"kern.disks";
  loop {
    let mut length = 0;
    // SAFETY: with no buffer, sysctlbyname only reports the value's length.
    crate::check(unsafe { libc::sysctlbyname(name.as_ptr(), ptr::null_mut(), &mut length, ptr::null(), 0) })?;
    let mut value = vec![0u8; length];
    // SAFETY: sysctlbyname writes no more than `length` bytes, which `value`
    // holds, and sets `length` to how many it wrote.
    let read = crate::check(unsafe {
      libc::sysctlbyname(name.as_ptr(), value.as_mut_ptr().cast(), &mut length, ptr::null(), 0)
    });
    match read {
      // A disk arrived between the calls.
      Err(error) if error.raw_os_error() == Some(libc::ENOMEM) => continue,
      Err(error) => return Err(error),
      Ok(_) => {}
    }
    value.truncate(length);
    let value = CStr::from_bytes_until_nul(&value).map_or(&value[..], CStr::to_bytes);

    return Ok(
      String::from_utf8_lossy(value)
        .split_whitespace()
        .map(str::to_string)
        .collect(),
    );
  }
}

#[cfg(not(target_os = "freebsd"))]
pub fn disks() -> io::Result<Vec<String>> {
  crate::unsupported("listing the disks")
}

/// The ident of the disk `name`, as diskinfo(8)'s `-s` reports it. For a
/// virtio-blk disk, it is the serial.
#[cfg(target_os = "freebsd")]
pub fn disk_ident(name: &str) -> io::Result<String> {
  use std::ffi::CStr;
  use std::os::fd::AsRawFd;

  /// `_IOR('d', 137, char[DISK_IDENT_SIZE])`, from <sys/disk.h>.
  const DIOCGIDENT: libc::c_ulong = 0x4100_6489;
  const DISK_IDENT_SIZE: usize = 256;
  let disk = std::fs::File::open(format!("/dev/{name}"))?;
  let mut ident = [0u8; DISK_IDENT_SIZE];

  // SAFETY: DIOCGIDENT writes no more than DISK_IDENT_SIZE bytes, which
  // `ident` holds, and the file keeps the descriptor open.
  crate::check(unsafe { libc::ioctl(disk.as_raw_fd(), DIOCGIDENT, ident.as_mut_ptr()) })?;
  Ok(
    CStr::from_bytes_until_nul(&ident)
      .map(|ident| ident.to_string_lossy().into_owned())
      .unwrap_or_default(),
  )
}

#[cfg(not(target_os = "freebsd"))]
pub fn disk_ident(name: &str) -> io::Result<String> {
  crate::unsupported(format_args!("reading disk {name}'s ident"))
}
