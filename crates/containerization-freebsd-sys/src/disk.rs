//! The guest's disks, and their idents.

use crate::sysctl;
use std::io;

/// The names of the guest's disks, such as `vtbd0`, from `kern.disks`.
pub fn disks() -> io::Result<Vec<String>> {
  let disks = sysctl::text(&sysctl::sysctl("kern.disks")?);

  Ok(disks.split_whitespace().map(str::to_string).collect())
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
