//! Setting the clock.

use std::io;

/// Sets CLOCK_REALTIME to `seconds` and `nanoseconds` past the Unix epoch,
/// clamping `nanoseconds` to the range clock_settime(2) accepts.
pub fn set_time(seconds: u64, nanoseconds: u32) -> io::Result<()> {
  let time = libc::timespec {
    tv_sec: seconds as libc::time_t,
    tv_nsec: libc::c_long::from(nanoseconds.min(999_999_999)),
  };

  // SAFETY: clock_settime reads a timespec, which outlives the call.
  crate::check(unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &raw const time) })?;
  Ok(())
}
