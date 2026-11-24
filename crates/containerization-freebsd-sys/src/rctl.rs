//! Resource limits and usage through rctl(2), which needs the
//! `kern.racct.enable` tunable: without it, these fail with ENOSYS.

use std::io;

#[cfg(target_os = "freebsd")]
unsafe extern "C" {
  fn rctl_get_racct(
    inbufp: *const libc::c_char,
    inbuflen: libc::size_t,
    outbufp: *mut libc::c_char,
    outbuflen: libc::size_t,
  ) -> libc::c_int;
  fn rctl_add_rule(
    inbufp: *const libc::c_char,
    inbuflen: libc::size_t,
    outbufp: *mut libc::c_char,
    outbuflen: libc::size_t,
  ) -> libc::c_int;
  fn rctl_remove_rule(
    inbufp: *const libc::c_char,
    inbuflen: libc::size_t,
    outbufp: *mut libc::c_char,
    outbuflen: libc::size_t,
  ) -> libc::c_int;
}

/// Adds the rule `rule`, such as `jail:web:pcpu:deny=200`.
#[cfg(target_os = "freebsd")]
pub fn add_rule(rule: &str) -> io::Result<()> {
  let rule = crate::c_string(rule)?;

  // SAFETY: rctl_add_rule reads the rule, which outlives the call, and has no
  // output buffer to write.
  crate::check(unsafe { rctl_add_rule(rule.as_ptr(), rule.as_bytes_with_nul().len(), std::ptr::null_mut(), 0) })?;
  Ok(())
}

#[cfg(not(target_os = "freebsd"))]
pub fn add_rule(rule: &str) -> io::Result<()> {
  crate::unsupported(format_args!("adding the rctl rule {rule}"))
}

/// Removes the rules that `filter` matches, such as `jail:web:` for all of
/// jail web's. Matching none is no failure.
#[cfg(target_os = "freebsd")]
pub fn remove_rules(filter: &str) -> io::Result<()> {
  let filter = crate::c_string(filter)?;

  // SAFETY: rctl_remove_rule reads the filter, which outlives the call, and
  // has no output buffer to write.
  let removed = crate::check(unsafe {
    rctl_remove_rule(
      filter.as_ptr(),
      filter.as_bytes_with_nul().len(),
      std::ptr::null_mut(),
      0,
    )
  });
  match removed {
    Err(error) if error.raw_os_error() != Some(libc::ESRCH) => Err(error),
    _ => Ok(()),
  }
}

#[cfg(not(target_os = "freebsd"))]
pub fn remove_rules(filter: &str) -> io::Result<()> {
  crate::unsupported(format_args!("removing the rctl rules {filter}"))
}

/// The usage that `filter` names, such as `jail:web:` for jail web's, as
/// `resource=amount` pairs separated by commas.
#[cfg(target_os = "freebsd")]
pub fn racct(filter: &str) -> io::Result<String> {
  let filter = crate::c_string(filter)?;
  let mut usage = vec![0u8; 4096];

  loop {
    // SAFETY: rctl_get_racct reads the filter, which outlives the call, and
    // writes no more than `usage` holds.
    let read = crate::check(unsafe {
      rctl_get_racct(
        filter.as_ptr(),
        filter.as_bytes_with_nul().len(),
        usage.as_mut_ptr().cast(),
        usage.len(),
      )
    });
    match read {
      Err(error) if error.raw_os_error() == Some(libc::ERANGE) => usage.resize(usage.len() * 4, 0),
      Err(error) => return Err(error),
      Ok(_) => return Ok(crate::sysctl::text(&usage)),
    }
  }
}

#[cfg(not(target_os = "freebsd"))]
pub fn racct(filter: &str) -> io::Result<String> {
  crate::unsupported(format_args!("reading the racct usage of {filter}"))
}
