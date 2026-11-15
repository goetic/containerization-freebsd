//! Quotas and statistics for what a jail's processes use together, through
//! rctl(8): Containerization's per-container limits and statistics. They
//! need `kern.racct.enable` set at boot, which preparing a base does.

use crate::error::{Error, Result};
use std::collections::HashMap;

/// Quotas on what a jail's processes use together.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Quotas {
  /// CPU, in percent of one core: 250 is two and a half. Its processes are
  /// slowed to keep within it.
  pub cpu_percent: Option<u64>,
  /// Resident memory, in bytes. The kernel pages out what is past it,
  /// which can thrash the machine.
  pub memory: Option<u64>,
  /// Processes: forking past it fails.
  pub processes: Option<u64>,
  /// File system reads and writes a second: its processes are slowed to
  /// keep within them. Writes include those to the cache.
  pub read_bytes_per_second: Option<u64>,
  pub write_bytes_per_second: Option<u64>,
  pub read_operations_per_second: Option<u64>,
  pub write_operations_per_second: Option<u64>,
}

/// What a jail's processes use together.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
  /// CPU time, in whole seconds.
  pub cpu_seconds: u64,
  /// Recent CPU, in percent of one core.
  pub cpu_percent: u64,
  /// Resident memory, in bytes.
  pub memory: u64,
  pub processes: u64,
  pub threads: u64,
  pub open_files: u64,
  /// Recent file system reads and writes a second.
  pub read_bytes_per_second: u64,
  pub write_bytes_per_second: u64,
  pub read_operations_per_second: u64,
  pub write_operations_per_second: u64,
}

/// Replaces the rules of the jail named `$1` with the rules after it, if
/// the kernel accounts.
pub(crate) const LIMIT: &str = r#"set -e
jail=$1
shift
if [ "$(sysctl -n kern.racct.enable 2>/dev/null)" = 1 ]; then
  [ -z "$(rctl "jail:$jail:")" ] || rctl -r "jail:$jail:"
elif [ $# -gt 0 ]; then
  echo "quotas need kern.racct.enable=1 at boot: prepare the base again" >&2
  exit 1
fi
[ $# -eq 0 ] || rctl -a "$@""#;

/// rctl(8)'s rules for `quotas` on the jail named `jail`.
pub(crate) fn rules(jail: &str, quotas: &Quotas) -> Vec<String> {
  let rule = |resource: &str, action: &str, amount: Option<u64>| {
    amount.map(|amount| format!("jail:{jail}:{resource}:{action}={amount}"))
  };

  [
    rule("pcpu", "deny", quotas.cpu_percent),
    rule("memoryuse", "deny", quotas.memory),
    rule("maxproc", "deny", quotas.processes),
    rule("readbps", "throttle", quotas.read_bytes_per_second),
    rule("writebps", "throttle", quotas.write_bytes_per_second),
    rule("readiops", "throttle", quotas.read_operations_per_second),
    rule("writeiops", "throttle", quotas.write_operations_per_second),
  ]
  .into_iter()
  .flatten()
  .collect()
}

/// The statistics in what `rctl -u` printed.
pub(crate) fn statistics(usage: &str) -> Result<Statistics> {
  let values: HashMap<&str, &str> = usage
    .lines()
    .filter_map(|line| line.split_once('='))
    .collect();
  let value = |resource: &str| {
    values
      .get(resource)
      .and_then(|value| value.trim().parse().ok())
      .ok_or_else(|| Error::Guest(format!("rctl gave no {resource} in {usage:?}")))
  };

  Ok(Statistics {
    cpu_seconds: value("cputime")?,
    cpu_percent: value("pcpu")?,
    memory: value("memoryuse")?,
    processes: value("maxproc")?,
    threads: value("nthr")?,
    open_files: value("openfiles")?,
    read_bytes_per_second: value("readbps")?,
    write_bytes_per_second: value("writebps")?,
    read_operations_per_second: value("readiops")?,
    write_operations_per_second: value("writeiops")?,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn makes_a_rule_for_each_quota_given() {
    let quotas = Quotas {
      cpu_percent: Some(150),
      memory: Some(256 << 20),
      write_bytes_per_second: Some(1 << 20),
      ..Quotas::default()
    };

    assert_eq!(
      rules("web", &quotas),
      [
        "jail:web:pcpu:deny=150",
        "jail:web:memoryuse:deny=268435456",
        "jail:web:writebps:throttle=1048576",
      ]
    );
    assert!(rules("web", &Quotas::default()).is_empty());
  }

  #[test]
  fn reads_what_rctl_says_a_jail_uses() {
    let usage = "cputime=12\ndatasize=397312\nstacksize=0\ncoredumpsize=0\nmemoryuse=7835648\n\
                 memorylocked=0\nmaxproc=3\nopenfiles=118\nvmemoryuse=48873472\npseudoterminals=0\n\
                 swapuse=0\nnthr=4\nmsgqqueued=0\nmsgqsize=0\nnmsgq=0\nnsem=0\nnsemop=0\nnshm=0\n\
                 shmsize=0\nwallclock=31\npcpu=7\nreadbps=4096\nwritebps=512\nreadiops=2\nwriteiops=1\n";

    assert_eq!(
      statistics(usage).unwrap(),
      Statistics {
        cpu_seconds: 12,
        cpu_percent: 7,
        memory: 7_835_648,
        processes: 3,
        threads: 4,
        open_files: 118,
        read_bytes_per_second: 4096,
        write_bytes_per_second: 512,
        read_operations_per_second: 2,
        write_operations_per_second: 1,
      }
    );
    assert!(statistics("cputime=12\n").is_err());
  }
}
