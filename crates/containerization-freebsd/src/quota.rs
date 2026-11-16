//! Limits on a jail's processes together, and what they use, through
//! rctl(8): the counterpart of Containerization's per-container cpus and
//! memory, which size its VMs, and of its statistics. They need
//! `kern.racct.enable` set at boot, which preparing a base does.

use crate::error::{Error, Result};
use std::collections::HashMap;

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
  echo "limits need kern.racct.enable=1 at boot: prepare the base again" >&2
  exit 1
fi
[ $# -eq 0 ] || rctl -a "$@""#;

/// rctl(8)'s rules limiting the jail named `jail` to `cpus` and
/// `memory_in_bytes` of resident memory.
pub(crate) fn rules(jail: &str, cpus: Option<u32>, memory_in_bytes: Option<u64>) -> Vec<String> {
  let rule = |resource: &str, amount: Option<u64>| amount.map(|amount| format!("jail:{jail}:{resource}:deny={amount}"));

  [
    rule("pcpu", cpus.map(|cpus| u64::from(cpus) * 100)),
    rule("memoryuse", memory_in_bytes),
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
  fn makes_a_rule_for_each_limit_given() {
    assert_eq!(
      rules("web", Some(2), Some(256 << 20)),
      ["jail:web:pcpu:deny=200", "jail:web:memoryuse:deny=268435456"]
    );
    assert_eq!(
      rules("web", None, Some(1 << 30)),
      ["jail:web:memoryuse:deny=1073741824"]
    );
    assert!(rules("web", None, None).is_empty());
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
