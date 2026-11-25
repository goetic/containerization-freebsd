//! Calls about a jail: its rctl rules, its statistics, and the steps of
//! stopping it.

use crate::sys;
use containerization_freebsd_protocol::message;
use std::collections::HashMap;
use std::io;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How often to check whether a removed jail has finished dying.
const POLL: Duration = Duration::from_millis(100);

/// Replaces the jail's rctl rules. Without `kern.racct.enable`, fails if any
/// rules are given, and otherwise does nothing.
pub(crate) fn set_rules(rules: &message::Rules) -> io::Result<()> {
  let subject = format!("jail:{}:", rules.jail);

  match sys::rctl::remove_rules(&subject) {
    Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => {
      if rules.rules.is_empty() {
        return Ok(());
      }
      return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "limits need kern.racct.enable=1 at boot: prepare the base again",
      ));
    }
    removed => removed?,
  }
  for rule in &rules.rules {
    sys::rctl::add_rule(&format!("{subject}{rule}"))?;
  }
  Ok(())
}

/// The jail's racct usage, a VNET jail's interface counters, and the I/O of
/// the dataset, if one is named.
pub(crate) fn statistics(of: &message::StatisticsOf) -> io::Result<message::Statistics> {
  let (jail, _) = sys::jail::find_jail(&of.jail)?;
  let mut statistics = usage(&sys::rctl::racct(&format!("jail:{}:", of.jail))?)?;

  if sys::jail::has_vnet(jail)? {
    statistics.networks = sys::interface::interfaces_in(jail)?
      .into_iter()
      .map(|interface| message::NetworkStatistics {
        interface: interface.name,
        received_packets: interface.received_packets,
        transmitted_packets: interface.transmitted_packets,
        received_bytes: interface.received_bytes,
        transmitted_bytes: interface.transmitted_bytes,
        received_errors: interface.received_errors,
        transmitted_errors: interface.transmitted_errors,
        received_dropped: interface.received_dropped,
        transmitted_dropped: interface.transmitted_dropped,
      })
      .collect();
  }
  if let Some(dataset) = &of.dataset {
    statistics.block_io = vec![dataset_io(dataset)?];
  }
  Ok(statistics)
}

/// Reads rctl's `resource=amount` pairs, separated by commas.
fn usage(usage: &str) -> io::Result<message::Statistics> {
  let amounts: HashMap<&str, &str> = usage
    .split(',')
    .filter_map(|pair| pair.split_once('='))
    .collect();
  let amount = |resource: &str| {
    amounts
      .get(resource)
      .and_then(|amount| amount.trim().parse().ok())
      .ok_or_else(|| io::Error::other(format!("rctl gave no {resource} in {usage:?}")))
  };

  Ok(message::Statistics {
    cpu_seconds: amount("cputime")?,
    cpu_percent: amount("pcpu")?,
    memory: amount("memoryuse")?,
    processes: amount("maxproc")?,
    threads: amount("nthr")?,
    open_files: amount("openfiles")?,
    read_bytes_per_second: amount("readbps")?,
    write_bytes_per_second: amount("writebps")?,
    read_operations_per_second: amount("readiops")?,
    write_operations_per_second: amount("writeiops")?,
    networks: Vec::new(),
    block_io: Vec::new(),
  })
}

/// The I/O counters of the mounted dataset `dataset`, from the objset kstats
/// whose `dataset_name` names it.
fn dataset_io(dataset: &str) -> io::Result<message::DatasetIo> {
  let pool = dataset.split('/').next().unwrap_or(dataset);
  let objsets = sys::sysctl::Mib::named(&format!("kstat.zfs.{pool}.dataset"))?;
  let mut leaf = objsets.clone();

  while let Some(next) = leaf.next()?.filter(|next| objsets.contains(next)) {
    let name = next.name()?;
    if let Some(objset) = name.strip_suffix(".dataset_name")
      && sys::sysctl::text(&next.value()?) == dataset
    {
      let counter = |which: &str| -> io::Result<u64> {
        let value = sys::sysctl::sysctl(&format!("{objset}.{which}"))?;
        let bytes = value
          .try_into()
          .map_err(|_| io::Error::other(format!("{objset}.{which} is not a 64-bit counter")))?;
        Ok(u64::from_ne_bytes(bytes))
      };
      return Ok(message::DatasetIo {
        dataset: dataset.to_string(),
        read_bytes: counter("nread")?,
        write_bytes: counter("nwritten")?,
        read_operations: counter("reads")?,
        write_operations: counter("writes")?,
      });
    }
    leaf = next;
  }
  Err(io::Error::new(
    io::ErrorKind::NotFound,
    format!("ZFS keeps no kstats for {dataset:?}, which may not be mounted"),
  ))
}

/// Sends SIGTERM to the jail's processes from a child attached to the jail,
/// and returns the wait for that child, which may take the whole grace
/// period.
pub(crate) fn terminate(wait: &message::JailWait) -> io::Result<impl FnOnce() -> io::Result<()> + Send + use<>> {
  let (jail, _) = sys::jail::find_jail(&wait.jail)?;
  let terminating = sys::jail::terminate_in(jail, Duration::from_secs(u64::from(wait.seconds)))?;

  Ok(move || terminating.wait())
}

/// Drops the jail's TCP connections. A VNET jail has its own stack, so only
/// a tcpdrop(8) run inside it, if it has one, reaches them. A jail on the
/// guest's stack has its connections listed by netstat(1)'s `-j` and
/// dropped one by one from the guest.
pub(crate) fn drop_connections(name: &str) -> io::Result<()> {
  let (jail, _) = sys::jail::find_jail(name)?;

  if sys::jail::has_vnet(jail)? {
    let mut tcpdrop = quiet("/usr/sbin/tcpdrop", &["-a"]);
    sys::exec::enter_on_exec(
      &mut tcpdrop,
      sys::exec::Entry {
        jail: Some(jail),
        limits: Vec::new(),
        umask: None,
        ids: None,
        cwd: None,
      },
    )?;
    // A jail without tcpdrop leaves its connections to time out.
    let _ = tcpdrop.status();
    return Ok(());
  }

  let listed = quiet("/usr/bin/netstat", &["-j", name, "-n", "-p", "tcp", "-a"])
    .stdout(Stdio::piped())
    .output()?;
  if !listed.status.success() {
    return Err(io::Error::other(format!("netstat exited with {}", listed.status)));
  }
  for connection in connections(&String::from_utf8_lossy(&listed.stdout)) {
    // A connection that closed since netstat listed it can't be dropped.
    let _ = quiet("/usr/sbin/tcpdrop", &connection.each_ref().map(String::as_str)).status();
  }
  Ok(())
}

/// A command for `program` with `args` and no input or output.
fn quiet(program: &str, args: &[&str]) -> Command {
  let mut command = Command::new(program);
  command
    .args(args)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
  command
}

/// The TCP connections, other than listeners, in netstat(1)'s `-n -p tcp -a`
/// table, each as tcpdrop(8)'s four arguments.
fn connections(table: &str) -> Vec<[String; 4]> {
  table
    .lines()
    .skip(2)
    .filter_map(|line| {
      let fields: Vec<&str> = line.split_whitespace().collect();
      let [_, _, _, local, foreign, state, ..] = fields.as_slice() else {
        return None;
      };
      if *state == "LISTEN" {
        return None;
      }
      let (local, local_port) = local.rsplit_once('.')?;
      let (foreign, foreign_port) = foreign.rsplit_once('.')?;
      Some([local, local_port, foreign, foreign_port].map(str::to_string))
    })
    .collect()
}

/// Waits for the removed jail to finish dying, checking every `POLL`.
pub(crate) fn await_removal(wait: &message::JailWait) -> io::Result<()> {
  let deadline = Instant::now() + Duration::from_secs(u64::from(wait.seconds));

  while sys::jail::jail_remains(&wait.jail)? {
    if Instant::now() >= deadline {
      return Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("it was still dying after {}s", wait.seconds),
      ));
    }
    std::thread::sleep(POLL);
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reads_what_rctl_says_a_jail_uses() {
    let reported = "cputime=12,datasize=397312,stacksize=0,coredumpsize=0,memoryuse=7835648,\
                    memorylocked=0,maxproc=3,openfiles=118,vmemoryuse=48873472,pseudoterminals=0,\
                    swapuse=0,nthr=4,msgqqueued=0,msgqsize=0,nmsgq=0,nsem=0,nsemop=0,nshm=0,\
                    shmsize=0,wallclock=31,pcpu=7,readbps=4096,writebps=512,readiops=2,writeiops=1";

    assert_eq!(
      usage(reported).unwrap(),
      message::Statistics {
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
        ..message::Statistics::default()
      }
    );
    assert!(usage("cputime=12").is_err());
  }

  #[test]
  fn lists_the_connections_tcpdrop_can_drop() {
    let table = "\
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0      0 10.66.0.2.22           10.66.0.1.50000        ESTABLISHED
tcp6       0      0 ::1.8080               ::1.40000              TIME_WAIT
tcp4       0      0 *.22                   *.*                    LISTEN
";

    assert_eq!(
      connections(table),
      [
        ["10.66.0.2", "22", "10.66.0.1", "50000"].map(str::to_string),
        ["::1", "8080", "::1", "40000"].map(str::to_string),
      ]
    );
  }
}
