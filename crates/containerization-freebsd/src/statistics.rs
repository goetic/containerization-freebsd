//! A jail's resource usage, like Containerization's container statistics:
//! racct counters from rctl(8), which needs the `kern.racct.enable` tunable
//! that `prepare` writes to the disk's `loader.env`; network counters from
//! netstat(1); and a container's block IO from ZFS kstats.

use crate::error::{Error, Result};
use std::collections::HashMap;

/// A jail's resource usage, like Containerization's `ContainerStatistics`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
  pub cpu_seconds: u64,
  /// Recent CPU usage, in percent of one core.
  pub cpu_percent: u64,
  /// Resident memory, in bytes.
  pub memory: u64,
  pub processes: u64,
  pub threads: u64,
  pub open_files: u64,
  /// Recent file system reads and writes per second.
  pub read_bytes_per_second: u64,
  pub write_bytes_per_second: u64,
  pub read_operations_per_second: u64,
  pub write_operations_per_second: u64,
  /// The interfaces, loopback included, of a VNET jail. Empty for a jail on
  /// the guest's stack, whose counters belong to the guest.
  pub networks: Vec<NetworkStatistics>,
  /// A container's dataset IO, in place of Containerization's block
  /// devices, since FreeBSD doesn't count block IO per jail. Empty for a
  /// plain jail.
  pub block_io: Vec<DatasetIo>,
}

/// Counters since the interface was created.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkStatistics {
  pub interface: String,
  pub received_packets: u64,
  pub transmitted_packets: u64,
  pub received_bytes: u64,
  pub transmitted_bytes: u64,
  pub received_errors: u64,
  pub transmitted_errors: u64,
  pub received_dropped: u64,
  pub transmitted_dropped: u64,
}

/// A dataset's objset kstats since it was mounted, which count reads served
/// from the ARC.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DatasetIo {
  pub dataset: String,
  pub read_bytes: u64,
  pub write_bytes: u64,
  pub read_operations: u64,
  pub write_operations: u64,
}

/// Parses what `scripts::STATISTICS` prints for a jail, with the counters
/// of `dataset` if one is given.
pub(crate) fn parse(output: &str, dataset: Option<&str>) -> Result<Statistics> {
  let parts: Vec<&str> = output.split("%%\n").collect();
  let [usage, interfaces, counters, ..] = parts.as_slice() else {
    return Err(Error::Guest(format!("the statistics script printed {output:?}")));
  };
  let mut statistics = rctl_usage(usage)?;
  statistics.networks = networks(interfaces)?;
  if let Some(dataset) = dataset {
    statistics.block_io = vec![dataset_io(dataset, counters)?];
  }

  Ok(statistics)
}

/// Parses the output of `rctl -u`.
fn rctl_usage(usage: &str) -> Result<Statistics> {
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
    networks: Vec::new(),
    block_io: Vec::new(),
  })
}

/// Parses the `<Link#n>` rows of netstat's interface table, finding columns
/// by header name.
fn networks(table: &str) -> Result<Vec<NetworkStatistics>> {
  let unreadable = || Error::Guest(format!("netstat printed {table:?}"));
  let mut lines = table.lines();
  let Some(header) = lines.next() else {
    return Ok(Vec::new());
  };
  let columns: Vec<&str> = header.split_whitespace().collect();
  let column = |name: &str| {
    columns
      .iter()
      .position(|column| *column == name)
      .ok_or_else(unreadable)
  };
  let network = column("Network")?;

  lines
    .map(|line| line.split_whitespace().collect::<Vec<_>>())
    .filter(|fields| {
      fields
        .get(network)
        .is_some_and(|field| field.starts_with("<Link#"))
    })
    .map(|fields| {
      if fields.len() != columns.len() {
        return Err(unreadable());
      }
      let value = |name: &str| -> Result<u64> { fields[column(name)?].parse().map_err(|_| unreadable()) };

      Ok(NetworkStatistics {
        interface: fields[column("Name")?].to_string(),
        received_packets: value("Ipkts")?,
        transmitted_packets: value("Opkts")?,
        received_bytes: value("Ibytes")?,
        transmitted_bytes: value("Obytes")?,
        received_errors: value("Ierrs")?,
        transmitted_errors: value("Oerrs")?,
        received_dropped: value("Idrop")?,
        transmitted_dropped: value("Drop")?,
      })
    })
    .collect()
}

/// Parses the counters of `dataset`, one to a line.
fn dataset_io(dataset: &str, counters: &str) -> Result<DatasetIo> {
  let values = counters
    .lines()
    .map(|line| line.trim().parse().ok())
    .collect::<Option<Vec<u64>>>();
  let Some([reads, read, writes, written]) = values.as_deref() else {
    return Err(Error::Guest(format!("ZFS counted {counters:?} for {dataset}")));
  };

  Ok(DatasetIo {
    dataset: dataset.to_string(),
    read_bytes: *read,
    write_bytes: *written,
    read_operations: *reads,
    write_operations: *writes,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reads_what_rctl_says_a_jail_uses() {
    let usage = "cputime=12\ndatasize=397312\nstacksize=0\ncoredumpsize=0\nmemoryuse=7835648\n\
                 memorylocked=0\nmaxproc=3\nopenfiles=118\nvmemoryuse=48873472\npseudoterminals=0\n\
                 swapuse=0\nnthr=4\nmsgqqueued=0\nmsgqsize=0\nnmsgq=0\nnsem=0\nnsemop=0\nnshm=0\n\
                 shmsize=0\nwallclock=31\npcpu=7\nreadbps=4096\nwritebps=512\nreadiops=2\nwriteiops=1\n";

    assert_eq!(
      rctl_usage(usage).unwrap(),
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
        ..Statistics::default()
      }
    );
    assert!(rctl_usage("cputime=12\n").is_err());
  }

  #[test]
  fn reads_netstats_link_rows() {
    let table = "\
Name      Mtu Network       Address              Ipkts Ierrs Idrop     Ibytes    Opkts Oerrs     Obytes  Coll  Drop
lo0     16384 <Link#1>      lo0                     12     0     0        840       12     0        840     0     0
lo0         - 127.0.0.0/8   127.0.0.1               12     -     -        840       12     -        840     -     -
epair0b  1500 <Link#2>      02:6d:2e:1f:a4:0b      104     1     2      14210       98     3      10324     0     4
epair0b     - 10.66.0.0/16  10.66.0.2               40     -     -       3200       38     -       2900     -     -
";

    assert_eq!(
      networks(table).unwrap(),
      [
        NetworkStatistics {
          interface: "lo0".into(),
          received_packets: 12,
          transmitted_packets: 12,
          received_bytes: 840,
          transmitted_bytes: 840,
          ..NetworkStatistics::default()
        },
        NetworkStatistics {
          interface: "epair0b".into(),
          received_packets: 104,
          transmitted_packets: 98,
          received_bytes: 14210,
          transmitted_bytes: 10324,
          received_errors: 1,
          transmitted_errors: 3,
          received_dropped: 2,
          transmitted_dropped: 4,
        },
      ]
    );
    assert_eq!(networks("").unwrap(), []);
    assert!(networks("Name Network Ipkts\nlo0 <Link#1>\n").is_err());
  }

  #[test]
  fn reads_a_datasets_counters() {
    assert_eq!(
      dataset_io("zroot/c/web", "7\n4096\n3\n512\n").unwrap(),
      DatasetIo {
        dataset: "zroot/c/web".into(),
        read_bytes: 4096,
        write_bytes: 512,
        read_operations: 7,
        write_operations: 3,
      }
    );
    assert!(dataset_io("zroot/c/web", "7\n4096\n").is_err());
  }

  #[test]
  fn reads_each_part_of_what_the_script_prints() {
    let usage = "cputime=1\nmemoryuse=2\nmaxproc=3\nnthr=4\nopenfiles=5\npcpu=6\nreadbps=7\nwritebps=8\n\
                 readiops=9\nwriteiops=10\n";

    let container = parse(&format!("{usage}%%\n%%\n7\n4096\n3\n512\n%%\n"), Some("zroot/c/web")).unwrap();
    let jail = parse(&format!("{usage}%%\n%%\n%%\n"), None).unwrap();

    assert_eq!(container.processes, 3);
    assert!(container.networks.is_empty());
    assert_eq!(container.block_io[0].read_bytes, 4096);
    assert!(jail.block_io.is_empty());
    assert!(parse(usage, None).is_err());
  }
}
