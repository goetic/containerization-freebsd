//! ZFS in the guest, through its agent: pools, datasets, snapshots and
//! clones. Names are passed as arguments, never through a shell.

use crate::agent::Agent;
use crate::error::Result;
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);
/// Extracting a base system, from a share, takes a minute or so.
const EXTRACTING: Duration = Duration::from_secs(600);

pub struct Zfs<'a> {
  agent: &'a Agent,
}

impl<'a> Zfs<'a> {
  pub fn new(agent: &'a Agent) -> Self {
    Self { agent }
  }

  /// A new pool on `device`, with lz4 compression and no access times,
  /// mounted at `/<pool>`.
  pub fn create_pool(&self, pool: &str, device: &str) -> Result<()> {
    self.check(
      &[
        "zpool",
        "create",
        "-O",
        "compression=lz4",
        "-O",
        "atime=off",
        pool,
        device,
      ],
      QUICK,
    )
  }

  /// Imports a pool another machine made or used, such as one on a disk the
  /// caller keeps across machines.
  pub fn import_pool(&self, pool: &str) -> Result<()> {
    self.check(&["zpool", "import", "-f", pool], QUICK)
  }

  /// Whether a pool is imported.
  pub fn has_pool(&self, pool: &str) -> Result<bool> {
    self.succeeds(&["zpool", "list", "-H", pool])
  }

  /// Whether a dataset or snapshot exists.
  pub fn exists(&self, name: &str) -> Result<bool> {
    self.succeeds(&["zfs", "list", "-H", "-t", "all", name])
  }

  /// Creates `dataset`, and any parents it lacks.
  pub fn create(&self, dataset: &str) -> Result<()> {
    self.check(&["zfs", "create", "-p", dataset], QUICK)
  }

  /// Snapshots `snapshot`, named `<dataset>@<name>`.
  pub fn snapshot(&self, snapshot: &str) -> Result<()> {
    self.check(&["zfs", "snapshot", snapshot], QUICK)
  }

  /// A writable dataset starting as `snapshot`, sharing its blocks.
  pub fn clone(&self, snapshot: &str, dataset: &str) -> Result<()> {
    self.check(&["zfs", "clone", "-p", snapshot, dataset], QUICK)
  }

  /// Destroys a dataset and its snapshots, or a snapshot. Fails if a clone
  /// depends on it.
  pub fn destroy(&self, name: &str) -> Result<()> {
    self.check(&["zfs", "destroy", "-r", name], QUICK)
  }

  /// The full names of the datasets directly under `dataset`.
  pub fn children(&self, dataset: &str) -> Result<Vec<String>> {
    let ran = self.agent.check(
      &[
        "zfs",
        "list",
        "-H",
        "-o",
        "name",
        "-t",
        "filesystem",
        "-r",
        "-d",
        "1",
        dataset,
      ],
      QUICK,
    )?;

    Ok(
      ran
        .lines()
        .into_iter()
        .filter(|name| *name != dataset)
        .map(str::to_string)
        .collect(),
    )
  }

  /// Where `dataset` is mounted.
  pub fn mountpoint(&self, dataset: &str) -> Result<String> {
    let ran = self
      .agent
      .check(&["zfs", "get", "-H", "-o", "value", "mountpoint", dataset], QUICK)?;

    Ok(ran.stdout.trim().to_string())
  }

  /// Extracts `archive`, a path in the guest such as the userland on a
  /// share, into `dataset`.
  pub fn extract(&self, archive: &str, dataset: &str) -> Result<()> {
    let mountpoint = self.mountpoint(dataset)?;

    self.check(&["tar", "-xf", archive, "-C", &mountpoint], EXTRACTING)
  }

  fn check(&self, argv: &[&str], timeout: Duration) -> Result<()> {
    self.agent.check(argv, timeout).map(|_| ())
  }

  fn succeeds(&self, argv: &[&str]) -> Result<bool> {
    Ok(matches!(self.agent.run(argv, QUICK)?.exit, crate::Exit::Code(0)))
  }
}
