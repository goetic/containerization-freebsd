//! Manages ZFS pools, datasets, snapshots, and clones in the guest through
//! the guest agent. Names are passed as arguments, never through a shell.

use crate::agent::Agent;
use crate::error::Result;
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);
/// Extracting a base system from a share takes about a minute.
const EXTRACTING: Duration = Duration::from_secs(600);

pub struct Zfs<'a> {
  agent: &'a Agent,
}

impl<'a> Zfs<'a> {
  pub fn new(agent: &'a Agent) -> Self {
    Self { agent }
  }

  /// Creates a pool on `device`, mounted at `/<pool>`, with lz4 compression
  /// and access times off.
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

  /// Imports a pool that another machine created or used, such as one on a
  /// disk the caller keeps across machines.
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

  /// Creates `dataset` and any missing parents.
  pub fn create(&self, dataset: &str) -> Result<()> {
    self.check(&["zfs", "create", "-p", dataset], QUICK)
  }

  /// Creates `dataset` if it does not exist, and makes sure it is mounted.
  /// If it would inherit no mountpoint, as datasets under the pool of
  /// FreeBSD's VM image do, it is mounted at `/<dataset>`. Its children
  /// inherit the mountpoint.
  pub fn create_mounted(&self, dataset: &str) -> Result<()> {
    if !self.exists(dataset)? {
      self.create(dataset)?;
    }
    if unmounted(&self.mountpoint(dataset)?) {
      self.check(&["zfs", "set", &format!("mountpoint=/{dataset}"), dataset], QUICK)?;
    }
    Ok(())
  }

  /// Creates the snapshot `snapshot`, named `<dataset>@<name>`.
  pub fn snapshot(&self, snapshot: &str) -> Result<()> {
    self.check(&["zfs", "snapshot", snapshot], QUICK)
  }

  /// Creates `dataset` as a writable clone of `snapshot` that shares its
  /// blocks.
  pub fn clone(&self, snapshot: &str, dataset: &str) -> Result<()> {
    self.check(&["zfs", "clone", "-p", snapshot, dataset], QUICK)
  }

  /// Destroys a dataset and its descendants, or a snapshot. Fails if a clone
  /// depends on what would be destroyed.
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

  /// Returns `dataset`'s `mountpoint` property, which may be `none` or
  /// `legacy`.
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

/// Whether a `mountpoint` property value means ZFS does not mount the
/// dataset.
pub(crate) fn unmounted(mountpoint: &str) -> bool {
  matches!(mountpoint, "none" | "legacy")
}
