//! ZFS pools, datasets, snapshots and clones in the guest, via the agent.
//! Names are passed as argv, never through a shell.

use crate::agent::{Agent, QUICK, Spawn};
use crate::error::{Error, Result};
use std::collections::HashSet;
use std::time::Duration;

/// Extracting a base system from a share takes about a minute.
const EXTRACTING: Duration = Duration::from_secs(600);

pub struct Zfs<'a> {
  agent: &'a Agent,
}

impl<'a> Zfs<'a> {
  pub fn new(agent: &'a Agent) -> Self {
    Self { agent }
  }

  /// Creates a pool on `device`, mounted at `/<pool>`, with `compression=lz4`
  /// and `atime=off`.
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

  /// Force-imports a pool, which may have been last imported by another
  /// machine, such as one on a disk the caller keeps across machines.
  pub fn import_pool(&self, pool: &str) -> Result<()> {
    self.check(&["zpool", "import", "-f", pool], QUICK)
  }

  /// Whether `pool` is imported.
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

  /// Creates `dataset` if needed, ensures ZFS mounts it, and returns the
  /// directory it is mounted at. A dataset whose mountpoint is `none` or
  /// `legacy`, as under the pool of FreeBSD's VM image, gets `/<dataset>`,
  /// which its children inherit.
  pub fn create_mounted(&self, dataset: &str) -> Result<String> {
    self.agent.mount_dataset(dataset)
  }

  /// `snapshot` is `<dataset>@<name>`.
  pub fn snapshot(&self, snapshot: &str) -> Result<()> {
    self.check(&["zfs", "snapshot", snapshot], QUICK)
  }

  /// Clones `snapshot` to `dataset`, creating missing parents.
  pub fn clone(&self, snapshot: &str, dataset: &str) -> Result<()> {
    self.check(&["zfs", "clone", "-p", snapshot, dataset], QUICK)
  }

  /// Destroys a dataset and its descendants, or a snapshot. Fails if a clone
  /// depends on it, since `-r` doesn't destroy dependents.
  pub fn destroy(&self, name: &str) -> Result<()> {
    self.check(&["zfs", "destroy", "-r", name], QUICK)
  }

  /// The full names of `dataset`, its snapshots, and the filesystems and
  /// snapshots under it.
  fn names_under(&self, dataset: &str) -> Result<Vec<String>> {
    let ran = self.agent.check(
      &[
        "zfs",
        "list",
        "-H",
        "-o",
        "name",
        "-t",
        "filesystem,snapshot",
        "-r",
        dataset,
      ],
      QUICK,
    )?;

    Ok(ran.lines().into_iter().map(str::to_string).collect())
  }

  /// The full names of the filesystems directly under `dataset`.
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

  /// The directory that `dataset`'s `mountpoint` property names. Fails if
  /// the property is `none` or `legacy`, since ZFS then doesn't mount the
  /// dataset.
  pub fn mountpoint(&self, dataset: &str) -> Result<String> {
    mounted_at(dataset, &self.mountpoint_property(dataset)?)
  }

  fn mountpoint_property(&self, dataset: &str) -> Result<String> {
    let ran = self
      .agent
      .check(&["zfs", "get", "-H", "-o", "value", "mountpoint", dataset], QUICK)?;

    Ok(ran.stdout.trim().to_string())
  }

  /// Extracts `archive`, a guest path such as the userland on a share, into
  /// `dataset`'s mountpoint.
  pub fn extract(&self, archive: &str, dataset: &str) -> Result<()> {
    let mountpoint = self.mountpoint(dataset)?;

    self.check(&["tar", "-xf", archive, "-C", &mountpoint], EXTRACTING)
  }

  fn check(&self, argv: &[&str], timeout: Duration) -> Result<()> {
    self.agent.check(argv, timeout).map(|_| ())
  }

  fn succeeds(&self, argv: &[&str]) -> Result<bool> {
    Ok(self.agent.run(argv, QUICK)?.exit.success())
  }
}

/// Datasets under `store`, each a clone of the snapshot below it, or a new
/// dataset at the bottom, and snapshotted as `<dataset>@<tag>` once filled.
/// A dataset's name says what fills it, so an existing snapshot is reused
/// rather than filled again. Builds and unpacked image layers are such
/// chains. Two chains in one store must not be filled concurrently.
pub(crate) struct SnapshotChain<'a> {
  zfs: &'a Zfs<'a>,
  store: &'a str,
  tag: &'static str,
  /// Where the store is mounted. Each dataset inherits a mountpoint under it.
  mountpoint: String,
  /// The datasets and snapshots that were in the store when the chain was
  /// opened.
  existing: HashSet<String>,
}

/// Whether `SnapshotChain::link` reused an existing snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cache {
  Hit,
  Miss,
}

impl<'a> SnapshotChain<'a> {
  /// Creates and mounts `store` if needed, and notes the datasets and
  /// snapshots already in it, so that no link needs to ask the guest.
  pub(crate) fn open(zfs: &'a Zfs<'a>, store: &'a str, tag: &'static str) -> Result<Self> {
    let mountpoint = zfs.create_mounted(store)?;
    let existing = zfs.names_under(store)?.into_iter().collect();

    Ok(Self {
      zfs,
      store,
      tag,
      mountpoint,
      existing,
    })
  }

  /// Where the store is mounted.
  pub(crate) fn mountpoint(&self) -> &str {
    &self.mountpoint
  }

  /// The snapshot of `<store>/<name>`, on top of the snapshot `below`. If it
  /// didn't exist when the chain was opened, makes the dataset, runs `fill`
  /// with the dataset and the directory it is mounted at, and snapshots it;
  /// if `fill` fails, the dataset is destroyed.
  pub(crate) fn link(
    &self,
    below: Option<&str>,
    name: &str,
    fill: impl FnOnce(&str, &str) -> Result<()>,
  ) -> Result<(String, Cache)> {
    let dataset = format!("{}/{name}", self.store);
    let snapshot = format!("{dataset}@{}", self.tag);
    if self.existing.contains(&snapshot) {
      return Ok((snapshot, Cache::Hit));
    }

    // An earlier attempt that failed without cleaning up, such as when the
    // guest stopped, can leave the dataset behind.
    if self.existing.contains(&dataset) {
      self.zfs.destroy(&dataset)?;
    }
    match below {
      Some(below) => self.zfs.clone(below, &dataset)?,
      None => self.zfs.create(&dataset)?,
    }
    let root = format!("{}/{name}", self.mountpoint.trim_end_matches('/'));
    fill(&dataset, &root).inspect_err(|_| {
      let _ = self.zfs.destroy(&dataset);
    })?;
    self.zfs.snapshot(&snapshot)?;
    Ok((snapshot, Cache::Miss))
  }
}

/// The directory `dataset` is mounted at, given its `mountpoint` property
/// `value`.
fn mounted_at(dataset: &str, value: &str) -> Result<String> {
  if unmounted(value) {
    return Err(Error::Invalid(format!(
      "{dataset} has mountpoint={value}, so ZFS doesn't mount it: give it, or a dataset it is under, a mountpoint"
    )));
  }
  Ok(value.to_string())
}

/// Whether a `mountpoint` value means ZFS doesn't mount the dataset.
fn unmounted(value: &str) -> bool {
  matches!(value, "none" | "legacy")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn refuses_a_mountpoint_zfs_does_not_mount() {
    for value in ["none", "legacy"] {
      let result = mounted_at("zroot/cfbsd", value);

      assert!(
        matches!(&result, Err(Error::Invalid(message)) if message.starts_with(&format!("zroot/cfbsd has mountpoint={value},"))),
        "{result:?}"
      );
    }
    assert_eq!(mounted_at("images/jails", "/images/jails").unwrap(), "/images/jails");
  }
}
