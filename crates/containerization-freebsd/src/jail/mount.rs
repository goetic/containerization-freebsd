//! File systems mounted into jails.

use super::Jail;
use crate::error::Result;
use containerization_freebsd_protocol::GuestPath;

/// A file system mounted into a jail, like Containerization's `Mount` for a
/// container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
  /// mount(8)'s `-t`, such as `nullfs` or `tmpfs`.
  pub kind: String,
  /// For nullfs, a guest directory.
  pub source: String,
  /// A path in the jail. Symlinks along it resolve within the jail, and
  /// missing directories are created.
  pub destination: String,
  /// mount(8)'s `-o`, such as `ro`, or tmpfs's `size=64m`.
  pub options: Vec<String>,
}

impl Mount {
  /// A nullfs mount of the guest directory `source` at `destination`.
  /// `source` may be a virtio-fs share mounted by `Machine::mount_share`, or
  /// a directory under one.
  pub fn directory(source: &str, destination: &str) -> Self {
    Self {
      kind: "nullfs".into(),
      source: source.into(),
      destination: destination.into(),
      options: Vec::new(),
    }
  }

  /// A tmpfs at `destination`.
  pub fn tmpfs(destination: &str) -> Self {
    Self {
      kind: "tmpfs".into(),
      source: "tmpfs".into(),
      destination: destination.into(),
      options: Vec::new(),
    }
  }

  pub fn read_only(mut self) -> Self {
    self.options.push("ro".into());
    self
  }
}

impl Jail<'_> {
  /// Mounts `mount` in the jail until `stop`. Mount before anything runs in
  /// the jail: otherwise a jailed process could swap a directory on the path
  /// for a symlink between the agent resolving it and mounting there.
  pub fn mount(&self, mount: &Mount) -> Result<()> {
    self.agent.mount(containerization_freebsd_protocol::Mount {
      kind: mount.kind.clone(),
      source: mount.source.clone(),
      destination: GuestPath {
        path: mount.destination.clone(),
        jail: Some(self.name.clone()),
      },
      options: mount.options.clone(),
    })
  }
}
