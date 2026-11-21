//! File systems mounted into jails.

use super::{Jail, QUICK};
use crate::error::Result;
use crate::scripts;

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
  /// for a symlink between resolution and mount(8).
  pub fn mount(&self, mount: &Mount) -> Result<()> {
    let root = self.root()?;
    let resolved = self
      .agent
      .check(&scripts::RESOLVE.argv(&[&root, &mount.destination]), QUICK)?
      .stdout;
    let point = resolved.strip_suffix('\n').unwrap_or(&resolved);
    let options = mount.options.join(",");
    let mut argv = vec!["mount", "-t", mount.kind.as_str()];
    if !options.is_empty() {
      argv.extend(["-o", options.as_str()]);
    }
    argv.extend([mount.source.as_str(), point]);

    self.agent.check(&argv, QUICK).map(|_| ())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::os::unix::fs::symlink;
  use std::path::Path;
  use std::process::Command;

  /// Runs `scripts::RESOLVE` on `path` in `root` with the host's sh, and
  /// returns its stdout or stderr.
  fn resolve(root: &Path, path: &str) -> std::result::Result<String, String> {
    let argv = scripts::RESOLVE.argv(&[root.to_str().unwrap(), path]);
    let output = Command::new(argv[0]).args(&argv[1..]).output().unwrap();

    if output.status.success() {
      Ok(String::from_utf8(output.stdout).unwrap())
    } else {
      Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
  }

  #[test]
  fn resolves_a_mount_point_as_the_jail_would() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::create_dir_all(root.join("srv/data")).unwrap();
    symlink("/srv", root.join("absolute")).unwrap();
    symlink("srv/data", root.join("relative")).unwrap();
    symlink("../../../..", root.join("srv/up")).unwrap();
    let inside = |path: &str| Ok(format!("{}{path}\n", root.display()));

    assert_eq!(resolve(root, "/absolute/data"), inside("/srv/data"));
    assert_eq!(resolve(root, "relative/new/./dir"), inside("/srv/data/new/dir"));
    assert!(root.join("srv/data/new/dir").is_dir());
    assert_eq!(resolve(root, "/srv/up/../srv/up/srv"), inside("/srv"));
  }

  #[test]
  fn refuses_a_mount_point_it_cannot_resolve() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    symlink("loop", root.join("loop")).unwrap();
    std::fs::write(root.join("file"), "").unwrap();

    assert!(
      resolve(root, "/loop")
        .unwrap_err()
        .contains("too many symbolic links")
    );
    assert!(
      resolve(root, "/srv/..")
        .unwrap_err()
        .contains("the jail's root")
    );
    assert!(resolve(root, "/file/under").is_err());
  }
}
