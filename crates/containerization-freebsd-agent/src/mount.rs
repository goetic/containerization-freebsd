//! File systems mounted in the guest and in jails, and ZFS datasets.

use crate::sys;
use containerization_freebsd_protocol::Mount;
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

/// How many symlinks resolving one path may follow, as many as FreeBSD's
/// MAXSYMLINKS.
const SYMLINKS: usize = 32;

/// Mounts what `mounting` describes, creating missing directories at its
/// destination. A destination in a jail resolves within the jail's root,
/// from the guest, since the jail can't mount.
pub(crate) fn mount(mounting: &Mount) -> io::Result<()> {
  let destination = &mounting.destination;
  let point = match &destination.jail {
    Some(jail) => {
      let (_, root) = sys::find_jail(jail)?;
      mount_point(&root, &destination.path)?
    }
    None => PathBuf::from(&destination.path),
  };

  std::fs::create_dir_all(&point)?;
  sys::mount(&mounting.kind, &mounting.source, &point, &mounting.options)
}

/// Resolves `path` in the jail rooted at `root` as `resolve` does, refusing
/// the root itself.
fn mount_point(root: &Path, path: &str) -> io::Result<PathBuf> {
  let point = resolve(root, path)?;

  if point == root {
    return Err(io::Error::new(io::ErrorKind::InvalidInput, "that is the jail's root"));
  }
  Ok(point)
}

/// Resolves `path` in the tree rooted at `root`, such as a jail's, and
/// returns its guest path. Symlinks resolve within the root, as under
/// chroot(2): absolute targets start at the root, and `..` stops there.
/// Resolving from the guest is safe only while nothing in the tree can swap a
/// directory on the path for a symlink.
pub(crate) fn resolve(root: &Path, path: &str) -> io::Result<PathBuf> {
  // The components still to resolve, the next one last.
  let mut rest = Vec::new();
  push(&mut rest, Path::new(path));
  let mut resolved = PathBuf::new();
  let mut links = 0;

  while let Some(part) = rest.pop() {
    if part == ".." {
      resolved.pop();
      continue;
    }
    let here = root.join(&resolved).join(&part);
    match std::fs::symlink_metadata(&here) {
      Ok(metadata) if metadata.file_type().is_symlink() => {
        links += 1;
        if links > SYMLINKS {
          return Err(io::Error::other("too many symbolic links"));
        }
        let target = std::fs::read_link(&here)?;
        if target.has_root() {
          resolved.clear();
        }
        push(&mut rest, &target);
      }
      _ => resolved.push(part),
    }
  }
  Ok(root.join(resolved))
}

/// Pushes the names and `..`s along `path` onto `rest`, the first one last.
fn push(rest: &mut Vec<OsString>, path: &Path) {
  let start = rest.len();

  rest.extend(path.components().filter_map(|component| match component {
    Component::Normal(name) => Some(name.to_os_string()),
    Component::ParentDir => Some("..".into()),
    Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
  }));
  rest[start..].reverse();
}

/// Unmounts every file system mounted under `path`, except ZFS datasets, the
/// most recently mounted first. A failure doesn't stop the rest; the first
/// one is returned.
pub(crate) fn unmount_under(path: &str) -> io::Result<()> {
  let under = Path::new(path);
  let mut failed = None;

  for mounted in sys::mounts()?.iter().rev() {
    if mounted.kind == "zfs" || mounted.point == under || !mounted.point.starts_with(under) {
      continue;
    }
    if let Err(error) = sys::unmount(&mounted.point) {
      failed.get_or_insert_with(|| io::Error::new(error.kind(), format!("{}: {error}", mounted.point.display())));
    }
  }
  failed.map_or(Ok(()), Err)
}

/// Creates `dataset` and any missing parents, makes sure ZFS mounts it, and
/// returns where. A dataset whose mountpoint is `none` or `legacy` gets
/// `/<dataset>`. A dataset that is already mounted needs no zfs(8) at all.
pub(crate) fn mount_dataset(dataset: &str) -> io::Result<String> {
  let mounted = sys::mounts()?
    .into_iter()
    .find(|mounted| mounted.kind == "zfs" && mounted.source == dataset);
  if let Some(mounted) = mounted {
    return Ok(mounted.point.to_string_lossy().into_owned());
  }

  zfs(&["create", "-p", dataset])?;
  let point = zfs(&["get", "-H", "-o", "value", "mountpoint", dataset])?;
  if point != "none" && point != "legacy" {
    return Ok(point);
  }
  let point = format!("/{dataset}");
  zfs(&["set", &format!("mountpoint={point}"), dataset])?;
  Ok(point)
}

/// Runs zfs(8) with `args`, and returns its output less the final newline.
fn zfs(args: &[&str]) -> io::Result<String> {
  let output = Command::new("/sbin/zfs")
    .args(args)
    .stdin(Stdio::null())
    .output()?;

  if !output.status.success() {
    return Err(io::Error::other(format!(
      "zfs {} exited with {}: {}",
      args.join(" "),
      output.status,
      String::from_utf8_lossy(&output.stderr).trim_end()
    )));
  }
  Ok(
    String::from_utf8_lossy(&output.stdout)
      .trim_end()
      .to_string(),
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::os::unix::fs::symlink;

  #[test]
  fn resolves_a_mount_point_as_the_jail_would() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::create_dir_all(root.join("srv/data")).unwrap();
    symlink("/srv", root.join("absolute")).unwrap();
    symlink("srv/data", root.join("relative")).unwrap();
    symlink("../../../..", root.join("srv/up")).unwrap();

    assert_eq!(resolve(root, "/absolute/data").unwrap(), root.join("srv/data"));
    assert_eq!(
      resolve(root, "relative/new/./dir").unwrap(),
      root.join("srv/data/new/dir")
    );
    assert_eq!(resolve(root, "/srv/up/../srv/up/srv").unwrap(), root.join("srv"));
  }

  #[test]
  fn refuses_a_mount_point_it_cannot_resolve() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    symlink("loop", root.join("loop")).unwrap();

    let error = |path| mount_point(root, path).unwrap_err().to_string();
    assert_eq!(error("/loop"), "too many symbolic links");
    assert_eq!(error("/srv/.."), "that is the jail's root");
    assert_eq!(error("/"), "that is the jail's root");
    assert_eq!(resolve(root, "/srv/..").unwrap(), root);
  }
}
