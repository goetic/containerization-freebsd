//! A guest's first boot from FreeBSD's VM image: what makes a base that
//! later machines clone or restore.

use crate::console;
use crate::error::{Error, Result};
use crate::image;
use crate::machine::{LOADER_ENV, Layout};
use std::path::Path;
use std::time::Duration;

/// The seed volume's user-data, which nuageinit runs on the first boot.
const FIRST_BOOT: &str = include_str!("../../../guest/first-boot.sh");
const FIRST_BOOT_DONE: &str = "firstboot-done";

/// What a guest's first boot brings up to date.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Upgrade {
  /// The image's own first boot: over NAT, it upgrades to the release's
  /// latest patches, and reboots if that installed anything. Minutes.
  Latest,
  /// The image as released: the first boot has no network, so nothing to
  /// upgrade. Seconds.
  None,
}

/// Clones `base` into `directory` as a disk of `size` bytes, boots it once
/// with a seed volume that installs the console, waits for the first boot to
/// finish, and powers it off. The layout boots the prepared disk again; it
/// has no seed or network.
pub fn prepare(base: &Path, directory: &Path, size: u64, upgrade: Upgrade) -> Result<Layout> {
  std::fs::create_dir_all(directory).map_err(Error::io(format!("making {}", directory.display())))?;

  let disk = directory.join("disk.raw");
  image::clone(base, &disk, size)?;
  image::write_loader_env(&disk, &directory.join("esp"), LOADER_ENV)?;

  let iso = directory.join("seed.iso");
  let staging = directory.join("seed");
  seed(directory, &staging, &iso)?;

  let mut layout = Layout::first(directory, disk)?;
  layout.nat = upgrade == Upgrade::Latest;
  layout.seed = Some(iso.clone());

  let mut machine = layout.machine("containerization-freebsd-prepare")?;
  machine.start()?;
  machine.wait_ready(Duration::from_secs(600))?;

  // rc deletes /firstboot only when it finishes, after rc.local starts the
  // console, and reboots then if the package upgrade installed anything.
  // Powered off sooner, the next boot is a first boot again.
  machine.console.send(&format!(
    "while [ -e /firstboot ]; do sleep 1; done; echo {FIRST_BOOT_DONE}"
  ))?;
  machine
    .console
    .wait_for_any(&[FIRST_BOOT_DONE, console::READY], Duration::from_secs(900))
    .ok_or_else(|| Error::Timeout("the first boot's rc did not finish within 900s".to_string()))?;
  machine.shut_down(Duration::from_secs(120))?;
  drop(machine);

  let _ = std::fs::remove_dir_all(&staging);
  let _ = std::fs::remove_file(&iso);
  layout.nat = false;
  layout.seed = None;

  Ok(layout)
}

fn seed(directory: &Path, staging: &Path, iso: &Path) -> Result<()> {
  let meta = directory.join("meta-data");
  let user = directory.join("user-data");
  let instance = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map_or(0, |since| since.as_secs());

  std::fs::write(
    &meta,
    format!("instance-id: freebsd-{instance}\nlocal-hostname: freebsd\n"),
  )
  .map_err(Error::io("writing meta-data"))?;
  std::fs::write(&user, FIRST_BOOT).map_err(Error::io("writing user-data"))?;

  let result = image::seed(staging, iso, &[("meta-data", &meta), ("user-data", &user)]);
  let _ = std::fs::remove_file(&meta);
  let _ = std::fs::remove_file(&user);
  result
}
