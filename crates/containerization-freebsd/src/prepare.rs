//! Runs a guest's first boot from FreeBSD's VM image. The result is the base
//! disk that later machines clone or restore.

use crate::error::{Error, Result};
use crate::image;
use crate::machine::{LOADER_ENV, Layout};
use std::path::Path;
use std::time::Duration;

/// The seed volume's user-data, which nuageinit runs on the first boot.
const FIRST_BOOT: &str = include_str!("../../../guest/first-boot.sh");
/// The guest bundle's name on the seed volume, where `FIRST_BOOT` finds it.
const BUNDLE: &str = "bundle.tar.xz";
/// The most boots to wait through. A first boot that upgrades reboots once,
/// and the agent then starts again.
const BOOTS: usize = 3;

/// What a guest's first boot brings up to date.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Upgrade {
  /// The first boot has NAT, upgrades to the release's latest patches, and
  /// reboots if that installed anything. This takes minutes.
  Latest,
  /// The first boot has no network and keeps the image as released. This
  /// takes seconds.
  None,
}

/// Clones `base` into `directory` as a disk of `size` bytes, boots it once
/// with a seed volume that installs `bundle` (the agent and the virtiofs
/// modules), waits for the first boot to finish, and powers the machine off.
/// The returned layout boots the prepared disk without a seed or network.
pub fn prepare(base: &Path, directory: &Path, size: u64, upgrade: Upgrade, bundle: &Path) -> Result<Layout> {
  std::fs::create_dir_all(directory).map_err(Error::io(format!("making {}", directory.display())))?;

  let disk = directory.join("disk.raw");
  image::clone(base, &disk, size)?;
  image::write_loader_env(&disk, &directory.join("esp"), LOADER_ENV)?;

  let iso = directory.join("seed.iso");
  let staging = directory.join("seed");
  seed(directory, &staging, &iso, bundle)?;

  let mut layout = Layout::first(directory, disk)?;
  layout.nat = upgrade == Upgrade::Latest;
  layout.seed = Some(iso.clone());

  let machine = layout.machine("containerization-freebsd-prepare")?;
  machine.start()?;
  wait_first_boot(&machine)?;
  machine.shut_down(Duration::from_secs(120))?;
  drop(machine);

  let _ = std::fs::remove_dir_all(&staging);
  let _ = std::fs::remove_file(&iso);
  layout.nat = false;
  layout.seed = None;

  Ok(layout)
}

/// Waits for rc to delete /firstboot. rc deletes it only after the first boot
/// finishes: the seed's script has started the agent, and the system has
/// rebooted if the upgrade installed anything. A machine powered off sooner
/// runs a first boot again on its next boot.
fn wait_first_boot(machine: &crate::Machine) -> Result<()> {
  let wait = ["sh", "-c", "while [ -e /firstboot ]; do sleep 1; done"];

  for _ in 0..BOOTS {
    machine.wait_ready(Duration::from_secs(600))?;
    match machine.agent.check(&wait, Duration::from_secs(900)) {
      Ok(_) => return Ok(()),
      // The upgrade's reboot.
      Err(Error::SessionEnded(_)) => {}
      Err(error) => return Err(error),
    }
  }
  Err(Error::Guest(format!(
    "the first boot did not finish within {BOOTS} boots"
  )))
}

fn seed(directory: &Path, staging: &Path, iso: &Path, bundle: &Path) -> Result<()> {
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

  let result = image::seed(
    staging,
    iso,
    &[("meta-data", &meta), ("user-data", &user), (BUNDLE, bundle)],
  );
  let _ = std::fs::remove_file(&meta);
  let _ = std::fs::remove_file(&user);
  result
}
