//! A guest's first boot from FreeBSD's VM image: what makes a base that
//! later machines clone or restore.

use crate::error::{Error, Result};
use crate::image;
use crate::machine::{LOADER_ENV, Layout};
use std::path::Path;
use std::time::Duration;

/// The seed volume's user-data, which nuageinit runs on the first boot.
const FIRST_BOOT: &str = include_str!("../../../guest/first-boot.sh");
/// The guest bundle's name on the seed volume, where `FIRST_BOOT` finds it.
const BUNDLE: &str = "bundle.tar.xz";
/// A first boot that upgrades reboots once, and the agent starts again.
const BOOTS: usize = 3;

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
/// with a seed volume that installs `bundle` (the guest bundle: the agent and
/// the virtiofs modules), waits for the first boot to finish, and powers it
/// off. The layout boots the prepared disk again; it has no seed or network.
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

/// Waits for rc to delete /firstboot, which it does only when it finishes,
/// after the seed's script starts the agent, and then reboots if the package
/// upgrade installed anything. Powered off sooner, the next boot is a first
/// boot again.
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
