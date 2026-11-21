//! A guest's first boot from FreeBSD's VM image, producing the base disk that
//! later machines clone or restore.

use crate::Machine;
use crate::error::{Error, Result};
use crate::image;
use crate::machine::{LOADER_ENV, Layout};
use crate::scripts;
use std::path::Path;
use std::time::{Duration, Instant};
use virtualization::VirtualMachineState;

/// The NoCloud seed's user-data, which nuageinit runs on the first boot.
const FIRST_BOOT: &str = include_str!("../../../guest/first-boot.sh");
/// The guest bundle's file name on the seed, where `FIRST_BOOT` expects it.
const BUNDLE: &str = "bundle.tar.xz";
/// The most boots to wait through. A first boot that upgrades reboots once,
/// and the agent then starts again.
const BOOTS: usize = 3;
/// The longest a power-off may take, or, if the guest reboots instead, its
/// boot up to the agent's session.
const POWER_OFF: Duration = Duration::from_secs(600);

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

/// Clones `base` into `directory` as a `size`-byte disk, writes `LOADER_ENV`,
/// boots it once with a seed that installs `bundle` (the agent and the
/// patched virtiofs modules), waits for the first boot to finish, and powers
/// off. The returned layout boots the prepared disk without seed or NAT.
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
  power_off(&machine)?;
  drop(machine);

  let _ = std::fs::remove_dir_all(&staging);
  let _ = std::fs::remove_file(&iso);
  layout.nat = false;
  layout.seed = None;

  Ok(layout)
}

/// Waits for rc to delete /firstboot, which it does at the end of the first
/// boot, after the seed's script has started the agent; a machine powered off
/// sooner repeats the first boot. If an upgrade requested a reboot
/// (/firstboot-reboot), rc deletes /firstboot and then reboots, so the wait
/// can succeed just before that reboot (see `power_off`), or end in
/// `SessionEnded` and succeed on the next boot.
fn wait_first_boot(machine: &Machine) -> Result<()> {
  let wait = scripts::FIRST_BOOT.argv(&[]);

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

/// Powers the guest off, and again if it boots instead. `wait_first_boot` can
/// return just before the upgrade's reboot: rc sends init SIGINT right after
/// deleting /firstboot, and nothing in the guest tells whether it will. If
/// `shutdown -p` reaches init first, or while init is going down, the guest
/// powers off. If the agent or `shutdown` is killed first, the guest reboots
/// and a new session starts.
fn power_off(machine: &Machine) -> Result<()> {
  for _ in 0..BOOTS {
    let sessions = machine.agent.sessions();
    // The reboot may already have ended the agent. A new session or the
    // timeout follows.
    let _ = machine.agent.launch(&["shutdown", "-p", "now"]);
    let started = Instant::now();

    while machine.agent.sessions() == sessions {
      match machine.state() {
        VirtualMachineState::Stopped => return Ok(()),
        VirtualMachineState::Error => return Err(Error::Guest("the machine stopped with an error".to_string())),
        _ => {}
      }
      if started.elapsed() >= POWER_OFF {
        return Err(Error::Timeout(format!(
          "the guest neither powered off nor booted again within {}s",
          POWER_OFF.as_secs()
        )));
      }
      std::thread::sleep(Duration::from_millis(100));
    }
  }
  Err(Error::Guest(format!(
    "the guest did not power off within {BOOTS} boots"
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
