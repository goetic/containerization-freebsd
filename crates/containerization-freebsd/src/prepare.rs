//! A guest's first boot from FreeBSD's VM image, producing the base disk that
//! later machines clone or restore.

use crate::Machine;
use crate::agent::FileType;
use crate::error::{Error, Result};
use crate::fat::Volume;
use crate::machine::Layout;
use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};

/// Tunables for `/efi/freebsd/loader.env`. Apple's virtio-net rejects the
/// checksum offload and multiqueue features vtnet(4) negotiates, and vtnet then
/// fails to attach ("desired features were not accepted"); the first two
/// tunables stop it requesting them. `kern.racct.enable` turns on the resource
/// accounting that rctl limits and jail statistics need.
const LOADER_ENV: &str = "hw.vtnet.csum_disable=1\nhw.vtnet.mq_disable=1\nkern.racct.enable=1\n";
/// The NoCloud seed's volume label, which nuageinit looks for.
const SEED_LABEL: [u8; 11] = *b"CIDATA     ";
/// The NoCloud seed's user-data, which nuageinit runs on the first boot.
const USER_DATA: &str = include_str!("scripts/user-data.sh");
/// The guest bundle's file name on the seed, where `USER_DATA` expects it.
const BUNDLE: &str = "bundle.tar.xz";
/// The most boots to wait through for a power-off. A first boot that
/// upgrades reboots once, and the agent then starts again.
const BOOTS: usize = 3;
/// The longest the first boot may take, through an upgrade's reboot.
const FIRST_BOOT: Duration = Duration::from_secs(1800);
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
  clone(base, &disk, size)?;
  write_loader_env(&disk)?;

  let seed = directory.join("seed.img");
  write_seed(&seed, bundle)?;

  let mut layout = Layout::first(directory, disk)?;
  layout.nat = upgrade == Upgrade::Latest;
  layout.seed = Some(seed.clone());

  let machine = layout.machine("containerization-freebsd-prepare")?;
  machine.start()?;
  wait_first_boot(&machine)?;
  power_off(&machine)?;
  drop(machine);

  let _ = std::fs::remove_file(&seed);
  layout.nat = false;
  layout.seed = None;

  Ok(layout)
}

/// Waits for rc to delete /firstboot, which it does at the end of the first
/// boot, after the seed's script has started the agent; a machine powered off
/// sooner repeats the first boot. If an upgrade requested a reboot
/// (/firstboot-reboot), rc deletes /firstboot and then reboots, so the wait
/// can succeed just before that reboot (see `power_off`). Or the reboot
/// takes the agent down before it answers, and the wait succeeds on the next
/// boot.
fn wait_first_boot(machine: &Machine) -> Result<()> {
  let deadline = Instant::now() + FIRST_BOOT;

  loop {
    machine.wait_ready(deadline.saturating_duration_since(Instant::now()))?;
    match machine.agent.file_type("/firstboot") {
      Ok(FileType::Missing) => return Ok(()),
      Ok(_) => {}
      // The upgrade's reboot ended the session, or the agent went down
      // before the next boot's agent could end it.
      Err(
        Error::SessionEnded(_)
        | Error::Timeout(_)
        | Error::Protocol {
          error: containerization_freebsd_protocol::Error::NoSession,
          ..
        },
      ) => {}
      Err(error) => return Err(error),
    }
    if Instant::now() >= deadline {
      return Err(Error::Timeout(format!(
        "the first boot did not finish within {}s",
        FIRST_BOOT.as_secs()
      )));
    }
    std::thread::sleep(Duration::from_secs(1));
  }
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
      if machine.stopped()? {
        return Ok(());
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

/// Writes the NoCloud seed `image`: a FAT volume labelled `SEED_LABEL` that
/// holds the meta-data, the user-data, and `bundle`.
fn write_seed(image: &Path, bundle: &Path) -> Result<()> {
  let instance = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map_or(0, |since| since.as_secs());
  let meta_data = format!("instance-id: freebsd-{instance}\nlocal-hostname: freebsd\n");
  let reading = || format!("reading {}", bundle.display());
  let mut bundle = File::open(bundle).map_err(Error::io(reading()))?;
  let bundle_size = bundle.metadata().map_err(Error::io(reading()))?.len();

  let seed = Volume::create(
    image,
    SEED_LABEL,
    (meta_data.len() + USER_DATA.len()) as u64 + bundle_size,
  )?;
  seed.write("meta-data", &mut meta_data.as_bytes())?;
  seed.write("user-data", &mut USER_DATA.as_bytes())?;
  seed.write(BUNDLE, &mut bundle)?;
  seed.finish()
}

/// Makes `destination` a copy of `base`, grown to at least `size` bytes for
/// the guest to expand into. On APFS, `std::fs::copy` makes the copy a clone
/// with fclonefileat(2), which shares `base`'s blocks until either changes.
fn clone(base: &Path, destination: &Path, size: u64) -> Result<()> {
  // fclonefileat refuses a destination that exists, and std::fs::copy would
  // then copy every byte.
  let _ = std::fs::remove_file(destination);
  std::fs::copy(base, destination).map_err(Error::io(format!(
    "copying {} to {}",
    base.display(),
    destination.display()
  )))?;

  let growing = || format!("growing {}", destination.display());
  let file = File::options()
    .write(true)
    .open(destination)
    .map_err(Error::io(growing()))?;
  if file.metadata().map_err(Error::io(growing()))?.len() < size {
    file.set_len(size).map_err(Error::io(growing()))?;
  }

  Ok(())
}

/// Writes `LOADER_ENV` to `/efi/freebsd/loader.env` on the disk's EFI system
/// partition. loader.efi(8) sets these variables before reading
/// `loader.conf` and passes them to the kernel as tunables.
fn write_loader_env(disk: &Path) -> Result<()> {
  let esp = Volume::esp(disk)?;

  esp.write("efi/freebsd/loader.env", &mut LOADER_ENV.as_bytes())?;
  esp.finish()
}
