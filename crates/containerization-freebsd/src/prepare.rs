//! A guest's first boot from FreeBSD's VM image, producing the base disk that
//! later machines clone or restore.

use crate::Machine;
use crate::error::{Error, Result};
use crate::host::run;
use crate::machine::Layout;
use crate::scripts;
use std::fs::File;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use virtualization::VirtualMachineState;

/// Tunables for `/efi/freebsd/loader.env`. Apple's virtio-net rejects the
/// checksum offload and multiqueue features vtnet(4) negotiates, and vtnet then
/// fails to attach ("desired features were not accepted"); the first two
/// tunables stop it requesting them. `kern.racct.enable` turns on the resource
/// accounting that rctl limits and jail statistics need.
const LOADER_ENV: &str = "hw.vtnet.csum_disable=1\nhw.vtnet.mq_disable=1\nkern.racct.enable=1\n";
/// The NoCloud seed's user-data, which nuageinit runs on the first boot.
const USER_DATA: &str = include_str!("scripts/user-data.sh");
/// The guest bundle's file name on the seed, where `USER_DATA` expects it.
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
  clone(base, &disk, size)?;
  write_loader_env(&disk, &directory.join("esp"), LOADER_ENV)?;

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
  let wait = scripts::FIRST_BOOT_DONE.argv(&[]);

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
  std::fs::write(&user, USER_DATA).map_err(Error::io("writing user-data"))?;

  let result = seed_volume(
    staging,
    iso,
    &[("meta-data", &meta), ("user-data", &user), (BUNDLE, bundle)],
  );
  let _ = std::fs::remove_file(&meta);
  let _ = std::fs::remove_file(&user);
  result
}

/// Makes `destination` an APFS clone of `base` (`clonefile(2)` via `cp -c`),
/// grown to at least `size` bytes for the guest to expand into.
fn clone(base: &Path, destination: &Path, size: u64) -> Result<()> {
  let _ = std::fs::remove_file(destination);
  run(Command::new("cp").arg("-c").arg(base).arg(destination))?;

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

/// Writes `/efi/freebsd/loader.env` on the disk's ESP. loader.efi(8) sets
/// these variables before reading `loader.conf` and passes them to the
/// kernel as tunables. The ESP is FAT, so macOS can mount it without root.
fn write_loader_env(disk: &Path, mount_point: &Path, contents: &str) -> Result<()> {
  let attached = run(
    Command::new("hdiutil")
      .args(["attach", "-nomount", "-imagekey", "diskimage-class=CRawDiskImage"])
      .arg(disk),
  )?;
  let whole = attached
    .split_whitespace()
    .next()
    .ok_or_else(|| Error::Guest(format!("hdiutil attached nothing of {}", disk.display())))?
    .to_string();

  let written = (|| {
    let partition = attached
      .lines()
      .find(|line| line.split_whitespace().nth(1) == Some("EFI"))
      .and_then(|line| line.split_whitespace().next())
      .ok_or_else(|| Error::Guest(format!("no EFI partition among:\n{attached}")))?;

    std::fs::create_dir_all(mount_point).map_err(Error::io(format!("making {}", mount_point.display())))?;
    run(
      Command::new("diskutil")
        .args(["mount", "-mountPoint"])
        .arg(mount_point)
        .arg(partition),
    )?;

    let directory = mount_point.join("efi/freebsd");
    let result = std::fs::create_dir_all(&directory)
      .and_then(|()| std::fs::write(directory.join("loader.env"), contents))
      .map_err(Error::io("writing loader.env"));

    run(Command::new("diskutil").arg("unmount").arg(mount_point))?;
    result
  })();

  run(Command::new("hdiutil").arg("detach").arg(&whole))?;
  written
}

/// Builds the cloud-init NoCloud seed volume `iso`, labelled `cidata`, via
/// the staging `directory`. `files` maps names on the volume to host files.
fn seed_volume(directory: &Path, iso: &Path, files: &[(&str, &Path)]) -> Result<()> {
  let _ = std::fs::remove_dir_all(directory);
  let _ = std::fs::remove_file(iso);
  std::fs::create_dir_all(directory).map_err(Error::io(format!("making {}", directory.display())))?;

  for (name, source) in files {
    let target = directory.join(name);

    std::fs::hard_link(source, &target)
      .or_else(|_| std::fs::copy(source, &target).map(|_| ()))
      .map_err(Error::io(format!("putting {} on the seed volume", source.display())))?;
  }

  run(
    Command::new("hdiutil")
      .args([
        "makehybrid",
        "-quiet",
        "-iso",
        "-joliet",
        "-default-volume-name",
        "cidata",
        "-o",
      ])
      .arg(iso)
      .arg(directory),
  )?;

  Ok(())
}
