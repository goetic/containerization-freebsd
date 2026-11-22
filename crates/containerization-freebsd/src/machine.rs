//! A guest's Virtualization.framework configuration and VM lifecycle: start,
//! pause, save, restore and shutdown.

use crate::agent::Agent;
use crate::clock::ClockSync;
use crate::error::{Error, Result};
#[cfg(feature = "kernel-messages")]
use crate::memory::Memory;
use crate::scripts;
use dispatch2::{DispatchQueue, DispatchRetained};
use std::fs::File;
use std::io::{PipeReader, PipeWriter};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use url::Url;
use virtualization::{
  DirectorySharingDeviceConfiguration, DiskImageStorageDeviceAttachment, EFIBootLoader, EFIVariableStore,
  EFIVariableStoreInitializationOptions, FileHandleSerialPortAttachment, GenericMachineIdentifier,
  GenericPlatformConfiguration, MACAddress, NATNetworkDeviceAttachment, NetworkDeviceConfiguration,
  SerialPortConfiguration, SharedDirectory, SingleDirectoryShare, StorageDeviceConfiguration,
  VirtioBlockDeviceConfiguration, VirtioConsoleDeviceSerialPortConfiguration, VirtioFileSystemDeviceConfiguration,
  VirtioNetworkDeviceConfiguration, VirtualMachine, VirtualMachineConfiguration, VirtualMachineState,
};

/// A host directory exported over virtio-fs and mounted in the guest with
/// `Machine::mount_share`.
///
/// On a case-insensitive volume (macOS's default), names differing only in
/// case are one file. FreeBSD's base has such pairs, like `/usr/bin/cc` and
/// `CC`, so a base tree extracted onto such a share loses one of each pair.
#[derive(Clone, Debug)]
pub struct Share {
  pub tag: String,
  pub path: PathBuf,
  pub read_only: bool,
}

/// A raw disk image attached after the root disk, such as one holding a ZFS
/// pool of images. `Machine::disk_device` finds its guest device.
#[derive(Clone, Debug)]
pub struct Disk {
  pub path: PathBuf,
  /// The virtio-blk serial, which the guest reports as the disk's ident: at
  /// most 20 ASCII bytes.
  pub identifier: String,
  pub read_only: bool,
}

impl Disk {
  /// Creates a sparse raw disk of `size` bytes at `path`, failing if `path`
  /// exists, and returns it to attach read-write as `identifier`.
  pub fn create(path: impl Into<PathBuf>, identifier: impl Into<String>, size: u64) -> Result<Self> {
    let path = path.into();
    File::options()
      .write(true)
      .create_new(true)
      .open(&path)
      .and_then(|file| file.set_len(size))
      .map_err(Error::io(format!("creating {}", path.display())))?;

    Ok(Self {
      path,
      identifier: identifier.into(),
      read_only: false,
    })
  }
}

/// The configuration that every boot of one guest must reuse.
#[derive(Clone, Debug)]
pub struct Layout {
  pub cpus: usize,
  pub disk: PathBuf,
  pub memory: u64,
  /// Attach a NAT network device with `mac`, as `vtnet0`.
  pub nat: bool,
  /// A read-only volume attached after the disk, such as a NoCloud seed.
  pub seed: Option<PathBuf>,
  /// Disks attached after the seed, in this order.
  pub disks: Vec<Disk>,
  pub shares: Vec<Share>,
  pub variables: PathBuf,
  pub identifier: Vec<u8>,
  pub mac: [u8; 6],
  /// MACs of extra NAT network devices for jails' interfaces
  /// (`Network::Interfaces`); each moves into the VNET jail that names it.
  /// They're declared up front because Virtualization can't hot-add devices.
  /// The guest runs DHCP only on `vtnet0`: the `nat` device, or the first of
  /// these when `nat` is off.
  pub interfaces: Vec<[u8; 6]>,
}

pub struct Machine {
  pub agent: Agent,
  clock: ClockSync,
  nat: bool,
  #[cfg_attr(not(feature = "kernel-messages"), allow(dead_code))]
  debug: DebugDevices,
  machine: VirtualMachine,
  queue: DispatchRetained<DispatchQueue>,
}

/// Devices added by debug features, which must live as long as the machine.
#[derive(Default)]
struct DebugDevices {
  #[cfg(feature = "kernel-messages")]
  memory: Memory,
}

fn url(path: &Path) -> Result<Url> {
  Url::from_file_path(path).map_err(|()| Error::Invalid(format!("{} is not absolute", path.display())))
}

impl Layout {
  /// A first-boot layout for `disk`: a new machine identifier, a random
  /// locally administered MAC, and a fresh EFI variable store in `directory`;
  /// 4 CPUs, 4 GiB, and no NAT, seed, extra disks, shares or interfaces.
  pub fn first(directory: &Path, disk: PathBuf) -> Result<Self> {
    let variables = directory.join("efi-variables");
    let _ = std::fs::remove_file(&variables);

    EFIVariableStore::with_creating_variable_store_at_and_options(
      &url(&variables)?,
      EFIVariableStoreInitializationOptions::new(0),
    )
    .map_err(Error::virtualization("create the EFI variable store"))?;

    Ok(Self {
      cpus: 4,
      disk,
      memory: 4 << 30,
      nat: false,
      seed: None,
      disks: Vec::new(),
      shares: Vec::new(),
      variables,
      identifier: GenericMachineIdentifier::new()
        .map_err(Error::virtualization("make a machine identifier"))?
        .data_representation(),
      mac: MACAddress::random_locally_administered()
        .map_err(Error::virtualization("make a MAC address"))?
        .ethernet_address(),
      interfaces: Vec::new(),
    })
  }

  #[cfg_attr(not(feature = "kernel-messages"), allow(unused_variables))]
  fn configuration(&self, debug: &DebugDevices) -> Result<(VirtualMachineConfiguration, PipeReader, PipeWriter)> {
    let failed = Error::virtualization;
    let configuration = VirtualMachineConfiguration::new().map_err(failed("make a configuration"))?;

    configuration.set_platform(&self.platform()?);
    configuration.set_boot_loader(Some(&self.boot_loader()?));
    configuration.set_cpu_count(isize::try_from(self.cpus).unwrap_or(isize::MAX));
    configuration.set_memory_size(self.memory);

    let storage = self.storage_devices()?;
    let storage: Vec<&dyn StorageDeviceConfiguration> = storage
      .iter()
      .map(|device| device as &dyn StorageDeviceConfiguration)
      .collect();
    configuration.set_storage_devices(&storage);

    let networks = self.network_devices()?;
    let networks: Vec<&dyn NetworkDeviceConfiguration> = networks
      .iter()
      .map(|device| device as &dyn NetworkDeviceConfiguration)
      .collect();
    configuration.set_network_devices(&networks);

    let (serial, output, input) = console()?;
    configuration.set_serial_ports(&[&serial]);

    let shares = self.share_devices()?;
    let shares: Vec<&dyn DirectorySharingDeviceConfiguration> = shares
      .iter()
      .map(|device| device as &dyn DirectorySharingDeviceConfiguration)
      .collect();
    configuration.set_directory_sharing_devices(&shares);

    #[cfg(feature = "kernel-messages")]
    configuration.set_custom_virtio_devices(&[&debug
      .memory
      .configuration()
      .map_err(failed("make the memory device"))?]);

    // No graphics device: FreeBSD hangs attaching vtgpu(4). No entropy
    // device: suspected of stalling rc. No USB: Apple's xHCI reportedly aborts
    // the VM under xhci(4).

    configuration
      .validate()
      .map_err(failed("validate the configuration"))?;

    Ok((configuration, output, input))
  }

  fn platform(&self) -> Result<GenericPlatformConfiguration> {
    let failed = Error::virtualization;
    let platform = GenericPlatformConfiguration::new().map_err(failed("make a platform"))?;
    let identifier = GenericMachineIdentifier::with_data_representation(&self.identifier)
      .map_err(failed("read the machine identifier"))?
      .ok_or_else(|| Error::Guest("the machine identifier did not parse".to_string()))?;

    platform.set_machine_identifier(&identifier);
    Ok(platform)
  }

  fn boot_loader(&self) -> Result<EFIBootLoader> {
    let failed = Error::virtualization;
    let boot_loader = EFIBootLoader::new().map_err(failed("make the EFI boot loader"))?;
    let variables = EFIVariableStore::new(&url(&self.variables)?).map_err(failed("open the EFI variable store"))?;

    boot_loader.set_variable_store(Some(&variables));
    Ok(boot_loader)
  }

  /// The disk, then the seed, then the other disks.
  fn storage_devices(&self) -> Result<Vec<VirtioBlockDeviceConfiguration>> {
    let mut devices = vec![block_device(&self.disk, false, "the disk")?];

    if let Some(seed) = &self.seed {
      devices.push(block_device(seed, true, "the seed")?);
    }
    for disk in &self.disks {
      VirtioBlockDeviceConfiguration::validate_block_device_identifier(&disk.identifier)
        .map_err(Error::virtualization("check the disk's identifier"))?;
      let device = block_device(&disk.path, disk.read_only, "a disk")?;
      device.set_block_device_identifier(&disk.identifier);
      devices.push(device);
    }
    Ok(devices)
  }

  /// A NAT network device with `mac` if `nat` is set, then one for each of
  /// `interfaces`.
  fn network_devices(&self) -> Result<Vec<VirtioNetworkDeviceConfiguration>> {
    let failed = Error::virtualization;

    self
      .nat
      .then_some(self.mac)
      .into_iter()
      .chain(self.interfaces.iter().copied())
      .map(|mac| {
        let network = VirtioNetworkDeviceConfiguration::new().map_err(failed("make a network device"))?;
        network.set_attachment(Some(&NATNetworkDeviceAttachment::new().map_err(failed("make NAT"))?));
        network.set_mac_address(&MACAddress::new(mac).map_err(failed("set a MAC address"))?);
        Ok(network)
      })
      .collect()
  }

  fn share_devices(&self) -> Result<Vec<VirtioFileSystemDeviceConfiguration>> {
    let failed = Error::virtualization;

    self
      .shares
      .iter()
      .map(|share| {
        let directory =
          SharedDirectory::new(&url(&share.path)?, share.read_only).map_err(failed("share the directory"))?;
        let device =
          VirtioFileSystemDeviceConfiguration::new(&share.tag).map_err(failed("make the virtio-fs device"))?;
        device.set_share(Some(
          &SingleDirectoryShare::new(&directory).map_err(failed("make the share"))?,
        ));
        Ok(device)
      })
      .collect()
  }

  /// Checks that Virtualization can save and restore this configuration.
  pub fn validate_save_restore(&self) -> Result<()> {
    let queue = DispatchQueue::new("containerization-freebsd-validate", None);
    let debug = DebugDevices::default();

    on_queue(&queue, || {
      let (configuration, _, _) = self.configuration(&debug)?;
      configuration
        .validate_save_restore_support()
        .map_err(Error::virtualization("validate save/restore support"))
    })
  }

  /// Creates a machine for this guest without starting it.
  pub fn machine(&self, name: &str) -> Result<Machine> {
    let queue = DispatchQueue::new(name, None);
    let debug = DebugDevices::default();
    let (machine, output, input) = on_queue(&queue, || {
      let (configuration, output, input) = self.configuration(&debug)?;
      let machine =
        VirtualMachine::with_queue(&configuration, &queue).map_err(Error::virtualization("make the machine"))?;

      Ok::<_, Error>((machine, output, input))
    })?;

    let agent = Agent::new(output, input);
    Ok(Machine {
      clock: ClockSync::start(agent.share()),
      agent,
      nat: self.nat,
      debug,
      machine,
      queue,
    })
  }
}

/// A virtio-blk device for the disk image at `path`; `what` names it in
/// errors.
fn block_device(path: &Path, read_only: bool, what: &str) -> Result<VirtioBlockDeviceConfiguration> {
  let attachment = DiskImageStorageDeviceAttachment::new(&url(path)?, read_only)
    .map_err(Error::virtualization(&format!("attach {what}")))?;

  VirtioBlockDeviceConfiguration::new(&attachment).map_err(Error::virtualization(&format!("make {what} device")))
}

/// The agent's channel, a single-port virtio console (`/dev/ttyV0.0` in the
/// guest), and the host's pipe ends for its output and input. Not multiport:
/// when vtcon(4) attaches a multiport console under Virtualization, rc stalls
/// before networking.
fn console() -> Result<(VirtioConsoleDeviceSerialPortConfiguration, PipeReader, PipeWriter)> {
  let failed = Error::virtualization;
  let (output, guest_output) = std::io::pipe().map_err(Error::io("make the console's pipes"))?;
  let (guest_input, input) = std::io::pipe().map_err(Error::io("make the console's pipes"))?;
  let serial = VirtioConsoleDeviceSerialPortConfiguration::new().map_err(failed("make the console"))?;

  serial.set_attachment(Some(
    &FileHandleSerialPortAttachment::new(Some(OwnedFd::from(guest_input)), Some(OwnedFd::from(guest_output)))
      .map_err(failed("attach the console"))?,
  ));
  Ok((serial, output, input))
}

pub(crate) fn on_queue<T: Send>(queue: &DispatchQueue, work: impl FnOnce() -> T + Send) -> T {
  let mut result = None;

  queue.exec_sync(|| result = Some(work()));

  result.expect("the queue ran the work")
}

type Done = Box<dyn FnOnce(Result<(), virtualization::Error>) + Send>;

impl Machine {
  /// Runs `operation` on the machine's queue, waits for its completion
  /// handler, and returns the elapsed seconds.
  fn completed(
    &self,
    action: &str,
    operation: impl FnOnce(&VirtualMachine, Done) -> Result<(), virtualization::Error> + Send,
  ) -> Result<f64> {
    let (sender, receiver) = mpsc::channel();
    let started = Instant::now();
    let machine = &self.machine;

    on_queue(&self.queue, || {
      operation(
        machine,
        Box::new(move |result| {
          let _ = sender.send(result);
        }),
      )
    })
    .map_err(Error::virtualization(action))?;

    receiver
      .recv()
      .map_err(|_| Error::Guest(format!("{action}: Virtualization dropped the completion handler")))?
      .map_err(Error::virtualization(action))?;

    Ok(started.elapsed().as_secs_f64())
  }

  pub fn start(&self) -> Result<f64> {
    self.completed("start", |machine, done| {
      machine.start(done);
      Ok(())
    })
  }

  pub fn pause(&self) -> Result<f64> {
    let seconds = self.completed("pause", |machine, done| {
      machine.pause(done);
      Ok(())
    })?;
    self.clock.set_paused(true);
    Ok(seconds)
  }

  /// Resumes the machine and syncs the guest's clock, which fell behind while
  /// the machine was paused.
  pub fn resume(&self) -> Result<f64> {
    let seconds = self.completed("resume", |machine, done| {
      machine.resume(done);
      Ok(())
    })?;
    self.clock.set_paused(false);
    let _ = self.agent.sync_clock();
    Ok(seconds)
  }

  /// Stops the VM without a guest shutdown, like pulling its power.
  pub fn force_stop(&self) -> Result<f64> {
    self.completed("stop", |machine, done| {
      machine.stop(done);
      Ok(())
    })
  }

  /// Unmounts the guest's virtio-fs shares, pauses, and saves the machine's
  /// state to `path`, leaving it paused. Fails if a share is busy. Remount the
  /// shares after restoring.
  ///
  /// A share mounted across a save goes stale: the host's virtio-fs server
  /// restarts with the restored machine and forgets the files the guest
  /// cached, so each cached file fails once.
  pub fn save(&self, path: &Path) -> Result<f64> {
    let started = Instant::now();
    let url = url(path)?;

    self
      .agent
      .check(&["umount", "-A", "-t", "virtiofs"], Duration::from_secs(60))?;
    self.pause()?;
    self.completed("save the machine's state", |machine, done| {
      machine.save_machine_state_to(&url, done)
    })?;
    Ok(started.elapsed().as_secs_f64())
  }

  /// Returns the guest device of the disk with `identifier`, such as
  /// `/dev/vtbd1`. It scans `kern.disks` because the image disables the
  /// `/dev/diskid` labels that would otherwise name it.
  pub fn disk_device(&self, identifier: &str) -> Result<String> {
    let ran = self
      .agent
      .check(&scripts::DISK_DEVICE.argv(&[identifier]), Duration::from_secs(60))?;

    match ran.lines().as_slice() {
      [device] => Ok(device.to_string()),
      [] => Err(Error::Guest(format!("no disk has the identifier {identifier:?}"))),
      devices => Err(Error::Guest(format!(
        "disks {devices:?} all have the identifier {identifier:?}"
      ))),
    }
  }

  /// Mounts the share tagged `tag` at `path` in the guest.
  pub fn mount_share(&self, tag: &str, path: &str) -> Result<()> {
    self
      .agent
      .check(&scripts::MOUNT_SHARE.argv(&[tag, path]), Duration::from_secs(60))
      .map(|_| ())
  }

  /// Restores a state written by `save` into this machine, which must have the
  /// same layout and not have started. The machine stays paused; on resume,
  /// the guest's agent answers the Hello this sends.
  pub fn restore(&self, path: &Path) -> Result<f64> {
    let url = url(path)?;

    let seconds = self.completed("restore the machine's state", |machine, done| {
      machine.restore_machine_state_from(&url, done)
    })?;
    self.clock.set_paused(true);
    self.agent.rejoin()?;
    Ok(seconds)
  }

  pub fn state(&self) -> VirtualMachineState {
    let machine = &self.machine;

    on_queue(&self.queue, || machine.state())
  }

  /// Waits for a session with the guest's agent and returns the elapsed
  /// seconds. With NAT, also waits for the default route and its interface's
  /// link: rc adds the route after starting the agent, and a restored
  /// machine's link comes up after the agent answers.
  pub fn wait_ready(&self, timeout: Duration) -> Result<f64> {
    let started = Instant::now();

    self.agent.wait_ready(timeout)?;
    if self.nat {
      match self
        .agent
        .check(&scripts::ROUTED.argv(&[]), timeout.saturating_sub(started.elapsed()))
      {
        Err(Error::Timeout(_)) => {
          return Err(Error::Timeout(format!(
            "the guest's NAT network was not up within {}s",
            timeout.as_secs()
          )));
        }
        result => result?,
      };
    }
    Ok(started.elapsed().as_secs_f64())
  }

  /// Asks the guest to power off and waits for it to stop.
  pub fn shut_down(&self, timeout: Duration) -> Result<f64> {
    self.agent.launch(&["shutdown", "-p", "now"])?;
    self.wait_stopped(timeout)
  }

  /// Waits for the guest to power itself off.
  pub fn wait_stopped(&self, timeout: Duration) -> Result<f64> {
    let started = Instant::now();

    while started.elapsed() < timeout {
      match self.state() {
        VirtualMachineState::Stopped => return Ok(started.elapsed().as_secs_f64()),
        VirtualMachineState::Error => return Err(Error::Guest("the machine stopped with an error".to_string())),
        _ => std::thread::sleep(Duration::from_millis(100)),
      }
    }

    Err(Error::Timeout(format!(
      "the guest did not stop within {}s",
      timeout.as_secs()
    )))
  }

  /// Returns the kernel message buffer, read from guest RAM, or why it
  /// couldn't be read.
  #[cfg(feature = "kernel-messages")]
  pub fn kernel_messages(&self) -> Result<String, String> {
    self.debug.memory.kernel_messages()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn refuses_a_relative_path() {
    let result = url(Path::new("disk.raw"));

    assert!(matches!(result, Err(Error::Invalid(_))), "{result:?}");
  }
}
