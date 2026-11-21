//! Configures a FreeBSD guest's virtual machine and drives it: start, pause,
//! save, restore, and shut down.

use crate::agent::Agent;
use crate::clock::ClockSync;
use crate::error::{Error, Result};
#[cfg(feature = "kernel-messages")]
use crate::memory::Memory;
use crate::scripts;
use dispatch2::{DispatchQueue, DispatchRetained};
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

/// Tunables for `/efi/freebsd/loader.env`. Apple's virtio-net rejects the
/// checksum offload and multiqueue features that vtnet(4) requests, and vtnet
/// then fails to attach ("desired features were not accepted"). The first two
/// tunables stop vtnet requesting them. The third turns on the kernel's
/// resource accounting, which jail limits and statistics need.
pub const LOADER_ENV: &str = "hw.vtnet.csum_disable=1\nhw.vtnet.mq_disable=1\nkern.racct.enable=1\n";

/// A host directory the guest mounts with `Machine::mount_share`.
///
/// On a case-insensitive volume, which is macOS's default, names that differ
/// only in case refer to one file. FreeBSD's base system has such pairs, like
/// `/usr/bin/cc` and `CC`, so a FreeBSD tree extracted onto such a share loses
/// one file of each pair.
#[derive(Clone, Debug)]
pub struct Share {
  pub tag: String,
  pub path: PathBuf,
  pub read_only: bool,
}

/// A raw disk image attached after the root disk, such as one holding a pool
/// of images. `Machine::disk_device` finds the disk's device in the guest.
#[derive(Clone, Debug)]
pub struct Disk {
  pub path: PathBuf,
  /// At most 20 ASCII bytes, as Virtualization requires.
  pub identifier: String,
  pub read_only: bool,
}

/// The configuration that every boot of one guest must reuse.
#[derive(Clone, Debug)]
pub struct Layout {
  pub cpus: usize,
  pub disk: PathBuf,
  pub memory: u64,
  /// Whether the guest gets NAT networking through the Mac.
  pub nat: bool,
  /// A read-only volume attached after the disk, such as a NoCloud seed.
  pub seed: Option<PathBuf>,
  /// Disks attached after the seed, in this order.
  pub disks: Vec<Disk>,
  pub shares: Vec<Share>,
  pub variables: PathBuf,
  pub identifier: Vec<u8>,
  pub mac: [u8; 6],
  /// MAC addresses of extra NAT network devices for jails' interfaces
  /// (`Network::Interfaces`). Each device moves into the jail that names it.
  /// They are listed here because Virtualization cannot add devices to a
  /// running machine. The guest runs DHCP only on `vtnet0`, which is the
  /// `nat` device, or the first of these when `nat` is off.
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
  Url::from_file_path(path).map_err(|()| Error::Guest(format!("{} is not absolute", path.display())))
}

impl Layout {
  /// Returns a layout for a guest's first boot from `disk`, with a new machine
  /// identifier, MAC address, and EFI variable store in `directory`. It has 4
  /// CPUs and 4 GiB of memory, and no network, seed, or shares.
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

    // The machine has no graphics device, because FreeBSD hangs attaching
    // vtgpu(4); no entropy device, which is suspected of stalling rc; and no
    // USB, because Apple's xHCI is reported to abort the VM under xhci(4).

    configuration
      .validate()
      .map_err(failed("validate the configuration"))?;

    Ok((configuration, output, input))
  }

  /// The platform, with this guest's machine identifier.
  fn platform(&self) -> Result<GenericPlatformConfiguration> {
    let failed = Error::virtualization;
    let platform = GenericPlatformConfiguration::new().map_err(failed("make a platform"))?;
    let identifier = GenericMachineIdentifier::with_data_representation(&self.identifier)
      .map_err(failed("read the machine identifier"))?
      .ok_or_else(|| Error::Guest("the machine identifier did not parse".to_string()))?;

    platform.set_machine_identifier(&identifier);
    Ok(platform)
  }

  /// The EFI boot loader, with this guest's variable store.
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

  /// A virtio-fs device for each of `shares`.
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

/// A virtio block device for the disk image at `path`, named `what` in
/// errors.
fn block_device(path: &Path, read_only: bool, what: &str) -> Result<VirtioBlockDeviceConfiguration> {
  let attachment = DiskImageStorageDeviceAttachment::new(&url(path)?, read_only)
    .map_err(Error::virtualization(&format!("attach {what}")))?;

  VirtioBlockDeviceConfiguration::new(&attachment).map_err(Error::virtualization(&format!("make {what} device")))
}

/// The agent's control channel, and the host's ends of it: the pipe to read
/// the guest's output from and the pipe to write its input to. The channel is
/// a single-port virtio console, `/dev/ttyV0.0` in the guest. A multiport
/// console device would not work: when vtcon(4) attaches one under
/// Virtualization, rc stalls and the guest never reaches networking.
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
  /// Calls `operation` on the machine's queue with a completion handler, waits
  /// for the handler, and returns the elapsed seconds.
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

  /// Stops the machine immediately, like pulling its power plug.
  pub fn stop(&self) -> Result<f64> {
    self.completed("stop", |machine, done| {
      machine.stop(done);
      Ok(())
    })
  }

  /// Unmounts the guest's shares, pauses the machine, and saves its state to
  /// `path`. The machine stays paused. This fails if a share is in use. Mount
  /// the shares again after restoring.
  ///
  /// Shares are unmounted because a share mounted across a save goes stale:
  /// the host's virtio-fs server restarts with the restored machine and
  /// forgets the files the guest cached, so each cached file fails once.
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

  /// Returns the guest's device for the disk with `identifier`, such as
  /// `/dev/vtbd1`. The device is found by searching because the image turns
  /// off the `/dev/diskid` labels that would otherwise name it.
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
  /// same layout and must not have started. The machine stays paused. When it
  /// resumes, the guest's agent answers the Hello that this machine has
  /// already sent.
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
  /// seconds. With NAT, it also waits for the default route and its
  /// interface's link, because rc sets up the route after starting the agent,
  /// and a restored machine's link comes up after the agent answers.
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

  /// Returns the kernel's messages so far, read from guest memory, or the
  /// reason they could not be read.
  #[cfg(feature = "kernel-messages")]
  pub fn kernel_messages(&self) -> Result<String, String> {
    self.debug.memory.kernel_messages()
  }
}
