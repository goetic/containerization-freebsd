//! A FreeBSD guest's virtual machine: the devices it gets, and the calls that
//! drive it.

use crate::agent::Agent;
use crate::error::{Error, Result};
#[cfg(feature = "kernel-messages")]
use crate::memory::Memory;
use dispatch2::{DispatchQueue, DispatchRetained};
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
/// offloads and multiqueue vtnet(4) asks for, and vtnet fails to attach
/// ("desired features were not accepted"); these drop them from the request.
pub const LOADER_ENV: &str = "hw.vtnet.csum_disable=1\nhw.vtnet.mq_disable=1\n";

/// A host directory the guest mounts with `Machine::mount_share`.
#[derive(Clone, Debug)]
pub struct Share {
  pub tag: String,
  pub path: PathBuf,
  pub read_only: bool,
}

/// Everything a boot of the same guest must find again.
#[derive(Clone, Debug)]
pub struct Layout {
  pub cpus: usize,
  pub disk: PathBuf,
  pub memory: u64,
  /// NAT networking through the Mac. Off unless asked for.
  pub nat: bool,
  /// A read-only volume attached after the disk, such as a NoCloud seed.
  pub seed: Option<PathBuf>,
  pub shares: Vec<Share>,
  pub variables: PathBuf,
  pub identifier: Vec<u8>,
  pub mac: [u8; 6],
}

pub struct Machine {
  pub agent: Agent,
  #[cfg_attr(not(feature = "kernel-messages"), allow(dead_code))]
  debug: DebugDevices,
  machine: VirtualMachine,
  queue: DispatchRetained<DispatchQueue>,
}

/// The devices debug features add, which the machine must keep.
#[derive(Default)]
struct DebugDevices {
  #[cfg(feature = "kernel-messages")]
  memory: Memory,
}

fn url(path: &Path) -> Result<Url> {
  Url::from_file_path(path).map_err(|()| Error::Guest(format!("{} is not absolute", path.display())))
}

impl Layout {
  /// A new machine identifier, MAC address and EFI variable store in
  /// `directory`, for a guest's first boot from `disk`: 4 CPUs and 4 GiB,
  /// with no network, seed or shares.
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
      shares: Vec::new(),
      variables,
      identifier: GenericMachineIdentifier::new()
        .map_err(Error::virtualization("make a machine identifier"))?
        .data_representation(),
      mac: MACAddress::random_locally_administered()
        .map_err(Error::virtualization("make a MAC address"))?
        .ethernet_address(),
    })
  }

  #[cfg_attr(not(feature = "kernel-messages"), allow(unused_variables))]
  fn configuration(
    &self,
    debug: &DebugDevices,
  ) -> Result<(VirtualMachineConfiguration, std::io::PipeReader, std::io::PipeWriter)> {
    let failed = Error::virtualization;
    let configuration = VirtualMachineConfiguration::new().map_err(failed("make a configuration"))?;

    let platform = GenericPlatformConfiguration::new().map_err(failed("make a platform"))?;
    let identifier = GenericMachineIdentifier::with_data_representation(&self.identifier)
      .map_err(failed("read the machine identifier"))?
      .ok_or_else(|| Error::Guest("the machine identifier did not parse".to_string()))?;
    platform.set_machine_identifier(&identifier);
    configuration.set_platform(&platform);

    let boot_loader = EFIBootLoader::new().map_err(failed("make the EFI boot loader"))?;
    let variables = EFIVariableStore::new(&url(&self.variables)?).map_err(failed("open the EFI variable store"))?;
    boot_loader.set_variable_store(Some(&variables));
    configuration.set_boot_loader(Some(&boot_loader));
    configuration.set_cpu_count(isize::try_from(self.cpus).unwrap_or(isize::MAX));
    configuration.set_memory_size(self.memory);

    let disk = DiskImageStorageDeviceAttachment::new(&url(&self.disk)?, false).map_err(failed("attach the disk"))?;
    let disk = VirtioBlockDeviceConfiguration::new(&disk).map_err(failed("make the disk device"))?;
    let seed = match &self.seed {
      Some(seed) => {
        let seed = DiskImageStorageDeviceAttachment::new(&url(seed)?, true).map_err(failed("attach the seed"))?;
        Some(VirtioBlockDeviceConfiguration::new(&seed).map_err(failed("make the seed device"))?)
      }
      None => None,
    };
    let mut storage: Vec<&dyn StorageDeviceConfiguration> = vec![&disk];
    storage.extend(
      seed
        .as_ref()
        .map(|seed| seed as &dyn StorageDeviceConfiguration),
    );
    configuration.set_storage_devices(&storage);

    if self.nat {
      let network = VirtioNetworkDeviceConfiguration::new().map_err(failed("make the network device"))?;
      network.set_attachment(Some(&NATNetworkDeviceAttachment::new().map_err(failed("make NAT"))?));
      network.set_mac_address(&MACAddress::new(self.mac).map_err(failed("set the MAC address"))?);
      configuration.set_network_devices(&[&network]);
    }

    // The control channel: a single-port virtio console, `/dev/ttyV0.0` in the
    // guest. Not a multiport console device: vtcon(4) attaching one stalls rc
    // under Virtualization, so the guest never reaches networking.
    let (output, guest_output) = std::io::pipe().map_err(Error::io("make the console's pipes"))?;
    let (guest_input, input) = std::io::pipe().map_err(Error::io("make the console's pipes"))?;
    let serial = VirtioConsoleDeviceSerialPortConfiguration::new().map_err(failed("make the console"))?;
    serial.set_attachment(Some(
      &FileHandleSerialPortAttachment::new(Some(OwnedFd::from(guest_input)), Some(OwnedFd::from(guest_output)))
        .map_err(failed("attach the console"))?,
    ));
    configuration.set_serial_ports(&[&serial]);

    let shares = self
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
      .collect::<Result<Vec<_>>>()?;
    let shares: Vec<&dyn DirectorySharingDeviceConfiguration> = shares
      .iter()
      .map(|share| share as &dyn DirectorySharingDeviceConfiguration)
      .collect();
    configuration.set_directory_sharing_devices(&shares);

    #[cfg(feature = "kernel-messages")]
    configuration.set_custom_virtio_devices(&[&debug
      .memory
      .configuration()
      .map_err(failed("make the memory device"))?]);

    // No graphics device (FreeBSD hangs attaching vtgpu(4)), no entropy device
    // (suspected of stalling rc), and no USB (Apple's xHCI is reported to abort
    // the VM under FreeBSD's xhci(4)).

    configuration
      .validate()
      .map_err(failed("validate the configuration"))?;

    Ok((configuration, output, input))
  }

  /// Whether Virtualization can save and restore this configuration.
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

  /// A machine for this guest, not yet started.
  pub fn machine(&self, name: &str) -> Result<Machine> {
    let queue = DispatchQueue::new(name, None);
    let debug = DebugDevices::default();
    let (machine, output, input) = on_queue(&queue, || {
      let (configuration, output, input) = self.configuration(&debug)?;
      let machine =
        VirtualMachine::with_queue(&configuration, &queue).map_err(Error::virtualization("make the machine"))?;

      Ok::<_, Error>((machine, output, input))
    })?;

    Ok(Machine {
      agent: Agent::new(output, input),
      debug,
      machine,
      queue,
    })
  }
}

pub(crate) fn on_queue<T: Send>(queue: &DispatchQueue, work: impl FnOnce() -> T + Send) -> T {
  let mut result = None;

  queue.exec_sync(|| result = Some(work()));

  result.expect("the queue ran the work")
}

type Done = Box<dyn FnOnce(Result<(), virtualization::Error>) + Send>;

impl Machine {
  /// Calls `operation` on the machine's queue with a completion handler, and
  /// waits for it. The seconds it took.
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
    self.completed("pause", |machine, done| {
      machine.pause(done);
      Ok(())
    })
  }

  pub fn resume(&self) -> Result<f64> {
    self.completed("resume", |machine, done| {
      machine.resume(done);
      Ok(())
    })
  }

  /// Stops the machine at once, as pulling its plug would.
  pub fn stop(&self) -> Result<f64> {
    self.completed("stop", |machine, done| {
      machine.stop(done);
      Ok(())
    })
  }

  /// Pauses the running machine and saves its state to `path`, leaving it
  /// paused. Fails if the guest has a share mounted, so save bases first and
  /// mount shares after restoring.
  ///
  /// A share mounted across a save goes stale: the host's virtio-fs server
  /// restarts with the restored machine, forgetting the files the guest
  /// cached, so each fails once. Nor can it be unmounted first: FreeBSD's
  /// virtiofs hangs on a second mount of a share in the same boot.
  pub fn save(&self, path: &Path) -> Result<f64> {
    let started = Instant::now();
    let url = url(path)?;

    let mounted = self
      .agent
      .check(&["mount", "-t", "virtiofs"], Duration::from_secs(60))?;
    if !mounted.stdout.trim().is_empty() {
      return Err(Error::Guest(format!(
        "the guest has shares mounted, which a restore would leave stale: {}",
        mounted.stdout.trim()
      )));
    }
    self.pause()?;
    self.completed("save the machine's state", |machine, done| {
      machine.save_machine_state_to(&url, done)
    })?;
    Ok(started.elapsed().as_secs_f64())
  }

  /// Mounts the share tagged `tag` at `path` in the guest.
  pub fn mount_share(&self, tag: &str, path: &str) -> Result<()> {
    let script = r#"mkdir -p "$2" && mount -t virtiofs "$1" "$2""#;

    self
      .agent
      .check(&["sh", "-c", script, "sh", tag, path], Duration::from_secs(60))
      .map(|_| ())
  }

  /// Restores a state `save` wrote, into a machine of the same layout that
  /// has not started. It is left paused; once resumed, its agent answers
  /// this machine's Hello, already sent.
  pub fn restore(&self, path: &Path) -> Result<f64> {
    let url = url(path)?;

    let seconds = self.completed("restore the machine's state", |machine, done| {
      machine.restore_machine_state_from(&url, done)
    })?;
    self.agent.rejoin()?;
    Ok(seconds)
  }

  pub fn state(&self) -> VirtualMachineState {
    let machine = &self.machine;

    on_queue(&self.queue, || machine.state())
  }

  /// Waits for a session with the guest's agent; returns the seconds it took.
  pub fn wait_ready(&self, timeout: Duration) -> Result<f64> {
    let started = Instant::now();

    self.agent.wait_ready(timeout)?;
    Ok(started.elapsed().as_secs_f64())
  }

  /// Asks the guest to power off, and waits for it to.
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

  /// The kernel's messages so far, read out of guest RAM, or why they
  /// couldn't be.
  #[cfg(feature = "kernel-messages")]
  pub fn kernel_messages(&self) -> Result<String, String> {
    self.debug.memory.kernel_messages()
  }
}
