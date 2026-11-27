//! Boots FreeBSD, runs a command in the guest, and runs a container on a
//! clone of FreeBSD's userland.
//!
//! Virtualization refuses to start a machine from a binary without the
//! `com.apple.security.virtualization` entitlement, so build and sign the
//! example before running it, from the workspace's root:
//!
//! ```sh
//! cargo build --example container
//! bin/dev/sign target/debug/examples/container
//! target/debug/examples/container ~/cfbsd-example
//! ```
//!
//! The directory holds the downloads, about 900 MB fetched once, and the
//! machine's disks, which start over on each run. Keep it on one APFS volume
//! so the machine's disk is a copy-on-write clone of the base.

use containerization_freebsd::agent::Spawn;
use containerization_freebsd::{container, error, machine, prepare, release, zfs};
use containerization_freebsd_protocol::message;
use std::path::PathBuf;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(60);

fn main() -> error::Result<()> {
  let Some(directory) = std::env::args_os().nth(1).map(PathBuf::from) else {
    eprintln!("usage: container <directory>");
    std::process::exit(2);
  };
  let cache = directory.join("cache");
  let work = directory.join("machine");
  let _ = std::fs::remove_dir_all(&work);

  // Fetch FreeBSD's VM image, the guest bundle that holds the agent, and the
  // userland that jails run on, checking each against its sha256.
  let base_disk = release::base_disk(&cache)?;
  let bundle = release::bundle(&cache)?;
  release::userland(&cache)?;

  // The first boot installs the bundle. The prepared disk is the base that
  // machines boot from.
  let mut layout = prepare::prepare(&base_disk, &work, 24 << 30, prepare::Upgrade::None, &bundle)?;
  layout
    .disks
    .push(machine::Disk::create(work.join("images.raw"), "images", 8 << 30)?);
  layout.shares.push(machine::Share {
    tag: "cache".into(),
    path: cache,
    read_only: true,
  });

  let machine = layout.machine("example")?;
  machine.start()?;
  machine.wait_ready(Duration::from_secs(300))?;
  let ran = machine.agent.check(&["freebsd-version", "-k"], TIMEOUT)?;
  println!("the guest's kernel is {}", ran.stdout.trim());

  // A pool on the images disk holds the userland as a snapshot that
  // containers clone.
  machine.mount_share("cache", "/mnt/cache")?;
  let zfs = zfs::Zfs::new(&machine.agent);
  zfs.create_pool("images", &machine.disk_device("images")?)?;
  zfs.create("images/userland")?;
  zfs.extract(&format!("/mnt/cache/{}", release::USERLAND), "images/userland")?;
  zfs.snapshot("images/userland@base")?;

  let containers = container::Containers::new(&machine.agent, "images/containers");
  let mut hello = containers.create(
    "hello",
    "images/userland@base",
    container::Configuration {
      process: message::Exec::new(["sh", "-c", "echo hello from $(hostname)"]),
      ..container::Configuration::default()
    },
  )?;
  hello.start()?;
  if let Some(main) = hello.main_process() {
    let exit = main.wait(&mut std::io::stdout(), &mut std::io::stderr())?;
    println!("its main process exited with {exit}");
  }
  let ran = hello.check(&["freebsd-version", "-u"], TIMEOUT)?;
  println!("its userland is {}", ran.stdout.trim());

  // Deleting a container stops it and destroys its clone.
  hello.delete()?;
  machine.shut_down(Duration::from_secs(120))
}
