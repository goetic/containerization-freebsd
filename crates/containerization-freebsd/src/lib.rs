//! FreeBSD virtual machines on macOS, through Apple's Virtualization
//! framework: the stock FreeBSD VM image, booted through UEFI from
//! copy-on-write clones, with host directories shared over virtio-fs, and
//! ZFS and jails in the guest.

pub mod agent;
mod error;
pub mod image;
pub mod jail;
pub mod lease;
pub mod machine;
#[cfg(feature = "kernel-messages")]
mod memory;
pub mod prepare;
pub mod zfs;

pub use agent::{Agent, Exec, Exit, Output, Process, Ran, Relay, WindowSize};
pub use error::{Error, Result};
pub use jail::Jail;
pub use machine::{Disk, Layout, Machine, Share};
pub use prepare::{Upgrade, prepare};
pub use zfs::Zfs;
