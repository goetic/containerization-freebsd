//! FreeBSD virtual machines on macOS, through Apple's Virtualization
//! framework: the stock FreeBSD VM image, booted through UEFI from
//! copy-on-write clones, with host directories shared over virtio-fs, and
//! ZFS, jails and containers in the guest, from OCI images or not.

pub mod agent;
pub mod build;
pub mod container;
mod error;
pub mod image;
pub mod images;
pub mod jail;
pub mod lease;
pub mod machine;
#[cfg(feature = "kernel-messages")]
mod memory;
pub mod oci;
pub mod prepare;
pub mod unpack;
pub mod zfs;

pub use agent::{Agent, Exec, Exit, Output, Process, Ran, Relay, WindowSize};
pub use build::{Builder, Built, Step};
pub use container::{Configuration, Container, Containers, Dns, Host};
pub use error::{Error, Result};
pub use images::{Image, ImageStore};
pub use jail::{Jail, Network};
pub use machine::{Disk, Layout, Machine, Share};
pub use prepare::{Upgrade, prepare};
pub use unpack::{Unpacked, Unpacker};
pub use zfs::Zfs;
