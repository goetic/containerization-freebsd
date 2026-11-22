//! FreeBSD guests on macOS through Virtualization.framework. Each machine
//! boots the stock FreeBSD VM image via UEFI from an APFS copy-on-write clone
//! and can mount host directories over virtio-fs. In the guest, the crate
//! manages ZFS datasets, jails, and containers, optionally from OCI images.

pub mod agent;
pub mod build;
mod clock;
pub mod container;
mod copy;
mod digest;
mod error;
mod host;
pub mod images;
pub mod jail;
#[cfg(feature = "kernel-messages")]
mod kernel_messages;
pub mod machine;
pub mod oci;
pub mod prepare;
pub mod release;
mod scripts;
pub mod socket;
pub mod statistics;
pub mod unpack;
pub mod zfs;

pub use agent::{Agent, Exec, Exit, Limit, Output, Process, Ran, Relay, Resource, Spawn, User, WindowSize};
pub use build::{Builder, Built, Step};
pub use container::{Configuration, Container, Containers, Dns, Host};
pub use copy::Parents;
pub use error::{Error, Result};
pub use images::{Image, ImageStore};
pub use jail::{Interface, Jail, Mount, Network};
pub use machine::{Disk, Layout, Mac, Machine, Share};
pub use prepare::{Upgrade, prepare};
pub use socket::{Direction, SocketRelay, UnixSocket};
pub use statistics::{DatasetIo, NetworkStatistics, Statistics};
pub use unpack::{Unpacked, Unpacker};
pub use zfs::Zfs;
