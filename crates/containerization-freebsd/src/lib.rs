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
mod fat;
mod http;
pub mod images;
pub mod jail;
#[cfg(feature = "kernel-messages")]
mod kernel_messages;
pub mod machine;
pub mod oci;
pub mod prepare;
pub mod release;
mod scratch;
pub mod socket;
#[cfg(test)]
mod testing;
pub mod unpack;
pub mod zfs;

pub use agent::{Agent, Exec, Exit, FileType, Limit, Output, Process, Ran, Relay, Resource, Spawn, User, WindowSize};
pub use build::{Builder, Built, Step};
pub use container::{Configuration, Container, Containers, Dns, Host};
pub use containerization_freebsd_protocol::{DatasetIo, NetworkStatistics, Statistics};
pub use copy::Parents;
pub use error::{Error, Result};
pub use images::{Image, ImageStore};
pub use jail::{Interface, Jail, Mount, Network};
pub use machine::{Disk, Layout, Mac, Machine, Share};
pub use prepare::{Upgrade, prepare};
pub use socket::{Direction, SocketRelay, UnixSocket};
pub use unpack::{Unpacked, Unpacker};
pub use zfs::Zfs;
