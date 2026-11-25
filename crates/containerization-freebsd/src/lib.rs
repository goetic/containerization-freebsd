//! FreeBSD guests on macOS through Virtualization.framework. Each machine
//! boots the stock FreeBSD VM image via UEFI from an APFS copy-on-write clone
//! and can mount host directories over virtio-fs. In the guest, the crate
//! manages ZFS datasets, jails, and containers, optionally from OCI images.
//!
//! Types live in the modules that define them, such as
//! [`machine::Machine`] and [`container::Container`]. The guest agent's
//! messages, such as `Exec`, come from `containerization-freebsd-protocol`.

pub mod agent;
pub mod build;
mod clock;
pub mod container;
pub mod copy;
pub mod digest;
pub mod error;
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
