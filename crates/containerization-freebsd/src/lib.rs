//! FreeBSD guests on macOS through Virtualization.framework. Each machine
//! boots the stock FreeBSD VM image via UEFI from an APFS copy-on-write clone
//! and can mount host directories over virtio-fs. In the guest, the crate
//! manages ZFS datasets, jails, and containers, optionally from OCI images.
//!
//! Types live in the modules that define them, such as
//! [`machine::Machine`] and [`container::Container`]. The guest agent's
//! messages, such as `Exec`, come from `containerization-freebsd-protocol`.
//!
//! # Example
//!
//! [`examples/container.rs`] downloads FreeBSD's VM image, the guest bundle,
//! and the userland; prepares a base; boots a machine; runs a command through
//! its agent; and runs a container on a ZFS clone of the userland.
//!
//! [`examples/container.rs`]: https://github.com/goetic/containerization-freebsd/blob/main/crates/containerization-freebsd/examples/container.rs
//!
//! # Requirements
//!
//! - macOS 27 or later on Apple silicon.
//! - A binary that starts a [`machine::Machine`] must be signed with the
//!   `com.apple.security.virtualization` entitlement after every build.
//! - Every binary that links this crate, test binaries included, needs an
//!   rpath to `/usr/lib/swift`, such as `-C link-arg=-Wl,-rpath,/usr/lib/swift`
//!   in its `.cargo/config.toml`. Without it, dyld can't find the Swift
//!   runtime that `virtualization` links, and the binary fails at launch.
//!
//! The project's [README] has the details.
//!
//! [README]: https://github.com/goetic/containerization-freebsd/blob/main/README.md

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
