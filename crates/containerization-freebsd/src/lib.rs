//! FreeBSD virtual machines on macOS, through Apple's Virtualization
//! framework: the stock FreeBSD VM image, booted through UEFI from
//! copy-on-write clones, with host directories shared over virtio-fs.

pub mod agent;
mod error;
pub mod image;
pub mod lease;
pub mod machine;
#[cfg(feature = "kernel-messages")]
mod memory;
pub mod prepare;

pub use agent::{Agent, Exit, Ran};
pub use error::{Error, Result};
pub use machine::{Layout, Machine, Share};
pub use prepare::{Upgrade, prepare};
