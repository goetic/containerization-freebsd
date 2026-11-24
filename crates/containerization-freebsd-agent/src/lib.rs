//! The guest agent, the counterpart of Apple's `vminitd`. It serves the
//! host's sessions over the guest's console port, runs processes, relays
//! connections to and from the guest's sockets, and answers the host's
//! Calls, such as for mounts, disks, and files in jails. Its binary's
//! `unpack` subcommand unpacks an image layer with [`unpack`].
//!
//! [`serve`] works over any byte stream, so the tests drive it over a socket
//! pair; the binary passes it `/dev/ttyV0.0`.

mod call;
mod jail;
mod listener;
mod mount;
mod net;
mod pipe;
mod process;
mod relay;
mod session;
mod unpack;
mod user;

use containerization_freebsd_sys as sys;
pub use session::serve;
pub use sys::make_raw;
pub use unpack::unpack;
