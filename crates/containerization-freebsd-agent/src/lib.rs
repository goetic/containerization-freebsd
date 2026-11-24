//! The guest agent, the counterpart of Apple's `vminitd`. It serves the
//! host's sessions over the guest's console port, runs processes, and relays
//! connections to and from the guest's sockets.
//!
//! [`serve`] works over any byte stream, so the tests drive it over a socket
//! pair; the binary passes it `/dev/ttyV0.0`.

mod call;
mod listener;
mod pipe;
mod process;
mod relay;
mod session;
mod user;

use containerization_freebsd_sys as sys;
pub use session::serve;
pub use sys::make_raw;
