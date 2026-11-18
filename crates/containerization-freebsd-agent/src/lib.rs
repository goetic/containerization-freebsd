//! The guest agent, the counterpart of Apple's `vminitd`: serves the host's
//! sessions over the guest's console port, running processes and relaying
//! to and from the guest's sockets.
//!
//! [`serve`] speaks the protocol over any byte stream, so the tests drive it
//! over a socket pair; the binary hands it `/dev/ttyV0.0`.

mod listener;
mod process;
mod relay;
mod session;
mod user;

use containerization_freebsd_sys as sys;
pub use session::serve;
pub use sys::make_raw;
