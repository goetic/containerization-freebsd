//! The guest agent, the counterpart of Apple's `vminitd`: serves the host's
//! sessions over the guest's console port, running processes and relaying
//! to the guest's local ports.
//!
//! [`serve`] speaks the protocol over any byte stream, so the tests drive it
//! over a socket pair; the binary hands it `/dev/ttyV0.0`.

mod process;
mod relay;
mod session;
mod sys;

pub use session::serve;
pub use sys::make_raw;
