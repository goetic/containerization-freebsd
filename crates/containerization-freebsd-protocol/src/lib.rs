//! The protocol between containerization-freebsd and its guest agent:
//! multiplexed channels in frames, over the guest's single virtio console port.
//!
//! - [`frame`]: frames on the byte stream, found again after corruption.
//! - [`message`]: what the frames carry.
//! - [`mux`]: a session's channels, from one side, and who may send what.
//!
//! Nothing here reads or writes. Each side pushes the bytes it reads into a
//! [`Decoder`], hands the frames to [`Mux::receive`], and writes the frames
//! [`Mux::open`] and [`Mux::send`] return.
//!
//! A session starts with the host's Hello, which the agent answers with its
//! own. An agent with no session, just started or having lost frames,
//! announces itself with a Hello, and the host starts one. Channel 0 carries
//! Hello, Ping and Pong. The host opens channels with
//! Exec, for a process on pipes or a pty, and Connect, for a relay to a guest
//! TCP port; the guest opens them with HostCommand, asking the host to run a
//! command. The opener sends Data (stdin, or relay bytes), Resize and Signal.
//! The runner answers Opened, then Data (stdout), Stderr and Exited. Eof ends
//! the sender's Data, and a relay closes once both ends have sent it. Error
//! closes any channel.

pub mod frame;
pub mod message;
pub mod mux;

pub use frame::{Decoder, Frame, MAGIC, MAX_PAYLOAD, Skipped};
pub use message::{DecodeError, Exec, Exit, Message, WindowSize};
pub use mux::{CONTROL, Error, Mux, Side, VERSIONS, VersionMismatch, negotiate};
