//! The protocol between containerization-freebsd and its guest agent:
//! channels multiplexed in frames over the guest's single virtio console port.
//!
//! - [`frame`] splits the byte stream into frames and resynchronizes after
//!   corruption.
//! - [`message`] encodes and decodes the messages that frames carry.
//! - [`mux`] tracks one side's view of a session's channels and checks who may
//!   send what.
//!
//! This crate does no I/O. Each side pushes the bytes it reads into a
//! [`Decoder`], passes the decoded frames to [`Mux::receive`], and writes the
//! frames that [`Mux::open`] and [`Mux::send`] return.
//!
//! A session starts when the host sends a Hello and the agent answers with
//! its own. Both Hellos must carry the same [`VERSION`]. An agent without a
//! session, because it just started or lost frames, announces itself with a
//! Hello, and the host then starts a session.
//!
//! Channel 0 is the control channel. It carries Hello, Ping and Pong, the
//! host's SetTime, and the agent's Received, which reports how much of the
//! console the agent has read. The console drops bytes it cannot buffer, so
//! the host keeps at most [`WINDOW`] bytes in flight.
//!
//! The host opens other channels with one of three messages:
//!
//! - Exec runs a process on pipes or a pty, in the guest or a jail, as a
//!   given user, with a umask and resource limits.
//! - Connect relays to a TCP port on loopback or to a Unix socket, in the
//!   guest or a jail.
//! - Listen makes the agent listen on a Unix socket. The agent relays each
//!   connection on a new channel that it opens with Accepted.
//!
//! The opener sends Data (stdin or relay bytes), Resize and Signal. The runner
//! answers with Opened, then Data (stdout), Stderr and Exited. Eof ends the
//! sender's Data. A relay closes once both ends have sent Eof. A Listen
//! channel closes the same way: the host's Eof stops the listener, and the
//! agent's Eof confirms it. Error closes any channel.

mod codec;
pub mod frame;
pub mod message;
pub mod mux;

pub use frame::{Decoder, Frame, MAGIC, MAX_PAYLOAD, Skipped};
pub use message::{Address, Connect, DecodeError, Exec, Exit, Limit, Listen, Message, Resource, User, WindowSize};
pub use mux::{CONTROL, Error, Mux, Side, VERSION, VersionMismatch, WINDOW};
