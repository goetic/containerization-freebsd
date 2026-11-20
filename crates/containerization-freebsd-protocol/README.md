# containerization-freebsd-protocol

The protocol between the host and the guest agent: multiplexed channels,
carried in frames over the virtio console. The crate docs (`src/lib.rs`)
describe the session. The project's [README](../../README.md) is the crate's
page on crates.io.

The crate has no dependencies because the agent also builds it for FreeBSD,
a Tier 3 target.
