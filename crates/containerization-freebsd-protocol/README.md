# containerization-freebsd-protocol

The protocol between the host and the guest agent: multiplexed channels,
carried in frames over the virtio console. The crate docs (`src/lib.rs`)
describe the session. The project's [README] describes its usage.

The crate has no dependencies because the agent also builds it for
`aarch64-unknown-freebsd`, a Tier 3 target.

[README]: https://github.com/goetic/containerization-freebsd/README.md
