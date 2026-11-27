# containerization-freebsd

The library: FreeBSD's VM image, prepared bases, machines and the agent
client; ZFS, jails, builds and containers in the guest; OCI images. The
project's [README] covers its requirements and the guest additions. In short,
it needs macOS 27 on Apple silicon, a binary signed with the
`com.apple.security.virtualization` entitlement, and an rpath to
`/usr/lib/swift`.

## Example

[`examples/container.rs`](examples/container.rs) downloads FreeBSD's VM
image, the guest bundle, and the userland; prepares a base; boots a machine;
runs a command through its agent; and runs a container on a ZFS clone of the
userland.

## Features

- `kernel-messages`: reads the kernel message buffer (msgbuf) from guest RAM
  through a custom virtio device, the only way to see a boot that never
  reaches the console. Off by default, because the device breaks save
  (`VZErrorDomain` 11).

[README]: https://github.com/goetic/containerization-freebsd/blob/main/README.md
