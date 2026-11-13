# containerization-freebsd

The library: FreeBSD's VM image, prepared bases, machines, and the console.
The project's [README](../../README.md) covers what a guest gets, and is the
crate's page on crates.io.

## Features

- `kernel-messages`: reads the kernel's message buffer out of guest RAM
  through a custom virtio device. It's the only view of a boot that never
  reaches the console. Off by default: it breaks save (`VZErrorDomain` 11).
