# containerization-freebsd

The library: FreeBSD's VM image, prepared bases, machines, and the console.
The project's [README](../../README.md) covers the guest additions and is
also this crate's page on crates.io.

## Features

- `kernel-messages`: reads the kernel's message buffer out of guest RAM
  through a custom virtio device. It is the only way to see a boot that never
  reaches the console. It is off by default because it breaks saving
  (`VZErrorDomain` 11).
