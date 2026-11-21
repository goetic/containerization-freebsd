# containerization-freebsd

The library: FreeBSD's VM image, prepared bases, machines and the agent
client; ZFS, jails, builds and containers in the guest; OCI images. The
project's [README] covers the guest additions.

## Features

- `kernel-messages`: reads the kernel message buffer (msgbuf) from guest RAM
  through a custom virtio device, the only way to see a boot that never
  reaches the console. Off by default, because the device breaks save
  (`VZErrorDomain` 11).
  
[README](https://github.com/goetic/containerization-freebsd/README.md)
