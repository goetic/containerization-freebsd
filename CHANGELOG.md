# Changelog

## Unreleased

- Boots FreeBSD 15.1 arm64 VMs on macOS: downloads and verifies the official
  image, clones disks instantly, prepares a base on first boot, and saves and
  restores running VMs. Preparing a base can skip the first boot's online
  upgrade.
- A guest agent, installed with the base as part of the guest bundle, over
  the virtio console: runs commands on pipes or in a terminal, with input,
  signals and resizing; relays TCP ports and Unix sockets; and keeps the
  guest's clock in step with the host's.
- Mounts shared host directories in the guest through virtiofs, with
  FreeBSD 15.1's modules built from upstream's virtiofs patch plus two of
  our own: the module Makefile's missing vnode_if.h, and re-enabling the
  virtqueue interrupts that unmounting turns off, so a share can be mounted
  again in the same boot.
- Attaches extra disks, found in the guest by their identifiers.
- ZFS in the guest: pools, datasets, snapshots and clones, including under
  the pool of FreeBSD's VM image.
- Jails on any path in the guest, on 15.1's pinned base system, with no
  network, the guest's, their own behind pf's NAT, or their own interfaces
  on Virtualization's NAT network.
- Processes run in jails as a user, by name or uid, with groups, a umask
  and resource limits.
- Cached builds: each step runs in a jail on a clone of the step before, and
  is snapshotted, so a step built before is skipped.
- Containers: each a jail on its own clone, with a main process and others
  beside it, its own hostname, network, resolver and hosts, and limits on
  CPU and memory, with statistics. A manager lists them and deletes those
  left behind.
- Mounts into containers and jails: guest directories through nullfs,
  tmpfs, or any file system mount(8) takes, read-only if asked.
- Copies files and directories into and out of containers and jails.
- Relays Unix sockets between the host and a jail or container, either way.
- OCI images: pulls from and pushes to registries, with authentication and
  platform selection; loads and saves OCI image layouts; and lists, tags and
  deletes images in a store on the host. Layers unpack into shared ZFS
  snapshots. A container can run an image's default process, as its user.
- The `kernel-messages` feature shows boot messages when the console stays
  silent. Off by default: it breaks saving.
