# Changelog

## Unreleased

- Boots FreeBSD 15.1 arm64 VMs on macOS: downloads and verifies the official
  image, clones disks instantly, prepares a base on first boot, and saves and
  restores running VMs.
- Runs commands in the guest through its agent, over the virtio console: on
  pipes or in a terminal, with input, signals and resizing. Connects to the
  guest's TCP ports.
- Preparing a base installs the guest bundle: the agent, and the virtiofs
  modules, loaded at every boot.
- Mounts shared host directories in the guest. Saving unmounts them, and
  fails if one is in use; mount them again after restoring.
- Fixes a second mount of a share in one boot hanging, with a patch of our
  own to the virtiofs modules.
- Attaches extra disks, found in the guest by their identifiers.
- Downloads 15.1's base system, pinned, as the userland for jails.
- ZFS in the guest: pools, datasets, snapshots and clones. Jails on any
  path in the guest, with processes run in them through the agent.
- Preparing a base can skip the first boot's online upgrade, taking seconds
  instead of minutes.
- A protocol for the coming guest agent: commands, terminals, port relays and
  host commands, side by side over the one console, and recovering from
  corrupted bytes.
- The `kernel-messages` feature shows boot messages when the console stays
  silent. Off by default: it breaks saving.
- Adds patches for virtiofs shared folders in FreeBSD 15.1 guests.
- The guest agent: runs commands on pipes or in a terminal, signals and
  resizes them, and relays to the guest's TCP ports.
