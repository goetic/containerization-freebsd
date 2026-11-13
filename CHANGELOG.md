# Changelog

## Unreleased

- Boots FreeBSD 15.1 arm64 VMs on macOS: downloads and verifies the official
  image, clones disks instantly, prepares a base on first boot, and saves and
  restores running VMs.
- Opens a shell in the guest over the virtio console.
- Preparing a base can skip the first boot's online upgrade, taking seconds
  instead of minutes.
- A protocol for the coming guest agent: commands, terminals, port relays and
  host commands, side by side over the one console, and recovering from
  corrupted bytes.
- The `kernel-messages` feature shows boot messages when the console stays
  silent. Off by default: it breaks saving.
- Adds patches for virtiofs shared folders in FreeBSD 15.1 guests.
