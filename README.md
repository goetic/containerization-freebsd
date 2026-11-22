# containerization-freebsd

FreeBSD virtual machines on macOS, in Rust, through Apple's Virtualization
framework. It is a counterpart to Apple's [Containerization] for FreeBSD
guests, built on [virtualization].

Guests boot the stock 15.1 kernel from FreeBSD's arm64 VM image through UEFI.
Each guest's disk is an APFS copy-on-write clone.

## Status

Pre-release.

## Guest additions

- A single-port virtio console, `/dev/ttyV0.0` in the guest, which the agent
  serves. A multiport console device stalls rc under Virtualization.
- The guest bundle, installed from the seed volume on the first boot. It holds
  the agent, which rc starts, and the patched virtiofs modules.
- No graphics, entropy or USB devices. FreeBSD hangs attaching vtgpu(4), and
  the others are suspected of stalling rc or aborting the VM.
- `hw.vtnet.csum_disable=1` and `hw.vtnet.mq_disable=1` in
  `/efi/freebsd/loader.env` on the disk's EFI partition, because Apple's
  virtio-net rejects the offloads vtnet(4) asks for by default.
- `kern.racct.enable=1` in the same file, for the racct accounting that
  rctl(8) limits and jail statistics need.
- NAT networking, only when requested.
- Host directories over virtio-fs. FreeBSD 15.1 can mount them only with the
  patched modules in `guest/`.

## Layout

| Path | What |
| --- | --- |
| `crates/containerization-freebsd` | The library: VM images, machines and the agent client; ZFS, jails, builds and containers in the guest; OCI images. |
| `crates/containerization-freebsd-protocol` | The protocol between host and agent. |
| `crates/containerization-freebsd-agent` | The guest agent. |
| `crates/containerization-freebsd-sys` | The agent's system calls, its only unsafe code. |
| `crates/containerization-freebsd-test` | The integration suite. |
| `guest/` | The guest bundle: virtiofs patches, rc.d scripts for the agent and modules, and build scripts. |

## Development

The integration suite boots VMs, so its binary must carry
`com.apple.security.virtualization`. `bin/dev/test-integration` builds, signs
and runs it, and is slow. Before the suite runs, nextest's setup scripts:

- download FreeBSD's VM image, the userland and the pinned guest bundle into
  `~/.cache/containerization-freebsd-tests` (`bin/dev/fetch-image`);
- build the guest bundle from the working tree
  (`bin/dev/build-guest-bundle`), which needs Homebrew's `llvm`, `lld`,
  `gnu-tar` and `xz`.

The suite never boots a released bundle, so the agent can change without a
release. Once the agent is stable, tag `guest-15.1-r<N>` and pin that bundle.

To sign with a team's identity, set `DEVELOPMENT_TEAM` in `.local/envrc`.
Without it, `bin/dev/sign` signs ad hoc.

## License

MIT. See [LICENSE.md](LICENSE.md).


[Containerization]: https://github.com/apple/containerization
[virtualization]: https://github.com/synchronal/virtualization