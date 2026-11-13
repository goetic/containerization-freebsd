# containerization-freebsd

FreeBSD virtual machines on macOS, in Rust via Apple's Virtualization framework.
A counterpart to Apple's
[Containerization] for FreeBSD
guests, built on [virtualization].com/synchronal/virtualization).

Guests boot the stock 15.1 kernel from FreeBSD's arm64 VM image, through UEFI,
from APFS copy-on-write clones.

## Status

Pre-release.

## Guest additions

- A single-port virtio console, `/dev/ttyV0.0` in the guest, which the agent
  serves. A multiport console device stalls rc under Virtualization.
- The guest bundle, installed from the seed volume on the first boot: the
  agent, started by rc, and the patched virtiofs modules, loaded at boot.
- No graphics, entropy or USB devices: FreeBSD hangs attaching vtgpu(4), and
  the others are suspected of stalling rc or aborting the VM.
- `hw.vtnet.csum_disable=1` and `hw.vtnet.mq_disable=1`, written to
  `/efi/freebsd/loader.env` on the disk's EFI partition: Apple's virtio-net
  rejects the offloads vtnet(4) otherwise asks for.
- NAT networking only when asked for.
- Host directories over virtio-fs, which FreeBSD 15.1 mounts only with the
  patched modules in `guest/`.

## Layout

| Path | What |
| --- | --- |
| `crates/containerization-freebsd` | The library: images, machines, and the agent client. |
| `crates/containerization-freebsd-protocol` | The protocol between host and agent. |
| `crates/containerization-freebsd-agent` | The guest agent. |
| `crates/containerization-freebsd-test` | The integration suite. |
| `guest/` | The guest bundle: virtiofs patches, agent setup, and build scripts. |

## Development

The integration suite boots VMs, so its binary must carry
`com.apple.security.virtualization`. `bin/dev/test-integration` builds, signs
and runs it, so is slow. Run `bin/dev/fetch-image` once prior to running
integration tests, to download FreeBSD's VM image and the pinned guest bundle in
`~/.cache/containerization-freebsd-tests`.

Set `DEVELOPMENT_TEAM` in `.local/envrc` to sign with that team's identity;
unset, `bin/dev/sign` signs ad hoc.

## License

MIT. See [LICENSE.md](LICENSE.md).


[Containerization]: https://github.com/apple/containerization
[virtualization]: https://github.com/synchronal/virtualization