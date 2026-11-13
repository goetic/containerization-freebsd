# containerization-freebsd

FreeBSD virtual machines on macOS, through Apple's Virtualization framework,
in Rust. A counterpart of Apple's
[Containerization](https://github.com/apple/containerization) for FreeBSD
guests, built on [`virtualization`](https://github.com/synchronal/virtualization).

FreeBSD itself is not rebuilt: guests boot the stock 15.1 kernel from
FreeBSD's own arm64 VM image, through UEFI, from APFS copy-on-write clones.

## Status

Early. The library boots FreeBSD guests, prepares bases that carry the guest
bundle (the agent and the virtiofs modules, which CI builds), and runs
commands through the agent. The bundle is a pre-release until the
integration suite has booted it. The CLI is still to come.

## What a guest gets

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
| `crates/containerization-freebsd` | The library: the image and the guest bundle, prepared bases, machines, and the agent's client. |
| `crates/containerization-freebsd-protocol` | The protocol between the host and the guest agent: multiplexed channels in frames, over the console. No dependencies, for the agent's sake. |
| `crates/containerization-freebsd-agent` | The guest agent: runs processes, on pipes or in a terminal, and relays to guest ports, for the host. POSIX, so its tests run on the Mac. Unpublished; it ships in the guest bundle. |
| `crates/containerization-freebsd-test` | The integration suite, which boots FreeBSD. Unpublished. |
| `guest/virtiofs-15.1.patch` | Emil Tsalapatis's virtiofs patches (D46295, D46296, D55047), rebased onto `releng/15.1`. sha256 `65cdc3ddf16ad504619fc729ba14dfbc79b67fb84819cb69538d987841afbc1c`. |
| `guest/virtiofs-makefile.patch` | Ours, applied after it: the virtiofs module's `SRCS` needs `vnode_if.h`. |
| `guest/first-boot.sh` | The seed volume's user-data, run once by nuageinit: installs the bundle from the seed and starts the agent. |
| `guest/build-modules` | Builds the three modules from a Linux or macOS host, through FreeBSD's `tools/build/make.py`. CI (`.github/workflows/guest.yml`) runs it on Linux arm64. |
| `guest/bundle` | The guest bundle's own files, at their paths in the guest: the agent's rc.d script, and loader settings for the modules. |
| `guest/build-bundle` | Packages `guest/bundle`, the modules and the agent as `freebsd-15.1-arm64-guest-<rev>.tar.xz`, reproducibly. CI publishes it as a pre-release for each `guest-15.1-r<N>` tag, replacing the last. |
| `guest/build-agent` | Cross-builds the agent for `aarch64-unknown-freebsd`, a Tier 3 target: std from source (`-Zbuild-std`), linked against 15.1's `base.txz`. |

## Development

The integration suite boots VMs in its own process, so its binary must carry
`com.apple.security.virtualization`. `bin/dev/test-integration` builds, signs
and runs it, in about 30 seconds. It never downloads: run `bin/dev/fetch-image`
once first, to put FreeBSD's VM image and the pinned guest bundle in
`~/.cache/containerization-freebsd-tests`.

Set `DEVELOPMENT_TEAM` in `.local/envrc` to sign with that team's identity;
unset, `bin/dev/sign` signs ad hoc.

## License

MIT. See [LICENSE.md](LICENSE.md).
