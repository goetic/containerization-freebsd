# containerization-freebsd

FreeBSD virtual machines on macOS, through Apple's Virtualization framework,
in Rust. A counterpart of Apple's
[Containerization](https://github.com/apple/containerization) for FreeBSD
guests, built on [`virtualization`](https://github.com/synchronal/virtualization).

FreeBSD itself is not rebuilt: guests boot the stock 15.1 kernel from
FreeBSD's own arm64 VM image, through UEFI, from APFS copy-on-write clones.

## Status

Early. The library boots and prepares FreeBSD guests, and drives them over a
shell on their virtio console. The guest agent, the framed protocol it
speaks, the guest bundle (virtiofs modules), and the CLI are still to come.

## What a guest gets

- A single-port virtio console, `/dev/ttyV0.0` in the guest, for the control
  channel. A multiport console device stalls rc under Virtualization.
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
| `crates/containerization-freebsd` | The library: the image, prepared bases, machines, the console. |
| `crates/containerization-freebsd-test` | The integration suite, which boots FreeBSD. Unpublished. |
| `guest/virtiofs-15.1.patch` | Emil Tsalapatis's virtiofs patches (D46295, D46296, D55047), rebased onto `releng/15.1`. sha256 `65cdc3ddf16ad504619fc729ba14dfbc79b67fb84819cb69538d987841afbc1c`. |
| `guest/virtiofs-makefile.patch` | Ours, applied after it: the virtiofs module's `SRCS` needs `vnode_if.h`. |
| `guest/first-boot.sh` | The seed volume's user-data, run once by nuageinit. |

## Development

The integration suite boots VMs in its own process, so its binary must carry
`com.apple.security.virtualization`. `bin/dev/test-integration` builds, signs
and runs it, in about 30 seconds. It never downloads: run `bin/dev/fetch-image`
once first, to put FreeBSD's VM image in `~/.cache/containerization-freebsd-tests`.

Set `DEVELOPMENT_TEAM` in `.local/envrc` to sign with that team's identity;
unset, `bin/dev/sign` signs ad hoc.

## License

MIT. See [LICENSE.md](LICENSE.md).
