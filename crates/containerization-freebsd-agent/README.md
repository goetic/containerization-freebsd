# containerization-freebsd-agent

The guest agent, the counterpart of Apple's `vminitd`. It runs in the FreeBSD
guest and serves the host over the console port, `/dev/ttyV0.0`, speaking
`containerization-freebsd-protocol`. It ships in the guest bundle, not on
crates.io.

## Building

`guest/build-agent`, which CI runs, cross-builds it for
`aarch64-unknown-freebsd`. The code is POSIX, so it also builds on the Mac,
where `cargo nextest run` runs tests that drive the agent over a socket pair, as
the host will.

## Behaviour

- **Console:** raw, at 115200 baud for the largest input queue FreeBSD gives
  it. After each read, the agent tells the host how many bytes it Received,
  so the host may send that many more.
- **Sessions:** the agent announces itself at startup and after losing frames.
  A new session kills the process groups of the old session's
  channels.
- **Exec:** the environment adds to the agent's own. Signal numbers are the
  guest's. Exited follows the end of output, so a process whose child
  holds its output open stays open until that child exits.
- **Terminals:** Eof is ignored; ^D, sent as Data, ends a terminal's input.
- **Connect:** relays to 127.0.0.1, or failing that ::1.

Unsafe code is confined to `src/sys.rs`.
