# containerization-freebsd-agent

The guest agent, the counterpart of Apple's `vminitd`. It runs in the FreeBSD
guest and serves the host over the console port, `/dev/ttyV0.0`, using
`containerization-freebsd-protocol`. It ships in the guest bundle, not on
crates.io.

## Building

`guest/build-agent`, which CI runs, cross-builds the agent for
`aarch64-unknown-freebsd`. The code is POSIX, so it also builds on macOS,
where `cargo nextest run` drives the agent over a socket pair, as the host
does over the console.

## Behaviour

- **Console:** raw mode at 115200 baud, because FreeBSD sizes a tty's input
  queue by its speed. After each read, the agent sends Received with the
  number of bytes read, so the host may send that many more.
- **Sessions:** the agent announces itself at startup and after losing frames.
  A new session kills the process groups of the old session's channels.
- **Clock:** SetTime sets the guest's clock, like `vminitd`'s setTime. The
  host sends it at each new session and every 30 seconds.
- **Exec:** the given environment is added to the agent's own. Signal and
  resource numbers are the guest's. Exited is sent only after the output
  ends, so if a child inherits a process's stdout and keeps it open, the
  channel stays open until that child exits.
- **Jails and users:** before it execs, a process attaches to its jail, sets
  its limits and umask, drops privileges to its user, then changes directory
  as that user. A process may run a tool from the guest's `/rescue`; the tool is
  opened before the process enters the jail, so the jail need not contain it.
  Users and groups are looked up as runc does, in the jail's `/etc/passwd` and
  `/etc/group`, or the guest's when there is no jail. A user name must be
  listed; a numeric uid need not be. A file whose path leads out of the jail's
  root is refused. `HOME` is set to the user's home directory unless the
  environment sets it.
- **Terminals:** Eof is ignored; the host sends ^D as Data to end a terminal's
  input. At a terminal's last close, FreeBSD gives the agent one second to
  read the remaining output, then frees the terminal. On a busy host, a
  process that writes as it exits can therefore lose that output.
- **Sockets:** for a jail, the socket is opened by a child process attached to
  the jail, so paths and loopback are the jail's. Connect relays to
  127.0.0.1, falling back to ::1, or to a Unix socket. Listen replaces any
  socket already at its path and opens an Accepted channel for each
  connection. The host's Eof stops the listener: the agent removes the
  socket file and closes the socket before sending its own Eof. An Error, or
  the end of the session, closes the socket but leaves the file for a later
  Listen to replace.

The agent forbids unsafe code. System calls that std does not wrap live in
`containerization-freebsd-sys`.
