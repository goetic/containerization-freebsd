# containerization-freebsd-sys

Safe wrappers for the system calls that `containerization-freebsd-agent` needs
and std does not provide: pseudo-terminals, raw mode, signals, waiting for an
exit without reaping it, the clock, jails, pre-exec hooks, and sockets opened
from inside a jail. This crate holds all of the agent's unsafe code; the agent
itself forbids unsafe code.

The functions take plain values, not the protocol's types. The crate also
builds on macOS, where the agent's tests run; there, looking up a jail fails,
so nothing ever enters one. It is not published, because only the agent uses
it.
