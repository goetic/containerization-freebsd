# containerization-freebsd-sys

The system calls `containerization-freebsd-agent` makes that std has no safe
API for: pseudo-terminals, raw mode, signals, waiting for an exit without
reaping it, the clock, jails, what a process takes on before it starts, and
sockets opened from inside a jail. Each is a safe function over the agent's
only unsafe code; the agent forbids its own.

It takes plain values, not the protocol's types, and builds on macOS too,
where the agent's tests run: there, finding a jail fails, and nothing enters
one. Not published: only the agent uses it.
