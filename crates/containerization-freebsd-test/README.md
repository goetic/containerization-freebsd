# containerization-freebsd-test

The integration suite, which boots FreeBSD. It runs on macOS only and is not
published.

It is not a default workspace member, so `cargo nextest run` skips it. Run it
through `bin/dev/test-integration`, which signs the test binaries:
Virtualization requires the test binary itself to carry
`com.apple.security.virtualization`.

`bin/dev/fetch-image` downloads FreeBSD's VM image, the userland and the
pinned guest bundle into the cache. The suite does not install the pinned
bundle: it boots the bundle that `bin/dev/build-guest-bundle` builds from the
working tree at `tmp/guest-bundle.tar.xz`.
