# containerization-freebsd-test

The integration suite, which boots FreeBSD. macOS only, and unpublished.

It isn't a default workspace member, so `cargo nextest run` skips it. It runs
only signed, through `bin/dev/test-integration`, because Virtualization
requires the test binary itself to carry `com.apple.security.virtualization`.

It installs the guest bundle the library pins, which `bin/dev/fetch-image`
downloads. To try an unreleased bundle, put one from `guest/build-bundle` at
`tmp/guest-bundle.tar.xz`: the suite uses it instead.
