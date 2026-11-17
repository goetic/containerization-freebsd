# Changelog

## Unreleased

- Boots FreeBSD 15.1 arm64 VMs on macOS: downloads and verifies the official
  image, clones disks instantly, prepares a base on first boot, and saves and
  restores running VMs.
- Runs commands in the guest through its agent, over the virtio console: on
  pipes or in a terminal, with input, signals and resizing. Connects to the
  guest's TCP ports.
- Preparing a base installs the guest bundle: the agent, and the virtiofs
  modules, loaded at every boot.
- Mounts shared host directories in the guest. Saving unmounts them, and
  fails if one is in use; mount them again after restoring.
- Fixes a second mount of a share in one boot hanging, with a patch of our
  own to the virtiofs modules.
- Attaches extra disks, found in the guest by their identifiers.
- Downloads 15.1's base system, pinned, as the userland for jails.
- ZFS in the guest: pools, datasets, snapshots and clones. Jails on any
  path in the guest, with processes run in them through the agent, and no
  network, the guest's, or their own behind pf's NAT.
- Cached builds: each step runs in a jail on a clone of the step before, and
  is snapshotted, so a step built before is skipped.
- Containers: each a jail on its own clone, with a main process, others run
  beside it, and its own hostname, network, resolver and hosts. Many share a
  machine, under a manager that lists them and deletes those left behind.
- OCI images: pulls them from registries, with token or account
  authentication and platform selection, into an OCI image layout on the
  host, which lists, tags and deletes them. Checks each layer against the
  image's config and unpacks it into a ZFS snapshot named by its chain id, so
  images share layers. A container can run an image's default process.
- Processes run as a user, by name or uid, with their own groups or a group
  given, and more, looked up in their jail's `/etc/passwd` and `/etc/group`;
  and with a umask and resource limits. A container of an image runs as the
  image's user. The agent enters jails itself, so a working directory in a
  jail no longer needs its shell. Protocol version 3.
- Relays Unix sockets between the host and the guest, a jail or a
  container, as Containerization does: a host socket appears inside, or
  one inside appears on the host, with the permissions given. A container
  relays its sockets while it runs. Connects to the Unix sockets and
  loopback ports of jails and containers too. Also protocol version 3.
- Mounts into containers and jails: guest directories, such as host
  shares, through nullfs; tmpfs; or any file system mount(8) takes, and
  read-only if asked. A mount point resolves as the jail sees it, so its
  symbolic links can't lead out. Stopping a jail unmounts all mounted in
  it.
- Loads and saves images as OCI image layout directories, as
  Containerization does; unpack an archive of one, such as FreeBSD's
  container images on download.freebsd.org, to load it. Loaded images are
  named as the layout names them.
- Pushes images to registries: the blobs a registry lacks, then the
  manifests, an index's before the index. Pushing or saving an image for
  one platform makes a new index of that platform's manifests, as
  Containerization does. Lists an image's platforms, the store's or a
  registry's, without pulling its layers.
- Limits a container's processes together to Containerization's `cpus`
  and `memoryInBytes`, through rctl, and reports what they use. Preparing
  a base now sets `kern.racct.enable`, which this needs: prepare older
  bases again. Statistics include network counters for each interface of
  a jail with its own network, and a container's block IO, counted as its
  ZFS dataset's reads and writes.
- Copies files and directories into and out of containers and jails, as
  Containerization's `copyIn` and `copyOut` do. Copying runs the guest's
  `/rescue` tools in the jail, so it needs nothing from the image, and
  paths resolve as the jail sees them. Exec's new `rescue` runs one of
  those tools. Also protocol version 3.
- Containers and jails with their own interfaces on Virtualization's NAT
  network, as Containerization's `interfaces`, so the host reaches them at
  their addresses: `Network::Interfaces`, each a spare network device from
  `Layout::interfaces`, moved into the jail. `Jail::start` takes the
  network by reference. Preparing a base now runs DHCP and IPv6
  autoconfiguration on the first network device only, so spare devices
  stay unconfigured until a jail claims one: prepare older bases again.
- Keeps the guest's clock with the host's, as Containerization's TimeSyncer
  does: at each new session with the agent, as after a boot or a restore,
  on resuming, and every 30 seconds while the machine runs. Also protocol
  version 3.
- Stopping a jail ends its processes, then drops the TCP connections they
  left, so one in TIME_WAIT no longer holds the jail up for a minute: with
  the guest's tcpdrop, or a VNET jail's own, which an image may lack.
- Fixes a NAT jail needing ifconfig and route of its own: its network is
  set up with the guest's `/rescue` tools, as an interface jail's is.
- Fixes a relay losing the host's last Data when the host's end finished
  second; stopping a jail returning before the jail is gone, while its TCP
  connections still hold it; and running a command failing when it exited
  before the host closed its input.
- Builds, containers and unpacked images can be stored under the pool of
  FreeBSD's VM image, whose root dataset isn't mounted.
- Preparing a base can skip the first boot's online upgrade, taking seconds
  instead of minutes.
- A protocol for the guest agent: commands, terminals and port relays, side
  by side over the one console, and recovering from corrupted bytes.
- Fixes the session ending when input outpaced the agent: FreeBSD's console
  drops what its tty can't hold, so the agent says what it has read, and the
  host keeps at most 16 KiB unread. Protocol version 2, in guest bundle r4.
- The `kernel-messages` feature shows boot messages when the console stays
  silent. Off by default: it breaks saving.
- Adds patches for virtiofs shared folders in FreeBSD 15.1 guests.
- The guest agent: runs commands on pipes or in a terminal, signals and
  resizes them, and relays to the guest's TCP ports.
