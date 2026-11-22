//! Integration tests that boot FreeBSD's VM image. They cover the first boot,
//! which installs the guest bundle; a cold boot of the prepared disk; a
//! restore from saved state; jails, builds and containers on ZFS clones; OCI
//! images pulled, unpacked into ZFS and run; and a build-sized workload on a
//! share. Run them through `bin/dev/test-integration`, which signs them.

use containerization_freebsd::oci::{ContentStore, Descriptor, Digest, Platform, media_type};
use containerization_freebsd::{
  Builder, Configuration, Container, Containers, Direction, Disk, Dns, Exec, Exit, Host, Image, ImageStore, Interface,
  Jail, Limit, Mac, Machine, Mount, Network, Output, Process, Resource, Share, Spawn, Step, UnixSocket, Unpacker,
  Upgrade, User, WindowSize, Zfs, release,
};
use containerization_freebsd_test::{base_disk, bundle, cache, userland};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DISK_SIZE: u64 = 24 << 30;
const TIMEOUT: Duration = Duration::from_secs(60);

/// Returns a fresh directory for a test's disks and state, under `target` so
/// that disks clone copy-on-write when `target` shares an APFS volume with the
/// cache.
fn work(name: &str) -> PathBuf {
  let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);

  let _ = std::fs::remove_dir_all(&directory);
  std::fs::create_dir_all(&directory).expect("make the work directory");
  directory
}

fn sh(script: &str) -> [&str; 3] {
  ["sh", "-c", script]
}

/// Waits for a process to exit and returns its stdout and exit status. Any
/// output on stderr fails the test.
fn finish(process: &Process) -> (String, Exit) {
  let mut stdout = Vec::new();

  loop {
    match process.recv().expect("its output") {
      Output::Stdout(bytes) => stdout.extend(bytes),
      Output::Stderr(bytes) => panic!("{}", String::from_utf8_lossy(&bytes)),
      Output::Exited(exit) => return (String::from_utf8_lossy(&stdout).into_owned(), exit),
    }
  }
}

/// Retries `attempt` for up to a minute and returns its first `Some` value.
/// Use it to wait for a server that was just started.
#[track_caller]
fn eventually<T>(mut attempt: impl FnMut() -> Option<T>) -> T {
  let started = Instant::now();

  loop {
    if let Some(value) = attempt() {
      return value;
    }
    assert!(started.elapsed() < TIMEOUT, "gave up after {}s", TIMEOUT.as_secs());
    std::thread::sleep(Duration::from_millis(100));
  }
}

/// Answers each connection to `listener` with the bytes it sent, in capitals,
/// once the client finishes writing.
fn answer_in_capitals(listener: UnixListener) {
  std::thread::spawn(move || {
    for stream in listener.incoming() {
      let mut stream = stream.expect("a connection");
      let mut received = Vec::new();
      stream
        .read_to_end(&mut received)
        .expect("read the question");
      stream
        .write_all(&received.to_ascii_uppercase())
        .expect("answer");
    }
  });
}

/// Sends `text` to the socket at `path` and returns the reply. The reply is
/// empty if the server closes the connection first.
fn ask(path: &Path, text: &str) -> String {
  let mut stream = UnixStream::connect(path).expect("connect");
  let _ = stream.write_all(text.as_bytes());
  let _ = stream.shutdown(Shutdown::Write);
  let mut answer = String::new();
  let _ = stream.read_to_string(&mut answer);
  answer
}

fn host_sha256(path: &std::path::Path) -> String {
  let output = std::process::Command::new("shasum")
    .args(["-a", "256"])
    .arg(path)
    .output()
    .expect("checksum on the host");

  String::from_utf8_lossy(&output.stdout)
    .split_whitespace()
    .next()
    .unwrap_or_default()
    .to_string()
}

#[test]
fn prepares_boots_and_restores() {
  let work = work("prepares_boots_and_restores");
  let shared = work.join("shared");
  std::fs::create_dir_all(&shared).expect("make the shared directory");
  std::fs::write(shared.join("from-host"), "written on the host\n").expect("write a shared file");

  // `Upgrade::Latest` would download the release's patches, which takes minutes.
  let mut layout = containerization_freebsd::prepare(&base_disk(), &work, DISK_SIZE, Upgrade::None, &bundle())
    .expect("prepare the base");
  layout.shares.push(Share {
    tag: "shared".into(),
    path: shared.clone(),
    read_only: false,
  });
  layout.nat = true;
  layout
    .validate_save_restore()
    .expect("the layout can be saved");

  let cold = layout.machine("cold").expect("make the machine");
  cold.start().expect("start");
  cold
    .wait_ready(Duration::from_secs(300))
    .expect("the agent starts");
  let ran = cold
    .agent
    .check(&["freebsd-version", "-k"], TIMEOUT)
    .expect("run a command");
  assert!(ran.stdout.starts_with("15.1-RELEASE"), "{ran:?}");
  streams_input_across_windows(&cold, &work);
  loads_the_bundles_modules(&cold);
  shares_files_with_the_host(&cold, &shared);
  let state = work.join("state.vzvmsave");
  saves_with_the_share_unused(&cold, &state);
  cold.force_stop().expect("stop");
  drop(cold);

  let restored = layout.machine("restored").expect("make the machine");
  restored.restore(&state).expect("restore");
  restored.resume().expect("resume");
  restored
    .wait_ready(TIMEOUT)
    .expect("the agent answers after restoring");
  resumes_where_it_left_off(&restored);
  runs_a_command_in_a_terminal(&restored);

  restored
    .shut_down(Duration::from_secs(120))
    .expect("power off");
}

/// Streams input spanning many flow-control windows through sha256(1). The
/// virtio console would drop bytes if the host outpaced the agent.
fn streams_input_across_windows(cold: &Machine, work: &Path) {
  let input: Vec<u8> = (0..16usize << 20)
    .map(|index| (index.wrapping_mul(2_654_435_761) >> 13) as u8)
    .collect();
  std::fs::write(work.join("input"), &input).expect("write the input");
  let checksum = cold
    .agent
    .spawn(Exec::new(["sha256", "-q"]))
    .expect("start a checksum");
  checksum.write(&input).expect("stream the input");
  checksum.close_input().expect("end the input");
  let mut sum = Vec::new();
  loop {
    match checksum.recv().expect("its output") {
      Output::Stdout(bytes) => sum.extend(bytes),
      Output::Stderr(bytes) => panic!("{}", String::from_utf8_lossy(&bytes)),
      Output::Exited(exit) => break assert_eq!(exit, Exit::Code(0)),
    }
  }
  assert_eq!(String::from_utf8_lossy(&sum).trim(), host_sha256(&work.join("input")));
}

/// Checks that rc loaded the bundle's patched modules, including its fusefs
/// rather than the stock one.
fn loads_the_bundles_modules(cold: &Machine) {
  let ran = cold
    .agent
    .check(&sh("kldstat -v | grep -E 'virtiofs|vtfs|fusefs'"), TIMEOUT)
    .expect("list the modules");
  for module in ["/boot/modules/fusefs.ko", "virtiofs", "vtfs"] {
    assert!(ran.stdout.contains(module), "{module} is not loaded: {ran:?}");
  }
}

/// Mounts the virtio-fs share of `shared` and reads and writes through it.
fn shares_files_with_the_host(cold: &Machine, shared: &Path) {
  cold
    .mount_share("shared", "/mnt/shared")
    .expect("mount the share");
  let ran = cold
    .agent
    .check(
      &sh("cat /mnt/shared/from-host && echo written in the guest > /mnt/shared/from-guest"),
      TIMEOUT,
    )
    .expect("use the share");
  assert_eq!(ran.lines(), ["written on the host"]);
  assert_eq!(
    std::fs::read_to_string(shared.join("from-guest")).expect("read the guest's file"),
    "written in the guest\n"
  );
}

/// Saves the guest's state to `state`. Saving first unmounts every virtiofs
/// file system, so it fails while the share is busy.
fn saves_with_the_share_unused(cold: &Machine, state: &Path) {
  cold
    .agent
    .check(
      &sh("(cd /mnt/shared && touch /tmp/busy && exec sleep 30) >/dev/null 2>&1 & while [ ! -e /tmp/busy ]; do sleep 0.1; done"),
      TIMEOUT,
    )
    .expect("use the share in the background");
  cold.save(state).expect_err("save with the share in use");
  cold
    .agent
    .check(
      &sh("pkill -x sleep; while pgrep -x sleep >/dev/null; do sleep 0.1; done"),
      TIMEOUT,
    )
    .expect("stop using the share");
  // Set the guest's clock an hour behind. Restoring should correct it.
  cold
    .agent
    .check(&sh("date -f %s $(($(date +%s) - 3600))"), TIMEOUT)
    .expect("set the guest's clock back");
  cold.save(state).expect("save");
}

/// Checks that the restored guest resumes where the cold boot left off: on
/// its NAT network, with its clock corrected, and with the share mounted
/// again.
fn resumes_where_it_left_off(restored: &Machine) {
  // Once its link is back, the guest keeps its saved NAT configuration: the
  // Mac answers through the default route.
  restored
    .agent
    .check(
      &sh("ping -c 1 -t 5 $(route -n get default | awk '/gateway:/ { print $2 }')"),
      TIMEOUT,
    )
    .expect("ping the gateway after restoring");
  let guest: u64 = restored
    .agent
    .check(&["date", "+%s"], TIMEOUT)
    .expect("read the guest's clock")
    .stdout
    .trim()
    .parse()
    .expect("seconds");
  let host = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .expect("the host's clock")
    .as_secs();
  assert!(
    guest.abs_diff(host) <= 5,
    "the guest's clock is {guest}, the host's {host}"
  );
  // The restored guest keeps the cold boot's kernel, so this is its second
  // mount of the share in the same boot.
  restored
    .mount_share("shared", "/mnt/shared")
    .expect("mount the share again");
  let ran = restored
    .agent
    .check(
      &sh("echo restored; cat /mnt/shared/from-host /mnt/shared/from-guest"),
      TIMEOUT,
    )
    .expect("use the share after restoring");
  assert_eq!(ran.lines(), ["restored", "written on the host", "written in the guest"]);
}

/// Runs a command on a pty, reading its output before it exits: FreeBSD
/// discards a pty's unread output a second after its last close.
fn runs_a_command_in_a_terminal(restored: &Machine) {
  let terminal = restored
    .agent
    .spawn(Exec {
      pty: Some(WindowSize { rows: 24, columns: 80 }),
      ..Exec::new(sh("tty; read line"))
    })
    .expect("run a command in a terminal");
  let mut output = Vec::new();
  while !output.contains(&b'\n') {
    match terminal.recv().expect("its output") {
      Output::Stdout(bytes) => output.extend(bytes),
      other => panic!("{other:?} after {:?}", String::from_utf8_lossy(&output)),
    }
  }
  assert!(
    output.starts_with(b"/dev/pts/"),
    "{:?}",
    String::from_utf8_lossy(&output)
  );
  terminal.write(b"\n").expect("answer it");
  let exit = loop {
    match terminal.recv().expect("its last output") {
      Output::Stdout(_) => {}
      Output::Exited(exit) => break exit,
      Output::Stderr(_) => unreachable!("a terminal merges stderr into stdout"),
    }
  };
  assert_eq!(exit, Exit::Code(0));
}

/// The MAC address of the guest's spare NAT device, which a container claims
/// as its own interface.
const SPARE: Mac = Mac([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]);

/// A script that succeeds if the spare device has no IPv4 address.
const UNCONFIGURED: &str = "for device in $(ifconfig -l ether); do \
       if ifconfig \"$device\" ether | grep -q 'ether 02:00:5e:10:00:01'; then \
         ! ifconfig \"$device\" inet | grep -q 'inet '; exit; \
       fi; \
     done; exit 1";

/// Connects to the host the image came from, resolved through the guest's
/// resolver.
const INTERNET: [&str; 7] = ["nc", "-4", "-z", "-w", "10", "download.freebsd.org", "443"];

#[test]
fn runs_a_jail_on_a_clone_of_the_userland() {
  let work = work("runs_a_jail_on_a_clone_of_the_userland");
  let machine = boot_for_jails(&work);
  pool_the_userland(&machine);
  let gateway = machine
    .agent
    .check(&sh("route -n get default | awk '/gateway:/ { print $2 }'"), TIMEOUT)
    .expect("find the guest's gateway")
    .stdout
    .trim()
    .to_string();

  let zfs = Zfs::new(&machine.agent);
  zfs
    .clone("images/userland@base", "images/jails/first")
    .expect("clone the userland");
  let root = zfs
    .mountpoint("images/jails/first")
    .expect("find the clone");
  runs_commands_in_a_jail(&machine, &root);
  reaches_the_network_in_each_mode(&machine, &root, &gateway);
  zfs
    .destroy("images/jails/first")
    .expect("destroy the clone");
  assert!(!zfs.exists("images/jails/first").expect("list datasets"));

  caches_build_steps(&machine);
  let containers = Containers::new(&machine.agent, "images/containers");
  runs_a_container(&machine, &containers);
  limits_a_container(&machine, &containers);
  gives_a_container_an_interface(&machine, &containers, &gateway);
  deletes_containers_left_behind(&machine, &containers);

  machine
    .shut_down(Duration::from_secs(120))
    .expect("power off");
}

/// Boots a guest for jails: with NAT, a spare NAT device, an empty images
/// disk, and the userland's share mounted at `/mnt/userland`.
fn boot_for_jails(work: &Path) -> Machine {
  let mut layout = containerization_freebsd::prepare(&base_disk(), work, DISK_SIZE, Upgrade::None, &bundle())
    .expect("prepare the base");

  let images = Disk::create(work.join("images.raw"), "images", 8 << 30).expect("make the images disk");
  layout.disks.push(images);
  layout.nat = true;
  layout.interfaces.push(SPARE);
  let userland = userland();
  layout.shares.push(Share {
    tag: "userland".into(),
    path: userland.parent().expect("the cache").to_path_buf(),
    read_only: true,
  });

  let machine = layout.machine("jails").expect("make the machine");
  machine.start().expect("start");
  machine
    .wait_ready(Duration::from_secs(300))
    .expect("the agent starts");
  // `wait_ready` waits for the NAT network too, although rc starts the agent
  // before the network.
  machine
    .agent
    .check(&["route", "-n", "get", "default"], TIMEOUT)
    .expect("a default route");
  machine
    .mount_share("userland", "/mnt/userland")
    .expect("mount the userland's share");
  // The guest runs DHCP on its NAT device only, leaving the spare interface
  // for a jail to claim. rc starts devd after netif, so waiting for devd waits
  // for the interfaces' configuration.
  machine
    .agent
    .check(&sh("until pgrep -qx devd; do sleep 0.5; done"), TIMEOUT)
    .expect("rc configures the network");
  let mac = layout.mac;
  machine
    .agent
    .check(
      &sh(&format!(
        "ifconfig vtnet0 | grep -q 'ether {mac}' && ifconfig vtnet0 | grep -q ACCEPT_RTADV"
      )),
      TIMEOUT,
    )
    .expect("vtnet0 is the NAT device, taking router advertisements");
  machine
    .agent
    .check(&sh(UNCONFIGURED), TIMEOUT)
    .expect("the spare has no address");
  machine
}

/// Makes a pool on the images disk and extracts the userland into it, as
/// `images/userland@base`.
fn pool_the_userland(machine: &Machine) {
  let device = machine.disk_device("images").expect("find the images disk");
  let zfs = Zfs::new(&machine.agent);
  zfs
    .create_pool("images", &device)
    .expect("make a pool on the disk");
  zfs
    .create("images/userland")
    .expect("make the userland's dataset");
  zfs
    .extract(&format!("/mnt/userland/{}", release::USERLAND), "images/userland")
    .expect("extract the userland");
  zfs
    .snapshot("images/userland@base")
    .expect("snapshot the userland");
}

fn runs_commands_in_a_jail(machine: &Machine, root: &str) {
  let jail = Jail::start(&machine.agent, "first", root, &Network::None, &["mount.devfs"]).expect("start a jail");
  let ran = jail
    .check(&["freebsd-version", "-u"], TIMEOUT)
    .expect("run a command in the jail");
  assert!(ran.stdout.starts_with("15.1-RELEASE"), "{ran:?}");
  // The jail's root is the clone, which has no agent; only the guest does.
  jail
    .check(
      &["test", "!", "-e", "/usr/local/sbin/containerization-freebsd-agent"],
      TIMEOUT,
    )
    .expect("a root of its own");

  // Files the jail writes stay in its clone.
  let process = jail
    .spawn(Exec {
      cwd: Some("/root".into()),
      ..Exec::new(sh("pwd; echo jailed > mark"))
    })
    .expect("spawn in the jail");
  process.close_input().expect("close its input");
  assert_eq!(process.recv().expect("its output"), Output::Stdout(b"/root\n".to_vec()));
  assert_eq!(process.recv().expect("its exit"), Output::Exited(Exit::Code(0)));
  machine
    .agent
    .check(&["test", "-e", &format!("{root}/root/mark")], TIMEOUT)
    .expect("the clone has the jail's file");
  machine
    .agent
    .check(&["test", "!", "-e", "/images/userland/root/mark"], TIMEOUT)
    .expect("the userland does not");

  jail.stop().expect("stop the jail");
}

/// Tries each network mode, in a jail on the clone at `root`, by pinging the
/// guest's `gateway` and by connecting to the internet. A NAT jail gets
/// answers only through pf's NAT, because the gateway has no route to
/// 10.66/16.
fn reaches_the_network_in_each_mode(machine: &Machine, root: &str, gateway: &str) {
  // Setting up a NAT jail's network must not depend on the jail's own
  // ifconfig or route.
  machine
    .agent
    .check(
      &["rm", &format!("{root}/sbin/ifconfig"), &format!("{root}/sbin/route")],
      TIMEOUT,
    )
    .expect("remove the clone's ifconfig and route");

  for (network, reaches) in [(Network::None, false), (Network::Inherit, true), (Network::Nat, true)] {
    let jail = Jail::start(
      &machine.agent,
      "first",
      root,
      &network,
      &["mount.devfs", "allow.raw_sockets"],
    )
    .unwrap_or_else(|error| panic!("start a jail with {network:?}: {error}"));
    let ran = jail
      .run(&["ping", "-c", "1", "-t", "5", gateway], TIMEOUT)
      .unwrap_or_else(|error| panic!("ping with {network:?}: {error}"));
    assert_eq!(ran.exit.success(), reaches, "{network:?}: {ran:?}");
    let ran = jail
      .run(&INTERNET, TIMEOUT)
      .unwrap_or_else(|error| panic!("connect out with {network:?}: {error}"));
    assert_eq!(ran.exit.success(), reaches, "{network:?} to the internet: {ran:?}");
    // Stopping drops the jail's connection instead of leaving it in TIME_WAIT,
    // which would hold the jail for a minute.
    let stopping = Instant::now();
    jail
      .stop()
      .unwrap_or_else(|error| panic!("stop the jail with {network:?}: {error}"));
    assert!(
      stopping.elapsed() < Duration::from_secs(30),
      "{network:?} took {:?} to stop",
      stopping.elapsed()
    );
  }
  machine
    .agent
    .check(&sh("! ifconfig -g epair | grep -q ."), TIMEOUT)
    .expect("no epairs left behind");
}

/// Builds in cached steps: each step becomes a snapshot, and a step built
/// before is skipped.
fn caches_build_steps(machine: &Machine) {
  let zfs = Zfs::new(&machine.agent);
  let builder = Builder::new(&machine.agent, "images/builds");
  let steps = [
    Step::new("echo one > /one; echo building"),
    Step {
      network: Network::None,
      ..Step::new("cat /one > /two")
    },
  ];
  let mut printed = Vec::new();
  let first = builder
    .build("images/userland@base", &steps, &mut |bytes| {
      printed.extend_from_slice(bytes)
    })
    .expect("build");
  assert_eq!((first.ran, first.cached), (2, 0));
  assert!(String::from_utf8_lossy(&printed).contains("building"), "{printed:?}");
  let again = builder
    .build("images/userland@base", &steps, &mut |_| {})
    .expect("build again");
  assert_eq!((again.ran, again.cached), (0, 2));
  assert_eq!(again.snapshot, first.snapshot);

  let built = first.snapshot.split('@').next().expect("a dataset");
  let built = zfs.mountpoint(built).expect("find the build");
  machine
    .agent
    .check(&sh(&format!("[ \"$(cat {built}/two)\" = one ]")), TIMEOUT)
    .expect("each step builds on the one before");
  machine
    .agent
    .check(&["test", "!", "-e", &format!("{built}/etc/resolv.conf")], TIMEOUT)
    .expect("the guest's resolver is not built in");

  // A changed step rebuilds from that step on. A failing step leaves no
  // dataset.
  let changed = builder
    .build(
      "images/userland@base",
      &[steps[0].clone(), Step::new("echo changed > /two")],
      &mut |_| {},
    )
    .expect("build a changed step");
  assert_eq!((changed.ran, changed.cached), (1, 1));
  let failed = builder
    .build(
      "images/userland@base",
      &[steps[0].clone(), Step::new("exit 3")],
      &mut |_| {},
    )
    .expect_err("build a failing step");
  assert!(failed.to_string().contains("step 2 of 2"), "{failed}");
  machine
    .agent
    .check(
      &sh("[ $(zfs list -H -r -d 1 -o name images/builds | wc -l) -eq 4 ]"),
      TIMEOUT,
    )
    .expect("only the steps that built have datasets");
}

/// Runs a container: a main process that stops cleanly on SIGTERM, in a jail
/// with its own hostname, resolver, hosts, mounts and sockets. The sockets
/// live in the temp directory because the work directory's paths overflow
/// `sun_path`.
fn runs_a_container(machine: &Machine, containers: &Containers) {
  machine
    .agent
    .check(
      &sh("mkdir -p /var/cfbsd-data && echo hello > /var/cfbsd-data/greeting"),
      TIMEOUT,
    )
    .expect("make a guest directory to mount");
  let sockets = std::env::temp_dir().join(format!("cfbsd-{}", std::process::id()));
  std::fs::create_dir_all(&sockets).expect("make a directory for sockets");
  let (host_socket, web_socket) = (sockets.join("host.sock"), sockets.join("web.sock"));
  answer_in_capitals(UnixListener::bind(&host_socket).expect("listen on the host"));
  let mut web = containers
    .create(
      "web",
      "images/userland@base",
      web_configuration(&host_socket, &web_socket),
    )
    .expect("create a container");
  assert_eq!(containers.list().expect("list containers"), ["web"]);
  web.start().expect("start its main process");
  let main = web.main_process().expect("its main process");
  assert_eq!(main.recv().expect("its output"), Output::Stdout(b"started\n".to_vec()));

  sets_its_hostname_resolver_and_hosts(&web);
  uses_its_mounts(&web);
  runs_processes_as_its_users(&web);
  relays_its_sockets(&web, &web_socket);
  counts_its_statistics(&web);

  // The main process's stderr is ignored below: sh reports there that its
  // sleep died of SIGTERM.
  web.stop().expect("stop the container");
  assert!(!web_socket.exists(), "its socket on the host outlived it");
  machine
    .agent
    .check(
      &sh(
        "! mount -p | awk '{ print $2 }' | grep -q '^/images/containers/web/' && \
         test ! -e /images/containers/web/scratch/x",
      ),
      TIMEOUT,
    )
    .expect("its mounts are gone, and the tmpfs's file with them");
  let mut stdout = Vec::new();
  let exit = loop {
    match main.recv().expect("its last output") {
      Output::Stdout(bytes) => stdout.extend(bytes),
      Output::Stderr(_) => {}
      Output::Exited(exit) => break exit,
    }
  };
  assert_eq!((stdout.as_slice(), exit), (&b"stopping\n"[..], Exit::Code(3)));
  // Delete only after the agent has closed the host's socket inside the
  // container.
  web.delete().expect("delete the container");
  std::fs::remove_dir_all(&sockets).expect("remove the sockets' directory");
}

/// The web container's configuration, with the host's socket at
/// `host_socket` inside it and its own socket at `web_socket` on the host.
fn web_configuration(host_socket: &Path, web_socket: &Path) -> Configuration {
  Configuration {
    process: Exec::new(sh(
      "trap 'echo stopping; exit 3' TERM; echo started; while :; do sleep 0.1; done",
    )),
    hostname: Some("web.test".into()),
    network: Network::Nat,
    // The container's own loopback, where nothing answers. getent looks up
    // IPv6 first, which /etc/hosts lacks for db, so it asks DNS; a
    // nameserver outside the guest would stall it until the Mac's network
    // dropped the query.
    dns: Some(Dns {
      nameservers: vec!["127.0.0.1".into()],
      search: vec!["test".into()],
      ..Dns::default()
    }),
    hosts: vec![Host {
      address: "192.0.2.1".into(),
      names: vec!["db.test".into(), "db".into()],
    }],
    mounts: vec![
      Mount::directory("/mnt/userland", "/mnt/userland"),
      Mount::directory("/var/cfbsd-data", "/var/data").read_only(),
      Mount::tmpfs("/scratch"),
    ],
    sockets: vec![
      UnixSocket {
        host: host_socket.to_path_buf(),
        guest: "/var/run/host.sock".into(),
        direction: Direction::Into,
        mode: Some(0o666),
      },
      UnixSocket {
        host: web_socket.to_path_buf(),
        guest: "/var/run/web.sock".into(),
        direction: Direction::OutOf,
        mode: Some(0o600),
      },
    ],
    ..Configuration::default()
  }
}

fn sets_its_hostname_resolver_and_hosts(web: &Container) {
  let ran = web
    .check(&sh("hostname; cat /etc/resolv.conf; getent hosts db"), TIMEOUT)
    .expect("run a command in the container");
  let lines = ran.lines();
  assert_eq!(
    lines[..3],
    ["web.test", "search test", "nameserver 127.0.0.1"],
    "{ran:?}"
  );
  assert_eq!(
    lines[3].split_whitespace().collect::<Vec<_>>(),
    ["192.0.2.1", "db.test", "db"]
  );
}

/// Uses the container's mounts: nullfs mounts of a virtio-fs share and of a
/// read-only guest directory, and a tmpfs.
fn uses_its_mounts(web: &Container) {
  let script = format!(
    "set -e; test -f /mnt/userland/{}; cat /var/data/greeting; \
     touch /var/data/x 2>/dev/null || echo read-only; echo kept > /scratch/x; cat /scratch/x",
    release::USERLAND
  );
  let ran = web.check(&sh(&script), TIMEOUT).expect("use its mounts");
  assert_eq!(ran.lines(), ["hello", "read-only", "kept"]);
}

/// Runs processes as a user in the container's passwd, with supplementary
/// groups, a umask, rlimits and a working directory; and as a uid missing from
/// its passwd.
fn runs_processes_as_its_users(web: &Container) {
  let script = "id -u; id -g; id -G; umask; ulimit -n; echo \"$HOME\"; pwd";
  let (stdout, exit) = finish(
    &web
      .exec(Exec {
        cwd: Some("/var/empty".into()),
        user: Some(User {
          name: "nobody".into(),
          group: None,
          groups: vec!["operator".into(), "4242".into()],
        }),
        umask: Some(0o077),
        limits: vec![Limit {
          resource: Resource::OPEN_FILES,
          soft: 100,
          hard: 100,
        }],
        ..Exec::new(sh(script))
      })
      .expect("run a process as nobody"),
  );
  assert_eq!(exit, Exit::Code(0), "{stdout}");
  let lines: Vec<&str> = stdout.lines().collect();
  assert_eq!(lines[..2], ["65534", "65534"], "{stdout}");
  // On FreeBSD 15, `id -G` lists only supplementary groups.
  let mut groups: Vec<&str> = lines[2].split_whitespace().collect();
  groups.sort_unstable();
  assert_eq!(groups, ["4242", "5"], "{stdout}");
  assert_eq!(lines[3..], ["0077", "100", "/nonexistent", "/var/empty"], "{stdout}");
  let (stdout, exit) = finish(
    &web
      .exec(Exec {
        user: Some(User {
          name: "4242".into(),
          ..User::default()
        }),
        ..Exec::new(sh("id -u; id -g; echo \"$HOME\""))
      })
      .expect("run a process as an unlisted uid"),
  );
  assert_eq!((stdout.as_str(), exit), ("4242\n0\n/\n", Exit::Code(0)));
}

/// Uses the container's sockets: the host's socket inside the container, open
/// to its users; the container's socket at `web_socket` on the host; and a
/// port on the container's loopback.
fn relays_its_sockets(web: &Container, web_socket: &Path) {
  let (stdout, exit) = finish(
    &web
      .exec(Exec {
        user: Some(User {
          name: "nobody".into(),
          ..User::default()
        }),
        ..Exec::new(sh(
          "stat -f %Lp /var/run/host.sock; echo hello | nc -N -U /var/run/host.sock",
        ))
      })
      .expect("use the host's socket"),
  );
  assert_eq!((stdout.as_str(), exit), ("666\nHELLO\n", Exit::Code(0)));
  let mode = std::fs::metadata(web_socket)
    .expect("the container's socket on the host")
    .permissions()
    .mode();
  assert_eq!(mode & 0o777, 0o600);
  let serve = |script: &str| {
    web
      .exec(Exec::new(sh(script)))
      .expect("serve in the container")
  };
  let server = serve("echo pong | nc -N -lU /var/run/web.sock");
  let answer = eventually(|| Some(ask(web_socket, "ping\n")).filter(|answer| !answer.is_empty()));
  assert_eq!(answer, "pong\n");
  assert_eq!(finish(&server), ("ping\n".to_string(), Exit::Code(0)));
  let server = serve("echo pong | nc -N -l 127.0.0.1 7000");
  let relay = eventually(|| web.connect(7000).ok());
  relay.write(b"ping\n").expect("write to its port");
  relay.close_write().expect("finish writing");
  let mut answer = Vec::new();
  while let Some(bytes) = relay.read().expect("read from its port") {
    answer.extend(bytes);
  }
  assert_eq!(answer, b"pong\n");
  assert_eq!(finish(&server), ("ping\n".to_string(), Exit::Code(0)));
}

/// Checks the container's statistics: its network counters, where its
/// loopback carried the relayed traffic, and its dataset's I/O from the files
/// it wrote.
fn counts_its_statistics(web: &Container) {
  let statistics = web.statistics().expect("its statistics");
  let loopback = statistics
    .networks
    .iter()
    .find(|network| network.interface == "lo0")
    .unwrap_or_else(|| panic!("its loopback in {statistics:?}"));
  assert!(loopback.received_bytes > 0, "{statistics:?}");
  assert!(
    statistics
      .networks
      .iter()
      .any(|network| network.interface.starts_with("epair")),
    "{statistics:?}"
  );
  let [dataset] = statistics.block_io.as_slice() else {
    panic!("one dataset in {statistics:?}");
  };
  assert_eq!(dataset.dataset, web.dataset());
  assert!(
    dataset.write_bytes > 0 && dataset.write_operations > 0,
    "{statistics:?}"
  );
}

/// Checks a container's rctl rules and statistics. racct samples memoryuse
/// once a second, so the test waits for a nonzero value.
fn limits_a_container(machine: &Machine, containers: &Containers) {
  let limited = containers
    .create(
      "limited",
      "images/userland@base",
      Configuration {
        cpus: Some(1),
        memory_in_bytes: Some(64 << 20),
        ..Configuration::default()
      },
    )
    .expect("create a container with limits");
  let ran = machine
    .agent
    .check(&["rctl", "jail:limited:"], TIMEOUT)
    .expect("list its rules");
  let mut rules = ran.lines();
  rules.sort_unstable();
  assert_eq!(
    rules,
    ["jail:limited:memoryuse:deny=67108864", "jail:limited:pcpu:deny=100"]
  );
  let sleeper = limited
    .exec(Exec::new(["sleep", "30"]))
    .expect("start a process in it");
  let statistics =
    eventually(|| Some(limited.statistics().expect("its statistics")).filter(|statistics| statistics.memory > 0));
  assert_eq!(statistics.processes, 1, "{statistics:?}");
  assert!(statistics.networks.is_empty(), "the guest's network in {statistics:?}");
  drop(sleeper);
  limited.delete().expect("delete the container with limits");
  let ran = machine
    .agent
    .check(&["rctl", "jail:limited:"], TIMEOUT)
    .expect("list its rules again");
  assert_eq!(ran.stdout, "", "its rules outlived it");
}

/// Gives a container its own interface on the NAT network, at an address the
/// NAT's DHCP server leased. The host can reach it and it can reach the
/// internet. Deleting the container returns the device to the guest.
fn gives_a_container_an_interface(machine: &Machine, containers: &Containers, gateway: &str) {
  let interface = Interface::leased(&machine.agent, SPARE).expect("lease an address");
  assert_eq!(interface.gateway.as_deref(), Some(gateway), "{interface:?}");
  machine
    .agent
    .check(&sh(UNCONFIGURED), TIMEOUT)
    .expect("leasing configures nothing");
  let address = interface
    .address
    .split_once('/')
    .expect("a prefix length")
    .0
    .to_string();
  let reachable = containers
    .create(
      "reachable",
      "images/userland@base",
      Configuration {
        network: Network::Interfaces(vec![interface]),
        ..Configuration::default()
      },
    )
    .expect("create a container with an interface");
  let server = reachable
    .exec(Exec::new(sh("echo reached | nc -N -l 8080")))
    .expect("serve in the container");
  let address: std::net::SocketAddr = format!("{address}:8080").parse().expect("its address");
  let mut stream = eventually(|| std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)).ok());
  stream
    .set_read_timeout(Some(TIMEOUT))
    .expect("time out reading");
  let mut answer = String::new();
  stream.read_to_string(&mut answer).expect("read from it");
  assert_eq!(answer, "reached\n");
  // nc keeps reading until the host closes the connection.
  drop(stream);
  assert_eq!(finish(&server), (String::new(), Exit::Code(0)));
  reachable
    .check(&INTERNET, TIMEOUT)
    .expect("connect out from its interface");
  reachable
    .delete()
    .expect("delete the container with an interface");
  machine
    .agent
    .check(&sh("ifconfig -a | grep -q 'ether 02:00:5e:10:00:01'"), TIMEOUT)
    .expect("its device is back in the guest");
}

fn deletes_containers_left_behind(machine: &Machine, containers: &Containers) {
  // A container whose handle was dropped can be deleted by id, mounts and all.
  drop(
    containers
      .create(
        "left",
        "images/userland@base",
        Configuration {
          mounts: vec![Mount::tmpfs("/scratch")],
          ..Configuration::default()
        },
      )
      .expect("create another container"),
  );
  containers
    .delete("left")
    .expect("delete the container by id");
  // A container whose jail is gone but whose limits and mounts remain, as
  // after removal outside the library or a stop that failed partway. Deleting
  // it removes the limits and mounts too.
  drop(
    containers
      .create(
        "removed",
        "images/userland@base",
        Configuration {
          memory_in_bytes: Some(64 << 20),
          mounts: vec![Mount::tmpfs("/scratch")],
          ..Configuration::default()
        },
      )
      .expect("create a container to remove"),
  );
  machine
    .agent
    .check(&["jail", "-r", "removed"], TIMEOUT)
    .expect("remove its jail outside");
  containers
    .delete("removed")
    .expect("delete the container whose jail is gone");
  let ran = machine
    .agent
    .check(&["rctl", "jail:removed:"], TIMEOUT)
    .expect("list its rules");
  assert_eq!(ran.stdout, "", "its rules outlived it");
  assert!(containers.list().expect("list containers").is_empty());
  assert!(
    Jail::find(&machine.agent, "left")
      .expect("look for its jail")
      .is_none()
  );
  machine
    .agent
    .check(&sh("! ifconfig -g epair | grep -q ."), TIMEOUT)
    .expect("no epairs left behind");
}

/// Counts the entries under `path`, including `path` itself, as find(1) does.
fn entries(path: &std::path::Path) -> usize {
  let children = std::fs::read_dir(path)
    .map(|children| {
      children
        .map(|child| {
          let child = child.expect("read a directory entry");
          let kind = child.file_type().expect("read an entry's type");
          if kind.is_dir() { entries(&child.path()) } else { 1 }
        })
        .sum()
    })
    .unwrap_or(0);

  1 + children
}

/// Writes a C project of 64 units, a `main.c` and a Makefile into `project`.
/// The built program prints 2016, the sum of the units' return values.
fn write_project(project: &std::path::Path) {
  const UNITS: usize = 64;

  std::fs::create_dir_all(project).expect("make the project");
  let mut main = String::from("#include <stdio.h>\n");
  let mut sum = String::new();
  let mut objects = String::from("main.o");
  for unit in 0..UNITS {
    std::fs::write(
      project.join(format!("unit{unit}.c")),
      format!("int unit{unit}(void) {{ return {unit}; }}\n"),
    )
    .expect("write a unit");
    main.push_str(&format!("int unit{unit}(void);\n"));
    sum.push_str(&format!("  sum += unit{unit}();\n"));
    objects.push_str(&format!(" unit{unit}.o"));
  }
  main.push_str(&format!(
    "int main(void) {{\n  int sum = 0;\n{sum}  printf(\"%d\\n\", sum);\n  return 0;\n}}\n"
  ));
  std::fs::write(project.join("main.c"), main).expect("write main");
  std::fs::write(
    project.join("Makefile"),
    format!("program: {objects}\n\tcc -o $@ {objects}\n"),
  )
  .expect("write the Makefile");
}

#[test]
fn runs_a_build_sized_workload_on_a_share() {
  let work = work("runs_a_build_sized_workload_on_a_share");
  let shared = work.join("shared");
  write_project(&shared.join("project"));

  let mut layout = containerization_freebsd::prepare(&base_disk(), &work, DISK_SIZE, Upgrade::None, &bundle())
    .expect("prepare the base");
  let userland = userland();
  layout.shares.push(Share {
    tag: "shared".into(),
    path: shared.clone(),
    read_only: false,
  });
  layout.shares.push(Share {
    tag: "userland".into(),
    path: userland.parent().expect("the cache").to_path_buf(),
    read_only: true,
  });

  let machine = layout.machine("workload").expect("make the machine");
  machine.start().expect("start");
  machine
    .wait_ready(Duration::from_secs(300))
    .expect("the agent starts");
  machine
    .mount_share("shared", "/mnt/shared")
    .expect("mount the share");
  machine
    .mount_share("userland", "/mnt/userland")
    .expect("mount the userland's share");

  // Extract the userland onto the share for many files, minus the 45 names
  // that collide on the Mac's case-insensitive volume: CC (cc), mail (Mail),
  // and man pages, whose trees are excluded whole.
  let extract = format!(
    "mkdir /mnt/shared/tree && tar -xf /mnt/userland/{} -C /mnt/shared/tree \
     --exclude ./usr/share/man --exclude ./usr/share/openssl/man --exclude ./usr/bin/CC --exclude ./usr/bin/mail \
     && find /mnt/shared/tree | wc -l",
    release::USERLAND
  );
  let ran = machine
    .agent
    .check(&sh(&extract), Duration::from_secs(600))
    .expect("extract onto the share");
  let in_guest: usize = ran.stdout.trim().parse().expect("a count");
  let tree = shared.join("tree");
  assert_eq!(entries(&tree), in_guest, "the host sees what the guest wrote");
  let guest_sum = machine
    .agent
    .check(&["sha256", "-q", "/mnt/shared/tree/bin/sh"], TIMEOUT)
    .expect("checksum in the guest")
    .stdout;
  assert_eq!(guest_sum.trim(), host_sha256(&tree.join("bin/sh")));

  // A parallel build on the share. The linker writes its output through mmap.
  let ran = machine
    .agent
    .check(
      &sh("make -C /mnt/shared/project -j4 >/dev/null && /mnt/shared/project/program"),
      Duration::from_secs(300),
    )
    .expect("build on the share");
  assert_eq!(ran.lines(), ["2016"]);
  assert!(shared.join("project/program").exists());

  machine
    .agent
    .check(&["rm", "-rf", "/mnt/shared/tree"], Duration::from_secs(600))
    .expect("delete from the share");
  assert!(!tree.exists(), "the host sees the tree gone");

  machine
    .shut_down(Duration::from_secs(120))
    .expect("power off");
}

/// Returns a layer tarball holding `files`, given as paths and contents. The
/// files are owned by root and carry no macOS metadata (AppleDouble files,
/// ACLs, xattrs such as `com.apple.provenance`), which FreeBSD can't restore.
fn layer(work: &Path, name: &str, files: &[(&str, &str)]) -> Vec<u8> {
  let staging = work.join(name);
  let mut tops: Vec<&str> = Vec::new();
  for (path, contents) in files {
    let file = staging.join(path);
    std::fs::create_dir_all(file.parent().expect("a directory")).expect("make the layer's directories");
    std::fs::write(&file, contents).expect("write a layer's file");
    let top = path.split('/').next().expect("a path");
    if !tops.contains(&top) {
      tops.push(top);
    }
  }

  let tarball = work.join(format!("{name}.tar"));
  let status = std::process::Command::new("tar")
    .env("COPYFILE_DISABLE", "1")
    .args([
      "--no-mac-metadata",
      "--no-xattrs",
      "--no-acls",
      "--uid",
      "0",
      "--gid",
      "0",
      "-cf",
    ])
    .arg(&tarball)
    .arg("-C")
    .arg(&staging)
    .args(&tops)
    .status()
    .expect("run tar");
  assert!(status.success(), "tar the layer");
  std::fs::read(&tarball).expect("read the layer")
}

fn gzip(bytes: &[u8], work: &Path) -> Vec<u8> {
  let path = work.join("gzip-input");
  std::fs::write(&path, bytes).expect("write gzip's input");
  let output = std::process::Command::new("gzip")
    .args(["-c", "-n"])
    .arg(&path)
    .output()
    .expect("run gzip");
  assert!(output.status.success(), "gzip the layer");
  output.stdout
}

/// Stores `bytes` as a blob of `media_type` and returns its descriptor.
fn blob(content: &ContentStore, media_type: &str, bytes: &[u8]) -> Descriptor {
  Descriptor {
    media_type: media_type.into(),
    digest: content.ingest(bytes).expect("store a blob"),
    size: bytes.len() as u64,
    platform: None,
    annotations: Default::default(),
  }
}

#[test]
fn pulls_unpacks_and_runs_oci_images() {
  let work = work("pulls_unpacks_and_runs_oci_images");
  let platform = Platform::default();
  let store = ImageStore::new(&cache().join("images")).expect("open the image store");
  let runtime = store
    .pull("ghcr.io/freebsd/freebsd-runtime:15.1", &platform, None)
    .expect("pull FreeBSD's runtime image");
  let whiteouts = layers_an_image_on_the_runtime(&work, &store, &runtime, &platform);

  let layout = containerization_freebsd::prepare(&base_disk(), &work, DISK_SIZE, Upgrade::None, &bundle())
    .expect("prepare the base");
  let machine = layout.machine("images").expect("make the machine");
  machine.start().expect("start");
  machine
    .wait_ready(Duration::from_secs(300))
    .expect("the agent starts");

  let (base, layered) = unpacks_each_layer_once(&machine, &runtime, &whiteouts, &platform);
  let containers = Containers::new(&machine.agent, "zroot/cfbsd/containers");
  runs_the_images_process(&containers, &runtime, &platform, &base);
  let hidden = containers
    .create(
      "whiteouts",
      &layered,
      Configuration {
        network: Network::None,
        ..Configuration::default()
      },
    )
    .expect("create a container of the layered image");
  applies_whiteouts(&hidden);
  copies_in_and_out(&hidden, &work);
  hidden.delete().expect("delete the container");

  machine
    .shut_down(Duration::from_secs(120))
    .expect("power off");
}

/// Makes an image of two layers on top of the runtime's and names it
/// `localhost/cfbsd/whiteouts:1`. The second layer whites out a file from the
/// first and one from the runtime's, and makes a directory opaque.
fn layers_an_image_on_the_runtime(work: &Path, store: &ImageStore, runtime: &Image, platform: &Platform) -> Image {
  let added = layer(
    work,
    "added",
    &[
      ("cfbsd/kept", "kept\n"),
      ("cfbsd/gone", "gone\n"),
      ("cfbsd/opaque/old", "old\n"),
    ],
  );
  let hiding = layer(
    work,
    "hiding",
    &[
      ("cfbsd/.wh.gone", ""),
      ("cfbsd/opaque/.wh..wh..opq", ""),
      ("cfbsd/opaque/new", "new\n"),
      ("cfbsd/x.wh.y", "kept too\n"),
      ("bin/.wh.freebsd-version", ""),
    ],
  );
  let content = store.content();
  let mut config = runtime.config(platform).expect("its config");
  config
    .rootfs
    .diff_ids
    .extend([Digest::of(&added), Digest::of(&hiding)]);
  let (_, mut manifest) = runtime.manifest(platform).expect("its manifest");
  manifest.config = blob(
    content,
    media_type::CONFIG,
    &serde_json::to_vec(&config).expect("encode the config"),
  );
  manifest
    .layers
    .push(blob(content, media_type::LAYER, &added));
  manifest
    .layers
    .push(blob(content, media_type::LAYER_GZIP, &gzip(&hiding, work)));
  let manifest = blob(
    content,
    media_type::MANIFEST,
    &serde_json::to_vec(&manifest).expect("encode the manifest"),
  );
  let whiteouts = store
    .create("localhost/cfbsd/whiteouts:1", manifest)
    .expect("name the image");
  let names: Vec<String> = store
    .list()
    .expect("list images")
    .into_iter()
    .map(|image| image.reference)
    .collect();
  for name in ["ghcr.io/freebsd/freebsd-runtime:15.1", "localhost/cfbsd/whiteouts:1"] {
    assert!(names.iter().any(|listed| listed == name), "{name} in {names:?}");
  }
  whiteouts
}

/// Unpacks the runtime image and `layered`, an image on it, and returns their
/// snapshots. Each layer becomes a snapshot, unpacked once however many
/// images share it.
fn unpacks_each_layer_once(
  machine: &Machine,
  runtime: &Image,
  layered: &Image,
  platform: &Platform,
) -> (String, String) {
  let unpacker = Unpacker::new(&machine.agent, "zroot/cfbsd/layers");
  let base = unpacker
    .unpack(runtime, platform)
    .expect("unpack the runtime image");
  assert_eq!((base.unpacked, base.cached), (1, 0));
  let layered = unpacker
    .unpack(layered, platform)
    .expect("unpack the image on it");
  assert_eq!((layered.unpacked, layered.cached), (2, 1));
  let again = unpacker
    .unpack(runtime, platform)
    .expect("unpack the runtime image again");
  assert_eq!((again.snapshot.as_str(), again.unpacked), (base.snapshot.as_str(), 0));
  (base.snapshot, layered.snapshot)
}

/// Runs a container of the runtime image, at `snapshot`, with the image's
/// configured process: a shell that reads commands from stdin.
fn runs_the_images_process(containers: &Containers, runtime: &Image, platform: &Platform, snapshot: &str) {
  let mut shell = containers
    .create(
      "runtime",
      snapshot,
      Configuration {
        process: runtime.config(platform).expect("its config").process(),
        network: Network::None,
        ..Configuration::default()
      },
    )
    .expect("create a container of the image");
  shell.start().expect("start its shell");
  let main = shell.main_process().expect("its shell");
  main
    .write(b"freebsd-version -u; exit 3\n")
    .expect("give it commands");
  main.close_input().expect("end its input");
  let mut stdout = Vec::new();
  let exit = loop {
    match main.recv().expect("its output") {
      Output::Stdout(bytes) => stdout.extend(bytes),
      Output::Stderr(bytes) => panic!("{}", String::from_utf8_lossy(&bytes)),
      Output::Exited(exit) => break exit,
    }
  };
  assert!(
    stdout.starts_with(b"15.1-RELEASE"),
    "{}",
    String::from_utf8_lossy(&stdout)
  );
  assert_eq!(exit, Exit::Code(3));
  shell.delete().expect("delete the container");
}

/// Checks `hidden`, a container of the layered image: the whiteouts hide a
/// file from the first layer, the opaque directory's old file and a file from
/// the runtime, while a name that only contains `.wh.` stays.
fn applies_whiteouts(hidden: &Container) {
  let ran = hidden
    .check(
      &sh("cat /cfbsd/kept /cfbsd/x.wh.y; ls -A /cfbsd/opaque /cfbsd; test ! -e /bin/freebsd-version && echo hidden"),
      TIMEOUT,
    )
    .expect("look at its files");
  assert_eq!(
    ran.lines(),
    [
      "kept",
      "kept too",
      "/cfbsd:",
      "kept",
      "opaque",
      "x.wh.y",
      "",
      "/cfbsd/opaque:",
      "new",
      "hidden"
    ]
  );
}

/// Copies files and directories in and out of `hidden`, through the guest's
/// `/rescue` tools rather than the image's.
fn copies_in_and_out(hidden: &Container, work: &Path) {
  let copies = work.join("copies");
  let tree = copies.join("tree");
  std::fs::create_dir_all(tree.join("sub")).expect("make a tree to copy");
  std::fs::write(tree.join("one"), "one\n").expect("write a file of the tree");
  std::fs::write(tree.join("sub/two"), "two\n").expect("write a file of the tree");
  let big: Vec<u8> = (0..1u32 << 20).map(|i| (i % 251) as u8).collect();
  std::fs::write(copies.join("big"), &big).expect("write a file to copy");
  hidden
    .copy_in(&copies.join("big"), "/cfbsd/new/", 0o644, true)
    .expect_err("copy a file into a missing directory");
  hidden
    .copy_in(&copies.join("big"), "/cfbsd/new/big", 0o600, true)
    .expect("copy a file in");
  hidden
    .copy_in(&tree, "/cfbsd", 0o644, true)
    .expect("copy a directory into a directory");
  hidden
    .copy_in(&tree, "/cfbsd/kept", 0o644, true)
    .expect_err("copy a directory over a file");
  let ran = hidden
    .check(
      &sh("ls -ln /cfbsd/new/big /cfbsd/tree/sub/two | while read mode links uid rest; do echo $mode $uid; done; cat /cfbsd/tree/one"),
      TIMEOUT,
    )
    .expect("look at the files copied in");
  assert_eq!(ran.lines(), ["-rw------- 0", "-rw-r--r-- 0", "one"]);
  let out = copies.join("out");
  hidden
    .copy_out("/cfbsd/new/big", &out.join("big"), true)
    .expect("copy a file out");
  assert_eq!(std::fs::read(out.join("big")).expect("read the file copied out"), big);
  let mode = std::fs::metadata(out.join("big"))
    .expect("the file copied out")
    .permissions()
    .mode();
  assert_eq!(mode & 0o777, 0o644);
  hidden
    .copy_out("/cfbsd/tree", &out.join("tree"), true)
    .expect("copy a directory out");
  for (path, text) in [("one", "one\n"), ("sub/two", "two\n")] {
    let copied = std::fs::read_to_string(out.join("tree").join(path)).expect("read a file copied out");
    assert_eq!(copied, text);
  }
  hidden
    .copy_out("/cfbsd/missing", &out.join("missing"), true)
    .expect_err("copy out what is missing");
  // Copying refuses devices and FIFOs, which could block or never end.
  hidden
    .copy_out("/dev/null", &out.join("null"), true)
    .expect_err("copy out a device");
  hidden
    .copy_in(&copies.join("big"), "/dev/null", 0o644, true)
    .expect_err("copy over a device");
  let fifo = copies.join("fifo");
  let made = std::process::Command::new("mkfifo")
    .arg(&fifo)
    .status()
    .expect("run mkfifo");
  assert!(made.success(), "make a FIFO on the host");
  hidden
    .copy_in(&fifo, "/cfbsd/fifo", 0o644, true)
    .expect_err("copy in a FIFO");
}
