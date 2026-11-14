//! Boots FreeBSD's VM image: its first boot, which installs the guest
//! bundle, a cold boot of the prepared disk, and a restore of its saved
//! state; and jails on ZFS clones, on a disk of their own. Run signed,
//! through `bin/dev/test-integration`.

use containerization_freebsd::{
  Builder, Disk, Exec, Exit, Jail, Network, Output, Share, Step, Upgrade, WindowSize, Zfs, image,
};
use containerization_freebsd_test::{base_disk, bundle, userland};
use std::path::PathBuf;
use std::time::Duration;

const DISK_SIZE: u64 = 24 << 30;
const SECONDS: Duration = Duration::from_secs(60);

/// A fresh directory for the test's disks and state. Under `target`, so on
/// the same volume as the cache when `target` is: clones are copy-on-write.
fn work(name: &str) -> PathBuf {
  let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);

  let _ = std::fs::remove_dir_all(&directory);
  std::fs::create_dir_all(&directory).expect("make the work directory");
  directory
}

fn sh(script: &str) -> [&str; 3] {
  ["sh", "-c", script]
}

#[test]
fn prepares_boots_and_restores() {
  let work = work("prepares_boots_and_restores");
  let shared = work.join("shared");
  std::fs::create_dir_all(&shared).expect("make the shared directory");
  std::fs::write(shared.join("from-host"), "written on the host\n").expect("write a shared file");

  // Not `Upgrade::Latest`: that downloads the release's patches, minutes of a run.
  let mut layout = containerization_freebsd::prepare(&base_disk(), &work, DISK_SIZE, Upgrade::None, &bundle())
    .expect("prepare the base");
  layout.shares.push(Share {
    tag: "shared".into(),
    path: shared.clone(),
    read_only: false,
  });
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
    .check(&["freebsd-version", "-k"], SECONDS)
    .expect("run a command");
  assert!(ran.stdout.starts_with("15.1-RELEASE"), "{ran:?}");

  // rc loaded the bundle's modules: ours, not the stock fusefs.
  let ran = cold
    .agent
    .check(&sh("kldstat -v | grep -E 'virtiofs|vtfs|fusefs'"), SECONDS)
    .expect("list the modules");
  for module in ["/boot/modules/fusefs.ko", "virtiofs", "vtfs"] {
    assert!(ran.stdout.contains(module), "{module} is not loaded: {ran:?}");
  }

  cold
    .mount_share("shared", "/mnt/shared")
    .expect("mount the share");
  let ran = cold
    .agent
    .check(
      &sh("cat /mnt/shared/from-host && echo written in the guest > /mnt/shared/from-guest"),
      SECONDS,
    )
    .expect("use the share");
  assert_eq!(ran.lines(), ["written on the host"]);
  assert_eq!(
    std::fs::read_to_string(shared.join("from-guest")).expect("read the guest's file"),
    "written in the guest\n"
  );

  // Saving unmounts the share, which it can't while the share is in use.
  let state = work.join("state.vzvmsave");
  cold
    .agent
    .check(
      &sh("(cd /mnt/shared && touch /tmp/busy && exec sleep 30) >/dev/null 2>&1 & while [ ! -e /tmp/busy ]; do sleep 0.1; done"),
      SECONDS,
    )
    .expect("use the share in the background");
  cold.save(&state).expect_err("save with the share in use");
  cold
    .agent
    .check(
      &sh("pkill -x sleep; while pgrep -x sleep >/dev/null; do sleep 0.1; done"),
      SECONDS,
    )
    .expect("stop using the share");
  cold.save(&state).expect("save");
  cold.stop().expect("stop");
  drop(cold);

  // Mounting it again is a second mount in the guest's boot.
  let restored = layout.machine("restored").expect("make the machine");
  restored.restore(&state).expect("restore");
  restored.resume().expect("resume");
  restored
    .wait_ready(SECONDS)
    .expect("the agent answers after restoring");
  restored
    .mount_share("shared", "/mnt/shared")
    .expect("mount the share again");
  let ran = restored
    .agent
    .check(
      &sh("echo restored; cat /mnt/shared/from-host /mnt/shared/from-guest"),
      SECONDS,
    )
    .expect("use the share after restoring");
  assert_eq!(ran.lines(), ["restored", "written on the host", "written in the guest"]);

  let terminal = restored
    .agent
    .spawn(Exec {
      argv: vec!["tty".into()],
      pty: Some(WindowSize { rows: 24, columns: 80 }),
      ..Exec::default()
    })
    .expect("run a command in a terminal");
  let mut output = Vec::new();
  loop {
    match terminal.recv().expect("its output") {
      Output::Stdout(bytes) => output.extend(bytes),
      Output::Exited(exit) => {
        assert_eq!(exit, Exit::Code(0));
        break;
      }
      Output::Stderr(_) => unreachable!("a terminal merges stderr into stdout"),
    }
  }
  assert!(
    output.starts_with(b"/dev/pts/"),
    "{:?}",
    String::from_utf8_lossy(&output)
  );

  restored
    .shut_down(Duration::from_secs(120))
    .expect("power off");
}

#[test]
fn runs_a_jail_on_a_clone_of_the_userland() {
  let work = work("runs_a_jail_on_a_clone_of_the_userland");
  let mut layout = containerization_freebsd::prepare(&base_disk(), &work, DISK_SIZE, Upgrade::None, &bundle())
    .expect("prepare the base");

  let images = Disk {
    path: work.join("images.raw"),
    identifier: "images".into(),
    read_only: false,
  };
  image::create_disk(&images.path, 8 << 30).expect("make the images disk");
  layout.disks.push(images);
  layout.nat = true;
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
  machine
    .mount_share("userland", "/mnt/userland")
    .expect("mount the userland's share");

  let device = machine.disk_device("images").expect("find the images disk");
  let zfs = Zfs::new(&machine.agent);
  zfs
    .create_pool("images", &device)
    .expect("make a pool on the disk");
  zfs
    .create("images/userland")
    .expect("make the userland's dataset");
  zfs
    .extract(&format!("/mnt/userland/{}", image::USERLAND), "images/userland")
    .expect("extract the userland");
  zfs
    .snapshot("images/userland@base")
    .expect("snapshot the userland");
  zfs
    .clone("images/userland@base", "images/jails/first")
    .expect("clone the userland");
  let root = zfs
    .mountpoint("images/jails/first")
    .expect("find the clone");

  let jail = Jail::start(&machine.agent, "first", &root, Network::None, &["mount.devfs"]).expect("start a jail");
  let ran = jail
    .check(&["freebsd-version", "-u"], SECONDS)
    .expect("run a command in the jail");
  assert!(ran.stdout.starts_with("15.1-RELEASE"), "{ran:?}");
  // Its root is the clone: the agent is the guest's, not the jail's.
  jail
    .check(
      &["test", "!", "-e", "/usr/local/sbin/containerization-freebsd-agent"],
      SECONDS,
    )
    .expect("a root of its own");

  // What it writes stays in its clone.
  let process = jail
    .spawn(Exec {
      argv: vec!["sh".into(), "-c".into(), "pwd; echo jailed > mark".into()],
      cwd: Some("/root".into()),
      ..Exec::default()
    })
    .expect("spawn in the jail");
  process.close_input().expect("close its input");
  assert_eq!(process.recv().expect("its output"), Output::Stdout(b"/root\n".to_vec()));
  assert_eq!(process.recv().expect("its exit"), Output::Exited(Exit::Code(0)));
  machine
    .agent
    .check(&["test", "-e", &format!("{root}/root/mark")], SECONDS)
    .expect("the clone has the jail's file");
  machine
    .agent
    .check(&["test", "!", "-e", "/images/userland/root/mark"], SECONDS)
    .expect("the userland does not");

  jail.stop().expect("stop the jail");

  // Each way to the network, tried by pinging the guest's gateway: only pf's
  // NAT gets a NAT jail an answer, as the gateway has no route to 10.66/16.
  let gateway = machine
    .agent
    .check(&sh("route -n get default | awk '/gateway:/ { print $2 }'"), SECONDS)
    .expect("find the guest's gateway")
    .stdout
    .trim()
    .to_string();
  for (network, reaches) in [(Network::None, false), (Network::Inherit, true), (Network::Nat, true)] {
    let jail = Jail::start(
      &machine.agent,
      "first",
      &root,
      network,
      &["mount.devfs", "allow.raw_sockets"],
    )
    .unwrap_or_else(|error| panic!("start a jail with {network:?}: {error}"));
    let ran = jail
      .run(&["ping", "-c", "1", "-t", "5", &gateway], SECONDS)
      .unwrap_or_else(|error| panic!("ping with {network:?}: {error}"));
    assert_eq!(ran.exit == Exit::Code(0), reaches, "{network:?}: {ran:?}");
    jail
      .stop()
      .unwrap_or_else(|error| panic!("stop the jail with {network:?}: {error}"));
  }
  machine
    .agent
    .check(&sh("! ifconfig -g epair | grep -q ."), SECONDS)
    .expect("no epairs left behind");

  zfs
    .destroy("images/jails/first")
    .expect("destroy the clone");
  assert!(!zfs.exists("images/jails/first").expect("list datasets"));

  // Cached builds: each step a snapshot, a step built before skipped.
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
    .check(&sh(&format!("[ \"$(cat {built}/two)\" = one ]")), SECONDS)
    .expect("each step builds on the one before");
  machine
    .agent
    .check(&["test", "!", "-e", &format!("{built}/etc/resolv.conf")], SECONDS)
    .expect("the guest's resolver is not built in");

  // A changed step builds again from there on; one that fails leaves nothing.
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
      SECONDS,
    )
    .expect("only the steps that built have datasets");

  machine
    .shut_down(Duration::from_secs(120))
    .expect("power off");
}
