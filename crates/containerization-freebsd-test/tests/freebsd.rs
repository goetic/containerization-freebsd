//! Boots FreeBSD's VM image: its first boot, which installs the guest
//! bundle, a cold boot of the prepared disk, and a restore of its saved
//! state; jails, builds and containers on ZFS clones, on their own disk; OCI
//! images pulled, unpacked into ZFS and run; and a build-sized workload on a
//! share. Run signed, through `bin/dev/test-integration`.

use containerization_freebsd::oci::{ContentStore, Descriptor, Platform, media_type, sha256_digest};
use containerization_freebsd::{
  Builder, Configuration, Containers, Disk, Dns, Exec, Exit, Host, ImageStore, Jail, Network, Output, Share, Step,
  Unpacker, Upgrade, WindowSize, Zfs, image,
};
use containerization_freebsd_test::{base_disk, bundle, cache, userland};
use std::path::{Path, PathBuf};
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

  // Input many windows long, which the console would drop if the host
  // outpaced the agent.
  let input: Vec<u8> = (0..16usize << 20)
    .map(|index| (index.wrapping_mul(2_654_435_761) >> 13) as u8)
    .collect();
  std::fs::write(work.join("input"), &input).expect("write the input");
  let checksum = cold
    .agent
    .spawn(Exec {
      argv: vec!["sha256".into(), "-q".into()],
      ..Exec::default()
    })
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

  // Containers: a main process that stops cleanly on SIGTERM, in its own
  // jail with its own hostname, resolver and hosts.
  let containers = Containers::new(&machine.agent, "images/containers");
  let mut web = containers
    .create(
      "web",
      "images/userland@base",
      Configuration {
        process: Exec {
          argv: vec![
            "sh".into(),
            "-c".into(),
            "trap 'echo stopping; exit 3' TERM; echo started; while :; do sleep 0.1; done".into(),
          ],
          ..Exec::default()
        },
        hostname: Some("web.test".into()),
        network: Network::Nat,
        dns: Some(Dns {
          nameservers: vec!["192.0.2.53".into()],
          search: vec!["test".into()],
          ..Dns::default()
        }),
        hosts: vec![Host {
          address: "192.0.2.1".into(),
          names: vec!["db.test".into(), "db".into()],
        }],
        ..Configuration::default()
      },
    )
    .expect("create a container");
  assert_eq!(containers.list().expect("list containers"), ["web"]);
  web.start().expect("start its main process");
  let main = web.process().expect("its main process");
  assert_eq!(main.recv().expect("its output"), Output::Stdout(b"started\n".to_vec()));

  let ran = web
    .check(&sh("hostname; cat /etc/resolv.conf; getent hosts db"), SECONDS)
    .expect("run a command in the container");
  let lines = ran.lines();
  assert_eq!(
    lines[..3],
    ["web.test", "search test", "nameserver 192.0.2.53"],
    "{ran:?}"
  );
  assert_eq!(
    lines[3].split_whitespace().collect::<Vec<_>>(),
    ["192.0.2.1", "db.test", "db"]
  );

  // Stderr is ignored: sh reports there its sleep dying of SIGTERM.
  web.stop().expect("stop the container");
  let mut stdout = Vec::new();
  let exit = loop {
    match main.recv().expect("its last output") {
      Output::Stdout(bytes) => stdout.extend(bytes),
      Output::Stderr(_) => {}
      Output::Exited(exit) => break exit,
    }
  };
  assert_eq!((stdout.as_slice(), exit), (&b"stopping\n"[..], Exit::Code(3)));
  web.delete().expect("delete the container");

  // One whose handle is gone, deleted by id.
  drop(
    containers
      .create("left", "images/userland@base", Configuration::default())
      .expect("create another container"),
  );
  containers
    .delete("left")
    .expect("delete the container by id");
  assert!(containers.list().expect("list containers").is_empty());
  assert!(
    Jail::find(&machine.agent, "left")
      .expect("look for its jail")
      .is_none()
  );
  machine
    .agent
    .check(&sh("! ifconfig -g epair | grep -q ."), SECONDS)
    .expect("no epairs left behind");

  machine
    .shut_down(Duration::from_secs(120))
    .expect("power off");
}

/// Counts what is under `path`, itself included, as find(1) does.
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

/// A C program of 64 files, built in parallel, which prints 2016.
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

  // Many files: the userland, extracted onto the share, less the 45 names
  // that collide on the Mac's case-insensitive volume (cc and CC, mail and
  // Mail, and man pages).
  let extract = format!(
    "mkdir /mnt/shared/tree && tar -xf /mnt/userland/{} -C /mnt/shared/tree \
     --exclude ./usr/share/man --exclude ./usr/share/openssl/man --exclude ./usr/bin/CC --exclude ./usr/bin/mail \
     && find /mnt/shared/tree | wc -l",
    image::USERLAND
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
    .check(&["sha256", "-q", "/mnt/shared/tree/bin/sh"], SECONDS)
    .expect("checksum in the guest")
    .stdout;
  assert_eq!(guest_sum.trim(), host_sha256(&tree.join("bin/sh")));

  // A parallel build on the share, whose linker writes through mmap.
  let ran = machine
    .agent
    .check(
      &sh("make -C /mnt/shared/project -j4 >/dev/null && /mnt/shared/project/program"),
      Duration::from_secs(300),
    )
    .expect("build on the share");
  assert_eq!(ran.lines(), ["2016"]);
  assert!(shared.join("project/program").exists());

  // Deleting it all again.
  machine
    .agent
    .check(&["rm", "-rf", "/mnt/shared/tree"], Duration::from_secs(600))
    .expect("delete from the share");
  assert!(!tree.exists(), "the host sees the tree gone");

  machine
    .shut_down(Duration::from_secs(120))
    .expect("power off");
}

/// A layer of `files`, each a path and its contents, as a tarball owned by
/// root and without the Mac's metadata, such as `com.apple.provenance`
/// attributes, which FreeBSD can't restore.
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

/// `bytes` in the store, as a blob of `media_type`.
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
  let runtime_config = runtime.config(&platform).expect("its config");
  let (_, runtime_manifest) = runtime.manifest(&platform).expect("its manifest");

  // Two layers on the runtime's, the second hiding a file of the first, every
  // file of a directory, and a file of the runtime's.
  let added = layer(
    &work,
    "added",
    &[
      ("cfbsd/kept", "kept\n"),
      ("cfbsd/gone", "gone\n"),
      ("cfbsd/opaque/old", "old\n"),
    ],
  );
  let hiding = layer(
    &work,
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
  let mut config = runtime_config.clone();
  config
    .rootfs
    .diff_ids
    .extend([sha256_digest(&added), sha256_digest(&hiding)]);
  let mut manifest = runtime_manifest.clone();
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
    .push(blob(content, media_type::LAYER_GZIP, &gzip(&hiding, &work)));
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

  let layout = containerization_freebsd::prepare(&base_disk(), &work, DISK_SIZE, Upgrade::None, &bundle())
    .expect("prepare the base");
  let machine = layout.machine("images").expect("make the machine");
  machine.start().expect("start");
  machine
    .wait_ready(Duration::from_secs(300))
    .expect("the agent starts");

  // Each layer a snapshot, unpacked once whichever image it is in.
  let unpacker = Unpacker::new(&machine.agent, "zroot/cfbsd/layers");
  let base = unpacker
    .unpack(&runtime, &platform)
    .expect("unpack the runtime image");
  assert_eq!((base.unpacked, base.cached), (1, 0));
  let layered = unpacker
    .unpack(&whiteouts, &platform)
    .expect("unpack the image on it");
  assert_eq!((layered.unpacked, layered.cached), (2, 1));
  let again = unpacker
    .unpack(&runtime, &platform)
    .expect("unpack the runtime image again");
  assert_eq!((again.snapshot.as_str(), again.unpacked), (base.snapshot.as_str(), 0));

  // The image's own process: its shell, reading what it is sent.
  let containers = Containers::new(&machine.agent, "zroot/cfbsd/containers");
  let mut shell = containers
    .create(
      "runtime",
      &base.snapshot,
      Configuration {
        process: runtime_config.process(),
        network: Network::None,
        ..Configuration::default()
      },
    )
    .expect("create a container of the image");
  shell.start().expect("start its shell");
  let main = shell.process().expect("its shell");
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

  let hidden = containers
    .create(
      "whiteouts",
      &layered.snapshot,
      Configuration {
        network: Network::None,
        ..Configuration::default()
      },
    )
    .expect("create a container of the layered image");
  let ran = hidden
    .check(
      &sh("cat /cfbsd/kept /cfbsd/x.wh.y; ls -A /cfbsd/opaque /cfbsd; test ! -e /bin/freebsd-version && echo hidden"),
      SECONDS,
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
  hidden.delete().expect("delete the container");

  machine
    .shut_down(Duration::from_secs(120))
    .expect("power off");
}
