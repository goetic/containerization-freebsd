//! Boots FreeBSD's VM image: its first boot, which installs the guest
//! bundle, a cold boot of the prepared disk, and a restore of its saved
//! state. Run signed, through `bin/dev/test-integration`.

use containerization_freebsd::{Exec, Exit, Output, Share, Upgrade, WindowSize};
use containerization_freebsd_test::{base_disk, bundle};
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

  // A clean base: saved before any share is mounted.
  let state = work.join("state.vzvmsave");
  cold.save(&state).expect("save");
  cold.stop().expect("stop");
  drop(cold);

  let restored = layout.machine("restored").expect("make the machine");
  restored.restore(&state).expect("restore");
  restored.resume().expect("resume");
  restored
    .wait_ready(SECONDS)
    .expect("the agent answers after restoring");
  restored
    .mount_share("shared", "/mnt/shared")
    .expect("mount the share");
  let ran = restored
    .agent
    .check(
      &sh("echo restored; cat /mnt/shared/from-host && echo written in the guest > /mnt/shared/from-guest"),
      SECONDS,
    )
    .expect("use the share after restoring");
  assert_eq!(ran.lines(), ["restored", "written on the host"]);
  assert_eq!(
    std::fs::read_to_string(shared.join("from-guest")).expect("read the guest's file"),
    "written in the guest\n"
  );
  restored
    .save(&work.join("mounted.vzvmsave"))
    .expect_err("save with a share mounted");

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
