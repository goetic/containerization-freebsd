//! Boots FreeBSD's VM image: its first boot, a cold boot of the prepared
//! disk, and a restore of its saved state. Run signed, through
//! `bin/dev/test-integration`.

use containerization_freebsd::Upgrade;
use containerization_freebsd_test::base_disk;
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

#[test]
fn prepares_boots_and_restores() {
  let base = base_disk();
  let work = work("prepares_boots_and_restores");

  // Not `Upgrade::Latest`: that downloads the release's patches, minutes of a run.
  let layout = containerization_freebsd::prepare(&base, &work, DISK_SIZE, Upgrade::None).expect("prepare the base");
  layout
    .validate_save_restore()
    .expect("the layout can be saved");

  let mut cold = layout.machine("cold").expect("make the machine");
  cold.console.set_echo(true);
  cold.start().expect("start");
  cold
    .wait_ready(Duration::from_secs(300))
    .expect("the console starts");
  let ran = cold
    .console
    .check("freebsd-version -k; ls /dev/ttyV0.0", SECONDS)
    .expect("run a command");
  assert!(ran.text().starts_with("15.1-RELEASE"), "{}", ran.text());

  let state = work.join("state.vzvmsave");
  cold.pause().expect("pause");
  cold.save(&state).expect("save");
  cold.stop().expect("stop");
  drop(cold);

  let mut restored = layout.machine("restored").expect("make the machine");
  restored.restore(&state).expect("restore");
  restored.resume().expect("resume");
  let ran = restored
    .console
    .check("echo restored", SECONDS)
    .expect("run a command after restoring");
  assert_eq!(ran.output, ["restored"]);

  restored
    .shut_down(Duration::from_secs(120))
    .expect("power off");
}
