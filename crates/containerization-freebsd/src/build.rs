//! Cached builds in the guest. Each step runs as root in a jail on a clone
//! of the snapshot before it, and becomes a snapshot named by the sha256 of
//! that snapshot and the step: a step built before is not run again.

use crate::agent::{Agent, Exec, Exit, Output};
use crate::error::{Error, Result};
use crate::jail::{Jail, Network};
use crate::zfs::Zfs;
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);
/// The name of the snapshot each step's dataset ends as.
const BUILT: &str = "built";
/// Removes the resolver configuration from the root at `$1` if it is the
/// guest's, as the jail copied it in: not the step's own.
const UNRESOLVER: &str = r#"! cmp -s /etc/resolv.conf "$1/etc/resolv.conf" || rm "$1/etc/resolv.conf""#;

/// A shell script run as root in the image, by `/bin/sh -c` in `/`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Step {
  pub script: String,
  pub network: Network,
}

impl Step {
  /// With the guest's network: `Network::Inherit`.
  pub fn new(script: impl Into<String>) -> Self {
    Self {
      script: script.into(),
      network: Network::default(),
    }
  }
}

/// What a build made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Built {
  /// The last step's snapshot.
  pub snapshot: String,
  /// How many steps ran, and how many were already built.
  pub ran: usize,
  pub cached: usize,
}

pub struct Builder<'a> {
  agent: &'a Agent,
  zfs: Zfs<'a>,
  store: String,
}

impl<'a> Builder<'a> {
  /// Builds into datasets under `store`, such as `images/builds`, which it
  /// creates if need be.
  pub fn new(agent: &'a Agent, store: &str) -> Self {
    Self {
      agent,
      zfs: Zfs::new(agent),
      store: store.to_string(),
    }
  }

  /// Builds `steps` on the snapshot `from`, running those not built before.
  /// What they print goes to `output`. Builds into the same store must not
  /// run at once.
  pub fn build(&self, from: &str, steps: &[Step], output: &mut dyn FnMut(&[u8])) -> Result<Built> {
    if !self.zfs.exists(&self.store)? {
      self.zfs.create(&self.store)?;
    }
    let mut built = Built {
      snapshot: from.to_string(),
      ran: 0,
      cached: 0,
    };

    for (index, step) in steps.iter().enumerate() {
      let key = self.key(&built.snapshot, step)?;
      let dataset = format!("{}/{key}", self.store);
      let snapshot = format!("{dataset}@{BUILT}");

      if self.zfs.exists(&snapshot)? {
        built.cached += 1;
      } else {
        self
          .run(&built.snapshot, &dataset, &key, step, output)
          .map_err(|error| Error::Guest(format!("step {} of {}: {error}", index + 1, steps.len())))?;
        self.zfs.snapshot(&snapshot)?;
        built.ran += 1;
      }
      built.snapshot = snapshot;
    }
    Ok(built)
  }

  /// The step's key: the sha256 of the snapshot it starts from, its network
  /// and its script.
  fn key(&self, from: &str, step: &Step) -> Result<String> {
    let identity = format!("{from}\n{:?}\n{}", step.network, step.script);
    let ran = self
      .agent
      .check(&["sha256", "-q", "-s", &identity], QUICK)?;

    Ok(ran.stdout.trim().to_string())
  }

  /// Runs `step` in a jail on a fresh clone of `from` at `dataset`, which
  /// is gone again if the step fails.
  fn run(&self, from: &str, dataset: &str, key: &str, step: &Step, output: &mut dyn FnMut(&[u8])) -> Result<()> {
    // Left by a step that failed without cleaning up, such as when the
    // guest stopped.
    if self.zfs.exists(dataset)? {
      self.zfs.destroy(dataset)?;
    }
    self.zfs.clone(from, dataset)?;

    let result = self.in_jail(dataset, key, step, output);
    if result.is_err() {
      let _ = self.zfs.destroy(dataset);
    }
    result
  }

  fn in_jail(&self, dataset: &str, key: &str, step: &Step, output: &mut dyn FnMut(&[u8])) -> Result<()> {
    let root = self.zfs.mountpoint(dataset)?;
    let name = format!("cfbsd-build-{}", &key[..16]);
    let jail = Jail::start(self.agent, &name, &root, step.network, &["mount.devfs"])?;

    let exit = run_script(&jail, &step.script, output);
    jail.stop()?;
    if step.network != Network::None {
      self
        .agent
        .check(&["sh", "-c", UNRESOLVER, "sh", &root], QUICK)?;
    }

    match exit? {
      Exit::Code(0) => Ok(()),
      exit => Err(Error::Guest(format!("the script exited {exit:?}"))),
    }
  }
}

fn run_script(jail: &Jail, script: &str, output: &mut dyn FnMut(&[u8])) -> Result<Exit> {
  let process = jail.spawn(Exec {
    argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
    cwd: Some("/".into()),
    ..Exec::default()
  })?;
  process.close_input()?;

  loop {
    match process.recv()? {
      Output::Stdout(bytes) | Output::Stderr(bytes) => output(&bytes),
      Output::Exited(exit) => return Ok(exit),
    }
  }
}
