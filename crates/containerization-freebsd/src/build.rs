//! Cached builds in the guest. Each step runs as root in a jail on a clone of
//! the previous step's snapshot, and its result is snapshotted under a key
//! hashed from that snapshot's name and the step, so a built step never runs
//! again.

use crate::agent::{Agent, Exec, Exit, Output, QUICK, Spawn};
use crate::digest::sha256;
use crate::error::{Error, Result};
use crate::jail::{Jail, Network};
use crate::scripts;
use crate::zfs::{Cache, SnapshotChain, Zfs};

/// The snapshot taken of each step's dataset once the step succeeds.
const BUILT: &str = "built";

/// A script run as root with `/bin/sh -c`, from `/`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Step {
  pub script: String,
  pub network: Network,
}

impl Step {
  /// A step on `Network::Inherit`.
  pub fn new(script: impl Into<String>) -> Self {
    Self {
      script: script.into(),
      network: Network::default(),
    }
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Built {
  /// The last step's snapshot.
  pub snapshot: String,
  /// Steps that ran, and steps already built.
  pub ran: usize,
  pub cached: usize,
}

pub struct Builder<'a> {
  agent: &'a Agent,
  zfs: Zfs<'a>,
  store: String,
}

impl<'a> Builder<'a> {
  /// Builds into datasets under `store`, such as `images/builds`. `build`
  /// creates and mounts `store` if needed.
  pub fn new(agent: &'a Agent, store: &str) -> Self {
    Self {
      agent,
      zfs: Zfs::new(agent),
      store: store.to_string(),
    }
  }

  /// Builds `steps` on the snapshot `from`, running only those not built
  /// before, with their stdout and stderr to `output`. Builds into one store
  /// must not run concurrently.
  pub fn build(&self, from: &str, steps: &[Step], output: &mut dyn FnMut(&[u8])) -> Result<Built> {
    self.zfs.create_mounted(&self.store)?;
    let chain = SnapshotChain::new(&self.zfs, &self.store, BUILT);
    let mut built = Built {
      snapshot: from.to_string(),
      ran: 0,
      cached: 0,
    };

    for (index, step) in steps.iter().enumerate() {
      let key = key(&built.snapshot, step);
      let (snapshot, cache) = chain
        .link(Some(&built.snapshot), &key, |dataset| {
          self.in_jail(dataset, &key, step, output)
        })
        .map_err(|error| error.context(format!("step {} of {}", index + 1, steps.len())))?;
      match cache {
        Cache::Hit => built.cached += 1,
        Cache::Miss => built.ran += 1,
      }
      built.snapshot = snapshot;
    }
    Ok(built)
  }

  /// Runs `step` in a jail on `dataset`.
  fn in_jail(&self, dataset: &str, key: &str, step: &Step, output: &mut dyn FnMut(&[u8])) -> Result<()> {
    let root = self.zfs.mountpoint(dataset)?;
    let name = format!("cfbsd-build-{}", &key[..16]);
    let jail = Jail::start(self.agent, &name, &root, &step.network, &["mount.devfs"])?;

    let exit = run_script(&jail, &step.script, output);
    jail.stop()?;
    if step.network != Network::None {
      self
        .agent
        .check(&scripts::REMOVE_RESOLV_CONF.argv(&[&root]), QUICK)?;
    }

    match exit? {
      exit if exit.success() => Ok(()),
      exit => Err(Error::Guest(format!("the script exited with {exit}"))),
    }
  }
}

/// The step's cache key: the sha256 of its base snapshot's name, its network
/// kind and its script. Interface addresses are left out, so a step on
/// re-leased interfaces keeps its key.
fn key(from: &str, step: &Step) -> String {
  let network = match step.network {
    // The variants' Debug names, which existing cached steps were keyed by.
    // Changing them invalidates those caches.
    Network::None => "None",
    Network::Inherit => "Inherit",
    Network::Nat => "Nat",
    Network::Interfaces(_) => "Interfaces",
  };
  sha256(format!("{from}\n{network}\n{}", step.script).as_bytes())
}

fn run_script(jail: &Jail, script: &str, output: &mut dyn FnMut(&[u8])) -> Result<Exit> {
  let process = jail.spawn(Exec {
    cwd: Some("/".into()),
    ..Exec::new(["/bin/sh", "-c", script])
  })?;
  process.close_input()?;

  loop {
    match process.recv()? {
      Output::Stdout(bytes) | Output::Stderr(bytes) => output(&bytes),
      Output::Exited(exit) => return Ok(exit),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::jail::Interface;
  use crate::machine::Mac;

  const FROM: &str = "images/userland@base";

  fn on(network: Network) -> Step {
    Step {
      network,
      ..Step::new("echo one")
    }
  }

  fn leased(address: &str) -> Network {
    Network::Interfaces(vec![Interface {
      mac: Mac([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]),
      address: address.into(),
      gateway: Some("192.168.64.1".into()),
    }])
  }

  #[test]
  fn keeps_the_keys_of_steps_built_before() {
    assert_eq!(
      key(FROM, &on(Network::Inherit)),
      "e7187d7e27746dc0bfd6ae4488cabaaf08312ce97e55317bdcfac2e7254604f9"
    );
    assert_eq!(
      key(FROM, &on(Network::None)),
      "f1a9bc418a10888b6829f466d3f2501fe3dd9fb97b32269d6b9357bd9f761801"
    );
  }

  #[test]
  fn keys_a_step_on_interfaces_by_its_network_not_its_addresses() {
    let first = key(FROM, &on(leased("192.168.64.3/24")));

    assert_eq!(key(FROM, &on(leased("192.168.64.140/24"))), first);
    assert_ne!(key(FROM, &on(Network::Nat)), first);
  }
}
