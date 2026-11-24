//! FreeBSD jails in the guest, managed through the guest agent.

mod mount;
mod network;

pub use mount::Mount;
pub use network::{Interface, Network};

use crate::agent::{Agent, Exec, FileType, Process, QUICK, Ran, Relay, Spawn};
use crate::copy::{self, Parents};
use crate::error::{Error, Result};
use crate::scripts;
use crate::socket::{SocketRelay, UnixSocket};
use crate::statistics::{self, Statistics};
use containerization_freebsd_protocol::{Address, Connect, GuestPath};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

/// How long `scripts::GONE` may wait: longer than TIME_WAIT, which is 2 × MSL
/// (`net.inet.tcp.msl`, 30 s by default).
const DYING: Duration = Duration::from_secs(90);

pub struct Jail<'a> {
  agent: &'a Agent,
  name: String,
  /// The guest path of the jail's root, once it is known.
  root: OnceLock<String>,
}

impl<'a> Jail<'a> {
  /// Creates a persistent jail named `name`, rooted at guest path `path`.
  /// `parameters` are jail(8) parameters, as `key=value` or a bare boolean
  /// such as `mount.devfs`; `host.hostname` defaults to `name`. A jail with a
  /// network gets a copy of the guest's resolv.conf unless its root has one.
  pub fn start(agent: &'a Agent, name: &str, path: &str, network: &Network, parameters: &[&str]) -> Result<Self> {
    let (name_parameter, path_parameter, hostname) = (
      format!("name={name}"),
      format!("path={path}"),
      format!("host.hostname={name}"),
    );
    let mut argv = vec!["jail", "-c", &name_parameter, &path_parameter, "persist"];
    if !parameters
      .iter()
      .any(|parameter| parameter.starts_with("host.hostname="))
    {
      argv.push(&hostname);
    }
    let (network_parameters, epair) = network.parameters(agent)?;
    argv.extend(network_parameters.iter().map(String::as_str));
    argv.extend_from_slice(parameters);

    if let Err(error) = agent.check(&argv, QUICK) {
      if let Some(epair) = &epair {
        let _ = epair.destroy(agent);
      }
      return Err(error);
    }
    let jail = Self {
      root: OnceLock::from(path.to_string()),
      ..Self::running(agent, name)
    };

    match jail.configure(path, network, epair.as_ref()) {
      Ok(()) => Ok(jail),
      Err(error) => {
        let _ = jail.stop();
        Err(error)
      }
    }
  }

  /// Refers to a jail that is already running, such as after a restore.
  pub fn running(agent: &'a Agent, name: &str) -> Self {
    Self {
      agent,
      name: name.to_string(),
      root: OnceLock::new(),
    }
  }

  /// The running jail named `name`, if any.
  pub fn find(agent: &'a Agent, name: &str) -> Result<Option<Self>> {
    let ran = agent.run(&["jls", "-j", name, "jid"], QUICK)?;

    Ok(ran.exit.success().then(|| Self::running(agent, name)))
  }

  pub fn name(&self) -> &str {
    &self.name
  }

  /// Connects to `port` on the jail's loopback, which is the guest's unless
  /// it is a VNET jail.
  pub fn connect(&self, port: u16) -> Result<Relay> {
    self.agent.relay(Connect {
      to: Address::Port(port),
      jail: Some(self.name.clone()),
    })
  }

  /// Connects to the Unix socket at `path` in the jail.
  pub fn connect_unix(&self, path: &str) -> Result<Relay> {
    self.agent.relay(Connect {
      to: Address::Unix(path.to_string()),
      jail: Some(self.name.clone()),
    })
  }

  /// The type of file at `path` in the jail, following symlinks as the jail
  /// sees them.
  pub fn file_type(&self, path: &str) -> Result<FileType> {
    self.agent.file_type_at(GuestPath {
      path: path.to_string(),
      jail: Some(self.name.clone()),
    })
  }

  /// Like `Agent::relay_socket`, with the socket's guest path in the jail.
  pub fn relay_socket(&self, socket: &UnixSocket) -> Result<SocketRelay> {
    self.agent.relay_socket_in(socket, Some(&self.name))
  }

  /// Replaces the jail's rctl(8) rules with `pcpu` and `memoryuse` deny
  /// limits on all its processes together: `cpus` CPUs and `memory_in_bytes`
  /// resident. Over a limit, they're throttled or paged out. `stop` lifts the
  /// rules.
  pub fn limit(&self, cpus: Option<u32>, memory_in_bytes: Option<u64>) -> Result<()> {
    let rules = rules(&self.name, cpus, memory_in_bytes);
    let mut args = vec![self.name.as_str()];
    args.extend(rules.iter().map(String::as_str));

    self
      .agent
      .check(&scripts::LIMIT.argv(&args), QUICK)
      .map(|_| ())
  }

  /// Copies `source`, a host file or directory, into the jail, like
  /// Containerization's `copyIn`: to `destination`, or into it if it is a
  /// directory. A copied file gets `mode`. `parents` says whether to create
  /// missing parent directories. Paths resolve as the jail sees them.
  pub fn copy_in(&self, source: &Path, destination: &str, mode: u32, parents: Parents) -> Result<()> {
    copy::copy_in(self, source, destination, mode, parents)
  }

  /// Copies `source`, a file or directory in the jail, to host path
  /// `destination`, like Containerization's `copyOut`. A file is written 0644;
  /// a directory's contents go into `destination`. `parents` says whether to
  /// create missing parent directories.
  pub fn copy_out(&self, source: &str, destination: &Path, parents: Parents) -> Result<()> {
    copy::copy_out(self, source, destination, parents)
  }

  /// The jail's aggregate racct usage (`rctl -u`) and its interface counters.
  pub fn statistics(&self) -> Result<Statistics> {
    self.statistics_with(None)
  }

  /// Like `statistics`, with the ZFS I/O counters of `dataset` if one is
  /// given, all from one script.
  pub(crate) fn statistics_with(&self, dataset: Option<&str>) -> Result<Statistics> {
    let ran = self.agent.check(
      &scripts::STATISTICS.argv(&[&self.name, dataset.unwrap_or_default()]),
      QUICK,
    )?;

    statistics::parse(&ran.stdout, dataset)
  }

  /// The guest path of the jail's root, which `jls` reports if the jail was
  /// found rather than started.
  fn root(&self) -> Result<&str> {
    if let Some(root) = self.root.get() {
      return Ok(root);
    }
    let ran = self
      .agent
      .check(&["jls", "-j", &self.name, "path"], QUICK)?;

    Ok(
      self
        .root
        .get_or_init(|| ran.stdout.trim_end_matches('\n').to_string()),
    )
  }

  /// Stops the jail: kills its processes, drops the TCP connections they
  /// left, removes it and waits for it to finish dying, about a minute longer
  /// if a connection couldn't be dropped. Then runs `clean_up` and destroys
  /// the jail's epair; by then the jail's interface devices are back in the
  /// guest. After removal, a failed step doesn't skip the rest; the first
  /// failure is returned.
  pub fn stop(self) -> Result<()> {
    let ran = self
      .agent
      .check(&["jls", "-j", &self.name, "path", "vnet"], QUICK)?;
    let (path, vnet) = ran
      .stdout
      .trim()
      .rsplit_once(' ')
      .ok_or_else(|| Error::Guest(format!("jls described jail {}: {:?}", self.name, ran.stdout)))?;
    let mut steps = Steps::default();
    // Only a VNET jail has its own interfaces. List its epairs while it can
    // still be entered.
    let epairs = if vnet == "new" {
      steps
        .take(self.rescue(&["ifconfig", "-g", "epair"]))
        .map_or_else(Vec::new, |ran| {
          ran
            .lines()
            .iter()
            .map(|inside| inside.trim().to_string())
            .collect()
        })
    } else {
      Vec::new()
    };

    steps.take(
      self
        .agent
        .check(&scripts::DROP.argv(&[&self.name, vnet]), QUICK),
    );
    // A failed removal leaves the jail running: return early so a later
    // `find` can stop it again.
    if steps
      .take(self.agent.check(&["jail", "-r", &self.name], QUICK))
      .is_none()
    {
      return steps.finish();
    }
    steps.take(self.agent.check(&scripts::GONE.argv(&[&self.name]), DYING));
    steps.take(clean_up(self.agent, &self.name, path));

    // Destroy the outside (a) end, which stays in the guest's vnet even while
    // the jail is dying; that destroys both ends.
    for inside in epairs {
      if let Some(unit) = inside.strip_suffix('b') {
        steps.take(
          self
            .agent
            .check(&["ifconfig", &format!("{unit}a"), "destroy"], QUICK),
        );
      }
    }
    steps.finish()
  }

  /// Like `check`, but runs the guest's `/rescue` tool `argv` names, so the
  /// jail needn't have it.
  fn rescue(&self, argv: &[&str]) -> Result<Ran> {
    let exec = Exec {
      rescue: true,
      ..Exec::new(argv)
    };

    self.check_exec(exec, QUICK)
  }
}

impl Spawn for Jail<'_> {
  /// Starts `exec`'s process in the jail, as `Agent::spawn` does in the
  /// guest. The working directory is a path in the jail, `/` by default, and
  /// the user is looked up in the jail's `/etc/passwd` and `/etc/group`.
  fn spawn(&self, exec: Exec) -> Result<Process> {
    self.agent.spawn(Exec {
      jail: Some(self.name.clone()),
      ..exec
    })
  }
}

/// Cleans up after the removed jail `name`, rooted at `path`: removes its
/// rctl rules, which rctl otherwise keeps by name for the next jail of that
/// name, and unmounts everything under the root except ZFS datasets. That
/// includes devfs: jail(8) mounts it for `mount.devfs`, but `jail -r <name>`
/// can't unmount it, because the parameter lives in jail(8), not the kernel,
/// so a jail removed by name has no record of it.
pub(crate) fn clean_up(agent: &Agent, name: &str, path: &str) -> Result<()> {
  let mut steps = Steps::default();

  steps.take(agent.check(&scripts::LIMIT.argv(&[name]), QUICK));
  steps.take(agent.check(&scripts::UNMOUNT.argv(&[path]), QUICK));
  steps.finish()
}

/// rctl(8) rules denying `jail` more than `cpus` CPUs (`pcpu`) and
/// `memory_in_bytes` of resident memory (`memoryuse`).
fn rules(jail: &str, cpus: Option<u32>, memory_in_bytes: Option<u64>) -> Vec<String> {
  let rule = |resource: &str, amount: Option<u64>| amount.map(|amount| format!("jail:{jail}:{resource}:deny={amount}"));

  [
    rule("pcpu", cpus.map(|cpus| u64::from(cpus) * 100)),
    rule("memoryuse", memory_in_bytes),
  ]
  .into_iter()
  .flatten()
  .collect()
}

/// Keeps the first failure among steps that each run regardless.
#[derive(Default)]
struct Steps(Option<Error>);

impl Steps {
  fn take<T>(&mut self, result: Result<T>) -> Option<T> {
    result
      .map_err(|error| {
        self.0.get_or_insert(error);
      })
      .ok()
  }

  fn finish(self) -> Result<()> {
    self.0.map_or(Ok(()), Err)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn makes_a_rule_for_each_limit_given() {
    assert_eq!(
      rules("web", Some(2), Some(256 << 20)),
      ["jail:web:pcpu:deny=200", "jail:web:memoryuse:deny=268435456"]
    );
    assert_eq!(
      rules("web", None, Some(1 << 30)),
      ["jail:web:memoryuse:deny=1073741824"]
    );
    assert!(rules("web", None, None).is_empty());
  }

  #[test]
  fn takes_every_step_and_keeps_the_first_failure() {
    let mut steps = Steps::default();

    assert_eq!(steps.take(Ok(1)), Some(1));
    assert_eq!(steps.take::<()>(Err(Error::Invalid("first".into()))), None);
    assert_eq!(steps.take(Ok(2)), Some(2));
    steps.take::<()>(Err(Error::Invalid("second".into())));
    assert!(matches!(steps.finish(), Err(Error::Invalid(why)) if why == "first"));
  }
}
