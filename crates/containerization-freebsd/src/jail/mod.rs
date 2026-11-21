//! Manages FreeBSD jails in the guest through the guest agent.

mod mount;
mod network;

pub use mount::Mount;
pub use network::{Interface, Network};

use crate::agent::{Agent, Exec, Exit, Process, Ran, Relay};
use crate::copy;
use crate::error::{Error, Result};
use crate::quota::{self, Statistics};
use crate::scripts;
use crate::socket::{SocketRelay, UnixSocket};
use containerization_freebsd_protocol::{Address, Connect};
use std::path::Path;
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);
/// How long `scripts::GONE` may wait. Longer than TIME_WAIT, which is twice
/// FreeBSD's default MSL of 30 seconds.
const DYING: Duration = Duration::from_secs(90);

pub struct Jail<'a> {
  agent: &'a Agent,
  name: String,
}

impl<'a> Jail<'a> {
  /// Starts a persistent jail named `name`, rooted at `path` in the guest.
  /// The hostname is `name` unless `parameters` set one. `parameters` are
  /// jail(8) parameters, as `key=value` or a bare flag such as `mount.devfs`.
  /// A jail with a network gets the guest's resolver configuration if it has
  /// none of its own.
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
    let jail = Self::running(agent, name);

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
    }
  }

  /// The running jail named `name`, if any.
  pub fn find(agent: &'a Agent, name: &str) -> Result<Option<Self>> {
    let ran = agent.run(&["jls", "-j", name, "jid"], QUICK)?;

    Ok((ran.exit == Exit::Code(0)).then(|| Self::running(agent, name)))
  }

  pub fn name(&self) -> &str {
    &self.name
  }

  /// Starts `exec`'s process in the jail, as `Agent::spawn` does in the
  /// guest. The working directory is a path in the jail, and the user is
  /// looked up in the jail's `/etc/passwd` and `/etc/group`.
  pub fn spawn(&self, exec: Exec) -> Result<Process> {
    self.agent.spawn(Exec {
      jail: Some(self.name.clone()),
      ..exec
    })
  }

  /// Connects to `port` on the jail's loopback, which is the guest's unless
  /// the jail has its own network.
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

  /// Like `Agent::relay_socket`, with the socket's guest path in the jail.
  pub fn relay_socket(&self, socket: &UnixSocket) -> Result<SocketRelay> {
    self.agent.relay_socket_in(socket, Some(&self.name))
  }

  /// Replaces the jail's limits with rctl(8). The jail's processes together
  /// get `cpus` CPUs and `memory_in_bytes` of resident memory. Beyond those
  /// limits they are slowed or paged out. `stop` lifts the limits.
  pub fn limit(&self, cpus: Option<u32>, memory_in_bytes: Option<u64>) -> Result<()> {
    let rules = quota::rules(&self.name, cpus, memory_in_bytes);
    let mut args = vec![self.name.as_str()];
    args.extend(rules.iter().map(String::as_str));

    self
      .agent
      .check(&scripts::LIMIT.argv(&args), QUICK)
      .map(|_| ())
  }

  /// Copies `source`, a file or directory on the host, into the jail, like
  /// Containerization's `copyIn`. The copy goes to `destination`, or into it
  /// if it is a directory. A copied file gets `mode`. With `create_parents`,
  /// missing parent directories are made. Paths resolve as the jail sees them.
  pub fn copy_in(&self, source: &Path, destination: &str, mode: u32, create_parents: bool) -> Result<()> {
    copy::copy_in(self, source, destination, mode, create_parents)
  }

  /// Copies `source`, a file or directory in the jail, to `destination` on
  /// the host, like Containerization's `copyOut`. A file is written with mode
  /// 0644; a directory's contents are copied into `destination`. With
  /// `create_parents`, the destination's missing parents are made.
  pub fn copy_out(&self, source: &str, destination: &Path, create_parents: bool) -> Result<()> {
    copy::copy_out(self, source, destination, create_parents)
  }

  /// Returns the jail's combined resource usage as rctl(8) accounts it, and
  /// its network counters.
  pub fn statistics(&self) -> Result<Statistics> {
    let ran = self
      .agent
      .check(&["rctl", "-u", &format!("jail:{}", self.name)], QUICK)?;
    let mut statistics = quota::statistics(&ran.stdout)?;
    let ran = self
      .agent
      .check(&scripts::INTERFACES.argv(&[&self.name]), QUICK)?;
    statistics.networks = quota::networks(&ran.stdout)?;

    Ok(statistics)
  }

  /// The guest path of the jail's root.
  fn root(&self) -> Result<String> {
    let ran = self
      .agent
      .check(&["jls", "-j", &self.name, "path"], QUICK)?;

    Ok(ran.stdout.trim_end_matches('\n').to_string())
  }

  /// Like `Agent::run`, in the jail.
  pub fn run(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.agent.run(&self.jexec(argv), timeout)
  }

  /// Like `Agent::check`, in the jail.
  pub fn check(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.agent.check(&self.jexec(argv), timeout)
  }

  /// Stops the jail: kills its processes, drops the TCP connections they
  /// left, and waits for the jail to disappear. A connection that cannot be
  /// dropped delays this by about a minute. Then it runs `clean_up` and
  /// destroys the jail's epair. By then the devices of the jail's interfaces
  /// are back in the guest. Once the jail is removed, a failed step does not
  /// skip the rest, and the first failure is returned.
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
    // Only a VNET jail has interfaces of its own; other jails see the guest's.
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
    // If removal fails, the jail is still running, so stop returns early and a
    // later `find` can stop it again.
    if steps
      .take(self.agent.check(&["jail", "-r", &self.name], QUICK))
      .is_none()
    {
      return steps.finish();
    }
    steps.take(self.agent.check(&scripts::GONE.argv(&[&self.name]), DYING));
    steps.take(clean_up(self.agent, &self.name, path));

    // Destroying one end of an epair destroys both. The outside end belongs
    // to the guest even while the jail is dying.
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

  /// Like `check`, but runs the guest's `/rescue` tool that `argv` names, so
  /// the jail does not need to have the tool.
  fn rescue(&self, argv: &[&str]) -> Result<Ran> {
    let exec = Exec {
      argv: argv.iter().map(|arg| arg.to_string()).collect(),
      jail: Some(self.name.clone()),
      rescue: true,
      ..Exec::default()
    };

    self.agent.check_exec(exec, QUICK)
  }

  fn jexec<'b>(&'b self, argv: &[&'b str]) -> Vec<&'b str> {
    let mut all = vec!["jexec", self.name.as_str()];
    all.extend_from_slice(argv);
    all
  }
}

/// Cleans up after the removed jail named `name`, rooted at `path`. It lifts
/// the jail's limits, which rctl otherwise keeps by name for the next jail of
/// that name. It also unmounts everything in the root except ZFS datasets.
/// That includes devfs: jail(8) mounts it for `mount.devfs` but cannot unmount
/// it, because the parameter belongs to jail(8), not the kernel, so a jail
/// removed by name has no record of it.
pub(crate) fn clean_up(agent: &Agent, name: &str, path: &str) -> Result<()> {
  let mut steps = Steps::default();

  steps.take(agent.check(&scripts::LIMIT.argv(&[name]), QUICK));
  steps.take(agent.check(&scripts::UNMOUNT.argv(&[path]), QUICK));
  steps.finish()
}

/// Collects the first failure among steps that each run even if earlier ones
/// failed.
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
  fn takes_every_step_and_keeps_the_first_failure() {
    let mut steps = Steps::default();

    assert_eq!(steps.take(Ok(1)), Some(1));
    assert_eq!(steps.take::<()>(Err(Error::Invalid("first".into()))), None);
    assert_eq!(steps.take(Ok(2)), Some(2));
    steps.take::<()>(Err(Error::Invalid("second".into())));
    assert!(matches!(steps.finish(), Err(Error::Invalid(why)) if why == "first"));
  }
}
