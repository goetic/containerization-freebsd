//! Containers: each a jail on its own ZFS clone, with a main process and its
//! own hostname, network, resolver and hosts. Where Containerization gives
//! each Linux container a VM, these share one machine; for a VM each, make a
//! machine each.

use crate::agent::{Agent, Exec, Exit, Output, Process, Ran};
use crate::error::{Error, Result};
use crate::jail::{Jail, Network};
use crate::zfs::Zfs;
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);

/// What a container is made with.
#[derive(Clone, Debug, Default)]
pub struct Configuration {
  /// Its main process, which `Container::start` starts. Its working
  /// directory is a path in the container.
  pub process: Exec,
  /// Defaults to its id.
  pub hostname: Option<String>,
  pub network: Network,
  /// Its resolver. Without one, a container with a network gets the
  /// guest's, unless its root has its own.
  pub dns: Option<Dns>,
  /// Lines added to its root's `/etc/hosts`.
  pub hosts: Vec<Host>,
  /// More jail(8) parameters, as `Jail::start` takes them. Containers mount
  /// devfs already.
  pub parameters: Vec<String>,
}

/// A container's `/etc/resolv.conf`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dns {
  pub nameservers: Vec<String>,
  pub domain: Option<String>,
  pub search: Vec<String>,
  pub options: Vec<String>,
}

/// An `/etc/hosts` line: an address and its names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
  pub address: String,
  pub names: Vec<String>,
}

/// A container: a jail named by its id, on its own clone. Its main process
/// carries its output, input, terminal, signals and exit. Dropping the
/// container kills that process but leaves its jail and clone: `delete` it,
/// or later `Containers::delete` it by id.
pub struct Container<'a> {
  agent: &'a Agent,
  jail: Jail<'a>,
  dataset: String,
  process: Exec,
  main: Option<Process>,
}

impl<'a> Container<'a> {
  /// Clones the snapshot `from` as `dataset`, and starts container `id`'s
  /// jail on it. Ids are unique in the guest: ASCII letters, digits, `-`
  /// and `_`, starting with a letter or digit, and not all digits, which
  /// would name a jail by number.
  pub fn create(agent: &'a Agent, id: &str, from: &str, dataset: &str, configuration: Configuration) -> Result<Self> {
    check_id(id)?;
    let zfs = Zfs::new(agent);
    zfs.clone(from, dataset)?;

    match set_up(agent, id, dataset, &configuration) {
      Ok(jail) => Ok(Self {
        agent,
        jail,
        dataset: dataset.to_string(),
        process: configuration.process,
        main: None,
      }),
      Err(error) => {
        let _ = zfs.destroy(dataset);
        Err(error)
      }
    }
  }

  pub fn id(&self) -> &str {
    self.jail.name()
  }

  pub fn dataset(&self) -> &str {
    &self.dataset
  }

  /// Starts its main process, at most once.
  pub fn start(&mut self) -> Result<()> {
    if self.main.is_some() {
      return Err(Error::Invalid(format!("container {} has started already", self.id())));
    }
    self.main = Some(self.jail.spawn(self.process.clone())?);
    Ok(())
  }

  /// Its main process, once started.
  pub fn process(&self) -> Option<&Process> {
    self.main.as_ref()
  }

  /// Starts another process in it, as `Jail::spawn` does.
  pub fn exec(&self, exec: Exec) -> Result<Process> {
    self.jail.spawn(exec)
  }

  /// As `Agent::run`, in the container.
  pub fn run(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.jail.run(argv, timeout)
  }

  /// As `Agent::check`, in the container.
  pub fn check(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.jail.check(argv, timeout)
  }

  /// Stops its jail: jail(8) sends its processes SIGTERM, and kills those
  /// left after 10 seconds. Its main process's last output and exit can
  /// still be read. Stopping a stopped container does nothing.
  pub fn stop(&self) -> Result<()> {
    stop(self.agent, self.id())
  }

  /// Stops it, and destroys its clone.
  pub fn delete(self) -> Result<()> {
    delete(self.agent, self.id(), &self.dataset)
  }
}

/// The containers of one machine, each cloned as `<store>/<id>`.
pub struct Containers<'a> {
  agent: &'a Agent,
  zfs: Zfs<'a>,
  store: String,
}

impl<'a> Containers<'a> {
  /// Containers under `store`, such as `images/containers`.
  pub fn new(agent: &'a Agent, store: &str) -> Self {
    Self {
      agent,
      zfs: Zfs::new(agent),
      store: store.to_string(),
    }
  }

  /// Creates container `id`, as `Container::create`, on a clone of the
  /// snapshot `from`.
  pub fn create(&self, id: &str, from: &str, configuration: Configuration) -> Result<Container<'a>> {
    Container::create(self.agent, id, from, &self.dataset(id), configuration)
  }

  /// The ids of the store's containers, running or not.
  pub fn list(&self) -> Result<Vec<String>> {
    if !self.zfs.exists(&self.store)? {
      return Ok(Vec::new());
    }
    let prefix = format!("{}/", self.store);

    Ok(
      self
        .zfs
        .children(&self.store)?
        .iter()
        .filter_map(|child| child.strip_prefix(&prefix).map(str::to_string))
        .collect(),
    )
  }

  /// Deletes container `id`, stopping its jail if it runs: for one whose
  /// `Container` is gone, as when its caller exited without deleting it.
  pub fn delete(&self, id: &str) -> Result<()> {
    check_id(id)?;
    delete(self.agent, id, &self.dataset(id))
  }

  fn dataset(&self, id: &str) -> String {
    format!("{}/{id}", self.store)
  }
}

impl Dns {
  /// As resolv.conf(5).
  fn resolv_conf(&self) -> String {
    let mut text = String::new();

    if let Some(domain) = &self.domain {
      text.push_str(&format!("domain {domain}\n"));
    }
    if !self.search.is_empty() {
      text.push_str(&format!("search {}\n", self.search.join(" ")));
    }
    for nameserver in &self.nameservers {
      text.push_str(&format!("nameserver {nameserver}\n"));
    }
    if !self.options.is_empty() {
      text.push_str(&format!("options {}\n", self.options.join(" ")));
    }
    text
  }
}

fn hosts(hosts: &[Host]) -> String {
  hosts
    .iter()
    .map(|host| format!("{} {}\n", host.address, host.names.join(" ")))
    .collect()
}

fn check_id(id: &str) -> Result<()> {
  let allowed = |character: char| character.is_ascii_alphanumeric() || character == '-' || character == '_';
  let valid = id.starts_with(|character: char| character.is_ascii_alphanumeric())
    && id.chars().all(allowed)
    && !id.chars().all(|character| character.is_ascii_digit());

  if valid {
    Ok(())
  } else {
    Err(Error::Invalid(format!("{id:?} can't name a container")))
  }
}

/// Starts container `id`'s jail on `dataset`, and writes its files.
fn set_up<'a>(agent: &'a Agent, id: &str, dataset: &str, configuration: &Configuration) -> Result<Jail<'a>> {
  let root = Zfs::new(agent).mountpoint(dataset)?;
  let hostname = format!("host.hostname={}", configuration.hostname.as_deref().unwrap_or(id));
  let mut parameters = vec!["mount.devfs", hostname.as_str()];
  parameters.extend(configuration.parameters.iter().map(String::as_str));
  let jail = Jail::start(agent, id, &root, configuration.network, &parameters)?;

  match write_files(&jail, configuration) {
    Ok(()) => Ok(jail),
    Err(error) => {
      let _ = jail.stop();
      Err(error)
    }
  }
}

fn write_files(jail: &Jail, configuration: &Configuration) -> Result<()> {
  if let Some(dns) = &configuration.dns {
    write(jail, "/etc/resolv.conf", &dns.resolv_conf(), false)?;
  }
  if !configuration.hosts.is_empty() {
    write(jail, "/etc/hosts", &hosts(&configuration.hosts), true)?;
  }
  Ok(())
}

/// Writes or appends `text` to `path` from inside the jail, so a symlink in
/// its root resolves within the root.
fn write(jail: &Jail, path: &str, text: &str, append: bool) -> Result<()> {
  let script = if append { r#"cat >> "$0""# } else { r#"cat > "$0""# };
  let process = jail.spawn(Exec {
    argv: vec!["/bin/sh".into(), "-c".into(), script.into(), path.into()],
    ..Exec::default()
  })?;
  process.write(text.as_bytes())?;
  process.close_input()?;

  let mut stderr = Vec::new();
  loop {
    match process.recv_timeout(QUICK)? {
      Some(Output::Exited(Exit::Code(0))) => return Ok(()),
      Some(Output::Exited(exit)) => {
        return Err(Error::Guest(format!(
          "writing {path} in jail {} exited {exit:?}: {}",
          jail.name(),
          String::from_utf8_lossy(&stderr).trim()
        )));
      }
      Some(Output::Stderr(bytes)) => stderr.extend(bytes),
      Some(Output::Stdout(_)) => {}
      None => {
        return Err(Error::Timeout(format!(
          "writing {path} in jail {} did not finish within {}s",
          jail.name(),
          QUICK.as_secs()
        )));
      }
    }
  }
}

fn stop(agent: &Agent, id: &str) -> Result<()> {
  match Jail::find(agent, id)? {
    Some(jail) => jail.stop(),
    None => Ok(()),
  }
}

fn delete(agent: &Agent, id: &str, dataset: &str) -> Result<()> {
  stop(agent, id)?;
  Zfs::new(agent).destroy(dataset)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn writes_resolv_conf_with_each_part_given() {
    let dns = Dns {
      nameservers: vec!["10.66.0.1".into(), "192.0.2.53".into()],
      domain: Some("example".into()),
      search: vec!["one.example".into(), "two.example".into()],
      options: vec!["ndots:2".into(), "edns0".into()],
    };

    assert_eq!(
      dns.resolv_conf(),
      "domain example\nsearch one.example two.example\nnameserver 10.66.0.1\nnameserver 192.0.2.53\noptions ndots:2 edns0\n"
    );
    assert_eq!(Dns::default().resolv_conf(), "");
  }

  #[test]
  fn writes_a_hosts_line_for_each_address() {
    let lines = hosts(&[
      Host {
        address: "192.0.2.1".into(),
        names: vec!["db.test".into(), "db".into()],
      },
      Host {
        address: "2001:db8::1".into(),
        names: vec!["cache".into()],
      },
    ]);

    assert_eq!(lines, "192.0.2.1 db.test db\n2001:db8::1 cache\n");
  }

  #[test]
  fn takes_ids_that_name_a_jail_and_a_dataset() {
    for id in ["web", "web-1", "build_2", "1st"] {
      assert!(check_id(id).is_ok(), "{id}");
    }
    for id in ["", "42", "a.b", "a/b", "a b", "-x", "_x", "café"] {
      assert!(check_id(id).is_err(), "{id:?}");
    }
  }
}
