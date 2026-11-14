//! FreeBSD jails in the guest, through its agent.

use crate::agent::{Agent, Exec, Process, Ran};
use crate::error::Result;
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);
/// Runs the rest of its arguments in the directory it gets first.
const IN_DIRECTORY: &str = r#"cd "$0" && exec "$@""#;

pub struct Jail<'a> {
  agent: &'a Agent,
  name: String,
}

impl<'a> Jail<'a> {
  /// Starts a persistent jail named `name`, with that hostname, rooted at
  /// `path` in the guest. `parameters` are jail(8)'s, as `key=value` or a
  /// bare flag such as `mount.devfs`. Without `ip4` or `ip6`, it has no
  /// network; `ip4=inherit` shares the guest's.
  pub fn start(agent: &'a Agent, name: &str, path: &str, parameters: &[&str]) -> Result<Self> {
    let (name_parameter, path_parameter, hostname) = (
      format!("name={name}"),
      format!("path={path}"),
      format!("host.hostname={name}"),
    );
    let mut argv = vec!["jail", "-c", &name_parameter, &path_parameter, &hostname, "persist"];
    argv.extend_from_slice(parameters);
    agent.check(&argv, QUICK)?;

    Ok(Self::running(agent, name))
  }

  /// One already running, such as after a restore.
  pub fn running(agent: &'a Agent, name: &str) -> Self {
    Self {
      agent,
      name: name.to_string(),
    }
  }

  pub fn name(&self) -> &str {
    &self.name
  }

  /// Starts `exec`'s process in the jail, as `Agent::spawn` does in the
  /// guest. Its working directory is a path in the jail.
  pub fn spawn(&self, mut exec: Exec) -> Result<Process> {
    let mut argv = vec!["jexec".to_string(), self.name.clone()];
    if let Some(cwd) = exec.cwd.take() {
      argv.extend(["/bin/sh".into(), "-c".into(), IN_DIRECTORY.into(), cwd]);
    }
    argv.append(&mut exec.argv);

    self.agent.spawn(Exec { argv, ..exec })
  }

  /// As `Agent::run`, in the jail.
  pub fn run(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.agent.run(&self.jexec(argv), timeout)
  }

  /// As `Agent::check`, in the jail.
  pub fn check(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.agent.check(&self.jexec(argv), timeout)
  }

  /// Stops the jail, killing its processes, and unmounts its devfs.
  pub fn stop(self) -> Result<()> {
    let path = self
      .agent
      .check(&["jls", "-j", &self.name, "path"], QUICK)?
      .stdout
      .trim()
      .to_string();
    self.agent.check(&["jail", "-r", &self.name], QUICK)?;

    // jail(8) mounts devfs for `mount.devfs`, but can't unmount it on its
    // own: the parameter is jail(8)'s, not the kernel's, so a jail removed
    // by name has no record of it.
    let devfs = format!("{path}/dev");
    let mounted = self.agent.check(&["mount", "-t", "devfs"], QUICK)?;
    if mounted
      .lines()
      .iter()
      .any(|line| line.starts_with(&format!("devfs on {devfs} ")))
    {
      self.agent.check(&["umount", &devfs], QUICK)?;
    }
    Ok(())
  }

  fn jexec<'b>(&'b self, argv: &[&'b str]) -> Vec<&'b str> {
    let mut all = vec!["jexec", self.name.as_str()];
    all.extend_from_slice(argv);
    all
  }
}
