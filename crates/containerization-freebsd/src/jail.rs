//! FreeBSD jails in the guest, through its agent.

use crate::agent::{Agent, Exec, Process, Ran};
use crate::error::{Error, Result};
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);
/// Runs the rest of its arguments in the directory it gets first.
const IN_DIRECTORY: &str = r#"cd "$0" && exec "$@""#;
/// The bridge NAT jails sit on, and its address: the jails' gateway.
const BRIDGE: &str = "cfbsd0";
const GATEWAY: &str = "10.66.0.1";

/// Sets up NAT for jails once per boot: the bridge, forwarding, and pf
/// translating 10.66/16 to the address of the guest's default interface.
const NAT: &str = r#"set -e
ifconfig cfbsd0 >/dev/null 2>&1 && exit 0
external=$(route -n get default 2>/dev/null | awk '/interface:/ { print $2 }')
if [ -z "$external" ]; then
  echo "the guest has no default route: NAT jails need the machine's NAT" >&2
  exit 1
fi
kldload -n if_bridge if_epair pf
bridge=$(ifconfig bridge create)
ifconfig "$bridge" name cfbsd0 >/dev/null
ifconfig cfbsd0 inet 10.66.0.1/16 up
sysctl -q net.inet.ip.forwarding=1
printf 'set skip on lo0\nnat on %s inet from 10.66.0.0/16 to any -> (%s)\npass all\n' "$external" "$external" |
  pfctl -q -f -
pfctl -s info | grep -q 'Status: Enabled' || pfctl -q -e"#;

/// Gives a NAT jail, `$1`, its loopback, its end of the epair `$2` at
/// address `$3`, and a default route through the bridge at `$4`.
const NAT_JAIL: &str = r#"set -e
jexec "$1" ifconfig lo0 inet 127.0.0.1/8 up
jexec "$1" ifconfig "$2" inet "$3/16" up
jexec "$1" route -q add default "$4""#;

/// Copies the guest's resolver configuration into the jail rooted at `$1`,
/// unless it has its own.
const RESOLVER: &str =
  r#"[ ! -e /etc/resolv.conf ] || [ -e "$1/etc/resolv.conf" ] || cp /etc/resolv.conf "$1/etc/resolv.conf""#;

/// How a jail reaches the network.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Network {
  /// It has none.
  None,
  /// It shares the guest's network stack and addresses.
  #[default]
  Inherit,
  /// It has a stack and an address of its own (VNET), on a bridge in the
  /// guest, and pf NATs it out through the guest's address. Needs the
  /// machine's NAT (`Layout::nat`).
  Nat,
}

pub struct Jail<'a> {
  agent: &'a Agent,
  name: String,
}

impl<'a> Jail<'a> {
  /// Starts a persistent jail named `name`, with that hostname, rooted at
  /// `path` in the guest. `parameters` are jail(8)'s, as `key=value` or a
  /// bare flag such as `mount.devfs`. A jail with a network gets the
  /// guest's resolver configuration if it has none of its own.
  pub fn start(agent: &'a Agent, name: &str, path: &str, network: Network, parameters: &[&str]) -> Result<Self> {
    let (name_parameter, path_parameter, hostname) = (
      format!("name={name}"),
      format!("path={path}"),
      format!("host.hostname={name}"),
    );
    let mut argv = vec!["jail", "-c", &name_parameter, &path_parameter, &hostname, "persist"];

    let epair = match network {
      Network::None => None,
      Network::Inherit => {
        argv.extend(["ip4=inherit", "ip6=inherit"]);
        None
      }
      Network::Nat => Some(epair(agent)?),
    };
    let interface = epair
      .as_ref()
      .map(|epair| format!("vnet.interface={}b", epair.name));
    if let Some(interface) = &interface {
      argv.extend(["vnet", interface.as_str()]);
    }
    argv.extend_from_slice(parameters);

    if let Err(error) = agent.check(&argv, QUICK) {
      if let Some(epair) = &epair {
        let _ = agent.check(&["ifconfig", &format!("{}a", epair.name), "destroy"], QUICK);
      }
      return Err(error);
    }
    let jail = Self::running(agent, name);

    if let Some(epair) = &epair {
      let inside = format!("{}b", epair.name);
      agent.check(
        &["sh", "-c", NAT_JAIL, "sh", name, &inside, &epair.address, GATEWAY],
        QUICK,
      )?;
    }
    if network != Network::None {
      agent.check(&["sh", "-c", RESOLVER, "sh", path], QUICK)?;
    }
    Ok(jail)
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

  /// Stops the jail, killing its processes, unmounts its devfs, and
  /// destroys its epair.
  pub fn stop(self) -> Result<()> {
    let ran = self
      .agent
      .check(&["jls", "-j", &self.name, "path", "vnet"], QUICK)?;
    let (path, vnet) = ran
      .stdout
      .trim()
      .rsplit_once(' ')
      .ok_or_else(|| Error::Guest(format!("jls described jail {}: {:?}", self.name, ran.stdout)))?;
    // Only a VNET jail's interfaces are its own: another sees the guest's.
    let epairs = if vnet == "new" {
      self
        .check(&["ifconfig", "-g", "epair"], QUICK)?
        .lines()
        .iter()
        .map(|inside| inside.trim().to_string())
        .collect()
    } else {
      Vec::new()
    };

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

    // Back in the guest once the jail is gone; destroying one end
    // destroys both.
    for inside in epairs {
      self.agent.check(&["ifconfig", &inside, "destroy"], QUICK)?;
    }
    Ok(())
  }

  fn jexec<'b>(&'b self, argv: &[&'b str]) -> Vec<&'b str> {
    let mut all = vec!["jexec", self.name.as_str()];
    all.extend_from_slice(argv);
    all
  }
}

/// A new epair, its `a` end on the bridge, and the address for its `b` end.
struct Epair {
  /// Such as `epair3`, without the end's letter.
  name: String,
  address: String,
}

fn epair(agent: &Agent) -> Result<Epair> {
  agent.check(&["sh", "-c", NAT], QUICK)?;
  let created = agent.check(&["ifconfig", "epair", "create"], QUICK)?;
  let outside = created.stdout.trim().to_string();
  let name = outside
    .strip_suffix('a')
    .ok_or_else(|| Error::Guest(format!("ifconfig made {outside:?}, not an epair")))?
    .to_string();
  let address = address(&name).ok_or_else(|| Error::Guest(format!("no address for {name}")))?;

  agent.check(&["ifconfig", BRIDGE, "addm", &outside], QUICK)?;
  agent.check(&["ifconfig", &outside, "up"], QUICK)?;
  Ok(Epair { name, address })
}

/// The address for `epair<unit>`'s jail. FreeBSD gives no two live epairs
/// the same unit, so no two NAT jails the same address; `GATEWAY` is .0.1.
fn address(epair: &str) -> Option<String> {
  let index = epair.strip_prefix("epair")?.parse::<u32>().ok()? + 2;

  (index < 0xffff).then(|| format!("10.66.{}.{}", index >> 8, index & 0xff))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn gives_each_epair_unit_its_own_address_after_the_gateway() {
    assert_eq!(address("epair0").as_deref(), Some("10.66.0.2"));
    assert_eq!(address("epair253").as_deref(), Some("10.66.0.255"));
    assert_eq!(address("epair254").as_deref(), Some("10.66.1.0"));
    assert_ne!(address("epair0").as_deref(), Some(GATEWAY));
    assert_eq!(address("epair65533"), None);
    assert_eq!(address("bridge0"), None);
  }
}
