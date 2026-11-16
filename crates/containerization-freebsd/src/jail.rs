//! FreeBSD jails in the guest, through its agent.

use crate::agent::{Agent, Exec, Exit, Process, Ran, Relay};
use crate::copy;
use crate::error::{Error, Result};
use crate::quota::{self, Statistics};
use crate::socket::{SocketRelay, UnixSocket};
use containerization_freebsd_protocol::{Address, Connect};
use std::path::Path;
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);
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

/// Waits for the jail named `$1` to be gone: once removed, it is dying
/// until what it left closes, such as a TCP connection in TIME_WAIT, and
/// until then holds its root and its network.
const GONE: &str = r#"while jls -d -j "$1" >/dev/null 2>&1; do sleep 0.1; done"#;
/// Past TIME_WAIT: twice FreeBSD's default MSL of 30 seconds.
const DYING: Duration = Duration::from_secs(90);

/// Copies the guest's resolver configuration into the jail rooted at `$1`,
/// unless it has its own.
const RESOLVER: &str =
  r#"[ ! -e /etc/resolv.conf ] || [ -e "$1/etc/resolv.conf" ] || cp /etc/resolv.conf "$1/etc/resolv.conf""#;

/// Prints `$2`, a path in the jail rooted at `$1`, as the guest's path to
/// what the jail would find there, and makes the directories it lacks.
/// Symbolic links resolve within the root, absolute ones from it, and `..`
/// stops at it.
const RESOLVE: &str = r#"set -e
root=$1 rest=$2 resolved= links=0
while [ -n "$rest" ]; do
  part=${rest%%/*}
  case $rest in */*) rest=${rest#*/} ;; *) rest= ;; esac
  case $part in
  '' | .) ;;
  ..) resolved=${resolved%/*} ;;
  *)
    if [ -L "$root$resolved/$part" ]; then
      links=$((links + 1))
      if [ "$links" -gt 32 ]; then
        echo "$2: too many symbolic links" >&2
        exit 1
      fi
      target=$(readlink "$root$resolved/$part")
      case $target in /*) resolved= ;; esac
      rest=$target/$rest
    else
      resolved=$resolved/$part
    fi
    ;;
  esac
done
if [ -z "$resolved" ]; then
  echo "$2: that is the jail's root" >&2
  exit 1
fi
mkdir -p "$root$resolved"
printf '%s\n' "$root$resolved""#;

/// Unmounts what is mounted under `$1` but datasets, the latest first.
/// mount -p writes a space in a path as \040.
const UNMOUNT: &str = r#"set -e
mount -p | awk -v under="$1/" 'index($2, under) == 1 && $3 != "zfs" { print $2 }' | tail -r |
  while read -r point; do umount "$(printf '%b' "$point")"; done"#;

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

/// A file system mounted into a jail, as Containerization's `Mount` is into
/// a container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
  /// mount(8)'s type: `nullfs`, `tmpfs` or another.
  pub kind: String,
  /// For nullfs, a directory in the guest.
  pub source: String,
  /// A path in the jail. Symbolic links on the way resolve within the
  /// jail, and the directories it lacks are made.
  pub destination: String,
  /// mount(8)'s `-o`, such as `ro`, or tmpfs's `size=64m`.
  pub options: Vec<String>,
}

impl Mount {
  /// The guest's directory `source` at `destination`, through nullfs: such
  /// as a host share `Machine::mount_share` mounted, or one under it.
  pub fn directory(source: &str, destination: &str) -> Self {
    Self {
      kind: "nullfs".into(),
      source: source.into(),
      destination: destination.into(),
      options: Vec::new(),
    }
  }

  /// A tmpfs at `destination`.
  pub fn tmpfs(destination: &str) -> Self {
    Self {
      kind: "tmpfs".into(),
      source: "tmpfs".into(),
      destination: destination.into(),
      options: Vec::new(),
    }
  }

  pub fn read_only(mut self) -> Self {
    self.options.push("ro".into());
    self
  }
}

pub struct Jail<'a> {
  agent: &'a Agent,
  name: String,
}

impl<'a> Jail<'a> {
  /// Starts a persistent jail named `name`, rooted at `path` in the guest,
  /// with that hostname unless `parameters` give one. `parameters` are
  /// jail(8)'s, as `key=value` or a bare flag such as `mount.devfs`. A jail
  /// with a network gets the guest's resolver configuration if it has none
  /// of its own.
  pub fn start(agent: &'a Agent, name: &str, path: &str, network: Network, parameters: &[&str]) -> Result<Self> {
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

    match jail.configure(path, network, epair.as_ref()) {
      Ok(()) => Ok(jail),
      Err(error) => {
        let _ = jail.stop();
        Err(error)
      }
    }
  }

  /// One already running, such as after a restore.
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
  /// guest. Its working directory is a path in the jail, and its user is
  /// looked up in the jail's `/etc/passwd` and `/etc/group`.
  pub fn spawn(&self, exec: Exec) -> Result<Process> {
    self.agent.spawn(Exec {
      jail: Some(self.name.clone()),
      ..exec
    })
  }

  /// Connects to `port` on the jail's loopback: the guest's, unless the
  /// jail has its own network.
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

  /// As `Agent::relay_socket`, with the socket's guest path in the jail.
  pub fn relay_socket(&self, socket: &UnixSocket) -> Result<SocketRelay> {
    self.agent.relay_socket_in(socket, Some(&self.name))
  }

  /// Mounts `mount` in the jail, until `stop`. Mount before anything runs
  /// in it: a process there could otherwise swap a directory on the way
  /// for a symbolic link as the mount is made.
  pub fn mount(&self, mount: &Mount) -> Result<()> {
    let root = self.root()?;
    let resolved = self
      .agent
      .check(&["sh", "-c", RESOLVE, "sh", &root, &mount.destination], QUICK)?
      .stdout;
    let point = resolved.strip_suffix('\n').unwrap_or(&resolved);
    let options = mount.options.join(",");
    let mut argv = vec!["mount", "-t", mount.kind.as_str()];
    if !options.is_empty() {
      argv.extend(["-o", options.as_str()]);
    }
    argv.extend([mount.source.as_str(), point]);

    self.agent.check(&argv, QUICK).map(|_| ())
  }

  /// Replaces the jail's limits, through rctl(8): its processes together
  /// get `cpus` and `memory_in_bytes` of resident memory. Past its CPUs
  /// they are slowed; past its memory, paged out. `stop` lifts the limits.
  pub fn limit(&self, cpus: Option<u32>, memory_in_bytes: Option<u64>) -> Result<()> {
    let rules = quota::rules(&self.name, cpus, memory_in_bytes);
    let mut argv = vec!["sh", "-c", quota::LIMIT, "sh", self.name.as_str()];
    argv.extend(rules.iter().map(String::as_str));

    self.agent.check(&argv, QUICK).map(|_| ())
  }

  /// Copies `source`, a file or directory on the host, into the jail, as
  /// Containerization's `copyIn` does: to `destination`, or into it if it
  /// is a directory. A file gets `mode`. With `create_parents`, missing
  /// directories on the way are made. Paths resolve as the jail sees them.
  pub fn copy_in(&self, source: &Path, destination: &str, mode: u32, create_parents: bool) -> Result<()> {
    copy::copy_in(self, source, destination, mode, create_parents)
  }

  /// Copies `source`, a file or directory in the jail, to `destination` on
  /// the host, as Containerization's `copyOut` does: a file with mode
  /// 0644, or a directory's contents into `destination`. With
  /// `create_parents`, the destination's missing parents are made.
  pub fn copy_out(&self, source: &str, destination: &Path, create_parents: bool) -> Result<()> {
    copy::copy_out(self, source, destination, create_parents)
  }

  /// What the jail's processes use together, as rctl(8) accounts for it,
  /// and its network's counters.
  pub fn statistics(&self) -> Result<Statistics> {
    let ran = self
      .agent
      .check(&["rctl", "-u", &format!("jail:{}", self.name)], QUICK)?;
    let mut statistics = quota::statistics(&ran.stdout)?;
    let ran = self
      .agent
      .check(&["sh", "-c", quota::INTERFACES, "sh", &self.name], QUICK)?;
    statistics.networks = quota::networks(&ran.stdout)?;

    Ok(statistics)
  }

  /// Its root's path in the guest.
  fn root(&self) -> Result<String> {
    let ran = self
      .agent
      .check(&["jls", "-j", &self.name, "path"], QUICK)?;

    Ok(ran.stdout.trim_end_matches('\n').to_string())
  }

  /// As `Agent::run`, in the jail.
  pub fn run(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.agent.run(&self.jexec(argv), timeout)
  }

  /// As `Agent::check`, in the jail.
  pub fn check(&self, argv: &[&str], timeout: Duration) -> Result<Ran> {
    self.agent.check(&self.jexec(argv), timeout)
  }

  /// Stops the jail, killing its processes, and waits for it to be gone,
  /// which a TCP connection it made can hold up for a minute. Then lifts
  /// its limits, unmounts what is mounted in it but datasets, and destroys
  /// its epair.
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
    self
      .agent
      .check(&["sh", "-c", GONE, "sh", &self.name], DYING)?;
    // rctl keeps a jail's rules by name, for the next jail of that name.
    self
      .agent
      .check(&["sh", "-c", quota::LIMIT, "sh", &self.name], QUICK)?;

    // Including devfs, which jail(8) mounts for `mount.devfs` but can't
    // unmount: the parameter is jail(8)'s, not the kernel's, so a jail
    // removed by name has no record of it.
    self
      .agent
      .check(&["sh", "-c", UNMOUNT, "sh", path], QUICK)?;

    // Back in the guest once the jail is gone; destroying one end
    // destroys both.
    for inside in epairs {
      self.agent.check(&["ifconfig", &inside, "destroy"], QUICK)?;
    }
    Ok(())
  }

  /// Sets up a new NAT jail's end of `epair`, and a networked jail's
  /// resolver.
  fn configure(&self, path: &str, network: Network, epair: Option<&Epair>) -> Result<()> {
    if let Some(epair) = epair {
      let inside = format!("{}b", epair.name);
      self.agent.check(
        &["sh", "-c", NAT_JAIL, "sh", &self.name, &inside, &epair.address, GATEWAY],
        QUICK,
      )?;
    }
    if network != Network::None {
      self
        .agent
        .check(&["sh", "-c", RESOLVER, "sh", path], QUICK)?;
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
  use std::os::unix::fs::symlink;
  use std::path::Path;
  use std::process::Command;

  /// What RESOLVE makes of `path` in `root`, through the host's sh: the
  /// guest path it prints, or its error.
  fn resolve(root: &Path, path: &str) -> std::result::Result<String, String> {
    let output = Command::new("sh")
      .args(["-c", RESOLVE, "sh"])
      .arg(root)
      .arg(path)
      .output()
      .unwrap();

    if output.status.success() {
      Ok(String::from_utf8(output.stdout).unwrap())
    } else {
      Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
  }

  #[test]
  fn resolves_a_mount_point_as_the_jail_would() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::create_dir_all(root.join("srv/data")).unwrap();
    symlink("/srv", root.join("absolute")).unwrap();
    symlink("srv/data", root.join("relative")).unwrap();
    symlink("../../../..", root.join("srv/up")).unwrap();
    let inside = |path: &str| Ok(format!("{}{path}\n", root.display()));

    assert_eq!(resolve(root, "/absolute/data"), inside("/srv/data"));
    assert_eq!(resolve(root, "relative/new/./dir"), inside("/srv/data/new/dir"));
    assert!(root.join("srv/data/new/dir").is_dir());
    assert_eq!(resolve(root, "/srv/up/../srv/up/srv"), inside("/srv"));
  }

  #[test]
  fn refuses_a_mount_point_it_cannot_resolve() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    symlink("loop", root.join("loop")).unwrap();
    std::fs::write(root.join("file"), "").unwrap();

    assert!(
      resolve(root, "/loop")
        .unwrap_err()
        .contains("too many symbolic links")
    );
    assert!(
      resolve(root, "/srv/..")
        .unwrap_err()
        .contains("the jail's root")
    );
    assert!(resolve(root, "/file/under").is_err());
  }

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
