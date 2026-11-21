//! Manages FreeBSD jails in the guest through the guest agent.

use crate::agent::{Agent, Exec, Exit, Process, Ran, Relay};
use crate::copy;
use crate::error::{Error, Result};
use crate::quota::{self, Statistics};
use crate::scripts;
use crate::socket::{SocketRelay, UnixSocket};
use containerization_freebsd_protocol::{Address, Connect};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

const QUICK: Duration = Duration::from_secs(60);
/// The bridge that NAT jails attach to, and its address, which is the jails'
/// gateway.
const BRIDGE: &str = "cfbsd0";
const GATEWAY: &str = "10.66.0.1";
/// How long `scripts::GONE` may wait. Longer than TIME_WAIT, which is twice
/// FreeBSD's default MSL of 30 seconds.
const DYING: Duration = Duration::from_secs(90);

/// How a jail reaches the network.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Network {
  /// The jail has no network.
  None,
  /// The jail shares the guest's network stack and addresses.
  #[default]
  Inherit,
  /// The jail has its own stack (VNET) and address on a bridge in the guest,
  /// and pf translates its traffic to the guest's address. This requires the
  /// machine's NAT (`Layout::nat`).
  Nat,
  /// The jail has its own stack with these interfaces, like
  /// Containerization's `interfaces`. The host reaches the jail at their
  /// addresses.
  Interfaces(Vec<Interface>),
}

/// A jail's interface on Virtualization's NAT network, which the host is also
/// on, like Containerization's `NATInterface`. It is one of the machine's
/// spare network devices (`Layout::interfaces`), and only that jail sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Interface {
  /// The device's MAC address.
  pub mac: [u8; 6],
  /// The IPv4 address and prefix length, such as `192.168.64.3/24`. The
  /// NAT's DHCP server leases from the same network, so choose an address it
  /// has not leased, or use one it leased with `Interface::leased`.
  pub address: String,
  /// The default route's gateway, such as `192.168.64.1`, if any.
  pub gateway: Option<String>,
}

impl Interface {
  /// Returns an interface on the spare device with MAC address `mac`, using
  /// the address the NAT's DHCP server leases to it and the lease's router as
  /// the gateway. The server gives that address to no other machine while the
  /// lease lasts. Nothing renews the lease, but the server leases the same
  /// address to the same MAC address again. Call this before a jail claims
  /// the device.
  pub fn leased(agent: &Agent, mac: [u8; 6]) -> Result<Self> {
    let colons = colons(mac);
    let ran = agent.check(&scripts::LEASE.argv(&[&colons]), LEASING)?;
    let (address, gateway) =
      lease(&ran.stdout).ok_or_else(|| Error::Guest(format!("the NAT's DHCP server leased {colons} no address")))?;

    Ok(Self { mac, address, gateway })
  }
}

/// dhclient's 30-second timeout in `scripts::LEASE`, plus a margin.
const LEASING: Duration = Duration::from_secs(45);

/// `mac` as ifconfig prints it.
fn colons(mac: [u8; 6]) -> String {
  mac.map(|byte| format!("{byte:02x}")).join(":")
}

/// Returns the address, with its prefix length, and the first router of the
/// last lease in `leases`, a dhclient.leases(5) file.
fn lease(leases: &str) -> Option<(String, Option<String>)> {
  let (_, last) = leases.rsplit_once("lease {")?;
  let value = |key: &str| {
    last.lines().find_map(|line| {
      line
        .trim()
        .strip_prefix(key)?
        .strip_suffix(';')
        .map(str::trim)
    })
  };
  let address: Ipv4Addr = value("fixed-address ")?.parse().ok()?;
  let mask: Ipv4Addr = value("option subnet-mask ")?.parse().ok()?;
  let gateway = value("option routers ")
    .and_then(|routers| routers.split(',').next())
    .map(|router| router.trim().to_string());

  Some((format!("{address}/{}", u32::from(mask).count_ones()), gateway))
}

/// A file system mounted into a jail, like Containerization's `Mount` for a
/// container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
  /// mount(8)'s type: `nullfs`, `tmpfs` or another.
  pub kind: String,
  /// For nullfs, a directory in the guest.
  pub source: String,
  /// A path in the jail. Symbolic links along the path resolve within the
  /// jail, and missing directories are made.
  pub destination: String,
  /// mount(8)'s `-o`, such as `ro`, or tmpfs's `size=64m`.
  pub options: Vec<String>,
}

impl Mount {
  /// Mounts the guest directory `source` at `destination` with nullfs.
  /// `source` may be a host share mounted by `Machine::mount_share`, or a
  /// directory under one.
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

    let epair = match network {
      Network::None => None,
      Network::Inherit => {
        argv.extend(["ip4=inherit", "ip6=inherit"]);
        None
      }
      Network::Nat => Some(epair(agent)?),
      Network::Interfaces(_) => {
        argv.push("vnet");
        None
      }
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

  /// Mounts `mount` in the jail until `stop`. Mount before anything runs in
  /// the jail: otherwise a process there could replace a directory on the
  /// path with a symbolic link while the mount is made.
  pub fn mount(&self, mount: &Mount) -> Result<()> {
    let root = self.root()?;
    let resolved = self
      .agent
      .check(&scripts::RESOLVE.argv(&[&root, &mount.destination]), QUICK)?
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

  /// Configures a new jail's network: the inside end of `epair` for a NAT
  /// jail, or its interfaces, and the resolver for any jail with a network.
  fn configure(&self, path: &str, network: &Network, epair: Option<&Epair>) -> Result<()> {
    if let Some(epair) = epair {
      let (inside, address) = (format!("{}b", epair.name), format!("{}/16", epair.address));
      self.rescue(&["ifconfig", "lo0", "inet", "127.0.0.1/8", "up"])?;
      self.rescue(&["ifconfig", &inside, "inet", &address, "up"])?;
      self.rescue(&["route", "-q", "add", "default", GATEWAY])?;
    }
    if let Network::Interfaces(interfaces) = network {
      self.rescue(&["ifconfig", "lo0", "inet", "127.0.0.1/8", "up"])?;
      for interface in interfaces {
        let claimed = self
          .agent
          .check(&scripts::CLAIM.argv(&[&self.name, &colons(interface.mac)]), QUICK)?;
        let device = claimed.stdout.trim();
        self.rescue(&["ifconfig", device, "inet", &interface.address, "up"])?;
        if let Some(gateway) = &interface.gateway {
          self.rescue(&["route", "-q", "add", "default", gateway])?;
        }
      }
    }
    if *network != Network::None {
      self.agent.check(&scripts::RESOLVER.argv(&[path]), QUICK)?;
    }
    Ok(())
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

/// A new epair whose `a` end is on the bridge, and the address for its `b`
/// end.
struct Epair {
  /// The name without the end's letter, such as `epair3`.
  name: String,
  address: String,
}

fn epair(agent: &Agent) -> Result<Epair> {
  agent.check(&scripts::NAT.argv(&[]), QUICK)?;
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

/// Returns the address for the jail on `epair<unit>`. FreeBSD never gives two
/// live epairs the same unit, so no two NAT jails share an address. Addresses
/// start after `GATEWAY`, which is 10.66.0.1.
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

  #[test]
  fn reads_the_last_lease() {
    let leases = "lease {\n  interface \"vtnet1\";\n  fixed-address 192.168.64.98;\n  option subnet-mask 255.255.255.0;\n}\n\
                  lease {\n  interface \"vtnet1\";\n  fixed-address 192.168.64.140;\n  option subnet-mask 255.255.0.0;\n  \
                  option routers 192.168.64.1, 192.168.64.2;\n  renew 3 2026/11/18 02:00:00;\n}\n";

    assert_eq!(
      lease(leases),
      Some(("192.168.64.140/16".into(), Some("192.168.64.1".into())))
    );
  }

  #[test]
  fn reads_a_lease_without_a_router() {
    let leases = "lease {\n  fixed-address 10.0.0.5;\n  option subnet-mask 255.255.255.0;\n}\n";

    assert_eq!(lease(leases), Some(("10.0.0.5/24".into(), None)));
  }

  #[test]
  fn reads_no_lease_from_nothing() {
    assert_eq!(lease(""), None);
    assert_eq!(lease("lease {\n  option subnet-mask 255.255.255.0;\n}\n"), None);
  }

  /// Runs `scripts::RESOLVE` on `path` in `root` with the host's sh, and
  /// returns the path it prints or its error.
  fn resolve(root: &Path, path: &str) -> std::result::Result<String, String> {
    let argv = scripts::RESOLVE.argv(&[root.to_str().unwrap(), path]);
    let output = Command::new(argv[0]).args(&argv[1..]).output().unwrap();

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
  fn takes_every_step_and_keeps_the_first_failure() {
    let mut steps = Steps::default();

    assert_eq!(steps.take(Ok(1)), Some(1));
    assert_eq!(steps.take::<()>(Err(Error::Invalid("first".into()))), None);
    assert_eq!(steps.take(Ok(2)), Some(2));
    steps.take::<()>(Err(Error::Invalid("second".into())));
    assert!(matches!(steps.finish(), Err(Error::Invalid(why)) if why == "first"));
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
