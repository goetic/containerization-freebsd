//! How jails reach the network: not at all, through the guest's stack, by NAT
//! from a bridge in the guest, or on interfaces of their own.

use super::{Jail, QUICK};
use crate::agent::Agent;
use crate::error::{Error, Result};
use crate::scripts;
use std::net::Ipv4Addr;
use std::time::Duration;

/// The bridge that NAT jails attach to, and its address, which is the jails'
/// gateway.
const BRIDGE: &str = "cfbsd0";
const GATEWAY: &str = "10.66.0.1";

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

impl Network {
  /// The jail(8) parameters that put a new jail on this network. For NAT, it
  /// first sets up NAT in the guest and makes the jail's epair, which it also
  /// returns.
  pub(super) fn parameters(&self, agent: &Agent) -> Result<(Vec<String>, Option<Epair>)> {
    Ok(match self {
      Self::None => (Vec::new(), None),
      Self::Inherit => (vec!["ip4=inherit".into(), "ip6=inherit".into()], None),
      Self::Nat => {
        let epair = epair(agent)?;
        let interface = format!("vnet.interface={}b", epair.name);
        (vec!["vnet".into(), interface], Some(epair))
      }
      Self::Interfaces(_) => (vec!["vnet".into()], None),
    })
  }
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

impl Jail<'_> {
  /// Configures a new jail's network: the inside end of `epair` for a NAT
  /// jail, or its interfaces, and the resolver for any jail with a network.
  pub(super) fn configure(&self, path: &str, network: &Network, epair: Option<&Epair>) -> Result<()> {
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
}

/// A new epair whose `a` end is on the bridge, and the address for its `b`
/// end.
pub(super) struct Epair {
  /// The name without the end's letter, such as `epair3`.
  name: String,
  address: String,
}

impl Epair {
  /// Destroys both ends, as destroying either does.
  pub(super) fn destroy(&self, agent: &Agent) -> Result<()> {
    agent
      .check(&["ifconfig", &format!("{}a", self.name), "destroy"], QUICK)
      .map(|_| ())
  }
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
