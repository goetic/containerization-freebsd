//! Jail networking: none, the guest's stack, VNET behind pf NAT on a guest
//! bridge, or VNET on dedicated Virtualization NAT devices.

use super::Jail;
use crate::agent::{Agent, QUICK, Spawn};
use crate::error::{Error, Result};
use crate::machine::Mac;
use containerization_freebsd_protocol::{Addressing, Bridge, DeviceAddress, FileCopy, GuestPath, Lease};
use std::net::Ipv4Addr;

/// The bridge that NAT jails' epairs join.
const BRIDGE: &str = "cfbsd0";
/// The subnet of NAT jails, which pf translates to the guest's address. The
/// bridge holds `GATEWAY`, the jails' default route; each jail holds an
/// address after it.
const SUBNET: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 0);
const PREFIX: u32 = 16;
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

/// How a jail reaches the network.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Network {
  None,
  /// The guest's network stack and addresses (`ip4=inherit`, `ip6=inherit`).
  #[default]
  Inherit,
  /// A VNET jail on an epair to a guest bridge, with pf NAT to the guest's
  /// address. Requires the machine's NAT (`Layout::nat`).
  Nat,
  /// A VNET jail with these interfaces, like Containerization's
  /// `interfaces`. The host reaches the jail at their addresses.
  Interfaces(Vec<Interface>),
}

/// A jail interface on Virtualization's NAT network, which the host is also
/// on, like Containerization's `NATInterface`. It is one of the machine's
/// spare network devices (`Layout::interfaces`), moved into the jail's vnet.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Interface {
  /// The device's MAC address.
  pub mac: Mac,
  /// IPv4 address and prefix length, such as `192.168.64.3/24`. The NAT's
  /// DHCP server leases from the same subnet, so pick an address it hasn't
  /// leased, or get a leased one from `Interface::leased`.
  pub address: String,
  /// The default route's gateway, such as `192.168.64.1`, if any.
  pub gateway: Option<String>,
}

impl Network {
  /// The jail(8) parameters for this network. For `Nat`, first sets up NAT in
  /// the guest and creates the jail's epair, which it also returns.
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
  /// An interface on the spare device with MAC `mac`, using the address the
  /// NAT's DHCP server leases it and the lease's first router as gateway.
  /// The server gives that address to no other machine while the lease lasts.
  /// Nothing renews the lease, but the server leases the same address to the
  /// same MAC again. Call this before a jail claims the device.
  pub fn leased(agent: &Agent, mac: Mac) -> Result<Self> {
    let Lease { address, gateway } = agent.lease(&mac.to_string())?;

    Ok(Self { mac, address, gateway })
  }
}

impl Jail<'_> {
  /// Configures a new jail's network: lo0 and the epair's b end for `Nat`,
  /// lo0 and the claimed devices for `Interfaces`, and resolv.conf for any
  /// networked jail.
  pub(super) fn configure(&self, network: &Network, epair: Option<&Epair>) -> Result<()> {
    if let Some(epair) = epair {
      let address = format!("{}/{PREFIX}", epair.address);
      self.set_address(Some((format!("{}b", epair.name), address)), Some(GATEWAY.to_string()))?;
    }
    if let Network::Interfaces(interfaces) = network {
      if interfaces.is_empty() {
        self.set_address(None, None)?;
      }
      for interface in interfaces {
        let claimed = self.agent.claim(&self.name, &interface.mac.to_string())?;
        self.set_address(Some((claimed, interface.address.clone())), interface.gateway.clone())?;
      }
    }
    if *network != Network::None {
      self.agent.copy_file(self.resolv_conf())?;
    }
    Ok(())
  }

  /// Removes the jail's resolv.conf if it is the copy of the guest's that
  /// `start` made, and nothing has changed it since.
  pub(crate) fn remove_resolv_conf(&self) -> Result<()> {
    self.agent.remove_copy(self.resolv_conf())
  }

  /// The guest's resolv.conf, and where the jail's is.
  fn resolv_conf(&self) -> FileCopy {
    let path = "/etc/resolv.conf".to_string();

    FileCopy {
      from: GuestPath {
        path: path.clone(),
        jail: None,
      },
      to: GuestPath {
        path,
        jail: Some(self.name.clone()),
      },
    }
  }

  /// Brings up the VNET jail's lo0, gives the device, if any, its address,
  /// and routes the jail's traffic through the gateway, if any.
  fn set_address(&self, device: Option<(String, String)>, gateway: Option<String>) -> Result<()> {
    self.agent.set_address(Addressing {
      jail: self.name.clone(),
      device: device.map(|(device, address)| DeviceAddress { device, address }),
      gateway,
    })
  }
}

/// A new epair whose `a` end is on the bridge, and the address for its `b`
/// end.
pub(super) struct Epair {
  /// The name without the end's letter, such as `epair3`.
  name: String,
  address: Ipv4Addr,
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
  let outside = agent.create_epair(Bridge {
    name: BRIDGE.to_string(),
    address: format!("{GATEWAY}/{PREFIX}"),
    subnet: format!("{SUBNET}/{PREFIX}"),
  })?;
  let name = outside
    .strip_suffix('a')
    .ok_or_else(|| Error::Guest(format!("ifconfig made {outside:?}, not an epair")))?
    .to_string();
  let address = address(&name).ok_or_else(|| Error::Guest(format!("no address for {name}")))?;

  Ok(Epair { name, address })
}

/// The address for the jail on `epair<unit>`: `SUBNET` at offset unit + 2, so
/// addresses start after `GATEWAY`, and end before the broadcast address.
/// FreeBSD never gives two live epairs the same unit, so no two NAT jails
/// share an address.
fn address(epair: &str) -> Option<Ipv4Addr> {
  let index = epair
    .strip_prefix("epair")?
    .parse::<u32>()
    .ok()?
    .checked_add(2)?;

  (index < (1 << (32 - PREFIX)) - 1).then(|| Ipv4Addr::from(u32::from(SUBNET) + index))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn gives_each_epair_unit_its_own_address_after_the_gateway() {
    assert_eq!(address("epair0"), Some(Ipv4Addr::new(10, 66, 0, 2)));
    assert_eq!(address("epair253"), Some(Ipv4Addr::new(10, 66, 0, 255)));
    assert_eq!(address("epair254"), Some(Ipv4Addr::new(10, 66, 1, 0)));
    assert_ne!(address("epair0"), Some(GATEWAY));
    assert_eq!(address("epair65532"), Some(Ipv4Addr::new(10, 66, 255, 254)));
    assert_eq!(address("epair65533"), None);
    assert_eq!(address("epair4294967295"), None);
    assert_eq!(address("bridge0"), None);
  }
}
