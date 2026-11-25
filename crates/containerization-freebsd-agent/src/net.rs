//! Calls about networking: devices moved into VNET jails and addressed
//! there, the guest's default route, NAT jails' epairs and bridge, and DHCP
//! leases for spare devices.

use crate::sys;
use containerization_freebsd_protocol::message;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How often to check on something being waited for.
const POLL: Duration = Duration::from_millis(100);
/// How long dhclient may take to get a lease: its own default timeout.
const LEASING: Duration = Duration::from_secs(30);

/// Moves the guest's network device with the claim's MAC address into the
/// claim's VNET jail, and returns the device's name.
pub(crate) fn claim(claim: &message::Claim) -> io::Result<String> {
  let (jail, _) = sys::jail::find_jail(&claim.jail)?;
  let device = with_mac(&claim.mac, "in no other jail")?;

  sys::netif::move_to_vnet(&device, jail)?;
  Ok(device)
}

/// Brings up the VNET jail's lo0, and gives it the device address and
/// default route that `addressing` asks for.
pub(crate) fn set_address(addressing: &message::Addressing) -> io::Result<()> {
  let (jail, _) = sys::jail::find_jail(&addressing.jail)?;
  let device = match &addressing.device {
    Some(device) => {
      let (address, prefix) = cidr(&device.address)?;
      Some((device.device.as_str(), address, prefix))
    }
    None => None,
  };
  let gateway = addressing.gateway.as_deref().map(ipv4).transpose()?;

  sys::netif::address_in(jail, &sys::netif::Addressing { device, gateway })
}

/// Waits up to `seconds` for the guest's default route, and for its
/// interface's link to go active.
pub(crate) fn await_route(seconds: u32) -> io::Result<()> {
  let deadline = Instant::now() + Duration::from_secs(u64::from(seconds));

  loop {
    if let Some(index) = sys::netif::default_route()?
      && sys::interface::interfaces()?
        .iter()
        .any(|interface| interface.index == index && interface.link_up)
    {
      return Ok(());
    }
    if Instant::now() >= deadline {
      return Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("the default route and its link were not up within {seconds}s"),
      ));
    }
    std::thread::sleep(POLL);
  }
}

/// Creates an epair, adds its `a` end to the bridge, and returns that end's
/// name, first setting up NAT if this boot has no bridge yet.
pub(crate) fn create_epair(bridge: &message::Bridge) -> io::Result<String> {
  if !sys::netif::interface_exists(&bridge.name)? {
    set_up_nat(bridge)?;
  }
  let outside = sys::netif::create_interface("epair")?;

  if let Err(error) = sys::netif::bridge_add(&bridge.name, &outside).and_then(|()| sys::netif::bring_up(&outside)) {
    let _ = sys::netif::destroy_interface(&outside);
    return Err(error);
  }
  Ok(outside)
}

/// Creates the bridge with its address, turns on IP forwarding, and has pf
/// translate the subnet to the address of the default route's interface.
fn set_up_nat(bridge: &message::Bridge) -> io::Result<()> {
  let (address, prefix) = cidr(&bridge.address)?;
  // Rewritten from its parts, so that only an address reaches pf's rules.
  let (subnet, subnet_prefix) = cidr(&bridge.subnet)?;
  let external = sys::netif::default_route()?
    .and_then(|index| {
      sys::interface::interfaces()
        .ok()?
        .into_iter()
        .find(|interface| interface.index == index)
    })
    .ok_or_else(|| {
      io::Error::new(
        io::ErrorKind::NotFound,
        "the guest has no default route: NAT jails need the machine's NAT",
      )
    })?
    .name;

  for module in ["if_bridge", "if_epair", "pf"] {
    sys::netif::load_module(module)?;
  }
  let created = sys::netif::create_interface("bridge")?;
  sys::netif::rename_interface(&created, &bridge.name)?;
  sys::netif::add_address(&bridge.name, address, prefix)?;
  sys::netif::bring_up(&bridge.name)?;
  sys::sysctl::set_int("net.inet.ip.forwarding", 1)?;
  pf_rules(&format!(
    "set skip on lo0\nnat on {external} inet from {subnet}/{subnet_prefix} to any -> ({external})\npass all\n"
  ))?;
  sys::netif::start_pf()
}

/// Replaces pf's rules with `rules`, through pfctl(8).
fn pf_rules(rules: &str) -> io::Result<()> {
  let mut pfctl = Command::new("/sbin/pfctl")
    .args(["-q", "-f", "-"])
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()?;
  if let Some(mut input) = pfctl.stdin.take() {
    input.write_all(rules.as_bytes())?;
  }
  let output = pfctl.wait_with_output()?;

  if !output.status.success() {
    return Err(io::Error::other(format!(
      "pfctl exited with {}: {}",
      output.status,
      String::from_utf8_lossy(&output.stderr).trim_end()
    )));
  }
  Ok(())
}

/// Starts dhclient on the guest's network device with MAC address `mac`,
/// and returns the wait for its lease, which may take `LEASING`. dhclient
/// configures nothing, since its script is true(1), and is killed once it
/// has a lease.
pub(crate) fn lease(mac: &str) -> io::Result<impl FnOnce() -> io::Result<message::Lease> + Send + use<>> {
  let device = with_mac(mac, "in no jail")?;
  let work = Work::new(&device)?;
  std::fs::write(work.0.join("conf"), "timeout 30;\nscript \"/usr/bin/true\";\n")?;
  let leases = work.0.join("leases");
  sys::netif::bring_up(&device)?;
  let dhclient = Command::new("/sbin/dhclient")
    .arg("-d")
    .arg("-c")
    .arg(work.0.join("conf"))
    .arg("-l")
    .arg(&leases)
    .arg(&device)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn();
  let mut dhclient = match dhclient {
    Ok(dhclient) => Dhclient {
      child: dhclient,
      device,
    },
    Err(error) => {
      let _ = sys::netif::bring_down(&device);
      return Err(error);
    }
  };
  let mac = mac.to_string();

  Ok(move || {
    let deadline = Instant::now() + LEASING;
    let leased = loop {
      let leased = std::fs::read_to_string(&leases)
        .ok()
        .and_then(|leases| parse_lease(&leases));
      if leased.is_some() || Instant::now() >= deadline || dhclient.exited() {
        break leased;
      }
      std::thread::sleep(POLL);
    };
    drop(dhclient);
    drop(work);
    leased.ok_or_else(|| io::Error::other(format!("the NAT's DHCP server leased {mac} no address")))
  })
}

/// A dhclient that `lease` started, which is killed, and its device taken
/// down, when it is dropped.
struct Dhclient {
  child: Child,
  device: String,
}

impl Dhclient {
  fn exited(&mut self) -> bool {
    matches!(self.child.try_wait(), Ok(Some(_)))
  }
}

impl Drop for Dhclient {
  fn drop(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
    let _ = sys::netif::bring_down(&self.device);
  }
}

/// A directory for one lease's files, removed when it is dropped.
struct Work(PathBuf);

impl Work {
  fn new(device: &str) -> io::Result<Self> {
    let path = std::env::temp_dir().join(format!("cfbsd-lease-{}-{device}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir(&path)?;
    Ok(Self(path))
  }
}

impl Drop for Work {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

/// The address, with its prefix length, and the first router of the last
/// whole lease in `leases`, a dhclient.leases(5) file.
fn parse_lease(leases: &str) -> Option<message::Lease> {
  let (_, last) = leases.rsplit_once("lease {")?;
  // dhclient may still be writing it.
  let (last, _) = last.split_once('}')?;
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

  Some(message::Lease {
    address: format!("{address}/{}", u32::from(mask).count_ones()),
    gateway,
  })
}

/// The name of the guest's network device with MAC address `mac`. A missing
/// device may be in a jail, so the error says it should be `elsewhere`.
fn with_mac(mac: &str, elsewhere: &str) -> io::Result<String> {
  let wanted = parse_mac(mac)?;

  sys::interface::interfaces()?
    .into_iter()
    .find(|interface| interface.address == wanted)
    .map(|interface| interface.name)
    .ok_or_else(|| {
      io::Error::new(
        io::ErrorKind::NotFound,
        format!(
          "the guest has no network device with MAC address {mac}: is it in the layout's interfaces, and {elsewhere}?"
        ),
      )
    })
}

/// The six bytes of a MAC address written like `02:6d:2e:1f:a4:0b`.
fn parse_mac(mac: &str) -> io::Result<[u8; 6]> {
  let bytes: Option<Vec<u8>> = mac
    .split(':')
    .map(|byte| u8::from_str_radix(byte, 16).ok())
    .collect();

  bytes
    .and_then(|bytes| bytes.try_into().ok())
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{mac:?} is no MAC address")))
}

/// An IPv4 address and prefix length written like `10.66.0.2/16`.
fn cidr(text: &str) -> io::Result<(Ipv4Addr, u8)> {
  let invalid = || {
    io::Error::new(
      io::ErrorKind::InvalidInput,
      format!("{text:?} is no IPv4 address and prefix length"),
    )
  };
  let (address, prefix) = text.split_once('/').ok_or_else(invalid)?;
  let prefix: u8 = prefix
    .parse()
    .ok()
    .filter(|&prefix| prefix <= 32)
    .ok_or_else(invalid)?;

  Ok((ipv4(address)?, prefix))
}

fn ipv4(text: &str) -> io::Result<Ipv4Addr> {
  text
    .parse()
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{text:?} is no IPv4 address")))
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
      parse_lease(leases),
      Some(message::Lease {
        address: "192.168.64.140/16".into(),
        gateway: Some("192.168.64.1".into()),
      })
    );
  }

  #[test]
  fn reads_a_lease_without_a_router() {
    let leases = "lease {\n  fixed-address 10.0.0.5;\n  option subnet-mask 255.255.255.0;\n}\n";

    assert_eq!(
      parse_lease(leases),
      Some(message::Lease {
        address: "10.0.0.5/24".into(),
        gateway: None,
      })
    );
  }

  #[test]
  fn reads_no_lease_from_nothing_or_half_a_lease() {
    assert_eq!(parse_lease(""), None);
    assert_eq!(parse_lease("lease {\n  option subnet-mask 255.255.255.0;\n}\n"), None);
    assert_eq!(
      parse_lease("lease {\n  fixed-address 10.0.0.5;\n  option subnet-mask 255.255.255.0;\n"),
      None
    );
  }

  #[test]
  fn reads_macs_and_addresses() {
    assert_eq!(
      parse_mac("02:6D:2e:1f:a4:0b").unwrap(),
      [0x02, 0x6d, 0x2e, 0x1f, 0xa4, 0x0b]
    );
    assert!(parse_mac("02:6d:2e:1f:a4").is_err() && parse_mac("02:6d:2e:1f:a4:0b:00").is_err());
    assert_eq!(cidr("10.66.0.2/16").unwrap(), (Ipv4Addr::new(10, 66, 0, 2), 16));
    assert!(cidr("10.66.0.2").is_err() && cidr("10.66.0.2/33").is_err() && cidr("web/8").is_err());
  }
}
