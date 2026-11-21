#!/bin/sh
# Prints, in dhclient.leases(5) format, the lease the NAT's DHCP server gives
# the guest's network device with MAC $1, without configuring the device:
# dhclient's script is true(1), and dhclient is killed once bound.
set -e
for device in $(ifconfig -l ether); do
  if ifconfig "$device" ether | grep -qix "[[:space:]]*ether $1"; then
    work=$(mktemp -d)
    trap 'pkill -f "^dhclient: $device( |\$)" || :
      while pgrep -qf "^dhclient: $device( |\$)"; do sleep 0.1; done
      ifconfig "$device" down
      rm -rf "$work"' EXIT
    printf 'timeout 30;\nscript "/usr/bin/true";\n' >"$work/conf"
    ifconfig "$device" up
    dhclient -c "$work/conf" -l "$work/leases" "$device" >/dev/null 2>&1
    cat "$work/leases" 2>/dev/null || :
    exit 0
  fi
done
echo "the guest has no network device with MAC address $1: is it in the layout's interfaces, and in no jail?" >&2
exit 1
