#!/bin/sh
# Sets up NAT for jails once per boot: creates the bridge, turns on
# forwarding, and has pf translate 10.66/16 to the address of the guest's
# default interface.
set -e
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
pfctl -s info | grep -q 'Status: Enabled' || pfctl -q -e
