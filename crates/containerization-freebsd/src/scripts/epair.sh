#!/bin/sh
# Creates an epair for a NAT jail, adds its a end to the bridge $1, and
# prints the a end's name. If this boot has no bridge yet, it first sets up
# NAT: creates the bridge with the address $2 (such as 10.66.0.1/16),
# enables IP forwarding, and has pf translate the subnet $3 (such as
# 10.66.0.0/16) to the default-route interface's address.
set -e
bridge=$1
gateway=$2
subnet=$3
if ! ifconfig "$bridge" >/dev/null 2>&1; then
  external=$(route -n get default 2>/dev/null | awk '/interface:/ { print $2 }')
  if [ -z "$external" ]; then
    echo "the guest has no default route: NAT jails need the machine's NAT" >&2
    exit 1
  fi
  kldload -n if_bridge if_epair pf
  created=$(ifconfig bridge create)
  ifconfig "$created" name "$bridge" >/dev/null
  ifconfig "$bridge" inet "$gateway" up
  sysctl -q net.inet.ip.forwarding=1
  printf 'set skip on lo0\nnat on %s inet from %s to any -> (%s)\npass all\n' "$external" "$subnet" "$external" |
    pfctl -q -f -
  pfctl -s info | grep -q 'Status: Enabled' || pfctl -q -e
  # Only the epair's name goes to stdout, so the setup's output doesn't.
fi >/dev/null

outside=$(ifconfig epair create)
if ! ifconfig "$bridge" addm "$outside" || ! ifconfig "$outside" up; then
  ifconfig "$outside" destroy
  exit 1
fi
echo "$outside"
