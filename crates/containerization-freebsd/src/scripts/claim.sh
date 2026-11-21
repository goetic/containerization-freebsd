#!/bin/sh
# Moves the guest's network device with MAC address $2 into the jail named
# $1, and prints the device's name.
set -e
for device in $(ifconfig -l ether); do
  if ifconfig "$device" ether | grep -qix "[[:space:]]*ether $2"; then
    ifconfig "$device" vnet "$1"
    echo "$device"
    exit 0
  fi
done
echo "the guest has no network device with MAC address $2: is it in the layout's interfaces, and in no other jail?" >&2
exit 1
