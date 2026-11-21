#!/bin/sh
# Prints the device of each disk with the identifier $1, such as /dev/vtbd1.
for disk in $(sysctl -n kern.disks); do
  [ "$(diskinfo -s "$disk" 2>/dev/null)" = "$1" ] && echo "/dev/$disk"
done; true
