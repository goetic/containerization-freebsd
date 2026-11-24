#!/bin/sh
# Creates the dataset $1 if it doesn't exist, and prints the directory ZFS
# mounts it at. A dataset whose mountpoint is none or legacy, as under the
# pool of FreeBSD's VM image, gets /$1, which its children inherit.
set -e
zfs list -H -o name "$1" >/dev/null 2>&1 || zfs create -p "$1"
mountpoint=$(zfs get -H -o value mountpoint "$1")
case "$mountpoint" in
  none | legacy)
    mountpoint=/$1
    zfs set "mountpoint=$mountpoint" "$1"
    ;;
esac
echo "$mountpoint"
