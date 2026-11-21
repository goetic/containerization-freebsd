#!/bin/sh
# Unmounts everything under $1 except ZFS datasets, in reverse mount order.
# `mount -p` encodes a space in a path as \040.
set -e
mount -p | awk -v under="$1/" 'index($2, under) == 1 && $3 != "zfs" { print $2 }' | tail -r |
  while read -r point; do umount "$(printf '%b' "$point")"; done
