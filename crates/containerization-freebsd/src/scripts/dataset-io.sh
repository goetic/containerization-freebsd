#!/bin/sh
# Prints the reads, bytes read, writes and bytes written of the dataset $1,
# from its ZFS kstats.
set -e
objset=kstat.zfs.${1%%/*}.dataset.objset-$(printf 0x%x "$(zfs get -Hp -o value objsetid "$1")")
sysctl -n "$objset.reads" "$objset.nread" "$objset.writes" "$objset.nwritten"
