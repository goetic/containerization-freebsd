#!/bin/sh
# Prints the statistics of the jail $1 in three parts, each ended by a line
# of %%: its racct usage; its interfaces with their counters, if it is a VNET
# jail; and, if $2 names a dataset, the dataset's reads, bytes read, writes,
# and bytes written, from its ZFS objset kstats.
set -e
rctl -u "jail:$1"
echo %%
[ "$(jls -j "$1" vnet)" != new ] || netstat -j "$1" -i -b -d -n -W
echo %%
if [ -n "$2" ]; then
  objset=kstat.zfs.${2%%/*}.dataset.objset-$(printf 0x%x "$(zfs get -Hp -o value objsetid "$2")")
  sysctl -n "$objset.reads" "$objset.nread" "$objset.writes" "$objset.nwritten"
fi
echo %%
