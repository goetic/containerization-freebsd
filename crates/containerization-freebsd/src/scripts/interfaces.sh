#!/bin/sh
# Prints the interfaces of jail $1, with their counters, if it is a VNET jail.
[ "$(jls -j "$1" vnet)" != new ] || exec netstat -j "$1" -i -b -d -n -W
