#!/bin/sh
# Prints the interfaces of the jail named $1, with their counters, if it has
# a network of its own.
[ "$(jls -j "$1" vnet)" != new ] || exec netstat -j "$1" -i -b -d -n -W
