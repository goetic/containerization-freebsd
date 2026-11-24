#!/bin/sh
# Brings up lo0 at 127.0.0.1 in the VNET jail $1, unless it is up already.
# If $2 names a device in the jail, gives it the address $3. If $4 names a
# gateway, routes the jail's traffic through it. The guest's ifconfig and
# route enter the jail themselves, so the jail needs neither.
set -e
ifconfig -j "$1" lo0 inet | grep -q 'inet 127\.0\.0\.1 ' ||
  ifconfig -j "$1" lo0 inet 127.0.0.1/8 up
[ -z "$2" ] || ifconfig -j "$1" "$2" inet "$3" up
[ -z "$4" ] || route -j "$1" -q add default "$4"
