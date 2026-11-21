#!/bin/sh
# Removes $1/etc/resolv.conf if it is the copy of the guest's that starting
# the jail put there, not one a build step wrote.
! cmp -s /etc/resolv.conf "$1/etc/resolv.conf" || rm "$1/etc/resolv.conf"
