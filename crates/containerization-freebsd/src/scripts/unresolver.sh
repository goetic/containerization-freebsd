#!/bin/sh
# Removes the resolver configuration from the root at $1 if it is the copy of
# the guest's that the jail put there, not one the step wrote.
! cmp -s /etc/resolv.conf "$1/etc/resolv.conf" || rm "$1/etc/resolv.conf"
