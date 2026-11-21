#!/bin/sh
# Copies the guest's resolv.conf into the jail rooted at $1, unless the jail
# has its own.
[ ! -e /etc/resolv.conf ] || [ -e "$1/etc/resolv.conf" ] || cp /etc/resolv.conf "$1/etc/resolv.conf"
