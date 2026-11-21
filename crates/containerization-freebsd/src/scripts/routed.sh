#!/bin/sh
# Waits for the guest's default route and for its interface's link to go
# active.
until interface=$(route -n get default 2>/dev/null | awk '/interface:/ { print $2 }') &&
  [ -n "$interface" ] && ifconfig "$interface" | grep -q 'status: active'; do
  sleep 0.1
done
