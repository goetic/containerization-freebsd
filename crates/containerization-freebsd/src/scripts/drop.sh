#!/bin/sh
# Ends the processes of jail $1 as `jail -r` would: SIGTERM and 10 seconds to
# exit. Then drops the TCP connections they left, which would otherwise keep
# the removed jail dying through TIME_WAIT. A VNET jail ($2 is `new`) has its
# own stack, so only a tcpdrop run inside it, if it has one, reaches them. A
# non-VNET jail's connections are in the guest's stack, where netstat -j
# lists them.
jid=$(jls -j "$1" jid)
pkill -j "$jid"
tries=100
while pgrep -j "$jid" >/dev/null && [ "$tries" -gt 0 ]; do sleep 0.1; tries=$((tries - 1)); done
if [ "$2" = new ]; then
  jexec "$jid" tcpdrop -a >/dev/null 2>&1
else
  netstat -j "$jid" -n -p tcp -a | awk 'NR > 2 && $6 != "LISTEN" {
    local = $4; local_port = $4; foreign = $5; foreign_port = $5
    sub(/\.[^.]*$/, "", local); sub(/.*\./, "", local_port)
    sub(/\.[^.]*$/, "", foreign); sub(/.*\./, "", foreign_port)
    print local, local_port, foreign, foreign_port
  }' | while read -r l lp f fp; do tcpdrop "$l" "$lp" "$f" "$fp" >/dev/null 2>&1; done
fi
true
