#!/bin/sh
# Replaces the rctl rules of the jail named $1 with the remaining arguments.
# Without kernel resource accounting, it fails if any rules are given and
# otherwise does nothing.
set -e
jail=$1
shift
if [ "$(sysctl -n kern.racct.enable 2>/dev/null)" = 1 ]; then
  [ -z "$(rctl "jail:$jail:")" ] || rctl -r "jail:$jail:"
elif [ $# -gt 0 ]; then
  echo "limits need kern.racct.enable=1 at boot: prepare the base again" >&2
  exit 1
fi
[ $# -eq 0 ] || rctl -a "$@"
