#!/bin/sh
# Resolves $2, a path in the jail rooted at $1, prints the guest path, and
# creates missing directories. Symlinks resolve within the root, as under
# chroot(2): absolute targets start at the root, and `..` stops there.
set -e
root=$1 rest=$2 resolved='' links=0
while [ -n "$rest" ]; do
  part=${rest%%/*}
  case $rest in */*) rest=${rest#*/} ;; *) rest= ;; esac
  case $part in
  '' | .) ;;
  ..) resolved=${resolved%/*} ;;
  *)
    if [ -L "$root$resolved/$part" ]; then
      links=$((links + 1))
      if [ "$links" -gt 32 ]; then
        echo "$2: too many symbolic links" >&2
        exit 1
      fi
      target=$(readlink "$root$resolved/$part")
      case $target in /*) resolved= ;; esac
      rest=$target/$rest
    else
      resolved=$resolved/$part
    fi
    ;;
  esac
done
if [ -z "$resolved" ]; then
  echo "$2: that is the jail's root" >&2
  exit 1
fi
mkdir -p "$root$resolved"
printf '%s\n' "$root$resolved"
