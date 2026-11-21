#!/bin/sh
# Applies the layer tarball $2, whose sha256 must be $3, to the root $1.
# Whiteouts delete files from the layers beneath, so they are applied before
# the layer's own files are extracted. A whiteout that resolves outside the
# root is an error.
set -e
root=$(realpath -- "$1")
layer=$2
actual=$(sha256 -q -- "$layer")
if [ "$actual" != "$3" ]; then
  echo "its sha256 is $actual, not the config's $3" >&2
  exit 1
fi
tar -tf "$layer" | grep -E '(^|/)\.wh\.[^/]+$' | while IFS= read -r entry; do
  case "$entry" in
    */*) directory=${entry%/*} ;;
    *) directory=. ;;
  esac
  name=${entry##*/}
  parent=$(realpath -q -- "$root/$directory") || continue
  case "$parent/" in
    "$root"/*) ;;
    *) echo "whiteout $entry is outside the root" >&2; exit 1 ;;
  esac
  if [ "$name" = .wh..wh..opq ]; then
    find "$parent" -mindepth 1 -maxdepth 1 -exec chflags -R -P 0 {} + 2>/dev/null || :
    find "$parent" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
  else
    hidden=${name#.wh.}
    case "$hidden" in
      '' | . | ..) echo "whiteout $entry hides nothing" >&2; exit 1 ;;
    esac
    if [ -e "$parent/$hidden" ] || [ -L "$parent/$hidden" ]; then
      chflags -R -P 0 "$parent/$hidden" 2>/dev/null || :
      rm -rf -- "${parent:?}/$hidden"
    fi
  fi
done
tar -xpf "$layer" -C "$root" --numeric-owner --exclude '.wh.*'
