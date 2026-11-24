#!/bin/sh
# Decompresses stdin with method $1 (gzip, zstd, or none) into the file $2.
# As it writes the tarball, it puts its sha256 in $2.sha256 and its whiteout
# entries in $2.whiteouts, so that applying the layer reads it only once.
set -e -o pipefail
hashing=$2.hashing
listing=$2.listing
trap 'rm -f -- "$hashing" "$listing"' EXIT
rm -f -- "$hashing" "$listing"
mkfifo -- "$hashing" "$listing"

sha256 -q <"$hashing" >"$2.sha256" &
hashed=$!
# tar stops reading at the archive's end, so cat reads the padding after it,
# and tee never writes to a FIFO with no reader.
{ tar -tf - | grep -E '(^|/)\.wh\.[^/]+$' || :; cat >/dev/null; } <"$listing" >"$2.whiteouts" &
listed=$!

case "$1" in
  gzip) gzip -dc ;;
  zstd) zstd -dcq ;;
  none) cat ;;
esac | tee -- "$hashing" "$listing" >"$2"
wait "$hashed"
wait "$listed"
