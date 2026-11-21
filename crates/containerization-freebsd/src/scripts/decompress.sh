#!/bin/sh
# Decompresses stdin with the method $1 and writes it to the file $2.
set -e
case "$1" in
  gzip) gzip -dc ;;
  zstd) zstd -dcq ;;
  none) cat ;;
esac > "$2"
