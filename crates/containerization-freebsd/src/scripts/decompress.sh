#!/bin/sh
# Decompresses stdin with method $1 (gzip, zstd or none) into the file $2.
set -e
case "$1" in
  gzip) gzip -dc ;;
  zstd) zstd -dcq ;;
  none) cat ;;
esac > "$2"
