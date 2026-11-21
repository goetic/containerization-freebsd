#!/bin/sh
# Mounts the virtio-fs share tagged $1 at $2, creating the directory if needed.
mkdir -p "$2" && mount -t virtiofs "$1" "$2"
