#!/bin/sh
# Mounts the virtiofs share tagged $1 at $2, making the directory if needed.
mkdir -p "$2" && mount -t virtiofs "$1" "$2"
