#!/bin/sh
# Waits for rc to delete /firstboot, which it does once the first boot
# finishes.
while [ -e /firstboot ]; do sleep 1; done
