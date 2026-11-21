#!/bin/sh
# Waits for the jail named $1 to disappear. A removed jail stays dying,
# holding its root and its network, until everything it left closes, such as
# a TCP connection in TIME_WAIT.
while jls -d -j "$1" >/dev/null 2>&1; do sleep 0.1; done
