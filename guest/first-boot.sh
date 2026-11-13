#!/bin/sh
# The seed volume's user-data: runs once, at the end of the first boot's rc
# (nuageinit_user_data_script), after nuageinit has unmounted the seed. Mounts
# it again to install the guest bundle from it, then starts the bundle's agent,
# which serves the host on /dev/ttyV0.0 at this boot and every later one.

set -e

seed=/media/cfbsd-seed
mkdir -p "$seed"
mount -t cd9660 /dev/iso9660/[cC][iI][dD][aA][tT][aA] "$seed"
tar -xf "$seed/bundle.tar.xz" -C /
umount "$seed"
rmdir "$seed"

sysrc cfbsd_agent_enable=YES
# The image boots at once already (autoboot_delay=-1). Later boots skip the
# first boot's package upgrade, which needs the network.
sysrc firstboot_pkg_upgrade_enable=NO

service cfbsd_agent start
