#!/bin/sh
# The seed volume's user-data. It runs once, at the end of the first boot's rc
# (nuageinit_user_data_script), after nuageinit has unmounted the seed. It
# mounts the seed again, installs the guest bundle from it, and starts the
# bundle's agent, which serves the host on /dev/ttyV0.0 from then on.

set -ex
# The host displays console text that arrives before the agent's first frame,
# so this script's trace is visible there.
exec >/dev/ttyV0.0 2>&1

seed=/media/cfbsd-seed
mkdir -p "$seed"
mount -t cd9660 /dev/iso9660/[cC][iI][dD][aA][tT][aA] "$seed"
tar -xf "$seed/bundle.tar.xz" -C /
umount "$seed"
rmdir "$seed"

sysrc cfbsd_agent_enable=YES
# The image already boots without delay (autoboot_delay=-1). Disable the
# first-boot package upgrade on later boots, because it needs the network.
sysrc firstboot_pkg_upgrade_enable=NO
# Run DHCP and IPv6 autoconfiguration only on the first network device, which
# is the NAT device. The others stay unconfigured until a jail claims one.
sysrc -x ifconfig_DEFAULT
sysrc ifconfig_vtnet0=SYNCDHCP ifconfig_vtnet0_ipv6="inet6 accept_rtadv"

service cfbsd_agent start
