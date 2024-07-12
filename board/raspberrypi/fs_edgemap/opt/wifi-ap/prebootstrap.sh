#!/bin/sh
#
# Edgemap for RPi zero 2w - prebootstrap.sh
#

if [ ! -f /opt/boot/bootstrap.sh ]; then
 cp /opt/wifi-ap/bootstrap.sh /opt/boot
fi

exit 0
