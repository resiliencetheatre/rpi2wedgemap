#!/bin/sh
#
# Source node config from boot partition
#
source /opt/boot/burnnode.conf

#
# Set macsec0 interface
#
ip link set $INTERFACE up
ip link add link $INTERFACE macsec0 type macsec encrypt on
#
# Set my TX key
#
ip macsec add macsec0 tx sa 0 pn 1 on key 01 $MY_TX_KEY
#
# Set peer RX keys
#
ip macsec add macsec0 rx port 1 address $REMOTE_MAC_ADDRESS
ip macsec add macsec0 rx port 1 address $REMOTE_MAC_ADDRESS sa 0 pn 1 on key 00 $REMOTE_RX_KEY
#
# Bring macsec up and give address
#
ip link set macsec0 up
ip addr add $MACSEC_IP dev macsec0
exit 0

