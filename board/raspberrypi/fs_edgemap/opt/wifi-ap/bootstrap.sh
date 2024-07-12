#!/bin/sh
#
# Edgemap for RPi zero 2w - bootstrap.sh
#

# Set wifi mode (ap or client)
WIFI_MODE=ap

# Set wifi password and ssid (client mode)
PSK=[password]
SSID=[ssid]

#
# Wifi client
#
if [ "$WIFI_MODE" == "client" ]
then
/bin/edgemap-ui -m "Connecting wifi as client..."
/bin/iwctl --passphrase $PSK station wlan0 connect $SSID
sleep 5
modprobe i2c-bcm2835
modprobe i2c-dev
sleep 10
/bin/edgemap-ui
exit
fi

#
# Wifi Accesspoint
#
if [ "$WIFI_MODE" == "ap" ]
then
/bin/edgemap-ui -m "Activating Wifi AP. Please wait..."
cp /opt/wifi-ap/wifi-ap/hostapd.service /etc/systemd/system
cp /opt/wifi-ap/wifi-ap/hostapd.conf /etc/
cp /opt/wifi-ap/wifi-ap/wlan0.network /etc/systemd/network
systemctl daemon-reload
systemctl restart systemd-networkd
systemctl restart hostapd
modprobe i2c-bcm2835
modprobe i2c-dev
sleep 10
/bin/edgemap-ui
exit 0
fi

exit 0
