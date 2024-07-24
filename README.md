# Edgemap for RPi Zero 2W

NOTE: This is 'meshtastic-maplibre4' branch. There is now support for meshtastic radios as message
bearer. There is also first boot service, which will create second partition to your MicroSD on
first boot. 

External tree for [buildroot](https://buildroot.org) to build 
[Raspberry Pi Zero 2 W](https://www.raspberrypi.com/products/raspberry-pi-zero-2-w/) firmware 
image with [Waveshare 2.13" display](https://www.waveshare.com/product/2.13inch-touch-e-paper-hat-with-case.htm) support.
With this small unit you are able to serve full world street level map and terrain model to any EUD with web browser.
Based on configuration unit can create wifi access point and serve full spatial situation scope system from small
and disposable unit. No need for internet or App's to EUD.

![rpi2wedgemap](https://raw.githubusercontent.com/resiliencetheatre/rpi2wedgemap/main/doc/rpizero2w-image.png?raw=true)

Please note that you need full OSM world map, edgemap user interface directory and optional imagery to second partition of MicroSD. 

## Building software

```
mkdir ~/build-directory
cd ~/build-directory
git clone https://git.buildroot.net/buildroot
git clone https://github.com/resiliencetheatre/rpi2wedgemap
```

Current build uses master branch of buildroot. Build is tested with bb8766cc5463e59b931a10ec67793a79fb06eda7.

Modify `rpi-firmware` package file and change firmware version tag to
match kernel version (6.1.77) we're using. 

```
# package/rpi-firmware/rpi-firmware.mk
RPI_FIRMWARE_VERSION = 7273369aded28c56937cda2ec8e305f86eaa1203
```

Disable hash check by deleting hash file:

```
cd ~/build-directory/buildroot
rm package/rpi-firmware/rpi-firmware.hash
```

After you're stable with kernel and firmware versions, re-create hash file.

If your PHP build fails, add following as **0007-crc.patch** file under package/php/ 

```
package/php/0007-crc.patch 
--- a/ext/standard/crc32.c	2024-01-16 14:19:32.000000000 +0200
+++ b/ext/standard/crc32.c	2024-02-21 18:10:38.737450406 +0200
@@ -67,7 +67,7 @@
 # if defined(__GNUC__)
 #  if!defined(__clang__)
 #   pragma GCC push_options
-#   pragma GCC target ("+nothing+crc")
+#   pragma GCC target ("arch=armv8-a+crc")
 #  else
 #   pragma clang attribute push(__attribute__((target("+nothing+crc"))), apply_to=function)
 #  endif
```

Define _external tree_ location to **BR2_EXTERNAL** variable:

```
export BR2_EXTERNAL=~/build-directory/rpi2wedgemap
```

Make edgemap configuration (defconfig) and start building:

```
cd ~/build-directory/buildroot
make rpi2w_edgemap_waveshare_6.6_defconfig
make
```

After build is completed, you find image file for MicroSD card at:

```
~/build-directory/buildroot/output/images/sdcard.img
```

## Installation

On first boot system checks if there is second partition available on MicroSD card. This partition
holds 'edgemap' directory and planet.pmtiles world map file. If first partition is missing, it gets 
created when first boot happen. Give it plenty of time to create this data partition on first boot.
You can follow progress on eInk display. When you see 'Partition and ext4 FS created!' on eInk, you 
can turn off device and extract 'data-partition.tar.gz' and 'planet.pmtiles' to second partition. 

'data-partition.tar.gz' directory can be found as tar on release page at Github and planet.pmtiles can be downloaded
from [here](https://maps.protomaps.com/builds/). You can optionally load global terrain RGB dataset 
from [Mapzen Joerd](https://github.com/tilezen/joerd) project and place it to second partition with
'terrarium_z9.pmtiles' as file name. 

You can untar provided 'data-partition.tar.gz' file with:

```
tar xf data-partition.tar.gz -C [mount_point_of_your_second_partition]
```

Remember to rename downloaded planet OSM pmtile file to 'planet.pmtiles'
on second partition.

## Configuration

You can place your SSH public key to 'authorized_keys' on second partition or
use root/root to access internals of your edgemap node. Please note that using
this image with root access active is only for demonstration purposes. To disable
or change root password, you need to re-compile image yourself.

If you like to use Meshtastic radios, you need to place 'meshtastic.env' to 
first partition of your card and define radio serial port as:

```
MESHTASTIC_PORT="/dev/ttyUSB0"
```

### bootstrap.sh

System executes 'bootstrap.sh' from boot partition, so you can place following file
to first partition on your MicroSD card. Adjust PSK and SSID if you like to use
wifi as client or change WIFI_MODE to 'ap' if you like to use edgemap as wifi Access Point.

```
#!/bin/sh
#
# Edgemap for RPi zero 2w - bootstrap.sh
#

# Set wifi mode (ap or client)
WIFI_MODE=client

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
cp /opt/data/wifi-ap/hostapd.service /etc/systemd/system
cp /opt/data/wifi-ap/hostapd.conf /etc/
cp /opt/data/wifi-ap/wlan0.network /etc/systemd/network
systemctl daemon-reload
systemctl restart systemd-networkd
systemctl restart hostapd
modprobe i2c-bcm2835
modprobe i2c-dev
sleep 2
/bin/edgemap-ui
exit 0
fi

exit 0
```

Remember to make script executable on your MicroSD card with:

```
chmod +x bootstrap.sh
```

## Building hardware

You can find bill of materials at my [Wiki](https://resilience-theatre.com/wiki/doku.php?id=edgemap:meshtastic_bom).














