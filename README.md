# Edgemap for RPi Zero 2W

External tree for [buildroot](https://buildroot.org) to build 
[Raspberry Pi Zero 2 W](https://www.raspberrypi.com/products/raspberry-pi-zero-2-w/) firmware 
image with [Waveshare 2.13" display](https://www.waveshare.com/product/2.13inch-touch-e-paper-hat-with-case.htm) support.
With this small unit you are able to serve full world street level map and terrain mode to any phone with web browser.
Based on configuration, unit can create wifi access point and serve full spatial situation scope system from small
and disposable unit. No need for internet or App's on EUD.


![rpi2wedgemap](https://raw.githubusercontent.com/resiliencetheatre/rpi2wedgemap/main/doc/rpizero2w-image.png?raw=true)

Please note that you need full OSM world map, edgemap user interface directory and optional imagery to second partition of MicroSD. 

## Building software

```
mkdir ~/build-directory
cd ~/build-directory
git clone https://git.buildroot.net/buildroot
git clone https://github.com/resiliencetheatre/rpi2wedgemap
```

Current build uses master branch of buildroot. Build is tested with 900bd80e9bfde5f1bb6c2dc746a9149a467f1f09.

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
make rpi2w_edgemap_waveshare_defconfig
make
```

After build is completed, you find image file for MicroSD card at:

```
~/build-directory/buildroot/output/images/sdcard.img
```

## Building hardware

![rpi2wedgemap](https://raw.githubusercontent.com/resiliencetheatre/rpi2wedgemap/main/doc/rpi2w-edgemap.png?raw=true)














