#!/bin/sh
if [ -d "/mnt/lost+found" ] 
then
    echo "/mnt partition found!" 
else
    echo "Creating third partition"
    TARGET_DEV=/dev/mmcblk0
    parted --script $TARGET_DEV 'mkpart primary ext4 1100 -1'
    mkfs.ext4 -F -F ${TARGET_DEV}p2
fi
exit 0

