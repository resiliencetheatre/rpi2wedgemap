#!/bin/sh
if [ -d "/opt/data/lost+found" ]
then
    echo "/opt/data partition found!"
    /bin/edgemap-ui -m "/opt/data partition found" -d 2000
else
    /bin/edgemap-ui -m "Creating partition for maps"
    echo "Creating third partition"
    TARGET_DEV=/dev/mmcblk0
    parted --script $TARGET_DEV 'mkpart primary ext4 1100 -1'
    mkfs.ext4 -F -F -L maps ${TARGET_DEV}p3
    /bin/edgemap-ui -m "Partition and ext4 FS created!"
fi
exit 0

