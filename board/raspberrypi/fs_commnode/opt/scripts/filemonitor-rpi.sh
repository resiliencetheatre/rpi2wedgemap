#!/bin/sh
#
# This script will read 'rpistatus_[INDEX]' file for blinkstick color.
# File is updated from keygen UI component using NFS file share.
#
# Remember you need to mount NFS with 'noac' option, eg:
#
# 10.100.0.20:/mnt/nfs /opt/nfs nfs4 defaults,user,exec,_netdev,noac 0 0
#

# Source NODE_ID
source /opt/boot/burnnode.conf

# Monitor file
FILE=/opt/nfs/rpistatus_$NODE_ID

# Clean state
rm $FILE
blinkstick-cli --color 0 0 0 --index 1

# State variable to reduce extensive writes
STATE=0

while [ ! -f /opt/nfs/nfs_ready ]
do
 echo "Waiting /opt/nfs/nfs_ready"
 sleep 5
done



while [ 1 ]
do
    if [ -e $FILE ]
    then
     COLOR_VALUE=$(cat $FILE)
     if [ "$STATE" = "0" ] | [ "$CACHED_COLOR_VALUE" != "$COLOR_VALUE" ]; then
        COLOR_VALUE=$(cat $FILE)
        blinkstick-cli --color $COLOR_VALUE --index 1
        STATE=1
        CACHED_COLOR_VALUE=$COLOR_VALUE
     fi
    else
     if [ "$STATE" = "1" ]; then
        blinkstick-cli --color 0 0 0 --index 1
        STATE=0
     fi
    fi
    sleep 2
done

exit 0
