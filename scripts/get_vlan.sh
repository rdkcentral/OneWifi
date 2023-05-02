#!/bin/sh

if [ $# -ne 1 ]; then
        exit 1
fi

iface=$1

case $1 in

wlan0.2 | wl0.3)
        lan=brlan2;;
wlan2.2 | wl1.3)
        lan=brlan3;;
wlan0.4 | wl0.5)
        lan=brlan4;;
wlan2.4 | wl1.5)
        lan=brlan5;;
wl2.3)
        lan=bropen6g;;
wl2.5)
        lan=brsecure6g;;
*)
        exit 1
esac

vlan=`brctl show | grep $lan | awk '{print $4}' | cut -d '.' -f2`
if [ "X$vlan" != "X" ]; then
        echo $vlan
else
        exit 1
fi
