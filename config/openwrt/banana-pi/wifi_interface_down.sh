#!/bin/sh

echo "Bringing down all wifi interfaces and deleting it"
ifconfig wifi0 down
ifconfig wifi0.1 down
ifconfig wifi0.2 down
ifconfig wifi1 down
ifconfig wifi1.1 down
ifconfig wifi1.2 down
ifconfig wifi1.3 down
ifconfig wifi2 down
#ifconfig wifi2.1 down
#ifconfig wifi2.2 down
ifconfig mld0 down

#delete the interfaces
iw dev wifi0 del
iw dev wifi0.1 del
iw dev wifi0.2 del
iw dev wifi1 del
iw dev wifi1.1 del
iw dev wifi1.2 del
iw dev wifi1.3 del
iw dev wifi2 del
#iw dev wifi2.1 del
#iw dev wifi2.2 del
iw dev mld0 del
