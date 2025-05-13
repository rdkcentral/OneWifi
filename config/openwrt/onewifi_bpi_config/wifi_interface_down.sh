#!/bin/sh

echo "Bringing down all wifi interfaces and deleting it"
ifconfig wifi0 down
ifconfig wifi1 down
ifconfig wifi1.1 down
ifconfig wifi1.2 down
ifconfig wifi2 down

#delete the interfaces
iw dev wifi0 del
iw dev wifi1 del
iw dev wifi1.1 del
iw dev wifi1.2 del
iw dev wifi2 del
