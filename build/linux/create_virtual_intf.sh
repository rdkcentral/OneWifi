#!/bin/sh

#This file creates virtual interfaces on the primary interface passed in argument#1
#The number of interfaces created is specified in argument#2.

#check whether number of input argument is 2
if [ $# -ne 2 ]; then
    echo "Usage: $0 <primary_interface> <number_of_interfaces>"
    exit 1
fi

primary_intf=$1
num_intf=$2

#check if primary interface exists before proceeding
if [ ! -e "/sys/class/net/$primary_intf" ]; then
    echo "Error: Primary interface $primary_intf does not exist"
    exit 1
fi

# Create virtual interfaces
for i in $(seq 1 $num_intf); do
    virtual_intf="${primary_intf}.$i"
    sudo iw dev "$primary_intf" interface add "$virtual_intf" type managed
    if [ -e "/sys/class/net/$virtual_intf" ]; then
        echo "Created virtual interface: $virtual_intf"
        sudo ifconfig "$virtual_intf" down
    else
        echo "Error: Unable to create virtual interface: $virtual_intf"
        exit 1
    fi
done

echo "Created $num_intf virtual interfaces based on $primary_intf"
