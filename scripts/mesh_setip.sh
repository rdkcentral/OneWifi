#!/bin/sh
######################################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:

#  Copyright 2018 RDK Management

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#######################################################################################

MODEL_NUM=`grep MODEL_NUM /etc/device.properties | cut -d "=" -f2`
IF_MESHBR24=`wifi_api wifi_getApBridgeInfo 12 "" "" "" | head -n 1`
IF_MESHBR50=`wifi_api wifi_getApBridgeInfo 13 "" "" "" | head -n 1`
MESHBR24_IP="169.254.0.1 netmask 255.255.255.0"
MESHBR50_IP="169.254.1.1 netmask 255.255.255.0"
IF_MESHEB="brebhaul"
MESHEB_IP="169.254.85.1 netmask 255.255.255.0"

BRIDGE_MTU=1600

ovs_enable=false

if [ -d "/sys/module/openvswitch/" ];then
   ovs_enable=true 
fi

bridgeUtilEnable=`syscfg get bridge_util_enable`
USE_BRIDGEUTILS=0

if [ "x$ovs_enable" = "xtrue" ] || [ "x$bridgeUtilEnable" = "xtrue" ] ; then
	if [ "$MODEL_NUM" == "CGM4331COM" ] || [ "$MODEL_NUM" == "CGM4981COM" ] || [ "$MODEL_NUM" == "SR300" ] || [ "$MODEL_NUM" == "SE501" ]; then
	  USE_BRIDGEUTILS=1
	fi
fi

#XF3 & CommScope XB7 specific changes
if [ "$MODEL_NUM" == "PX5001" ] || [ "$MODEL_NUM" == "CGM4331COM" ] || [ "$MODEL_NUM" == "CGM4981COM" ] || [ "$MODEL_NUM" == "TG4482A" ]; then
 IF_MESHBR24="brlan112"
 IF_MESHBR50="brlan113"

 if [ "$MODEL_NUM" == "TG4482A" ]; then
    IF_MESHVAP24="wlan0.6"
    IF_MESHVAP50="wlan2.6"
 else
    IF_MESHVAP24="wl0.6"
    IF_MESHVAP50="wl1.6"
 fi
 PLUME_BH1_NAME="brlan112"
 PLUME_BH2_NAME="brlan113"
 PLUME_BHAUL_NAME="br403"
 DEFAULT_MESHBHUAL_IPV4_ADDR="192.168.245.1"
 DEFAULT_PLUME_BH1_IPV4_ADDR="169.254.0.1"
 DEFAULT_PLUME_BH2_IPV4_ADDR="169.254.1.1"
 DEFAULT_PLUME_BH_NETMASK="255.255.255.0"
fi

#SKYHUB4 specific changes
if [ "$MODEL_NUM" == "SR201" ] || [ "$MODEL_NUM" == "SR203" ] || [ "$MODEL_NUM" == "SR300" ] ||  [ "$MODEL_NUM" == "SE501" ]; then
 IF_MESHBR24="brlan6"
 IF_MESHBR50="brlan7"
 IF_MESHVAP24="wl0.6"
 IF_MESHVAP50="wl1.6"
 PLUME_BH1_NAME="brlan6"
 PLUME_BH2_NAME="brlan7"
 PLUME_BHAUL_NAME="br403"
 DEFAULT_MESHBHUAL_IPV4_ADDR="192.168.245.1"
 DEFAULT_PLUME_BH1_IPV4_ADDR="169.254.0.1"
 DEFAULT_PLUME_BH2_IPV4_ADDR="169.254.1.1"
 DEFAULT_PLUME_BH_NETMASK="255.255.255.0"
fi

if [ "$MODEL_NUM" == "PX5001" ]; then
 IF_ETH_IFACE="eth0 eth1 eth2 eth3"
fi
mesh_bridges()
{

echo "ADD wifi interfaces to the Bridge $PLUME_BH1_NAME" > /dev/console
for WIFI_IFACE in $IF_MESHVAP24
do
   /sbin/ifconfig $WIFI_IFACE down
done

for WIFI_IFACE in $IF_MESHVAP24
do
   brctl addif $PLUME_BH1_NAME $WIFI_IFACE
   /sbin/ifconfig $WIFI_IFACE 0.0.0.0 up
done

echo inf add wl0.6 > /proc/driver/flowmgr/cmd

echo 1 > /sys/class/net/$PLUME_BH1_NAME/bridge/nf_call_iptables
echo 1 > /sys/class/net/$PLUME_BH1_NAME/bridge/nf_call_arptables
   /sbin/ifconfig $PLUME_BH1_NAME $DEFAULT_PLUME_BH1_IPV4_ADDR netmask $DEFAULT_PLUME_BH_NETMASK up


echo "ADD wifi interfaces to the Bridge $PLUME_BH2_NAME" > /dev/console
for WIFI_IFACE in $IF_MESHVAP50
do
   /sbin/ifconfig $WIFI_IFACE down
done

for WIFI_IFACE in $IF_MESHVAP50
do
   brctl addif $PLUME_BH2_NAME $WIFI_IFACE
   /sbin/ifconfig $WIFI_IFACE 0.0.0.0 up
done

echo inf add wl1.6 > /proc/driver/flowmgr/cmd

echo 1 > /sys/class/net/$PLUME_BH2_NAME/bridge/nf_call_iptables
echo 1 > /sys/class/net/$PLUME_BH2_NAME/bridge/nf_call_arptables
   /sbin/ifconfig $PLUME_BH2_NAME $DEFAULT_PLUME_BH2_IPV4_ADDR netmask $DEFAULT_PLUME_BH_NETMASK up

}

mesh_bhaul()
{
 brctl addbr $PLUME_BHAUL_NAME
 echo 1 > /sys/class/net/$PLUME_BHAUL_NAME/bridge/nf_call_iptables
 echo 1 > /sys/class/net/$PLUME_BHAUL_NAME/bridge/nf_call_arptables
 /sbin/ifconfig $PLUME_BHAUL_NAME $DEFAULT_MESHBHUAL_IPV4_ADDR netmask $DEFAULT_PLUME_BH_NETMASK up
 ifconfig $PLUME_BHAUL_NAME up
}

is_vlan() {
    ifn="$1"
    [ -z "$ifn" ] && return 1

    ip -d link show $ifn | grep vlan > /dev/null
    return $?
}

vlan_root() {
    echo "$1" | cut -d '.' -f 1
}

bridge_interfaces() {
    br_ifn="$1"
    [ -z "$br_ifn" ] && return

    brctl show $br_ifn | grep -v STP | while read a b c d; do
        [ ${#d} -eq 0 ] && echo $a || echo $d
    done
}

bridge_set_mtu() {
    br_ifn="$1"
    br_mtu="$2"
    [ -z "$br_ifn" -o -z "$br_mtu" ] && return

    echo "...Setting bridge $br_ifn MTU to $br_mtu"
    for ifn in $(bridge_interfaces $br_ifn); do
        echo "......Setting $(vlan_root $ifn) MTU to $br_mtu"
        ifconfig $ifn mtu $br_mtu
    done

    ifconfig $br_ifn $br_mtu
}

mesh_bridge_setup() {

brctl addbr $PLUME_BH1_NAME
brctl addbr $PLUME_BH2_NAME
/sbin/ifconfig $PLUME_BH1_NAME $DEFAULT_PLUME_BH1_IPV4_ADDR netmask $DEFAULT_PLUME_BH_NETMASK up
/sbin/ifconfig $PLUME_BH2_NAME $DEFAULT_PLUME_BH2_IPV4_ADDR netmask $DEFAULT_PLUME_BH_NETMASK up

if [ "$MODEL_NUM" == "TG4482A" ]; then
    ifconfig $IF_MESHBR24 mtu $BRIDGE_MTU
    ifconfig $IF_MESHVAP24 mtu $BRIDGE_MTU
    ifconfig $IF_MESHBR50 mtu $BRIDGE_MTU
    ifconfig $IF_MESHVAP50 mtu $BRIDGE_MTU
fi

brctl delif brlan0 $IF_MESHVAP24
brctl delif brlan0 $IF_MESHVAP50
brctl addif $PLUME_BH1_NAME $IF_MESHVAP24
brctl addif $PLUME_BH2_NAME $IF_MESHVAP50

}

#Setup backhaul bridge for Ethernet Pod connection
if [ "$1" == "set_eb" ];then 
    if [ "$2" == "1" ];then
     brctl addbr $IF_MESHEB
     /sbin/ifconfig $IF_MESHEB $MESHEB_IP up
     for iface in $IF_ETH_IFACE;do
      vconfig add $iface 123
      ifconfig $iface.123 up
      brctl addif $IF_MESHEB $iface.123
     done
     echo e 0 > /proc/driver/ethsw/vlan
    else
     for iface in $IF_ETH_IFACE;do
      ip link del $iface.123
     done
    fi
    exit 0
fi

if [ "$MODEL_NUM" == "SR201" ] || [ "$MODEL_NUM" == "SR203" ]  || [ "$MODEL_NUM" == "SR300" ] ||  [ "$MODEL_NUM" == "SE501" ] || [ "$MODEL_NUM" == "CGM4981COM" ] || [ "$MODEL_NUM" == "CGM4331COM" ] || [ "$MODEL_NUM" == "TG4482A" ]; then
  if [ $USE_BRIDGEUTILS -eq 1 ]; then
    sysevent set multinet-up 13
    sysevent set multinet-up 14
  else
    mesh_bridge_setup
  fi
fi

if [ -n "${IF_MESHBR24}" ] && [ $USE_BRIDGEUTILS -eq 0 ]; then
    echo "Configuring $IF_MESHBR24"
    bridge_set_mtu $IF_MESHBR24 $BRIDGE_MTU
    ifconfig $IF_MESHBR24 $MESHBR24_IP
    if [ "$MODEL_NUM" == "PX5001" ] || [ "$MODEL_NUM" == "CGM4331COM" ] || [ "$MODEL_NUM" == "CGM4981COM" ] || [ "$MODEL_NUM" == "SR201" ] || [ "$MODEL_NUM" == "SR203" ] || [ "$MODEL_NUM" == "SR300" ] ||  [ "$MODEL_NUM" == "SE501" ]; then
     ifconfig $IF_MESHBR24 mtu $BRIDGE_MTU
     ifconfig $IF_MESHVAP24 mtu $BRIDGE_MTU
    fi
fi

if [ -n "${IF_MESHBR50}" ] && [ $USE_BRIDGEUTILS -eq 0 ]; then
    echo "Configuring $IF_MESHBR50"
    bridge_set_mtu $IF_MESHBR50 $BRIDGE_MTU
    ifconfig $IF_MESHBR50 $MESHBR50_IP
    if [ "$MODEL_NUM" == "PX5001" ] || [ "$MODEL_NUM" == "CGM4331COM" ] || [ "$MODEL_NUM" == "CGM4981COM" ] || [ "$MODEL_NUM" == "SR201" ] || [ "$MODEL_NUM" == "SR203" ] || [ "$MODEL_NUM" == "SR300" ] ||  [ "$MODEL_NUM" == "SE501" ]; then
     ifconfig $IF_MESHBR50 mtu $BRIDGE_MTU
     ifconfig $IF_MESHVAP50 mtu $BRIDGE_MTU
    fi
fi


if [ "$MODEL_NUM" == "PX5001" ] || [ "$MODEL_NUM" == "CGM4331COM" ] || [ "$MODEL_NUM" == "CGM4981COM" ] || [ "$MODEL_NUM" == "SR201" ] || [ "$MODEL_NUM" == "SR203" ]  || [ "$MODEL_NUM" == "SR300" ] ||  [ "$MODEL_NUM" == "SE501" ] || [ "$MODEL_NUM" == "TG4482A" ]; then
        if [ "$MODEL_NUM" == "TG4482A" ]; then
                brctl112=`brctl show | grep wlan0.6`
                brctl113=`brctl show | grep wlan2.6`
        else
                brctl113=`brctl show | grep wl1.6`
                brctl112=`brctl show | grep wl0.6`
        fi
        if [ "$brctl113" == "" ] || [ "$brctl112" == "" ] && [ "$MODEL_NUM" == "PX5001" ]; then
                mesh_bridges
        fi
        #RDKB-15951- Xf3 & Sky specific change: Moving over bhaul to br403 Prash
        if [ "x$ovs_enable" = "xtrue" ] || [ "x$bridgeUtilEnable" = "xtrue" ];then
	    if [ "x$ovs_enable" = "xtrue" ]; then
            	ifbr403=`ovs-vsctl show | grep br403`
	    else
		ifbr403=`brctl show | grep br403`
	    fi
            if [ "$ifbr403" == "" ]; then
                sysevent set meshbhaul-setup 10
            fi
        else
            brctl403=`brctl show | grep br403`
            if [ "$brctl403" == "" ]; then
                mesh_bhaul
            fi
        fi

fi

