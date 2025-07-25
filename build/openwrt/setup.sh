#!/bin/sh

ONEWIFI_DIR=$(pwd)
OPENWRT_ROOT="$(pwd)/../../.."
HOSTAP_DIR="$(pwd)/../rdk-wifi-libhostap/source"
RDK_WIFI_HAL_DIR="$(pwd)/../rdk-wifi-hal"
KERNEL_PATCH_DIR="$RDK_WIFI_HAL_DIR/platform/banana-pi/kernel-patches/openwrt"
UPSTREAM_HOSTAP_URL="git://w1.fi/hostap.git"
SRCREV_2_10="9d07b9447e76059a2ddef2a879c57d0934634188"

#git clone other wifi related components
cd ..
git clone https://github.com/rdkcentral/rdk-wifi-hal.git rdk-wifi-hal
git clone https://github.com/rdkcentral/rdkb-halif-wifi.git halinterface
cd $ONEWIFI_DIR
mkdir -p install/bin
mkdir -p install/lib


#Check if the HOSTAP_DIR already present before creating
if [ -d "$HOSTAP_DIR" ]; then
        echo "Hostap directory $HOSTAP_DIR  already exists."
else
        mkdir -p $HOSTAP_DIR
fi

#clone the upstream hostap in HOSTAP_DIR as hostap-x.xx
#and move to the relevant commit
cd $HOSTAP_DIR
echo "Cloning hostap in $HOSTAP_DIR"
git clone $UPSTREAM_HOSTAP_URL hostap-2.10
cd hostap-2.10
git reset --hard $SRCREV_2_10

#clone the hostap-patches and apply
git clone https://github.com/rdkcentral/hostap-patches.git hostap-patches

#Apply the patch
patch_filenames="hostap-patches/0001-OneWifi-related-hostap-patch-for-2.10-based-hostap.patch \
	hostap-patches/0002-radius_failover_2.10.patch \
	hostap-patches/0003-mbssid_support_2.10.patch \
        hostap-patches/wpa3_compatibility_hostap_2_10.patch \
        hostap-patches/0005-RDKB-58414-Dynamically-update-NAS_2_10.patch \
        hostap-patches/0006-RDKB-59523-connectivity-via-supplicant.patch \
        hostap-patches/mdu_radius_psk_auth_2_10.patch"
echo "Applying patches ..."
git am $patch_filenames

#Delete the hostap-patches directory after applying
rm -rf hostap-patches

#return back to initial directory
cd $ONEWIFI_DIR
#Copy the Toplevel Makefile of OpenWRT for Easymesh package and golden MT7966 config
cp build/openwrt/Makefile_package ../Makefile
cp build/openwrt/MT7966.config ../../../.config
#Copy the avro dependency to package/libs
cp -r build/openwrt/avro ../../libs/.

#Applying kernel patch from openwrt root directory
cd $OPENWRT_ROOT
patch --forward -p1 < $KERNEL_PATCH_DIR/0001-BPIR4_Enable_Beacon_Frame_Subscription.patch
cd $ONEWIFI_DIR
