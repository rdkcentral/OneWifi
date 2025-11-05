#!/bin/sh

ONEWIFI_DIR=$(pwd)
HOSTAP_DIR="$(pwd)/../rdk-wifi-libhostap/source"
UPSTREAM_HOSTAP_URL="https://git.w1.fi/hostap.git"
SRCREV_2_10="9d07b9447e76059a2ddef2a879c57d0934634188"

#git clone other wifi related components
cd ..
git clone https://github.com/rdkcentral/rdk-wifi-hal.git rdk-wifi-hal
git clone https://github.com/rdkcentral/rdkb-halif-wifi.git halinterface
git clone https://github.com/xmidt-org/trower-base64.git trower-base64

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
