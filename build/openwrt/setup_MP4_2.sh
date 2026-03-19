#!/bin/sh

ONEWIFI_DIR=$(pwd)
OPENWRT_ROOT="$(pwd)/../../.."
HOSTAP_DIR="$(pwd)/../rdk-wifi-libhostap"
HOSTAP_SRC_DIR="$HOSTAP_DIR/source"
HOSTAP_PATCH_LIST="$ONEWIFI_DIR/build/openwrt/hostap_patch_list.txt"
HOSTAP_PATCH_DIR_META_CMF_BPI="$HOSTAP_DIR/meta-cmf-bananapi/meta-rdk-mtk-bpir4/recipes-ccsp/rdk-wifi-libhostap/files/2.11/kernel_6_6"
HOSTAP_PATCH_DIR_META_FILOGIC="$HOSTAP_DIR/meta-filogic/recipes-wifi/hostapd/files/kernel6-6-patches"
HOSTAP_PATCH_FLAG="$HOSTAP_DIR/.hostap_patched"
RDK_WIFI_HAL_DIR="$(pwd)/../rdk-wifi-hal"
KERNEL_PATCH_DIR="$RDK_WIFI_HAL_DIR/platform/banana-pi/kernel-patches_6.6/openwrt"
UPSTREAM_HOSTAP_URL="https://git.w1.fi/hostap.git"
SRCREV_2_11="4b8ac10cb77c3d4dbf7ccefbe697dc0578da374c"
META_CMF_BPI_URL="https://github.com/rdkcentral/meta-cmf-bananapi.git"
META_FILOGIC_URL="https://git01.mediatek.com/filogic/rdk-b/meta-filogic"
SRCREV_META_FILOGIC="c67a32a7c8876b328a8d1eeaca213e860d85b3ce"

# Apply network optimizations for reliable git clone
export GIT_HTTP_LOW_SPEED_LIMIT=0
export GIT_HTTP_LOW_SPEED_TIME=999999

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
        echo "Hostap directory $HOSTAP_DIR already exists."
else
        mkdir -p $HOSTAP_DIR
fi

#Check if the HOSTAP_SRC_DIR already present before creating
if [ -d "$HOSTAP_SRC_DIR" ]; then
    echo "Hostap source directory $HOSTAP_SRC_DIR already exists."
else
    mkdir -p "$HOSTAP_SRC_DIR"
    #clone the upstream hostap in HOSTAP_DIR as hostap-x.xx
    #and move to the relevant commit
    cd $HOSTAP_SRC_DIR
    echo "Cloning hostap in $HOSTAP_SRC_DIR"
    git clone $UPSTREAM_HOSTAP_URL hostap-2.11
    cd hostap-2.11
    git reset --hard $SRCREV_2_11
    cd $HOSTAP_DIR
fi

if [ -f "$HOSTAP_PATCH_FLAG" ]; then
    echo "Hostap patches are already applied. Retry after deleting $HOSTAP_DIR"
else
    #Clone meta-cmf-bananapi, meta-filogic and  apply hostap patches
    [ ! -d "meta-cmf-bananapi" ] && git clone "$META_CMF_BPI_URL" meta-cmf-bananapi

    if [ ! -d "meta-filogic" ]; then
        mkdir -p meta-filogic && cd meta-filogic
        git init
        git remote add origin "$META_FILOGIC_URL"
        #Increased HTTP post buffer to 1GB to prevent "RPC failed" or "Broken pipe" errors.
        git config http.postBuffer 1048576000
        git fetch --depth 1 origin "$SRCREV_META_FILOGIC"
        git reset --hard FETCH_HEAD
        cd "$HOSTAP_DIR"
    fi

    echo "Applying hostap patches ..."

    if [ ! -f "$HOSTAP_PATCH_LIST" ]; then
        echo "$HOSTAP_PATCH_LIST not found!"
        exit 1
    fi

    while IFS= read -r line || [ -n "$line" ]; do

        [ -z "$line" ] && continue
        line=$(echo "$line" | sed 's/\\$//' | xargs)
        raw_patch_file=$(echo "$line" | cut -d';' -f1)
        eval patch_file="$raw_patch_file"

        patch_dir=$(echo "$line" | grep -o 'patchdir=[^;]*' | cut -d'=' -f2)

        echo "Applying patch: $patch_file"

        if [ -n "$patch_dir" ]; then
            patch --forward -p1 -d "$patch_dir" < "$patch_file"
        else
            patch --forward -p1 < "$patch_file"
        fi

        if [ $? -ne 0 ]; then
            echo "Patch failed: $patch_file"
            exit 1
        fi

    done < "$HOSTAP_PATCH_LIST"
    touch "$HOSTAP_PATCH_FLAG"
    echo "All patches applied successfully."
fi

#Delete the meta-cmf-bananapi and meta-filogic directories after applying patches
rm -rf meta-cmf-bananapi
rm -rf meta-filogic

#return back to initial directory
cd $ONEWIFI_DIR
#Copy the Toplevel Makefile of OpenWRT for Easymesh package and golden MT7966 config
cp build/openwrt/Makefile_package_MP4_2 ../Makefile
cp build/openwrt/MT7966_4_2.config ../../../.config
#Copy the avro dependency to package/libs
cp -r build/openwrt/avro ../../libs/.

#Applying kernel patch from openwrt root directory
cd $OPENWRT_ROOT
if patch --dry-run --forward -p1 < $KERNEL_PATCH_DIR/0001-BPIR4_Enable_Beacon_Frame_Subscription.patch; then
        patch --forward -p1 < $KERNEL_PATCH_DIR/0001-BPIR4_Enable_Beacon_Frame_Subscription.patch
fi
cd $ONEWIFI_DIR
