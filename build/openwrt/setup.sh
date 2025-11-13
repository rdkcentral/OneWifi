#!/bin/sh

ONEWIFI_DIR=$(pwd)
OPENWRT_ROOT="$(pwd)/../../.."
HOSTAP_DIR="$(pwd)/../rdk-wifi-libhostap"
HOSTAP_SRC_DIR="$HOSTAP_DIR/source"
HOSTAP_PATCH_DIR="$HOSTAP_DIR/meta-cmf-bananapi/meta-rdk-mtk-bpir4/recipes-ccsp/rdk-wifi-libhostap/files/2.11"
RDK_WIFI_HAL_DIR="$(pwd)/../rdk-wifi-hal"
KERNEL_PATCH_DIR="$RDK_WIFI_HAL_DIR/platform/banana-pi/kernel-patches/openwrt"
UPSTREAM_HOSTAP_URL="https://git.w1.fi/hostap.git"
SRCREV_2_11="96e48a05aa0a82e91e3cab75506297e433e253d0"

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
fi

#clone the upstream hostap in HOSTAP_DIR as hostap-x.xx
#and move to the relevant commit
cd $HOSTAP_SRC_DIR
echo "Cloning hostap in $HOSTAP_SRC_DIR"
git clone $UPSTREAM_HOSTAP_URL hostap-2.11
cd hostap-2.11
git reset --hard $SRCREV_2_11
cd $HOSTAP_DIR

#Clone meta-cmf-bananapi and apply hostap patches
git clone https://github.com/rdkcentral/meta-cmf-bananapi.git meta-cmf-bananapi
echo "Applying patches ..."
patch --forward -p1 < $HOSTAP_PATCH_DIR/Bpi_rdkwifilibhostap_2_11_changes.patch
patch --forward -p1 -d source/hostap-2.11 < $HOSTAP_PATCH_DIR/0001-mtk-hostapd-patch-all-in-one.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/comcast_changes_merged_to_source_2_11.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/onewifi_lib_2_12.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/RDKB-53254_Telemetry_2.11.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/wps_term_session.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/cmxb7_dfs.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/cohosted_bss_param_211.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/ht_rifs_211.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/vht_oper_basic_mcs_set_211.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/tx_pwr_envelope_211.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/pwr_constraint_211.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/supported_op_classes_211.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/he_2ghz_40mghz_bw_211.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/rnr_col_211.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/tpc_report_211.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/driver_aid_211.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/sta_assoc_req.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/wps_event_notify_cb.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/nl_attr_rx_phy_rate_info.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/hostapd_bss_link_deinit.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/radius_failover_2_11.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/mbssid_support_2_11.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/export_valid_chan_func_2_11.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/increase_eapol_timeout.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/Dynamic_NAS_IP_Update_2_11.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/patch_issues_with2_12.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/wpa3_compatibility_hostap_2_11.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/wpa3_compatibility_telem_hostap_2_11.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/0002-mtk-disable-sae-commit-status.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/mlo_configuration.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/open_auth_workaround.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/mdu_radius_psk_auth_2_11.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/supplicant_new.patch
patch --forward -p1 < $HOSTAP_PATCH_DIR/bpi.patch

#Delete the meta-cmf-bananapi directory after applying patches
rm -rf meta-cmf-bananapi

#return back to initial directory
cd $ONEWIFI_DIR
#Copy the Toplevel Makefile of OpenWRT for Easymesh package and golden MT7966 config
cp build/openwrt/Makefile_package ../Makefile
cp build/openwrt/MT7966.config ../../../.config
#Copy the avro dependency to package/libs
cp -r build/openwrt/avro ../../libs/.

#Applying kernel patch from openwrt root directory
cd $OPENWRT_ROOT
if patch --dry-run --forward -p1 < $KERNEL_PATCH_DIR/0001-BPIR4_Enable_Beacon_Frame_Subscription.patch; then
        patch --forward -p1 < $KERNEL_PATCH_DIR/0001-BPIR4_Enable_Beacon_Frame_Subscription.patch
fi
cd $ONEWIFI_DIR
