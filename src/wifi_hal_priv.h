/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2018 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/


#ifndef WIFI_HAL_PRIV_H
#define WIFI_HAL_PRIV_H

#include <stdint.h>
#include <utils/includes.h>
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/uuid.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "common/sae.h"
#include "radius/radius.h"
#include "radius/radius_client.h"
#include "fst/fst.h"
#include "crypto/crypto.h"
#include "crypto/tls.h"
#include "hostapd.h"
#include "accounting.h"
#include "ieee802_1x.h"
#include "ieee802_11.h"
#include "ieee802_11_auth.h"
#include "wpa_auth.h"
#include "preauth_auth.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "beacon.h"
#include "ap_mlme.h"
#include "vlan_init.h"
#include "gas_serv.h"
#include "wnm_ap.h"
#include "sta_info.h"
#include "vlan.h"
#include "wps_hostapd.h"
#include "hostapd/ctrl_iface.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/wpa_i.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "eap_peer/eap_config.h"
#include "eap_peer/eap.h"
#include <stdbool.h>
#include "wifi_hal.h"
#include "wifi_hal_sta.h"
#include "wifi_hal_rdk_framework.h"
#include "wifi_hal_wnm_rrm.h"
#include "collection.h"
#include "driver.h"

#if defined(CONFIG_WIFI_EMULATOR) || defined(BANANA_PI_PORT)
#include "wpa_supplicant_i.h"
#include "bss.h"
#include "sme.h"
#endif

/*
switch to use nl80211_copy.h because 'linux/nl80211.h' from linux header does not contain
6GHz definitions. The 6GHz defines for nl80211 are in hostapd 2.10 but not hostapd 2.9.
*/
// #include <linux/nl80211.h>
#include <drivers/nl80211_copy.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <netlink/handlers.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "driver_nl80211.h"
#include "hw_features.h"

#include <sys/prctl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_HAL_MAJOR  3
#define WIFI_HAL_MINOR  0
#ifdef HOSTAPD_2_11
    #define HOSTAPD_VERSION 211
#elif HOSTAPD_2_10
    #define HOSTAPD_VERSION 210
#else
    #define HOSTAPD_VERSION 209
#endif

#define EM_CFG_FILE "/nvram/EasymeshCfg.json"

#ifdef CONFIG_WIFI_EMULATOR
#define MAX_NUM_SIMULATED_CLIENT (MAX_NUM_RADIOS*100)
#endif

/*
 * Copyright (c) 2003-2013, Jouni Malinen <j@w1.fi>
 * Licensed under the BSD-3 License
*/
#if 0
#define RSN_SELECTOR(a, b, c, d) \
   ((((unsigned int) (a)) << 24) | (((unsigned int) (b)) << 16) | (((unsigned int) (c)) << 8) | \
   (unsigned int) (d))
#endif
#define RSN_CIPHER_SUITE_NONE RSN_SELECTOR(0x00, 0x0f, 0xac, 0)
#define RSN_CIPHER_SUITE_TKIP RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#if 0
#define RSN_CIPHER_SUITE_WRAP RSN_SELECTOR(0x00, 0x0f, 0xac, 3)
#endif
#define RSN_CIPHER_SUITE_CCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
#define RSN_CIPHER_SUITE_AES_128_CMAC RSN_SELECTOR(0x00, 0x0f, 0xac, 6)
#define RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED RSN_SELECTOR(0x00, 0x0f, 0xac, 7)
#define RSN_CIPHER_SUITE_GCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 8)
#define RSN_CIPHER_SUITE_GCMP_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 9)
#define RSN_CIPHER_SUITE_CCMP_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 10)
#define RSN_CIPHER_SUITE_BIP_GMAC_128 RSN_SELECTOR(0x00, 0x0f, 0xac, 11)
#define RSN_CIPHER_SUITE_BIP_GMAC_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 12)
#define RSN_CIPHER_SUITE_BIP_CMAC_256 RSN_SELECTOR(0x00, 0x0f, 0xac, 13)

#define WIFI_CIPHER_CAPA_ENC_WEP40   0x00000001
#define WIFI_CIPHER_CAPA_ENC_WEP104  0x00000002
#define WIFI_CIPHER_CAPA_ENC_TKIP    0x00000004
#define WIFI_CIPHER_CAPA_ENC_CCMP    0x00000008
#define WIFI_CIPHER_CAPA_ENC_WEP128  0x00000010
#define WIFI_CIPHER_CAPA_ENC_GCMP    0x00000020
#define WIFI_CIPHER_CAPA_ENC_GCMP_256    0x00000040
#define WIFI_CIPHER_CAPA_ENC_CCMP_256    0x00000080
#define WIFI_CIPHER_CAPA_ENC_BIP     0x00000100
#define WIFI_CIPHER_CAPA_ENC_BIP_GMAC_128    0x00000200
#define WIFI_CIPHER_CAPA_ENC_BIP_GMAC_256    0x00000400
#define WIFI_CIPHER_CAPA_ENC_BIP_CMAC_256    0x00000800
#define WIFI_CIPHER_CAPA_ENC_GTK_NOT_USED    0x00001000

#define DEFAULT_WPA_DISABLE_EAPOL_KEY_RETRIES 0
#define RADIUS_CLIENT_MAX_RETRIES 5
#define RADIUS_CLIENT_MAX_WAIT 120
#define ecw2cw(ecw) ((1 << (ecw)) - 1)

#define     MAX_BSSID_IN_ESS    8

#define MAX_FREQ_LIST_SIZE 128

#define BUF_SIZE         32
#define NL_SOCK_MAX_BUF_SIZE             262144
#define NVRAM_NAME_SIZE  32
#define WPS_METHODS_SIZE 512
#define WPS_PIN_SIZE     9

#define IEEE80211_HE_PPE_THRES_MAX_LEN 25

#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G        0x02
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G  0x04
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G       0x08
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G 0x10
#define IEEE80211_HE_PHY_CAP3_SU_BEAMFORMER                        0x80
#define IEEE80211_HE_PHY_CAP4_SU_BEAMFORMEE                        0x01
#define IEEE80211_HE_PHY_CAP4_MU_BEAMFORMER                        0x02

#define IEEE80211_EXTCAPIE_BSSTRANSITION     0x00080000
#define IEEE80211_VHTCAP_MU_BFORMER          0x00080000 /* B19 MU Beam Formee */
#define IEEE80211_VHTCAP_MU_BFORMEE          0x00100000 /* B20 MU Beam Formee */
#define IEEE80211_VHTCAP_SHORTGI_160         0x00000040
#define IEEE80211_HTCAP_C_CHWIDTH40          0x0002
#define IEEE80211_HTCAP_C_SM_MASK            0x000c

#define IEEE80211_RRM_CAPS_LINK_MEASUREMENT             BIT(0)
#define IEEE80211_RRM_CAPS_NEIGHBOR_REPORT              BIT(1)
#define IEEE80211_RRM_CAPS_BEACON_REPORT_PASSIVE        BIT(4)
#define IEEE80211_RRM_CAPS_BEACON_REPORT_ACTIVE         BIT(5)
#define IEEE80211_RRM_CAPS_BEACON_REPORT_TABLE          BIT(6)
/* byte 2 (out of 5) */
#define IEEE80211_RRM_CAPS_LCI_MEASUREMENT              BIT(4)
/* byte 5 (out of 5) */
#define IEEE80211_RRM_CAPS_FTM_RANGE_REPORT             BIT(2)

/* 2GHz radio */
#define MIN_FREQ_MHZ_2G             2412
#define MAX_FREQ_MHZ_2G             2484
#define MIN_CHANNEL_2G              1
#define MAX_CHANNEL_2G              14

/* 5GHz radio */
#define MIN_FREQ_MHZ_5G             5180
#ifndef _PLATFORM_BANANAPI_R4_
#define MAX_FREQ_MHZ_5G             5825
#else //_PLATFORM_BANANAPI_R4_
#define MAX_FREQ_MHZ_5G             5885
#endif //_PLATFORM_BANANAPI_R4_
#define MIN_CHANNEL_5G              36
#ifndef _PLATFORM_BANANAPI_R4_
#define MAX_CHANNEL_5G              165
#else //_PLATFORM_BANANAPI_R4_
#define MAX_CHANNEL_5G              177
#endif //_PLATFORM_BANANAPI_R4_

/* 6GHz radio */
#define MIN_FREQ_MHZ_6G             5935
#define MAX_FREQ_MHZ_6G             7115
#define MIN_CHANNEL_6G              1
#define MAX_CHANNEL_6G              229

#define MAX_WPS_CONN_TIMEOUT        120

#define MGMT_FRAME_RESPONSE_STATUS_OK 0
#define MGMT_FRAME_RESPONSE_STATUS_DENY 1
#define MAX_APPS 12

#define SSID_MAX_LEN                32
#define MAX_STEERING_GROUP_NUM      8
#define ACS_MAX_VECTOR_LEN  (256 * 7) /* Max Possible non operable (Exclude) chanspecs in a radio is 256*/

/* use one sta table for different type lists:
 * ASSOC:     the STA is associated
 * ClientSet: the STA is configured by wifi_hal API ClientSet
 * MACLIST:   the STA is added to mac filter for probe/auth response control
 */
#define BM_STA_TYPE_ASSOC      0x01
#define BM_STA_TYPE_CLIENT_SET 0x02
#define BM_STA_TYPE_MACLIST    0x04

#define INACTIVITY_TIMEOUT      60
#define STA_INFO_UPDATE_TIMEOUT 10

#define AUTH_INVAL_REASON       2       /* Previous authentication no longer valid */

#define BM_SENT_E_DISASSOC      (1 << 0)
#define BM_SENT_E_ASSOC         (1 << 1)

#if HOSTAPD_VERSION >= 211
#define CHANWIDTH_320MHZ CONF_OPER_CHWIDTH_320MHZ
#endif /* HOSTAPD_VERSION >= 211 */

extern const struct wpa_driver_ops g_wpa_driver_nl80211_ops;
#ifdef CONFIG_WIFI_EMULATOR
extern const struct wpa_driver_ops g_wpa_supplicant_driver_nl80211_ops;
#endif

extern const unsigned int wifi_2g_channels[];
extern const unsigned int wifi_2g_channels_count;

extern const unsigned int wifi_5g_channels[];
extern const unsigned int wifi_5g_channels_count;

extern const unsigned int wifi_6g_channels[];
extern const unsigned int wifi_6g_channels_count;
typedef struct wifi_enum_to_str_map
{
    int enum_val;
    const char *str_val;
} wifi_enum_to_str_map_t;

typedef struct {
    void    *arg;
    int     *err;
} wifi_finish_data_t;

typedef struct {
    unsigned int    op_class;
    unsigned int    global_op_class;
    unsigned int    num;
    unsigned int    ch_list[16];
} wifi_radio_op_class_t;

struct wifiCountryEnumStrMap {
    wifi_countrycode_type_t countryCode;
    char countryStr[4];
};

struct wifiEnvironmentEnumStrMap {
    wifi_operating_env_t operatingEnvironment;
    char environment[2];
};

typedef struct {
    wifi_countrycode_type_t    cc;
    wifi_radio_op_class_t   op_class[6];
} wifi_country_radio_op_class_t;

typedef struct {
    struct wpa_driver_capa capa;

    u8 *extended_capa, *extended_capa_mask;
    unsigned int extended_capa_len;
#if HOSTAPD_VERSION >= 211 //2.11
    struct drv_nl80211_iface_capa iface_ext_capa[NL80211_IFTYPE_MAX];
#else
    struct drv_nl80211_ext_capa iface_ext_capa[NL80211_IFTYPE_MAX];
#endif // 2.11
    unsigned int num_iface_ext_capa;

    unsigned int num_multichan_concurrent;
    unsigned int has_key_mgmt:1;
    unsigned int has_key_mgmt_iftype:1;
    unsigned int auth_supported:1;
    unsigned int connect_supported:1;
    unsigned int wmm_ac_supported:1;
    unsigned int mac_addr_rand_scan_supported:1;
    unsigned int mac_addr_rand_sched_scan_supported:1;
    unsigned int p2p_go_supported:1;
    unsigned int p2p_client_supported:1;
    unsigned int p2p_concurrent:1;
    unsigned int channel_switch_supported:1;
    unsigned int set_qos_map_supported:1;
    unsigned int update_ft_ies_supported:1;
    unsigned int multicast_registrations:1;
    unsigned int fils_discovery:1;
    unsigned int unsol_bcast_probe_resp:1;
    unsigned int disabled_11b_rates:1;
    unsigned int pending_remain_on_chan:1;
    unsigned int in_interface_list:1;
    unsigned int device_ap_sme:1;
    unsigned int poll_command_supported:1;
    unsigned int data_tx_status:1;
    unsigned int scan_for_auth:1;
    unsigned int retry_auth:1;
    unsigned int use_monitor:1;
    unsigned int ignore_next_local_disconnect:1;
    unsigned int ignore_next_local_deauth:1;
    unsigned int hostapd:1;
    unsigned int start_mode_ap:1;
    unsigned int start_iface_up:1;
    unsigned int test_use_roc_tx:1;
    unsigned int ignore_deauth_event:1;
    unsigned int vendor_cmd_test_avail:1;
    unsigned int roaming_vendor_cmd_avail:1;
    unsigned int dfs_vendor_cmd_avail:1;
    unsigned int have_low_prio_scan:1;
    unsigned int force_connect_cmd:1;
    unsigned int addr_changed:1;
    unsigned int get_features_vendor_cmd_avail:1;
    unsigned int set_rekey_offload:1;
    unsigned int p2p_go_ctwindow_supported:1;
    unsigned int setband_vendor_cmd_avail:1;
    unsigned int get_pref_freq_list:1;
    unsigned int set_prob_oper_freq:1;
    unsigned int scan_vendor_cmd_avail:1;
    unsigned int connect_reassoc:1;
    unsigned int set_wifi_conf_vendor_cmd_avail:1;
    unsigned int fetch_bss_trans_status:1;
    unsigned int roam_vendor_cmd_avail:1;
    unsigned int get_supported_akm_suites_avail:1;
} wifi_driver_data_t;

typedef struct {
    int     sta_sock_fd;

    // supplicant specific data
    struct wpa_sm     *wpa_sm;
    struct eap_peer_config wpa_eapol_config;
    struct eap_method_type wpa_eapol_method;
    unsigned char   assoc_req[512];
    unsigned int    assoc_req_len;
    unsigned char   assoc_rsp[512];
    unsigned int    assoc_rsp_len;
    unsigned char   eapol_msg[512];

    wifi_bss_info_t backhaul;
    bool    connected;

    enum wpa_states state;
    bool pending_rx_eapol;
    unsigned char rx_eapol_buff[2048];
    mac_address_t src_addr;
    int buff_len;
    int sta_4addr;
} wifi_sta_priv_t;

typedef struct {
    int     br_sock_fd;

    // hostapd specific interface data
    struct hostapd_data     hapd;
    struct hostapd_iface    iface;
    struct hostapd_bss_config   conf;
    bool    hapd_initialized;
    bool    iface_initialized;
    bool    conf_initialized;
    struct hostapd_radius_servers radius;
    struct hostapd_radius_server    auth_serv;
    char   auth_shared_secret[64];
    char   nas_identifier[64];
    // array elements reference
    struct hostapd_data     *hapds[1];
    int eloop_signal_sock[2];
} wifi_ap_priv_t;

typedef struct {
    mac_addr_str_t mac_addr_str;
    mac_address_t mac_addr;
} acl_map_t;

typedef enum scan_state_type_e {
    WIFI_SCAN_STATE_NONE,
    WIFI_SCAN_STATE_ERROR,
    WIFI_SCAN_STATE_STARTED,
    WIFI_SCAN_STATE_ABORTED,
} scan_state_type_e;

/* Scan result falg */
#define WIFI_SCAN_RES_NONE            0x00  // - no scan results
#define WIFI_SCAN_RES_COLLECTED_API   0x01  // - scan results are available for API call
#define WIFI_SCAN_RES_COLLECTED_TEST  0x02  // - scan results are available only for test purposes
#define WIFI_SCAN_RES_COLLECTED       (WIFI_SCAN_RES_COLLECTED_API | WIFI_SCAN_RES_COLLECTED_TEST)

// dynamic array object
typedef struct uint_array_t {
    uint num;
    uint *values;
} uint_array_t;

// setup dynamic array
int uint_array_set(uint_array_t *array, uint num, const uint values[]);
static inline uint uint_array_size(const uint_array_t *array) {
    return array ? array->num : 0;
}
static inline uint* uint_array_values(const uint_array_t *array) {
    return array ? array->values : NULL;
}

#if defined(CONFIG_WIFI_EMULATOR) || defined(BANANA_PI_PORT)
typedef struct ie_info {
    uint8_t *buff;
    size_t  buff_len;
} wifi_ie_info_t;
#endif

typedef struct wifi_interface_info_t {
    char name[32];
    char bridge[32];
    unsigned int index;
    unsigned int phy_index;
    unsigned int rdk_radio_index;
    mac_address_t   mac;
    unsigned int type;
    unsigned int interface_status;
    bool primary;
    wifi_vap_info_t vap_info;
    bool vap_initialized;
    bool bss_started;
    bool vap_configured; // important flag, flag = true means that hostap is configured for this and
                         // interface is ready to receive 802.11 data frames
    bool bridge_configured;
    struct nl_handle *nl_event;
    int nl_event_fd;
    struct nl_cb *nl_cb;

    struct nl_handle *spurious_nl_event;
    int spurious_nl_event_fd;
    struct nl_cb *spurious_nl_cb;


    struct nl_handle *bss_nl_connect_event;
    int bss_nl_connect_event_fd;
    struct nl_cb *bss_nl_cb;

    union {
        wifi_ap_priv_t  ap;
        wifi_sta_priv_t sta;
    } u;

    char   wpa_passphrase[64];
    char   device_name[64], manufacturer[64], model_name[64], model_number[64];
    char   serial_number[64], friendly_name[64], manufacturer_url[64], firmware_version[64];
    char   model_description[64], model_url[64];
    int    vlan;
    char   ctrl_interface[32];
    char   wps_config_methods[64];
    char   pin[64];
    int beacon_set;
    int mgmt_frames_registered;
    int spurious_frames_registered;
    int bss_frames_registered;
    hash_map_t  *acl_map;

    /* Scan support */
    enum scan_state_type_e scan_state;
    pthread_mutex_t scan_state_mutex;
    struct uint_array_t scan_filter;
    hash_map_t *scan_info_map;
    hash_map_t *scan_info_ap_map[2];
    pthread_mutex_t scan_info_mutex;
    pthread_mutex_t scan_info_ap_mutex;
    uint8_t scan_has_results;

    /* BTM support */
#ifndef CONFIG_USE_HOSTAP_BTM_PATCH
    bool wnm_bss_trans_query_auto_resp;
    u8 bss_transition_token;
#endif
    /* Wi-Fi band steering sta_list_map */
    hash_map_t  *bm_sta_map;
#if defined(CONFIG_WIFI_EMULATOR) || defined(BANANA_PI_PORT)
    wifi_ie_info_t bss_elem_ie[MAX_NUM_RADIOS];
    wifi_ie_info_t beacon_elem_ie[MAX_NUM_RADIOS];
    struct wpa_supplicant wpa_s;
    struct wpa_ssid current_ssid_info;
#endif
    char mld_name[32];
} wifi_interface_info_t;

#define MAX_RATES   16
typedef struct {
    char name[32];
    unsigned int index;
    unsigned int rdk_radio_index;
    unsigned long dev_id;
    wifi_radio_capabilities_t   capab;
    wifi_radio_operationParam_t oper_param;
    hash_map_t  *interface_map;
    queue_t     *supported_cmds;
    
    // hostapd related data for radio config
    struct hostapd_config   iconf;
    wifi_driver_data_t  driver_data;
    struct hostapd_hw_modes hw_modes[NUM_NL80211_BANDS];  // This can be one of enum nl80211_band  
    struct hostapd_channel_data channel_data[NUM_NL80211_BANDS][MAX_CHANNELS];
    int     rates[NUM_NL80211_BANDS][MAX_RATES];
    int     basic_rates[NUM_NL80211_BANDS][MAX_RATES]; // supported rates per band in 100 kbps units
    struct hostapd_rate_data    rate_data[NUM_NL80211_BANDS][MAX_RATES];
    struct wpa_driver_ops   driver_ops;
    struct hapd_interfaces  interfaces;
    struct hostapd_iface *iface[MAX_NUM_VAP_PER_RADIO];
    struct hostapd_bss_config *bss[MAX_NUM_VAP_PER_RADIO];
    bool configured;
    unsigned int  prev_channel;
    unsigned int  prev_channelWidth;
    bool radio_presence; //True for ECO mode Active radio, false for ECO mode power down sleeping radio
    bool radar_detected;
} wifi_radio_info_t;

typedef wifi_vap_name_t wifi_vap_type_t;

typedef enum {
    PLATFORM_FLAGS_SET_BSS                 = 0x1,
    PLATFORM_FLAGS_CONTROL_PORT_FRAME      = 0x1 << 1,
    PLATFORM_FLAGS_PROBE_RESP_OFFLOAD      = 0x1 << 2,
    PLATFORM_FLAGS_UPDATE_WIPHY_ON_PRIMARY = 0x1 << 3,
    PLATFORM_FLAGS_STA_INACTIVITY_TIMER    = 0x1 << 4,
} wifi_hal_platform_flags_t;

#if HAL_IPC
typedef int (* app_get_ap_assoc_dev_diag_res3_t)(int ap_index,
                                                 wifi_associated_dev3_t *assoc_dev_array,
                                                 unsigned int *output_array_size);

typedef int (* app_get_neighbor_ap2_t) (int radio_index,
                                        wifi_neighbor_ap2_t *neighbor_results,
                                        unsigned int *output_array_size);

typedef int (* app_get_radio_channel_stats_t) (int radio_index,
                                               wifi_channelStats_t *channel_stats_array,
                                               int *array_size);

typedef int (* app_get_radio_traffic_stats_t) (int radio_index,
                                               wifi_radioTrafficStats2_t *radio_traffic_stats);

typedef struct {
    unsigned int version;
    app_get_ap_assoc_dev_diag_res3_t app_get_ap_assoc_dev_diag_res3_fn;
    app_get_neighbor_ap2_t           app_get_neighbor_ap2_fn;
    app_get_radio_channel_stats_t    app_get_radio_channel_stats_fn;
    app_get_radio_traffic_stats_t    app_get_radio_traffic_stats_fn;
} wifi_app_info_t;

typedef struct{
    wifi_vap_info_map_t *vap_map;
    wifi_app_info_t *app_info;
} wifi_hal_post_init_t;
#endif // HAL_IPC

typedef struct {
    struct nl_cb *nl_cb;
    struct nl_handle *nl;
} wifi_netlink_thread_info_t;

typedef struct {
    unsigned int num_hooks;
    wifi_hal_frame_hook_fn_t frame_hooks_fn[MAX_APPS];
} wifi_device_frame_hooks_t;

/* bm group info */
typedef struct wifi_steering_apStats {
    uint32_t avg_chan_util;
    uint32_t chan_util_cnt;
} wifi_steering_ap_stats_t;

typedef struct wifi_bm_steering_group_info {
    wifi_steering_apConfig_t  config;
    //wifi_steering_ap_stats_t  bm_stats;
} wifi_bm_steering_group_info_t;

typedef struct wifi_steering_group {
    uint32_t group_index;
    uint32_t group_enable;
    /* 0: 2G, 1: 5G, 2: 6G */
    wifi_bm_steering_group_info_t bm_group_info[MAX_NUM_RADIOS];
} wifi_bm_steering_group_t;

typedef struct wifi_hal_rate_limit {
    bool enabled;
    int rate_limit;
    int window_size;
    int cooldown_time;
} wifi_hal_mgt_frame_rate_limit_t;

typedef struct {
    pthread_t nl_tid;
    pthread_t hapd_eloop_tid;
    fd_set   drv_rfds;
    int nl_event_fd;
    int link_fd;
    struct nl_cb *nl_cb;
    int nl80211_id;
    struct nl_handle *nl;
    struct nl_handle *nl_event;
    unsigned int port_bitmap[32];
    unsigned int num_radios;
#ifdef CONFIG_WIFI_EMULATOR
     wifi_radio_info_t radio_info[MAX_NUM_SIMULATED_CLIENT];
#else
    wifi_radio_info_t radio_info[MAX_NUM_RADIOS];
#endif
    wifi_device_callbacks_t device_callbacks;
    wifi_hal_platform_flags_t platform_flags;
    pthread_mutex_t	nl_create_socket_lock;
    wifi_device_frame_hooks_t hooks;
    hash_map_t  *netlink_socket_map;
#if HAL_IPC
    wifi_app_info_t app_info;
#endif
    pthread_mutexattr_t hapd_lock_attr;
    pthread_mutex_t hapd_lock;
    pthread_mutex_t steering_data_lock;
    wifi_bm_steering_group_t  bm_steer_groups[MAX_STEERING_GROUP_NUM];
    hash_map_t *mgt_frame_rate_limit_hashmap;
    wifi_hal_mgt_frame_rate_limit_t mgt_frame_rate_limit;
} wifi_hal_priv_t;

extern wifi_hal_priv_t g_wifi_hal;

typedef int    (* platform_pre_init_t)();
#if HAL_IPC
typedef int    (* platform_post_init_t)(wifi_hal_post_init_t *post_init_struct);
#else
typedef int    (* platform_post_init_t)(wifi_vap_info_map_t *vap_map);
#endif
typedef int    (* platform_keypassphrase_default_t)(char *password, int vap_index);
typedef int    (* platform_radius_key_default_t)(char *radius_key);
typedef int    (* platform_ssid_default_t)(char *ssid, int vap_index);
typedef int    (* platform_wps_pin_default_t)(char *pin);
typedef int    (* platform_country_code_default_t)(char *code);
typedef int    (* platform_set_radio_params_t)(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
typedef int    (* platform_set_radio_pre_init_t)(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
typedef int    (* platform_pre_create_vap_t)(wifi_radio_index_t index, wifi_vap_info_map_t *map);
typedef int    (* platform_create_vap_t)(wifi_radio_index_t index, wifi_vap_info_map_t *map);
typedef int    (* platform_wps_event_t)(wifi_wps_event_t data);
typedef int    (* platform_flags_init_t)(int *flags);
typedef int    (* platform_get_aid_t)(void* priv, u16* aid, const u8* addr);
typedef int    (* platform_free_aid_t)(void* priv, u16* aid);
typedef int    (* platform_sync_done_t)(void* priv);
typedef int    (* platform_update_radio_presence_t)();
typedef int    (* platform_set_txpower_t)(void* priv, uint txpower);
typedef int    (* platform_set_offload_mode_t)(void* priv, uint offload_mode);
typedef int    (* platform_get_ApAclDeviceNum_t)(int vap_index, uint *acl_count);
typedef int    (* platform_get_chanspec_list_t)(unsigned int radioIndex, wifi_channelBandwidth_t bandwidth, wifi_channels_list_t channels, char *buff);
typedef int    (* platform_set_acs_exclusion_list_t)(unsigned int radioIndex, char* str);
typedef int    (* platform_get_vendor_oui_t)(char* vendor_oui, int vendor_oui_len);
typedef int    (* platform_set_neighbor_report_t)(uint apIndex, uint add, mac_address_t mac);
typedef int    (* platform_get_radio_phytemperature_t)(wifi_radio_index_t index, wifi_radioTemperature_t *radioPhyTemperature);
typedef int    (* platform_set_dfs_t)(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
typedef int    (* platform_get_radio_caps_t)(wifi_radio_index_t index);
typedef int    (* platform_get_RegDomain_t)(wifi_radio_index_t index, uint *reg_domain);

int wifi_hal_parse_rrm_beacon_rep(wifi_interface_info_t *interface, char *buff,
        size_t len, struct rrm_measurement_beacon_report *meas_rep);
typedef struct wifi_hal_rrm_request {
    uint8_t dialog_token;
    uint8_t duration;
    bool    duration_mandatory;
    uint8_t op_class;
    uint8_t channel;
} wifi_hal_rrm_request_t; 

typedef struct {
    wifi_channelStats_t *arr;
    int arr_size;
}channel_stats_arr_t;
struct ieee80211_he_cap_elem {
    u8 mac_cap_info[6];
    u8 phy_cap_info[11];
} __attribute__((__packed__));


typedef struct {
    unsigned char dialog_token;
    size_t size;
    wifi_BeaconReport_t *beacon_repo;
} wifi_hal_rrm_report_t;


struct ieee80211_he_mcs_nss_supp {
    __le16 rx_mcs_80;
    __le16 tx_mcs_80;
    __le16 rx_mcs_160;
    __le16 tx_mcs_160;
    __le16 rx_mcs_80p80;
    __le16 tx_mcs_80p80;
} __attribute__((__packed__));

struct ieee80211_sta_he_cap {
    bool has_he;
    struct ieee80211_he_cap_elem he_cap_elem;
    struct ieee80211_he_mcs_nss_supp he_mcs_nss_supp;
    u8 ppe_thres[IEEE80211_HE_PPE_THRES_MAX_LEN];
};

typedef struct {
    char        *device_name;
    char        *manufacturer;
    char        *model_name;
    char        *model_number;
    char        *model_description;
    char        *model_url;
    char        *serial_number;
    char        *friendly_name;
    char        *manufacturer_url;
} wifi_device_info_t;

typedef struct {
    char            *device;
    char            *driver_name;
    wifi_device_info_t      device_info;
    platform_pre_init_t     platform_pre_init_fn;
    platform_post_init_t    platform_post_init_fn;
    platform_set_radio_params_t platform_set_radio_fn;
    platform_set_radio_pre_init_t platform_set_radio_pre_init_fn;
    platform_pre_create_vap_t   platform_pre_create_vap_fn;
    platform_create_vap_t   platform_create_vap_fn;
    platform_ssid_default_t           platform_ssid_default_fn;
    platform_keypassphrase_default_t  platform_keypassphrase_default_fn;
    platform_radius_key_default_t  platform_radius_key_default_fn;
    platform_wps_pin_default_t        platform_wps_pin_default_fn;
    platform_country_code_default_t platform_country_code_default_fn;
    platform_wps_event_t              platform_wps_event_fn;
    platform_flags_init_t             platform_flags_init_fn;
    platform_get_aid_t                platform_get_aid_fn;
    platform_free_aid_t               platform_free_aid_fn;
    platform_sync_done_t              platform_sync_done_fn;
    platform_update_radio_presence_t  platform_update_radio_presence_fn;
    platform_set_txpower_t            platform_set_txpower_fn;
    platform_set_offload_mode_t       platform_set_offload_mode_fn;
    platform_get_ApAclDeviceNum_t     platform_get_ApAclDeviceNum_fn;
    platform_get_chanspec_list_t      platform_get_chanspec_list_fn;
    platform_set_acs_exclusion_list_t platform_set_acs_exclusion_list_fn;
    platform_get_vendor_oui_t         platform_get_vendor_oui_fn;
    platform_set_neighbor_report_t    platform_set_neighbor_report_fn;
    platform_get_radio_phytemperature_t platform_get_radio_phytemperature_fn;
    platform_set_dfs_t                platform_set_dfs_fn;
    platform_get_radio_caps_t         platform_get_radio_caps_fn;
    platform_get_RegDomain_t platform_get_RegDomain_fn;
} wifi_driver_info_t;

typedef enum bm_sta_rssi_type {
    BM_STA_RSSI_PROBE = 1,
    BM_STA_RSSI_AUTH,
    BM_STA_RSSI_INACTIVE,
    BM_STA_RSSI_XING,
    BM_STA_RSSI_MAX_TYPE
} bm_sta_rssi_type_t;

typedef enum client_state {
    ACTIVE = 1,
    INACTIVE,
    MAX_STATE
} client_state_t;

typedef struct {
    mac_address_t mac_addr;
    time_t assoc_time;              /* Assoc Timestamp */
    time_t disassoc_time;           /* Disassoc Timestamp */
    time_t active;                  /* activity timestamp */
    uint8_t vap_index;              /* if index */
    char    ssid[SSID_MAX_LEN];
    uint8_t inactive_state;         /* based on traffic */
    int32_t rssi;                   /* per antenna rssi */
    int32_t rssi_changed;           /* crossing state */
    int32_t  rssi_change_auth;      /* crossing state */
    int32_t  rssi_change_assoc;     /* crossing state */
    uint8_t  type;                  /* the mac is added by API (clientSet) or assoc */
    uint8_t  is_acl_set;
    client_state_t state;           /* Connected, disconnected etc */
    uint32_t event_sent;            /* avoid duplicates */
    unsigned long int rx_tot_pkts;
    unsigned long int tx_tot_pkts;
    wifi_steering_clientConfig_t  bm_client_cfg;
} bm_sta_list_t;

INT wifi_hal_init();
INT wifi_hal_pre_init();
#if HAL_IPC
INT wifi_hal_post_init(wifi_hal_post_init_t *post_init_struct);
#else
INT wifi_hal_post_init(wifi_vap_info_map_t *vap_map);
#endif
INT wifi_hal_ssid_init(char *ssid, int vap_index);
INT wifi_hal_keypassphrase_init(char *password, int vap_index);
INT wifi_hal_wps_pin_init(char *pin);
INT wifi_hal_hostApGetErouter0Mac(char *out);
INT wifi_hal_send_mgmt_frame_response(int ap_index, int type, int status, int status_code, uint8_t *frame, uint8_t *mac, int len, int rssi);
void wifi_hal_deauth(int vap_index, int status, uint8_t *mac);
INT wifi_hal_getInterfaceMap(wifi_interface_name_idex_map_t *if_map, unsigned int max_entries,
    unsigned int *if_map_size);
INT wifi_hal_getHalCapability(wifi_hal_capability_t *hal);
INT wifi_hal_connect(INT ap_index, wifi_bss_info_t *bss);
INT wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
INT wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map);
INT wifi_hal_kickAssociatedDevice(INT ap_index, mac_address_t mac);
INT wifi_hal_startScan(wifi_radio_index_t index, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT num, UINT *chan_list);
INT wifi_hal_disconnect(INT ap_index);
INT wifi_hal_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map);
INT wifi_hal_setApWpsButtonPush(INT apIndex);
INT wifi_hal_setApWpsPin(INT ap_index, char *wps_pin);
INT wifi_hal_setApWpsCancel(INT ap_index);
INT wifi_hal_set_acs_keep_out_chans(wifi_radio_operationParam_t *wifi_radio_oper_param, int radioIndex);
INT wifi_hal_sendDataFrame(int vap_id, unsigned char *dmac, unsigned char *data_buff, int data_len, BOOL insert_llc, int protocal, int priority);
#ifdef WIFI_HAL_VERSION_3_PHASE2
INT wifi_hal_addApAclDevice(INT apIndex, mac_address_t DeviceMacAddress);
INT wifi_hal_delApAclDevice(INT apIndex, mac_address_t DeviceMacAddress);
#else
INT wifi_hal_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress);
INT wifi_hal_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress);
#endif
INT wifi_hal_delApAclDevices(INT apIndex);
INT wifi_hal_steering_eventRegister(wifi_steering_eventCB_t event_cb);
INT wifi_hal_setRadioTransmitPower(wifi_radio_index_t radioIndex, uint txpower);
INT wifi_hal_getRadioTransmitPower(INT radioIndex, ULONG *tx_power);
INT wifi_hal_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list);
INT wifi_hal_getNeighboringWiFiStatus(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size);
INT wifi_hal_getNeighboringWiFiStatus_test(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size);
INT wifi_hal_setBTMRequest(UINT apIndex, mac_address_t peerMac, wifi_BTMRequest_t *request);
INT wifi_hal_setRMBeaconRequest(UINT apIndex, mac_address_t peer_mac, wifi_BeaconRequest_t *in_req, UCHAR *out_DialogToken);
INT wifi_hal_cancelRMBeaconRequest(UINT apIndex, UCHAR dialogToken);
INT wifi_hal_configNeighborReports(UINT apIndex, bool enable, bool auto_resp);
INT wifi_hal_setNeighborReports(UINT apIndex, UINT numNeighborReports, wifi_NeighborReport_t *neighborReports);
void wifi_hal_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback func);
void wifi_hal_apDisassociatedDevice_callback_register(wifi_device_disassociated_callback func);
void wifi_hal_stamode_callback_register(wifi_stamode_callback func);
void wifi_hal_apStatusCode_callback_register(wifi_apStatusCode_callback func);
void wifi_hal_radiusEapFailure_callback_register(wifi_radiusEapFailure_callback func);
void wifi_hal_radiusFallback_failover_callback_register(wifi_radiusFallback_failover_callback func);
void wifi_hal_apDeAuthEvent_callback_register(wifi_device_deauthenticated_callback func);
void wifi_hal_ap_max_client_rejection_callback_register(wifi_apMaxClientRejection_callback func);
INT wifi_hal_BTMQueryRequest_callback_register(UINT apIndex,
                                            wifi_BTMQueryRequest_callback btmQueryCallback,
                                            wifi_BTMResponse_callback btmResponseCallback);
INT wifi_hal_RMBeaconRequestCallbackRegister(UINT apIndex, wifi_RMBeaconReport_callback beaconReportCallback);
INT wifi_hal_RMBeaconRequestCallbackUnregister(UINT apIndex, wifi_RMBeaconReport_callback beaconReportCallback);
int wifi_rrm_send_beacon_resp(unsigned int ap_index, wifi_neighbor_ap2_t *bss, unsigned int num_ssid, unsigned int token,
                            unsigned int num_count);
int wifi_hal_parse_rm_beacon_request(unsigned int apIndex, char* buff, size_t len,
    wifi_hal_rrm_request_t *req);
wifi_radio_info_t *get_radio_by_index(wifi_radio_index_t index);
wifi_interface_info_t *get_interface_by_vap_index(unsigned int vap_index);
wifi_interface_info_t *get_interface_by_if_index(unsigned int if_index);
BOOL get_ie_by_eid(unsigned int eid, unsigned char *buff, unsigned int buff_len, unsigned char **ie_out, size_t *ie_out_len);
BOOL get_ie_ext_by_eid(unsigned int eid, unsigned char *buff, unsigned int buff_len, unsigned char **ie_out, unsigned short *ie_out_len);
const u8 * get_vendor_ie_by_type(const u8 *pos, size_t len, u32 vendor_type);
INT get_coutry_str_from_code(wifi_countrycode_type_t code, char *country);
INT get_coutry_str_from_oper_params(wifi_radio_operationParam_t *operParams, char *country);
char *to_mac_str    (mac_address_t mac, mac_addr_str_t key);
const char *wifi_freq_bands_to_string(wifi_freq_bands_t band);
const char *wpa_alg_to_string(enum wpa_alg alg);
int nl80211_update_wiphy(wifi_radio_info_t *radio);
wifi_interface_info_t* get_private_vap_interface(wifi_radio_info_t *radio);
wifi_interface_info_t* get_primary_interface(wifi_radio_info_t *radio);
wifi_interface_info_t* get_private_vap_interface(wifi_radio_info_t *radio);
int wifi_hal_get_vap_interface_type(wifi_vap_name_t vap_name, wifi_vap_type_t vap_type);
wifi_interface_info_t *wifi_hal_get_vap_interface_by_type(wifi_radio_info_t *radio,
    wifi_vap_type_t vap_type);
int nl80211_init_primary_interfaces();
int nl80211_init_radio_info();
int getIpStringFromAdrress(char * ipString,  ip_addr_t * ip);
int get_mac_address (char *intf_name,  mac_address_t mac);
int create_ecomode_interfaces(void);
void update_ecomode_radio_capabilities(wifi_radio_info_t *radio);
int convert_string_to_int(int **int_list, char *val);
int print_rate_list(int *list);
int wifi_channelBandwidth_from_str(const char *str, wifi_channelBandwidth_t *bandwidth);
int convert_string_mcs_to_int(char *string_mcs);
int init_nl80211();
void wifi_hal_nl80211_wps_pbc(unsigned int ap_index);
int wifi_hal_nl80211_wps_pin(unsigned int ap_index, char *wps_pin);
void wifi_hal_nl80211_wps_cancel(unsigned int ap_index);
int     update_channel_flags();
int     handle_public_action_frame(INT ap_index, mac_address_t sta_mac, wifi_publicActionFrameHdr_t *ppublic_hdr, UINT len);
int     nl80211_create_interface(wifi_radio_info_t *radio, wifi_vap_info_t *vap, wifi_interface_info_t **interface);
int     nl80211_enable_ap(wifi_interface_info_t *interface, bool enable);
int     nl80211_kick_device(wifi_interface_info_t *interface, mac_address_t mac);
int     nl80211_create_bridge(const char *if_name, const char *br_name);
int     nl80211_remove_from_bridge(const char *if_name);
int     nl80211_update_interface(wifi_interface_info_t *interface);
int     nl80211_interface_enable(const char *ifname, bool enable);
int     nl80211_retry_interface_enable(wifi_interface_info_t *interface, bool enable);
void    nl80211_steering_event(UINT steeringgroupIndex, wifi_steering_event_t *event);
int     nl80211_connect_sta(wifi_interface_info_t *interface);

#if defined(TCXB8_PORT) || defined(XB10_PORT) || defined(SCXER10_PORT)
int     nl80211_set_amsdu_tid(wifi_interface_info_t *interface, uint8_t *amsdu_tid);
#endif
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT)

// emu_neighbor_stats_t is used by both CCI and Onewifi
typedef struct {
    bool emu_enable;
    uint32_t radio_index;
    uint32_t neighbor_count;
    wifi_neighbor_ap2_t data[];  // flexible array member
} emu_neighbor_stats_t;

#if defined(CONFIG_WIFI_EMULATOR)
int     wifi_hal_emu_set_radio_channel_stats(unsigned int radio_index, bool emu_state, wifi_channelStats_t *chan_stat, unsigned int count, unsigned int phy_index, unsigned int interface_index);
int     wifi_hal_emu_set_assoc_clients_stats(unsigned int vap_index, bool emu_state, wifi_associated_dev3_t *assoc_cli_stat, unsigned int count, unsigned int phy_index, unsigned int interface_index);
int     wifi_hal_emu_set_radio_temp (unsigned int radio_index, bool emu_state, int temperature, unsigned int phy_index, unsigned int interface_index);
int     wifi_hal_emu_set_radio_diag_stats(unsigned int radio_index, bool emu_state, wifi_radioTrafficStats2_t *radio_diag_stat, unsigned int count, unsigned int phy_index, unsigned int interface_index);
int     wifi_hal_emu_set_neighbor_stats(unsigned int radio_index, bool emu_state, wifi_neighbor_ap2_t *neighbor_stats, unsigned int count);
#endif //CONFIG_WIFI_EMULATOR
#endif
int     nl80211_register_mgmt_frames(wifi_interface_info_t *interface);
int     nl80211_start_scan(wifi_interface_info_t *interface, uint flags,
        unsigned int num_freq, unsigned int  *freq_list, unsigned int dwell_time,
        unsigned int num_ssid,  ssid_t *ssid_list);
int     nl80211_get_scan_results(wifi_interface_info_t *interface);
int     nl80211_switch_channel(wifi_radio_info_t *radio);
int     nl80211_tx_control_port(wifi_interface_info_t *interface, const u8 *dest, u16 proto, const u8 *buf, size_t len, int no_encrypt, int link_id);
int     nl80211_set_acl(wifi_interface_info_t *interface);
int     nl80211_set_acl_mode(wifi_interface_info_t *interface, uint32_t mac_filter_mode);
int     nl80211_set_mac(wifi_interface_info_t *interface);
int     nl80211_dfs_cac_started(wifi_interface_info_t *interface, int freq, int ht_enabled, int sec_channel_offset, int bandwidth, int bw, int cf1, int cf2);
int     nl80211_dfs_radar_cac_aborted(wifi_interface_info_t *interface, int freq, int ht_enabled, int sec_channel_offset, int bandwidth, int bw, int cf1, int cf2);
int     nl80211_dfs_radar_cac_finished(wifi_interface_info_t *interface, int freq, int ht_enabled, int sec_channel_offset, int bandwidth, int bw, int cf1, int cf2);
int     nl80211_dfs_pre_cac_expired(wifi_interface_info_t *interface, int freq, int ht_enabled, int sec_channel_offset, int bandwidth, int bw, int cf1, int cf2);
int     nl80211_dfs_nop_finished(wifi_interface_info_t *interface, int freq, int ht_enabled, int sec_channel_offset, int bandwidth, int bw, int cf1, int cf2);
int     nl80211_dfs_radar_detected(wifi_interface_info_t *interface, int freq, int ht_enabled, int sec_chan_offset, int bandwidth, int bw, int cf1, int cf2);
int     nl80211_start_dfs_cac(wifi_radio_info_t *radio);
int     set_freq_and_interface_enable(wifi_interface_info_t *interface, wifi_radio_info_t *radio);
int     reenable_prim_interface(wifi_radio_info_t *radio);
int     init_hostap_hw_features(wifi_interface_info_t *interface);
int     update_hostap_data(wifi_interface_info_t *interface);
int     update_hostap_interfaces(wifi_radio_info_t *radio);
int     update_hostap_interface_params(wifi_interface_info_t *interface);
int     update_hostap_iface(wifi_interface_info_t *interface);
int     update_hostap_iface_flags(wifi_interface_info_t *interface);
int     update_hostap_config_params(wifi_radio_info_t *radio);
int     update_hostap_radio_param(wifi_radio_info_t *radio, const wifi_radio_operationParam_t *newParam);
int     nl80211_get_channel_bw_conn(wifi_interface_info_t *interface);
void    update_wpa_sm_params(wifi_interface_info_t *interface);
void    update_eapol_sm_params(wifi_interface_info_t *interface);
void    *nl_recv_func(void *arg);
int     start_bss(wifi_interface_info_t *interface);
void    deinit_bss(struct hostapd_data *hapd);
int     process_global_nl80211_event(struct nl_msg *msg, void *arg);
int     no_seq_check(struct nl_msg *msg, void *arg);
void    *eloop_run_thread(void *data);
int     wifi_send_eapol(void *priv, const u8 *addr, const u8 *data,
                    size_t data_len, int encrypt,
                    const u8 *own_addr, u32 flags);
void   *wifi_drv_init(struct hostapd_data *hapd, struct wpa_init_params *params);
struct nl_msg *nl80211_drv_cmd_msg(int nl80211_id, wifi_interface_info_t *intf, int flags, uint8_t cmd);
struct nl_msg *nl80211_drv_vendor_cmd_msg(int nl80211_id, wifi_interface_info_t *intf, int flags,
    uint32_t vendor_id, uint32_t subcmd);
int nl80211_send_and_recv(struct nl_msg *msg, int (*valid_handler)(struct nl_msg *, void *),
    void *valid_data, int (*valid_finish_handler)(struct nl_msg *, void *),
    void *valid_finish_data);
int interface_info_handler(struct nl_msg *msg, void *arg);

#if HOSTAPD_VERSION >= 210 //2.10
int wifi_drv_vendor_cmd(void *priv, unsigned int vendor_id,
    unsigned int subcmd, const u8 *data,
    size_t data_len, enum nested_attr nested_attr_flag, struct wpabuf *buf);
#else
int wifi_drv_vendor_cmd(void *priv, unsigned int vendor_id,
                  unsigned int subcmd, const u8 *data,
                  size_t data_len, struct wpabuf *buf);
#endif // HOSTAPD_VERSION >= 210

int     wifi_drv_set_txpower(void* priv, uint txpower);

enum offload_mode {
    /* offload ON (default)             | only necessary frames are forwared to user space */
    PROBEREQ_OFFLOAD_ON,
    /* turn of wildcard SSID offload    | only necessary frames + wildcards SSID's are forwared to user space */
    PROBEREQ_OFFLOAD_WILDCARD_SSID_OFF,
    /* offload OFF                      | all frames are forwarded to user space (may degrade performance in a busy environment) */
    PROBEREQ_OFFLOAD_OFF
};
int     wifi_drv_set_offload_mode(void *priv, enum offload_mode offload_mode);

int     wifi_set_privacy(void *priv, int enabled);
int     wifi_set_ssid(void *priv, const u8 *buf, int len);
int     wifi_drv_set_operstate(void *priv, int state);
int     wifi_flush(void *priv);
int     wifi_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, int reason_code);
int     wifi_set_key(const char *ifname, void *priv, enum wpa_alg alg,
                    const u8 *addr, int key_idx, int set_tx, const u8 *seq,
                    size_t seq_len, const u8 *key, size_t key_len);
int     wifi_set_authmode(void *priv, int auth_algs);
int     wifi_set_ieee8021x(void *priv, struct wpa_bss_params *params);
int     wifi_set_opt_ie(void *priv, const u8 *ie, size_t ie_len);
int     wifi_set_ap(void *priv, struct wpa_driver_ap_params *params);
int     wifi_sta_set_flags(void *priv, const u8 *addr,
                unsigned int total_flags, unsigned int flags_or,
                unsigned int flags_and);
int     wifi_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr, u16 reason_code);
int     wifi_sta_assoc(void *priv, const u8 *own_addr, const u8 *addr,
                int reassoc, u16 status_code, const u8 *ie, size_t len);
int     wifi_set_ap_wps_ie(void *priv, const struct wpabuf *beacon,
                      const struct wpabuf *proberesp,
                      const struct wpabuf *assocresp);
int     wifi_sta_get_seqnum(const char *ifname, void *priv, const u8 *addr, int idx, u8 *seq);
int     wifi_commit(void *priv);
wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index);
int set_interface_properties(unsigned int phy_index, wifi_interface_info_t *interface);
int get_op_class_from_radio_params(wifi_radio_operationParam_t *param);
void wifi_send_wpa_supplicant_event(int ap_index, uint8_t *frame, int len);
int wifi_send_response_failure(int ap_index, const u8 *mac, int frame_type, int status_code, int rssi);
wifi_interface_info_t* get_primary_interface(wifi_radio_info_t *radio);
int nl80211_disconnect_sta(wifi_interface_info_t *interface);
int wifi_hal_purgeScanResult(unsigned int vap_index, unsigned char *sta_mac);
void get_wifi_interface_info_map(wifi_interface_name_idex_map_t *interface_map);
void get_radio_interface_info_map(radio_interface_mapping_t *radio_interface_map);
unsigned int get_sizeof_interfaces_index_map(void);
int validate_radio_operation_param(wifi_radio_operationParam_t *param);
int validate_wifi_interface_vap_info_params(wifi_vap_info_t *vap_info, char *msg, int len);
int is_backhaul_interface(wifi_interface_info_t *interface);
void update_vap_mode(wifi_interface_info_t *interface);
int get_interface_name_from_vap_index(unsigned int vap_index, char *interface_name);
int get_ap_vlan_id(char *interface_name);
int get_vap_mode_str_from_int_mode(unsigned char vap_mode, char *vap_mode_str);
int get_security_mode_str_from_int(wifi_security_modes_t security_mode, unsigned int vap_index, char *security_mode_str);
int get_security_mode_int_from_str(char *security_mode_str,char *mfp_str,wifi_security_modes_t *security_mode);
int get_security_encryption_mode_str_from_int(wifi_encryption_method_t encryption_mode, unsigned int vap_index, char *encryption_mode_str);
int get_security_mode_support_radius(int mode);
void wps_enum_to_string(unsigned int methods, char *str, int len);
int get_radio_variant_str_from_int(unsigned int variant, char *variant_str);
#ifndef FEATURE_SINGLE_PHY
wifi_radio_info_t *get_radio_by_phy_index(wifi_radio_index_t index);
int get_rdk_radio_index(unsigned int phy_index);
#else //FEATURE_SINGLE_PHY
int get_rdk_radio_indices(unsigned int phy_index, int *rdk_radio_indices, int *num_radios_mapped);
int get_rdk_radio_index_from_interface_name(char *interface_name);
#endif //FEATURE_SINGLE_PHY
int get_interface_name_from_radio_index(uint8_t radio_index, char *interface_name);
int get_sec_channel_offset(wifi_radio_info_t *radio, int freq);
int get_bw80_center_freq(wifi_radio_operationParam_t *param, const char *country);
int get_bw160_center_freq(wifi_radio_operationParam_t *param, const char *country);
#ifdef CONFIG_IEEE80211BE
int get_bw320_center_freq(wifi_radio_operationParam_t *param, const char *country);
#endif /* CONFIG_IEEE80211BE */
int pick_akm_suite(int sel);
int wifi_hal_send_mgmt_frame(int apIndex,mac_address_t sta, const u8 *data,size_t data_len,unsigned int freq, unsigned int wait);
#if defined(BANANA_PI_PORT) && defined(KERNEL_6_6)
int wifi_drv_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr, u16 reason, int link_id);
#else
int wifi_drv_sta_disassoc(void *priv, const u8 *own_addr, const u8 *addr, u16 reason);
#endif
void wifi_hal_disassoc(int vap_index, int status, uint8_t *mac);
#if HOSTAPD_VERSION >= 211 //2.11
int wifi_drv_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, u16 reason,int link_id);
#else
int wifi_drv_sta_deauth(void *priv, const u8 *own_addr, const u8 *addr, u16 reason);
#endif
#ifdef HOSTAPD_2_11 //2.11
 int wifi_drv_send_mlme(void *priv, const u8 *data,
                      size_t data_len,int noack,
                      unsigned int freq, const u16 *csa_offs,
                      size_t csa_offs_len, int no_encrypt,
                      unsigned int wait, int link_id);
#elif HOSTAPD_2_10 //2.10
 int wifi_drv_send_mlme(void *priv, const u8 *data,
                      size_t data_len,int noack,
                      unsigned int freq, const u16 *csa_offs,
                      size_t csa_offs_len, int no_encrypt,
                      unsigned int wait);
#else
 int wifi_drv_send_mlme(void *priv, const u8 *data,
                                          size_t data_len, int noack,
                                          unsigned int freq,
                                          const u16 *csa_offs,
                                          size_t csa_offs_len);
#endif

BOOL is_wifi_hal_vap_private(UINT ap_index);
BOOL is_wifi_hal_vap_xhs(UINT ap_index);
BOOL is_wifi_hal_vap_hotspot(UINT ap_index);
BOOL is_wifi_hal_vap_hotspot_open(UINT ap_index);
BOOL is_wifi_hal_vap_lnf(UINT ap_index);
BOOL is_wifi_hal_vap_lnf_psk(UINT ap_index);
BOOL is_wifi_hal_vap_mesh(UINT ap_index);
BOOL is_wifi_hal_vap_mesh_backhaul(UINT ap_index);
BOOL is_wifi_hal_vap_hotspot_secure(UINT ap_index);
BOOL is_wifi_hal_vap_lnf_radius(UINT ap_index);
BOOL is_wifi_hal_vap_mesh_sta(UINT ap_index);
BOOL is_wifi_hal_vap_hotspot_from_interfacename(char *interface_name);
wifi_vap_info_t* get_wifi_vap_info_from_interfacename(char *interface_name);

BOOL is_wifi_hal_6g_radio_from_interfacename(char *interface_name);

int nvram_get_current_password(char *l_password, int vap_index);
int nvram_get_current_ssid(char *l_ssid, int vap_index);
int nvram_get_default_xhs_ssid(char *l_ssid, int vap_index);
int nvram_get_mgmt_frame_power_control(int vap_index, int* output_dbm);
int nl80211_set_regulatory_domain(wifi_countrycode_type_t country_code);
int platform_get_channel_bandwidth(wifi_radio_index_t index, wifi_channelBandwidth_t *channelWidth);
int wifi_drv_getApAclDeviceNum(int vap_index, uint *acl_count);
int wifi_drv_get_chspc_configs(unsigned int radioIndex, wifi_channelBandwidth_t bandwidth, wifi_channels_list_t channels, char* buff);
int wifi_drv_set_acs_exclusion_list(unsigned int radioIndex, char* str);
int platform_get_acl_num(int vap_index, uint *acl_hal_count);
int steering_set_acl_mode(uint32_t apIndex, uint32_t mac_filter_mode);

wifi_steering_apConfig_t* steering_find_ap_cfg(int vap_index, uint32_t *g_idx);
int wifi_steering_add_mac_list(uint32_t vap_index, bm_sta_list_t *sta_info);
int wifi_steering_del_mac_list(uint32_t vap_index, bm_sta_list_t *sta_info);
INT wifi_hal_steering_clientDisconnect( UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac,
                                        wifi_disconnectType_t type, UINT reason);
bm_sta_list_t *steering_add_stalist(wifi_interface_info_t *interface, char *ssid, mac_address_t client_mac, uint8_t type);
void steering_del_stalist(wifi_interface_info_t *interface, mac_address_t client_mac, uint8_t type);
void re_configure_steering_mac_list(wifi_interface_info_t *interface);
time_t get_boot_time_in_sec(void);

int get_total_num_of_vaps(void);
int wifi_setQamPlus(void *priv);
int wifi_setApRetrylimit(void *priv);
int configure_vap_name_basedon_colocated_mode(char *ifname, int colocated_mode);
int json_parse_string(const char* file_name, const char *item_name, char *val, size_t len);
int json_parse_integer(const char* file_name, const char *item_name, int *val);
int json_parse_boolean(const char* file_name, const char *item_name, bool *val);
bool get_ifname_from_mac(const mac_address_t *mac, char *ifname);
int wifi_hal_configure_sta_4addr_to_bridge(wifi_interface_info_t *interface, int add);
int wifi_convert_freq_band_to_radio_index(int band, int *radio_index);
struct wpa_ssid *get_wifi_wpa_current_ssid(wifi_interface_info_t *interface);

#ifdef CONFIG_IEEE80211BE
int nl80211_drv_mlo_msg(struct nl_msg *msg, struct nl_msg **msg_mlo, void *priv,
    struct wpa_driver_ap_params *params);
int nl80211_send_mlo_msg(struct nl_msg *msg);
void wifi_drv_get_phy_eht_cap_mac(struct eht_capabilities *eht_capab, struct nlattr **tb);
int update_hostap_mlo(wifi_interface_info_t *interface);
#endif /* CONFIG_IEEE80211BE */

wifi_interface_info_t *wifi_hal_get_mbssid_tx_interface(wifi_radio_info_t *radio);
void wifi_hal_configure_mbssid(wifi_radio_info_t *radio);

void wifi_hal_set_mgt_frame_rate_limit(bool enable, int rate_limit, int window_size,
    int cooldown_time);

#ifdef __cplusplus
}
#endif

typedef enum {
    WIFI_HAL_LOG_LVL_DEBUG,
    WIFI_HAL_LOG_LVL_INFO,
    WIFI_HAL_LOG_LVL_ERROR,
    WIFI_HAL_LOG_LVL_MAX
}wifi_hal_log_level_t;

//wifi_halstats
typedef enum {
    WIFI_HAL_STATS_LOG_LVL_DEBUG,
    WIFI_HAL_STATS_LOG_LVL_INFO,
    WIFI_HAL_STATS_LOG_LVL_ERROR,
    WIFI_HAL_STATS_LOG_LVL_MAX
}wifi_hal_stats_log_level_t;

void wifi_hal_print(wifi_hal_log_level_t level, const char *format, ...)__attribute__((format(printf, 2, 3)));

//wifi_halstats
void wifi_hal_stats_print(wifi_hal_stats_log_level_t level, const char *format, ...)__attribute__((format(printf, 2, 3)));

#define wifi_hal_dbg_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_DEBUG, format, ##__VA_ARGS__)
#define wifi_hal_info_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_INFO, format, ##__VA_ARGS__)
#define wifi_hal_error_print(format, ...)  wifi_hal_print(WIFI_HAL_LOG_LVL_ERROR, format, ##__VA_ARGS__)

//wifi_halstats
#define wifi_hal_stats_dbg_print(format, ...)  wifi_hal_stats_print(WIFI_HAL_STATS_LOG_LVL_DEBUG, format, ##__VA_ARGS__)
#define wifi_hal_stats_info_print(format, ...)  wifi_hal_stats_print(WIFI_HAL_STATS_LOG_LVL_INFO, format, ##__VA_ARGS__)
#define wifi_hal_stats_error_print(format, ...)  wifi_hal_stats_print(WIFI_HAL_STATS_LOG_LVL_ERROR, format, ##__VA_ARGS__)

bool lsmod_by_name(const char *name);
wifi_device_callbacks_t *get_hal_device_callbacks();
wifi_device_frame_hooks_t *get_device_frame_hooks();
char *get_wifi_drv_name();
wifi_device_info_t get_device_info_details();
typedef char * PCHAR;
extern int platform_pre_init();
#if HAL_IPC
extern int platform_post_init(wifi_hal_post_init_t *post_init_struct);
#else
extern int platform_post_init(wifi_vap_info_map_t *vap_map);
#endif
extern int platform_get_keypassphrase_default(char *password, int vap_index);
extern int platform_get_radius_key_default(char *radius_key);
extern int platform_get_ssid_default(char *ssid, int vap_index);
extern int platform_get_wps_pin_default(char *pin);
extern int platform_wps_event(wifi_wps_event_t data);
extern int platform_get_country_code_default(char *code);
extern int platform_set_radio(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
extern int platform_pre_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map);
extern int platform_create_vap(wifi_radio_index_t index, wifi_vap_info_map_t *map);
extern int platform_set_radio_pre_init(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
extern int platform_flags_init(int *flags);
extern int platform_get_aid(void* priv, u16* aid, const u8* addr);
extern int platform_free_aid(void* priv, u16* aid);
extern int platform_sync_done(void* priv);
extern int platform_update_radio_presence(void);
extern int platform_set_txpower(void* priv, uint txpower);
extern int platform_get_chanspec_list(unsigned int radioIndex, wifi_channelBandwidth_t bandwidth, wifi_channels_list_t channels, char *buff);
extern int platform_set_acs_exclusion_list(unsigned int radioIndex, char* str);
extern int platform_get_vendor_oui(char* vendor_oui, int vendor_oui_len);
extern int platform_set_neighbor_report(uint apIndex, uint add, mac_address_t mac);
extern int platform_get_radio_phytemperature(wifi_radio_index_t index, wifi_radioTemperature_t *radioPhyTemperature);
extern int platform_set_offload_mode(void* priv, uint offload_mode);
extern int platform_get_radio_caps(wifi_radio_index_t index);

#ifdef CMXB7_PORT
extern int platform_get_vap_measurements(void *priv, struct intel_vendor_vap_info *vap_info);
extern int platform_get_radio_info(void *priv, struct intel_vendor_radio_info *radio_info);
extern int platform_get_sta_measurements(void *priv, const u8 *sta_addr, struct intel_vendor_sta_info *sta_info);
#endif
extern int platform_set_dfs(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);

#if defined(VNTXER5_PORT)
INT platform_create_interface_attributes(struct nl_msg **msg_ptr, wifi_radio_info_t *radio,
    wifi_vap_info_t *vap);
INT platform_set_radio_mld_bonding(wifi_radio_info_t *radio);
INT platform_set_intf_mld_bonding(wifi_radio_info_t *radio, wifi_interface_info_t *interface);
#endif

#if defined(SCXER10_PORT) && defined(CONFIG_IEEE80211BE)
extern bool (*g_eht_event_notify)(wifi_interface_info_t *interface);
int platform_set_amsdu_tid(wifi_interface_info_t *interface, uint8_t *amsdu_tid);
#if defined(KERNEL_NO_320MHZ_SUPPORT)
void platform_switch_channel(wifi_interface_info_t *interface, struct csa_settings *settings);
void platform_config_eht_chanspec(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
bool platform_is_bss_up(char* ifname);
void platform_bss_enable(char* ifname, bool enable);
enum nl80211_chan_width platform_get_bandwidth(wifi_interface_info_t *interface);
void platform_set_csa(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam);
void platform_set_chanspec(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam, bool b_check_radio);
#endif
#endif

#if defined(BANANA_PI_PORT) && (HOSTAPD_VERSION >= 211)
extern void supplicant_event(void *ctx, enum wpa_event_type event,
     union wpa_event_data *data);
#endif

#if defined(TARGET_GEMINI7_2)
extern int platform_get_reg_domain(wifi_radio_index_t radioIndex, UINT *reg_domain);
#endif

platform_pre_init_t     	get_platform_pre_init_fn();
platform_post_init_t    	get_platform_post_init_fn();
platform_keypassphrase_default_t     get_platform_keypassphrase_default_fn();
platform_ssid_default_t              get_platform_ssid_default_fn();
platform_wps_pin_default_t           get_platform_wps_pin_default_fn();
platform_wps_event_t                 get_platform_wps_event_fn();
platform_country_code_default_t get_platform_country_code_default_fn();
platform_set_radio_params_t 	get_platform_set_radio_fn();
platform_set_radio_pre_init_t get_platform_set_radio_pre_init_fn();
platform_pre_create_vap_t           get_platform_pre_create_vap_fn();
platform_create_vap_t 		get_platform_create_vap_fn();
platform_radius_key_default_t       get_platform_radius_key_default_fn();
platform_flags_init_t               get_platform_flags_init_fn();
platform_get_aid_t                  get_platform_get_aid_fn();
platform_free_aid_t                 get_platform_free_aid_fn();
platform_sync_done_t                get_platform_sync_done_fn();
platform_update_radio_presence_t    get_platform_update_radio_presence_fn();
platform_set_txpower_t              get_platform_set_txpower_fn();
platform_get_ApAclDeviceNum_t get_platform_ApAclDeviceNum_fn();
platform_get_chanspec_list_t        get_platform_chanspec_list_fn();
platform_set_acs_exclusion_list_t   get_platform_acs_exclusion_list_fn();
platform_get_vendor_oui_t           get_platform_vendor_oui_fn();
platform_set_neighbor_report_t      get_platform_set_neighbor_report_fn();
platform_get_radio_phytemperature_t get_platform_get_radio_phytemperature_fn();
platform_set_offload_mode_t         get_platform_set_offload_mode_fn();
platform_set_dfs_t                  get_platform_dfs_set_fn();
platform_get_radio_caps_t           get_platform_get_radio_caps_fn();
platform_get_RegDomain_t get_platform_get_RegDomain_fn();

INT wifi_hal_wps_event(wifi_wps_event_t data);
INT wifi_hal_get_default_wps_pin(char *pin);


typedef unsigned long bitmap_type;
#define BITS_PER_ULONG (sizeof(bitmap_type) * 8)

/* bitmap for 256 bits */
typedef bitmap_type u8_bitmap[256 / BITS_PER_ULONG];

static inline u8 get_bit_u8(u8_bitmap bits, u8 bit)
{
    bitmap_type *word = &bits[bit / BITS_PER_ULONG];
    return !!((*word) & (1 << (bit % BITS_PER_ULONG)));
}

static inline void set_bit_u8(u8_bitmap bits, u8 bit)
{
    bitmap_type *word = &bits[bit / BITS_PER_ULONG];
    (*word) |= 1 << (bit % BITS_PER_ULONG);
}

static inline void reset_bit_u8(u8_bitmap bits, u8 bit)
{
    bitmap_type *word = &bits[bit / BITS_PER_ULONG];
    (*word) &= ~(1 << (bit % BITS_PER_ULONG));
}

static inline void clear_bits(u8_bitmap *bits)
{
    memset(bits, 0, sizeof(u8_bitmap));
}

extern u8_bitmap g_DialogToken[MAX_AP_INDEX];

int wifi_freq_to_channel(int freq, uint *channel);
int wifi_channel_to_freq(const char* country, UCHAR opclass, uint channel, uint *freq);
enum nl80211_band wifi_freq_band_to_nl80211_band(wifi_freq_bands_t band);
enum nl80211_band get_nl80211_band_from_rdk_radio_index(unsigned int rdk_radio_index);
const char* get_chan_dfs_state(struct hostapd_channel_data *chan);

static inline size_t wifi_strnlen(const char *src, size_t maxlen) {
    return (src == NULL) ? 0 : strnlen(src, maxlen);
}
int wifi_strcpy(char *dest, size_t dest_size, const char *src);
int wifi_strcat(char *dest, size_t dest_size, const char *src);
int wifi_strncpy(char *dest, size_t dest_size, const char *src, size_t count);
int str_list_append(char *dest, size_t dest_size, const char *src);
int wifi_ieee80211Variant_to_str(char *dest, size_t dest_size, wifi_ieee80211Variant_t variant,
    const char *str);
int wifi_channelBandwidth_to_str(char *dest, size_t dest_size, wifi_channelBandwidth_t bandwidth);
int wifi_bitrate_to_str(char *dest, size_t dest_size, wifi_bitrate_t bitrate);
void init_interface_map(void);
#ifdef CONFIG_WIFI_EMULATOR
void rearrange_interfaces_map();
void update_interfaces_map(unsigned int phy_index, unsigned int interface_radio_index);
void update_interface_names(unsigned int phy_index, char *interface_name);
#endif

int _syscmd(char *cmd, char *retBuf, int retBufSize);
static inline enum nl80211_iftype wpa_driver_nl80211_if_type(enum wpa_driver_if_type type)
{
    switch (type) {
    case WPA_IF_STATION:
        return NL80211_IFTYPE_STATION;
    case WPA_IF_P2P_CLIENT:
    case WPA_IF_P2P_GROUP:
        return NL80211_IFTYPE_P2P_CLIENT;
    case WPA_IF_AP_VLAN:
        return NL80211_IFTYPE_AP_VLAN;
    case WPA_IF_AP_BSS:
        return NL80211_IFTYPE_AP;
    case WPA_IF_P2P_GO:
        return NL80211_IFTYPE_P2P_GO;
    case WPA_IF_P2P_DEVICE:
        return NL80211_IFTYPE_P2P_DEVICE;
    case WPA_IF_MESH:
        return NL80211_IFTYPE_MESH_POINT;
    default:
        return -1;
    }
}
int wifi_drv_set_supp_port(void *priv, int authorized);
#ifdef RDKB_ONE_WIFI_PROD
void remap_wifi_interface_name_index_map();
#endif /* RDKB_ONE_WIFI_PROD */

char *wifi_hal_get_mld_name_by_interface_name(char *ifname);
char *wifi_hal_get_interface_name(wifi_interface_info_t *interface);
unsigned int wifi_hal_get_interface_ifindex(wifi_interface_info_t *interface);
bool wifi_hal_is_mld_enabled(wifi_interface_info_t *interface);
int wifi_hal_set_mld_enabled(wifi_interface_info_t *interface, bool enabled);
int wifi_hal_get_mld_link_id(wifi_interface_info_t *interface);
int wifi_hal_set_mld_link_id(wifi_interface_info_t *interface, int link_id);
uint8_t *wifi_hal_get_mld_mac_address(wifi_interface_info_t *interface);
int wifi_hal_set_mld_mac_address(wifi_interface_info_t *interface, mac_address_t mac);
wifi_interface_info_t *wifi_hal_get_mld_interface_by_link_id(wifi_interface_info_t *interface,
    int link_id);
wifi_interface_info_t *wifi_hal_get_mld_interface_by_freq(wifi_interface_info_t *interface,
    uint32_t freq);
wifi_interface_info_t *wifi_hal_get_mld_link_interface_by_mac(wifi_interface_info_t *interface,
    mac_address_t mac);
int wifi_hal_get_mac_address(const char *ifname, mac_address_t mac);
unsigned int get_band_info_from_rdk_radio_index(unsigned int rdk_radio_index);
#endif // WIFI_HAL_PRIV_H
