/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2018 RDK Management
  
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
  http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#ifndef _WIFI_UTIL_H_
#define _WIFI_UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include "wifi_hal.h"
#include <pthread.h>
#include <sys/prctl.h>
#include "wifi_base.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum {
    WIFI_DB,
    WIFI_WEBCONFIG,
    WIFI_CTRL,
    WIFI_PASSPOINT,
    WIFI_MGR,
    WIFI_DPP,
    WIFI_MON,
    WIFI_DMCLI,
    WIFI_LIB,
    WIFI_PSM,
    WIFI_ANALYTICS,
    WIFI_APPS,
    WIFI_SERVICES,
    WIFI_HARVESTER,
    WIFI_SM,
    WIFI_BLASTER,
    WIFI_OCS
}wifi_dbg_type_t;

typedef enum {
    WIFI_LOG_LVL_DEBUG,
    WIFI_LOG_LVL_INFO,
    WIFI_LOG_LVL_ERROR,
    WIFI_LOG_LVL_MAX
}wifi_log_level_t;

void wifi_util_print(wifi_log_level_t level, wifi_dbg_type_t module, char *format, ...);

#define wifi_util_dbg_print(module, format, ...)  wifi_util_print(WIFI_LOG_LVL_DEBUG, module, format, ##__VA_ARGS__)
#define wifi_util_info_print(module, format, ...)  wifi_util_print(WIFI_LOG_LVL_INFO, module, format, ##__VA_ARGS__)
#define wifi_util_error_print(module, format, ...)  wifi_util_print(WIFI_LOG_LVL_ERROR, module, format, ##__VA_ARGS__)

#define ENUM_TO_STRING 1
#define STRING_TO_ENUM 2

#define PARTNER_ID_LEN 64

#define MIN_MAC_LEN 12
#define MAC_ADDR_LEN 6
typedef unsigned char   mac_addr_t[MAC_ADDR_LEN];

#define MAX_WIFI_COUNTRYCODE 247
#define MIN_NUM_RADIOS 2
struct wifiCountryEnumStrMapMember {
    wifi_countrycode_type_t countryCode;
    char countryStr[4];
    char countryId[4];
};

struct wifiEnvironmentEnumStrMap {
    wifi_operating_env_t operatingEnvironment;
    char environment[2];
};

extern struct wifiEnvironmentEnumStrMap wifiEnviromentMap[4];
extern struct wifiCountryEnumStrMapMember wifiCountryMapMembers[MAX_WIFI_COUNTRYCODE];

#define LM_GEN_STR_SIZE     64
#define LM_MAX_HOSTS_NUM    256

typedef struct {
    unsigned char ssid[LM_GEN_STR_SIZE];
    unsigned char AssociatedDevice[LM_GEN_STR_SIZE];
    unsigned char phyAddr[32]; /* Byte alignment*/
    int RSSI;
    int Status;
}__attribute__((packed, aligned(1))) LM_wifi_host_t;

typedef struct{
    int count;
    LM_wifi_host_t   host[LM_MAX_HOSTS_NUM];
}__attribute__((packed, aligned(1))) LM_wifi_hosts_t;

#define VAP_PREFIX_PRIVATE          "private_ssid"
#define VAP_PREFIX_IOT              "iot_ssid"
#define VAP_PREFIX_MESH_STA         "mesh_sta"
#define VAP_PREFIX_MESH_BACKHAUL    "mesh_backhaul"
#define VAP_PREFIX_HOTSPOT          "hotspot"
#define VAP_PREFIX_HOTSPOT_OPEN     "hotspot_open"
#define VAP_PREFIX_HOTSPOT_SECURE   "hotspot_secure"
#define VAP_PREFIX_LNF_PSK          "lnf_psk"
#define VAP_PREFIX_LNF_RADIUS       "lnf_radius"

#define VAP_INDEX(hal_cap, map_index)   hal_cap.wifi_prop.interface_map[map_index].index
#define RADIO_INDEX(hal_cap, map_index) hal_cap.wifi_prop.interface_map[map_index].rdk_radio_index

#define VAP_ARRAY_INDEX(i, hal_cap, vap_index) {\
    i = 0;\
    while((hal_cap.wifi_prop.interface_map[i].interface_name[0] != '\0') && \
          (hal_cap.wifi_prop.interface_map[i].vap_name[0] != '\0')) {\
        if(hal_cap.wifi_prop.interface_map[i].index == vap_index) {\
            break;\
        }\
        (i)++;\
    }\
}

#define NAME_FREQUENCY_2_4_G        "2g"
#define NAME_FREQUENCY_5_G          "5g"
#define NAME_FREQUENCY_6_G          "6g"
#define NAME_FREQUENCY_5H_G         "5gh"
#define NAME_FREQUENCY_5L_G         "5gl"

#define NAME_FREQUENCY_2_4          "2"
#define NAME_FREQUENCY_5            "5"
#define NAME_FREQUENCY_6            "6"
#define NAME_FREQUENCY_5H           "5H"
#define NAME_FREQUENCY_5L           "5L"

/* 2GHz radio */
#define MIN_FREQ_MHZ_2G             2412
#define MAX_FREQ_MHZ_2G             2484
#define MIN_CHANNEL_2G              1
#define MAX_CHANNEL_2G              13

/* 5GHz radio */
#define MIN_FREQ_MHZ_5G             5180
#define MAX_FREQ_MHZ_5G             5825
#define MIN_CHANNEL_5G              36
#define MAX_CHANNEL_5G              165

/* 5GHz Low radio */
#define MIN_FREQ_MHZ_5GL            5180
#define MAX_FREQ_MHZ_5GL            5320
#define MIN_CHANNEL_5GL             36
#define MAX_CHANNEL_5GL             64

/* 5GHz High radio */
#define MIN_FREQ_MHZ_5GH            5500
#define MAX_FREQ_MHZ_5GH            5825
#define MIN_CHANNEL_5GH             100
#define MAX_CHANNEL_5GH             165

/* 6GHz radio */
#define MIN_FREQ_MHZ_6G             5955
#define MAX_FREQ_MHZ_6G             7115
#define MIN_CHANNEL_6G              1
#define MAX_CHANNEL_6G              229

/* utility functions declarations */
int get_number_of_radios(wifi_platform_property_t *wifi_prop);
int get_total_number_of_vaps(wifi_platform_property_t *wifi_prop);
bool get_radio_presence(wifi_platform_property_t *wifi_prop, int index);
char *get_vap_name(wifi_platform_property_t *wifi_prop, int vap_index);
int convert_vap_index_to_name(wifi_platform_property_t* wifi_prop, int vap_index, char *vap_name);
int convert_vap_index_to_name(wifi_platform_property_t* wifi_prop, int vap_index, char *vap_name);
void write_to_file(const char *file_name, char *fmt, ...);
int convert_radio_name_to_index(unsigned int *index,char *name);
char *get_formatted_time(char *time);
int WiFi_IsValidMacAddr(const char* mac);
INT getIpAddressFromString (const char * ipString, ip_addr_t * ip);
INT getIpStringFromAdrress (char * ipString, const ip_addr_t * ip);
void uint8_mac_to_string_mac(uint8_t *mac, char *s_mac);
void string_mac_to_uint8_mac(uint8_t *mac, char *s_mac);
int security_mode_support_radius(int mode);
bool is_sec_mode_enterprise(wifi_security_modes_t mode);
bool is_sec_mode_personal(wifi_security_modes_t mode);
int convert_vap_name_to_index(wifi_platform_property_t *wifi_prop, char *vap_name);
int convert_vap_name_to_array_index(wifi_platform_property_t * wifi_prop, char *vap_name);
int convert_vap_name_to_radio_array_index(wifi_platform_property_t *wifi_prop, char *vap_name);
//getVAPArrayIndexFromVAPIndex() need to be used in case of VAPS considered as single array (from 0 to MAX_VAP)
//In case of to get vap array index per radio, use convert_vap_index_to_vap_array_index()
int convert_vap_index_to_vap_array_index(wifi_platform_property_t *wifi_prop, unsigned int vap_index);
int convert_radio_name_to_radio_index(char *name);
int convert_radio_index_to_radio_name(int index, char *name);
int convert_security_mode_integer_to_string(int m,char *mode);
int convert_security_mode_string_to_integer(int *m,char *mode);
int convert_freq_band_to_radio_index(int band, int *radio_index);
BOOL is_radio_band_5G(int band);
int convert_ifname_to_radio_index(wifi_platform_property_t *wifi_prop, char *if_name, unsigned int *radio_index);
int convert_radio_index_to_ifname(wifi_platform_property_t *wifi_prop, unsigned int radio_index, char *if_name, int ifname_len);
int convert_apindex_to_ifname(wifi_platform_property_t *wifi_prop, int idx, char *if_name, unsigned int len);
int convert_ifname_to_vapname(wifi_platform_property_t *wifi_prop, char *if_name, char *vap_name, int vapname_len);
int convert_ifname_to_vap_index(wifi_platform_property_t *wifi_prop, char *if_name);
int vap_mode_conversion(wifi_vap_mode_t *vapmode_enum, char *vapmode_str, size_t vapmode_str_len, unsigned int conv_type);
int macfilter_conversion(char *mac_list_type, size_t string_len,  wifi_vap_info_t *vap_info, unsigned int conv_type);
int ssid_broadcast_conversion(char *broadcast_string, size_t string_len, BOOL *broadcast_bool, unsigned int conv_type);
int get_vap_and_radio_index_from_vap_instance(wifi_platform_property_t *wifi_prop, uint8_t vap_instance, uint8_t *radio_index, uint8_t *vap_index);
int freq_band_conversion(wifi_freq_bands_t *band_enum, char *freq_band, int freq_band_len, unsigned int conv_type);
BOOL wifi_util_is_vap_index_valid(wifi_platform_property_t *wifi_prop, int vap_index);
BOOL is_vap_private(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_xhs(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_hotspot(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_hotspot_open(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_lnf(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_lnf_psk(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_mesh(wifi_platform_property_t *wifi_prop, UINT ap_index);
BOOL is_vap_mesh_backhaul(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_hotspot_secure(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_hotspot_open_5g(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_hotspot_open_6g(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_hotspot_secure_5g(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_hotspot_secure_6g(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_lnf_radius(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_mesh_sta(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
int country_code_conversion(wifi_countrycode_type_t *country_code, char *country, int country_len, unsigned int conv_type);
int country_id_conversion(wifi_countrycode_type_t *country_code, char *country_id, int country_id_len, unsigned int conv_type);
int hw_mode_conversion(wifi_ieee80211Variant_t *hw_mode_enum, char *hw_mode, int hw_mode_len, unsigned int conv_type);
int ht_mode_conversion(wifi_channelBandwidth_t *ht_mode_enum, char *ht_mode, int ht_mode_len, unsigned int conv_type);
int get_sta_vap_index_for_radio(wifi_platform_property_t *wifi_prop, unsigned int radio_index);
int channel_mode_conversion(BOOL *auto_channel_bool, char *auto_channel_string, int auto_channel_strlen, unsigned int conv_type);
int channel_state_enum_to_str(wifi_channelState_t channel_state_enum, char *channel_state_string, unsigned int channel_state_strlen);
int is_wifi_channel_valid(wifi_platform_property_t *wifi_prop, wifi_freq_bands_t wifi_band, UINT wifi_channel);
int key_mgmt_conversion_legacy(wifi_security_modes_t *mode_enum, wifi_encryption_method_t *encryp_enum, char *str_mode, int mode_len, char *str_encryp, int encryp_len, unsigned int conv_type);
int key_mgmt_conversion(wifi_security_modes_t *enum_sec, char *str_sec, char *str_sec2, int sec_len, int sec_len2, unsigned int conv_type, int *len);
int get_radio_if_hw_type(unsigned int radio_index, char *str, int str_len);
char *to_mac_str(mac_address_t mac, mac_addr_str_t key);
int is_ssid_name_valid(char *ssid_name);
void str_to_mac_bytes (char *key, mac_addr_t bmac);
int get_cm_mac_address(char *mac);
int get_ssid_from_device_mac(char *ssid);
wifi_interface_name_t *get_interface_name_for_vap_index(unsigned int vap_index, wifi_platform_property_t *wifi_prop);
int convert_vapname_to_ifname(wifi_platform_property_t *wifi_prop, char *vap_name, char *if_name, int ifname_len);
int get_bridgename_from_vapname(wifi_platform_property_t *wifi_prop, char *vap_name, char *bridge_name, int bridge_name_len);
unsigned int create_vap_mask(wifi_platform_property_t *wifi_prop, unsigned int num_names, ...);
int get_interface_name_from_radio_index(wifi_platform_property_t *wifi_prop, uint8_t radio_index, char *interface_name);
unsigned long long int get_current_ms_time(void);
long long int get_current_time_in_sec(void);
int get_list_of_vap_names(wifi_platform_property_t *wifi_prop, wifi_vap_name_t vap_names[], int list_size, int num_types, ...);
int get_list_of_private_ssid(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_hotspot_open(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t *vap_names);
int get_list_of_hotspot_secure(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t *vap_names);
int get_list_of_lnf_psk(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_lnf_radius(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_mesh_backhaul(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_mesh_sta(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_iot_ssid(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_radio_index_for_vap_index(wifi_platform_property_t* wifi_prop, int vap_index);
int min_hw_mode_conversion(unsigned int vapIndex, char *inputStr, char *outputStr, char *tableType);
int vif_radio_idx_conversion(unsigned int vapIndex, int *input, int *output, char *tableType);
int get_on_channel_scan_list(wifi_freq_bands_t band, wifi_channelBandwidth_t bandwidth, int primary_channel, int *channel_list, int *channels_num);
int get_allowed_channels(wifi_freq_bands_t band, wifi_radio_capabilities_t *radio_cap, int *channels, int *channels_len, bool dfs_enabled);
int get_allowed_channels_str(wifi_freq_bands_t band, wifi_radio_capabilities_t *radio_cap, char *buf, size_t buf_size, bool dfs_enabled);
int convert_radio_index_to_freq_band(wifi_platform_property_t *wifi_prop, unsigned int radio_index, int *band);
void wifidb_print(char *format, ...);
void copy_string(char*  destination, char*  source);
bool wifiStandardStrToEnum(char *pWifiStdStr, wifi_ieee80211Variant_t *p80211VarEnum, ULONG instance_number, bool twoG80211axEnable);
int stats_type_conversion(stats_type_t *stat_type_enum, char *stat_type, int stat_type_len, unsigned int conv_type);
int report_type_conversion(reporting_type_t *report_type_enum, char *report_type, int report_type_len, unsigned int conv_type);
int survey_type_conversion(survey_type_t *survey_type_enum, char *survey_type, int survey_type_len, unsigned int conv_type);
int get_steering_cfg_id(char *key, int key_len, unsigned char * id, int id_len, const steering_config_t *st_cfg);
int get_stats_cfg_id(char *key, int key_len, unsigned char *id, int id_len, const unsigned int stats_type, const unsigned int report_type, const unsigned int radio_type, const unsigned int survey_type);
int get_steering_clients_id(char *key, int key_len, unsigned char *id, int id_len, const char *mac);
int cs_state_type_conversion(cs_state_t *cs_state_type_enum, char *cs_state, int cs_state_len, unsigned int conv_type);
int cs_mode_type_conversion(cs_mode_t *cs_mode_type_enum, char *cs_mode, int cs_mode_len, unsigned int conv_type);
int force_kick_type_conversion(force_kick_t *force_kick_type_enum, char *force_kick, int force_kick_len, unsigned int conv_type);
int kick_type_conversion(kick_type_t *kick_type_enum, char *kick_type, int kick_type_len, unsigned int conv_type);
int pref_5g_conversion(pref_5g_t *pref_5g_enum, char *pref_5g, int pref_5g_len, unsigned int conv_type);
int reject_detection_conversion(reject_detection_t *reject_detection_enum, char *reject_detection, int reject_detection_len, unsigned int conv_type);
int sc_kick_type_conversion(sc_kick_type_t *sc_kick_enum, char *sc_kick, int sc_kick_len, unsigned int conv_type);
int sticky_kick_type_conversion(sticky_kick_type_t *sticky_kick_enum, char *sticky_kick, int sticky_kick_len, unsigned int conv_type);
int get_vif_neighbor_id(char *key, int key_len, unsigned char *id, int id_len, const char *mac);
int vif_neighbor_htmode_conversion(ht_mode_t *ht_mode_enum, char *ht_mode, int ht_mode_len, unsigned int conv_type);
int convert_channel_to_freq(int band, unsigned char chan);
BOOL is_bssid_valid(const bssid_t bssid);
bool is_bandwidth_and_hw_variant_compatible(uint32_t variant, wifi_channelBandwidth_t current_bw);
int validate_radio_parameters(const wifi_radio_operationParam_t *radio_info);
int wifi_radio_operationParam_validation(wifi_hal_capability_t  *hal_cap, wifi_radio_operationParam_t *oper);
int convert_ascii_string_to_bool(char *l_string, bool *l_bool_param);
int convert_bool_to_ascii_string(bool l_bool_param, char *l_string, size_t str_len);
void json_param_obscure(char *json, char *param);
bool is_5g_20M_channel_in_dfs(int channel);
bool is_6g_supported_device(wifi_platform_property_t *wifi_prop);
#ifdef __cplusplus
}
#endif
#endif//_WIFI_UTIL_H_
