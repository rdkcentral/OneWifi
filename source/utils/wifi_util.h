#ifndef _WIFI_UTIL_H_
#define _WIFI_UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include "wifi_hal.h"
#include "wifi_blaster.h"
#include "wifi_ctrl.h"

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
    WIFI_PSM
}wifi_dbg_type_t;

#define ENUM_TO_STRING 1
#define STRING_TO_ENUM 2
#define ARRAY_SZ(x)    (sizeof(x) / sizeof((x)[0]))

#define MIN_MAC_LEN 12
#define MAC_ADDR_LEN 6
typedef unsigned char   mac_addr_t[MAC_ADDR_LEN];

#define MAX_WIFI_COUNTRYCODE 247
#define MIN_NUM_RADIOS 2
struct wifiCountryEnumStrMap {
    wifi_countrycode_type_t countryCode;
    char countryStr[4];
};
extern struct wifiCountryEnumStrMap wifiCountryMap[MAX_WIFI_COUNTRYCODE];

typedef struct radio_interface_mapping {
    uint8_t radio_index;
    char radio_name[16];
    char interface_name[16];
} radio_interface_mapping_t;

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

#define VAP_INDEX(hal_cap, map_index)   hal_cap.wifi_prop.interface_map[map_index].index;

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

/* utility functions declarations */
int get_number_of_radios(wifi_platform_property_t *wifi_prop);
int get_total_number_of_vaps(wifi_platform_property_t *wifi_prop);
char *get_vap_name(wifi_platform_property_t *wifi_prop, int vap_index);
int convert_vap_index_to_name(wifi_platform_property_t* wifi_prop, int vap_index, char *vap_name);
void write_to_file(const char *file_name, char *fmt, ...);
int convert_radio_name_to_index(unsigned int *index,char *name);
char *get_formatted_time(char *time);
void wifi_util_dbg_print(wifi_dbg_type_t module, char *format, ...);
int WiFi_IsValidMacAddr(const char* mac);
INT getIpAddressFromString (const char * ipString, ip_addr_t * ip);
INT getIpStringFromAdrress (char * ipString, const ip_addr_t * ip);
void uint8_mac_to_string_mac(uint8_t *mac, char *s_mac);
void string_mac_to_uint8_mac(uint8_t *mac, char *s_mac);
int security_mode_support_radius(int mode);
int convert_vap_name_to_index(wifi_platform_property_t *wifi_prop, char *vap_name);
int convert_vap_name_to_array_index(wifi_platform_property_t * wifi_prop, char *vap_name);
int convert_vap_name_to_radio_array_index(wifi_platform_property_t *wifi_prop, char *vap_name);
int convert_radio_name_to_radio_index(char *name);
int convert_radio_index_to_radio_name(int index, char *name);
int convert_security_mode_integer_to_string(int m,char *mode);
int convert_security_mode_string_to_integer(int *m,char *mode);
int convert_freq_band_to_radio_index(int band, int *radio_index);
int convert_ifname_to_radio_index(wifi_platform_property_t *wifi_prop, char *if_name, unsigned int *radio_index);
int convert_radio_index_to_ifname(wifi_platform_property_t *wifi_prop, unsigned int radio_index, char *if_name, int ifname_len);
int convert_apindex_to_ifname(wifi_platform_property_t *wifi_prop, int idx, char *if_name, unsigned int len);
int convert_ifname_to_vapname(wifi_platform_property_t *wifi_prop, char *if_name, char *vap_name, int vapname_len);
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
BOOL is_vap_lnf_radius(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
BOOL is_vap_mesh_sta(wifi_platform_property_t *wifi_prop, unsigned int ap_index);
int country_code_conversion(wifi_countrycode_type_t *country_code, char *country, int country_len, unsigned int conv_type);
int hw_mode_conversion(wifi_ieee80211Variant_t *hw_mode_enum, char *hw_mode, int hw_mode_len, unsigned int conv_type);
int ht_mode_conversion(wifi_channelBandwidth_t *ht_mode_enum, char *ht_mode, int ht_mode_len, unsigned int conv_type);
int get_sta_vap_index_for_radio(wifi_platform_property_t *wifi_prop, unsigned int radio_index);
int channel_mode_conversion(BOOL *auto_channel_bool, char *auto_channel_string, int auto_channel_strlen, unsigned int conv_type);
int is_wifi_channel_valid(wifi_freq_bands_t wifi_band, UINT wifi_channel);
int key_mgmt_conversion_legacy(wifi_security_modes_t *mode_enum, wifi_encryption_method_t *encryp_enum, char *str_mode, int mode_len, char *str_encryp, int encryp_len, unsigned int conv_type);
int key_mgmt_conversion(wifi_security_modes_t *enum_sec, char *str_sec, int sec_len, unsigned int conv_type);
int get_radio_if_hw_type(char *str, int str_len);
char *to_mac_str(mac_address_t mac, mac_addr_str_t key);
int is_ssid_name_valid(char *ssid_name);
void str_to_mac_bytes (char *key, mac_addr_t bmac);
int get_cm_mac_address(char *mac);
int get_ssid_from_device_mac(char *ssid);
wifi_interface_name_t *get_interface_name_for_vap_index(unsigned int vap_index, wifi_platform_property_t *wifi_prop);
int convert_vapname_to_ifname(wifi_platform_property_t *wifi_prop, char *vap_name, char *if_name, int ifname_len);
unsigned int create_vap_mask(wifi_platform_property_t *wifi_prop, unsigned int num_names, ...);
int get_interface_name_from_radio_index(wifi_platform_property_t *wifi_prop, uint8_t radio_index, char *interface_name);
unsigned long long int get_current_ms_time(void);
wifi_vap_info_t *get_wifi_radio_vap_info_map(rdk_wifi_radio_t *wifi_radio, const char *vap_name_prefix);
int get_list_of_vap_names(wifi_platform_property_t *wifi_prop, wifi_vap_name_t vap_names[], int list_size, int num_types, ...);
int get_list_of_private_ssid(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_hotspot_open(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_hotspot_secure(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_lnf_psk(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_lnf_radius(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_mesh_backhaul(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_mesh_sta(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_list_of_iot_ssid(wifi_platform_property_t *wifi_prop, int list_size, wifi_vap_name_t vap_names[]);
int get_radio_index_for_vap_index(wifi_platform_property_t* wifi_prop, int vap_index);
int min_hw_mode_conversion(unsigned int vapIndex, char *inputStr, char *outputStr, char *tableType);
int vif_radio_idx_conversion(unsigned int vapIndex, int *input, int *output, char *tableType);
int get_allowed_channels(wifi_freq_bands_t band, wifi_radio_capabilities_t *radio_cap, int *channels, int *channels_len);
#endif//_WIFI_UTIL_H_
