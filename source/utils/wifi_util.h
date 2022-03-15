
#ifndef _WIFI_UTIL_H_
#define _WIFI_UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include "wifi_hal.h"
#include "wifi_blaster.h"
#include <stdint.h>

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
    WIFI_LIB
}wifi_dbg_type_t;

#define ENUM_TO_STRING 1
#define STRING_TO_ENUM 2
#define ARRAY_SZ(x)    (sizeof(x) / sizeof((x)[0]))

#define MIN_MAC_LEN 12
#define MAC_ADDR_LEN 6
typedef unsigned char   mac_addr_t[MAC_ADDR_LEN];

int WiFi_IsValidMacAddr(const char* mac);

void wifi_util_dbg_print(wifi_dbg_type_t module, char *format, ...);

INT getIpAddressFromString (const char * ipString, ip_addr_t * ip);

INT getIpStringFromAdrress (char * ipString, const ip_addr_t * ip);

int convert_vap_name_to_index(char *vap_name);

char *get_formatted_time(char *time);

int convert_vap_name_to_array_index(char *vap_name);

void uint8_mac_to_string_mac(uint8_t *mac, char *s_mac);

void string_mac_to_uint8_mac(uint8_t *mac, char *s_mac);

#define MAX_WIFI_COUNTRYCODE 247
#define MIN_NUM_RADIOS 2
struct wifiCountryEnumStrMap {
    wifi_countrycode_type_t countryCode;
    char countryStr[4];
};

typedef struct {
    char if_name[16];
    char vap_name[32];
} ap_name_translator_t;

struct wifiCountryEnumStrMap wifiCountryMap[MAX_WIFI_COUNTRYCODE];
int vap_mode_conversion(wifi_vap_mode_t *vapmode_enum, char *vapmode_str, size_t vapmode_str_len, unsigned int conv_type);
int macfilter_conversion(char *mac_list_type, size_t string_len,  wifi_vap_info_t *vap_info, unsigned int conv_type);
int ssid_broadcast_conversion(char *broadcast_string, size_t string_len, BOOL *broadcast_bool, unsigned int conv_type);
int convert_apindex_to_ifname(int idx, char *iface, int len);
int freq_band_conversion(wifi_freq_bands_t *band_enum, char *freq_band, int freq_band_len, unsigned int conv_type);
int country_code_conversion(wifi_countrycode_type_t *country_code, char *country, int country_len, unsigned int conv_type);
int hw_mode_conversion(wifi_ieee80211Variant_t *hw_mode_enum, char *hw_mode, int hw_mode_len, unsigned int conv_type);
int ht_mode_conversion(wifi_channelBandwidth_t *ht_mode_enum, char *ht_mode, int ht_mode_len, unsigned int conv_type);
BOOL is_vap_private(unsigned int ap_index);
BOOL is_vap_xhs(unsigned int ap_index);
BOOL is_vap_hotspot(unsigned int ap_index);
BOOL is_vap_lnf(unsigned int ap_index);
BOOL is_vap_lnfpsk(unsigned int ap_index);
BOOL is_vap_mesh_backhaul(unsigned int ap_index);
BOOL is_vap_mesh_sta(unsigned int ap_index);
BOOL is_vap_hotspotsecure(unsigned int ap_index);
BOOL is_vap_lnfsecure(unsigned int ap_index);
int channel_mode_conversion(BOOL *auto_channel_bool, char *auto_channel_string, int auto_channel_strlen, unsigned int conv_type);
int is_ssid_name_valid(char *ssid_name);
int is_wifi_channel_valid(wifi_freq_bands_t wifi_band, UINT wifi_channel);
#endif//_WIFI_UTIL_H_
