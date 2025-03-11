#ifndef WIFI_DML_API_H
#define WIFI_DML_API_H

#include "wifi_data_model.h"
#include "wifi_hal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REG_DOMAIN_SZ 3
#define ENV_SZ 1

#define BS_SOURCE_WEBPA_STR "webpa"
#define BS_SOURCE_RFC_STR "rfc"
#define MACFILTER_TABLE_SYNC_TIME_IN_SEC 2

#define MAX_STR_MAC_ADDR_LEN 17
#define MIN_STR_MAC_ADDR_LEN 12

#define STR_CMP(PARAM_NAME, STR) (strncmp(PARAM_NAME, STR, strlen(STR) + 1) == 0)
#define STR_COPY(PARAM_NAME, STR) (strncpy(PARAM_NAME, STR, strlen(STR) + 1))
#define ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))

#define STR_CAT(DEST, SRC)                                       \
    do {                                                         \
        strncat((DEST), (SRC), sizeof(DEST) - strlen(DEST) - 1); \
    } while (0)

typedef struct wifi_freq_band_hal_map {
    wifi_freq_bands_t hal_wifi_freq_band;
    char str_wifi_freq_band[16];
} wifi_freq_band_hal_map_t;

typedef struct wifi_sec_mode_hal_map {
    wifi_security_modes_t hal_sec_mode;
    char str_sec_mode[32];
} wifi_sec_mode_hal_map_t;

typedef struct wifi_sec_mfp_hal_map {
    wifi_mfp_cfg_t hal_sec_mfp;
    char str_sec_mfp[32];
} wifi_sec_mfp_hal_map_t;

typedef struct wifi_sec_encr_hal_map {
    wifi_encryption_method_t hal_sec_encr_method;
    char str_sec_encr_type[16];
} wifi_sec_encr_hal_map_t;

typedef struct wifi_guard_interval_map {
    wifi_guard_interval_t hal_guard_interval;
    char str_guard_interval[8];
} wifi_guard_interval_map_t;

typedef struct wifi_variant_hal_map {
    wifi_ieee80211Variant_t hal_radio_variant;
    char str_radio_variant[4];
} wifi_variant_hal_map_t;

typedef struct wifi_chan_width_hal_map {
    wifi_channelBandwidth_t hal_wifi_chan_width;
    char str_wifi_chan_width[16];
} wifi_chan_width_hal_map_t;

typedef struct wifi_data_tx_rate_hal_map {
    wifi_bitrate_t hal_data_tx_rate;
    char str_data_tx_rate[8];
} wifi_data_tx_rate_hal_map_t;

typedef struct wifi_wps_method_hal_map {
    wifi_onboarding_methods_t hal_wifi_wps_method;
    char str_wifi_wps_method[32];
} wifi_wps_method_hal_map_t;

typedef struct table_index_timer_arg {
    uint32_t vap_index;
    char table_row[64];
} table_index_timer_arg_t;

int set_output_string(scratch_data_buff_t *output_value, char *str);
uint32_t get_sec_mode_string_from_int(wifi_security_modes_t security_mode, char *security_name);
int get_sec_mode_int_from_string(const char *p_sec_name, wifi_security_modes_t *p_sec_mode);
int get_sec_modes_supported(int vap_index, int *mode);
int get_mfp_type_from_string(const char *p_mfp_name, wifi_mfp_cfg_t *p_mfp_type);
int get_sec_encr_int_from_string(const char *p_sec_encr_name,
    wifi_encryption_method_t *p_sec_encr_type);
int get_sec_encr_string_from_int(wifi_encryption_method_t l_sec_encr_type, char *p_sec_encr_name);
int get_radio_band_string_from_int(wifi_freq_bands_t l_radio_band, char *p_str_radio_band);
int get_radio_guard_interval_string_from_int(wifi_guard_interval_t l_guard_interval,
    char *p_guard_interval_name);
int get_radio_guard_interval_int_from_string(const char *p_guard_interval_name,
    wifi_guard_interval_t *p_guard_interval);
int get_radio_variant_string_from_int(wifi_ieee80211Variant_t l_radio_variant,
    char *p_radio_variant_name);
int get_radio_variant_int_from_string(const char *p_radio_variant_name,
    wifi_ieee80211Variant_t *p_radio_variant);
int get_radio_bandwidth_string_from_int(wifi_channelBandwidth_t l_chan_width,
    char *p_chan_width_name);
int get_radio_bandwidth_int_from_string(const char *p_chan_width_name,
    wifi_channelBandwidth_t *p_chan_width);
uint32_t get_reg_domain_string_from_int(wifi_countrycode_type_t l_country_code,
    wifi_operating_env_t l_oper_env, char *str_reg_domain);
int get_reg_domain_int_from_string(const char *p_reg_domain,
    wifi_countrycode_type_t *p_country_code, wifi_operating_env_t *p_oper_env);
int get_wifi_data_tx_rate_int_from_string(const char *p_tx_rate_name, wifi_bitrate_t *p_tx_rate);
uint32_t get_wifi_data_tx_rate_string_from_int(wifi_bitrate_t l_tx_rate, char *p_tx_rate_name);
int get_beacon_rate_int_from_string(const char *beacon_name, wifi_bitrate_t *beacon_type);
uint32_t get_beacon_rate_string_from_int(wifi_bitrate_t beacon_type, char *beacon_name);
int get_wifi_wps_method_int_from_string(const char *p_wps_method_name,
    wifi_onboarding_methods_t *p_wps_method);
uint32_t get_wifi_wps_method_string_from_int(wifi_onboarding_methods_t l_wps_method,
    char *p_wps_method_name);
int get_radio_band_int_from_string(const char *p_str_radio_band, wifi_freq_bands_t *p_radio_band);

uint32_t get_total_dbg_log_enable_str_value(char *p_output_str);
int disable_dbg_logs(char *p_input_str);

bool is_valid_transmit_rate(char *input_str);

int radio_wifi_channel_is_valid(uint32_t radio_index, uint32_t input_channel);
bool is_radio_tx_power_valid(char *p_supported_power_list, int l_tx_power);
int enable_wifi_telnet(bool enabled);
int dm_wifi_set_webconfig(char *webconfstr, uint32_t size);
bool is_valid_mac_address(char *mac);
assoc_dev_data_t *get_sta_assoc_data_map(uint32_t ap_index, uint32_t sta_index);
int init_dm_params(void);
bool validate_def_reporting_period_value(unsigned long period);
bool validate_inst_client_mac_value(char *phys_address);
int is_sec_mode_open_for_private_ap(uint32_t vap_index);
int max_macfilter_number_of_entries(wifi_vap_info_t *vap_param, uint32_t *p_max_macfilter_entries);
acl_entry_t *get_macfilter_entry(wifi_vap_info_t *vap_info, uint32_t acl_entry_index);
int sync_dml_macfilter_table(uint32_t vap_index, char *table_row_name);
int sync_dml_macfilter_table_entries(void);
int sync_dml_sta_assoc_table_entries(void);
char *getDeviceMac(void);
int initparodusTask(void);
int get_requestor_string(char *str);
void get_cur_time_str(char *str_time, uint32_t str_len);
int get_wifi_region_update_source(char *str_output);
int set_wifi_region_update_source(char *str_input);
int update_json_param(char *p_key, char *partner_id, char *p_value, char *p_source,
    char *p_current_time);
int push_data_to_ssp_queue(const void *msg, unsigned int len, uint32_t type, uint32_t sub_type);

#endif // WIFI_DML_API_H
