#include "scheduler.h"
#include "wifi_dml_api.h"
#include "wifi_stubs.h"
#include "wifi_util.h"
#include "dml_onewifi_api.h"
#include "wifi_events.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cjson/cJSON.h>

extern sem_t *sem;

#define PARTNERS_INFO_FILE              "/nvram/partners_defaults.json"
#define BOOTSTRAP_INFO_FILE             "/opt/secure/bootstrap.json"
#define BOOTSTRAP_INFO_FILE_BACKUP      "/nvram/bootstrap.json"
#define CLEAR_TRACK_FILE                "/nvram/ClearUnencryptedData_flags"
#define NVRAM_BOOTSTRAP_CLEARED         (1 << 0)

int set_output_string(scratch_data_buff_t *output_value, char *str)
{   
    if (str == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: input string buffer is NULL\n",__func__, __LINE__);
        return RETURN_ERR;
    } else if (output_value == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: output buffer is NULL:%s\n",__func__, __LINE__, str);
        return RETURN_ERR;
    }
    
    uint32_t str_size = strlen(str) + 1;
    
    if (output_value->buff == NULL) {
        output_value->buff = malloc(str_size);
    }

    if (str_size > 1) {
        strncpy(output_value->buff, str, str_size);
    } else {
        memset(output_value->buff, 0, str_size);
    }
    output_value->buff_len = str_size;
    return RETURN_OK;
}

uint32_t get_sec_mode_string_from_int(wifi_security_modes_t security_mode, char *security_name)
{
    uint32_t index;
    wifi_sec_mode_hal_map_t wifi_sec_mode_map[] = {
        { wifi_security_mode_none,                "None" },
        { wifi_security_mode_wep_64,              "WEP_64" },
        { wifi_security_mode_wep_128,             "WEP_128" },
        { wifi_security_mode_wpa_personal,        "WPA-Personal" },
        { wifi_security_mode_wpa2_personal,       "WPA2-Personal" },
        { wifi_security_mode_wpa3_personal,       "WPA3-Personal" },
        { wifi_security_mode_wpa_wpa2_personal,   "WPA-WPA2-Personal" },
        { wifi_security_mode_wpa3_transition,     "WPA3-Personal-Transition" },
        { wifi_security_mode_wpa_enterprise,      "WPA-Enterprise" },
        { wifi_security_mode_wpa2_enterprise,     "WPA2-Enterprise" },
        { wifi_security_mode_wpa3_enterprise,     "WPA3-Enterprise" },
        { wifi_security_mode_wpa_wpa2_enterprise, "WPA-WPA2-Enterprise" },
        { wifi_security_mode_enhanced_open,       "Enhanced-Open" }
    };

    for (index = 0 ; index < (uint32_t)ARRAY_SZ(wifi_sec_mode_map) ; index++) {
        if (security_mode & wifi_sec_mode_map[index].hal_sec_mode) {
            if (strlen(security_name) != 0) {
                strcat(security_name, ",");
                strcat(security_name, wifi_sec_mode_map[index].str_sec_mode);
            } else {
                strcpy(security_name, wifi_sec_mode_map[index].str_sec_mode);
            }
        }
    }

    if (strlen(security_name) == 0) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Invalid Security type:%d enum\n",__func__, __LINE__, security_mode);
    } else {
        return strlen(security_name) + 1;
    }

    return 0;
}

int get_sec_mode_int_from_string(const char *p_sec_name, wifi_security_modes_t *p_sec_mode)
{
    DM_CHECK_NULL_WITH_RC(p_sec_name, 0);
    DM_CHECK_NULL_WITH_RC(p_sec_mode, 0);
    uint32_t index;
    wifi_sec_mode_hal_map_t wifi_sec_mode_map[] = {
        { wifi_security_mode_none,                "None" },
        { wifi_security_mode_wep_64,              "WEP_64" },
        { wifi_security_mode_wep_128,             "WEP_128" },
        { wifi_security_mode_wpa_personal,        "WPA-Personal" },
        { wifi_security_mode_wpa2_personal,       "WPA2-Personal" },
        { wifi_security_mode_wpa3_personal,       "WPA3-Personal" },
        { wifi_security_mode_wpa_wpa2_personal,   "WPA-WPA2-Personal" },
        { wifi_security_mode_wpa3_transition,     "WPA3-Personal-Transition" },
        { wifi_security_mode_wpa_enterprise,      "WPA-Enterprise" },
        { wifi_security_mode_wpa2_enterprise,     "WPA2-Enterprise" },
        { wifi_security_mode_wpa3_enterprise,     "WPA3-Enterprise" },
        { wifi_security_mode_wpa_wpa2_enterprise, "WPA-WPA2-Enterprise" },
        { wifi_security_mode_enhanced_open,       "Enhanced-Open" }
    };


    for (index = 0 ; index < (uint32_t)ARRAY_SZ(wifi_sec_mode_map) ; index++) {
        if(STR_CMP(p_sec_name, wifi_sec_mode_map[index].str_sec_mode)) {
            *p_sec_mode = wifi_sec_mode_map[index].hal_sec_mode;
            return wifi_sec_mode_map[index].hal_sec_mode;
        }
    }

    return 0;
}

int get_sec_modes_supported(int vap_index, int *mode)
{
    int band;
    uint32_t radio_index;
    wifi_vap_info_t *vap_info;
    bool passpoint_enabled;

    radio_index = getRadioIndexFromAp((unsigned int)vap_index);
    if (convert_radio_index_to_freq_band(&get_webconfig_dml()->hal_cap.wifi_prop, radio_index,
        &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d failed to convert radio index %u to band\n",
            __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    vap_info = get_dml_cache_vap_info(vap_index);
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d failed to get vap info for index %d\n",
            __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }
    passpoint_enabled = vap_info->u.bss_info.interworking.passpoint.enable;

    if (band == WIFI_FREQUENCY_6_BAND) {
        *mode = passpoint_enabled ? wifi_security_mode_wpa3_enterprise :
            wifi_security_mode_wpa3_personal | wifi_security_mode_wpa3_enterprise |
            wifi_security_mode_enhanced_open;
    } else if (passpoint_enabled) {
        *mode = wifi_security_mode_wpa_enterprise | wifi_security_mode_wpa2_enterprise |
            wifi_security_mode_wpa_wpa2_enterprise | wifi_security_mode_wpa3_enterprise;
    } else {
        *mode = wifi_security_mode_none | wifi_security_mode_enhanced_open |
            wifi_security_mode_wpa_personal | wifi_security_mode_wpa_enterprise |
            wifi_security_mode_wpa2_personal | wifi_security_mode_wpa2_enterprise |
            wifi_security_mode_wpa_wpa2_personal | wifi_security_mode_wpa_wpa2_enterprise |
            wifi_security_mode_wpa3_personal | wifi_security_mode_wpa3_transition |
            wifi_security_mode_wpa3_enterprise;
    }

    return RETURN_OK;
}

int get_mfp_type_from_string(const char *p_mfp_name, wifi_mfp_cfg_t *p_mfp_type)
{
    int      ret     = RETURN_ERR;
    uint32_t counter = 0;
    DM_CHECK_NULL_WITH_RC(p_mfp_name, ret);
    DM_CHECK_NULL_WITH_RC(p_mfp_type, ret);

    wifi_sec_mfp_hal_map_t wifi_sec_mfp_map[] = {
        { wifi_mfp_cfg_disabled, "Disabled" },
        { wifi_mfp_cfg_optional, "Optional" },
        { wifi_mfp_cfg_required, "Required" },
    };

    for (counter = 0 ; counter < (uint32_t)ARRAY_SZ(wifi_sec_mfp_map) ; ++counter) {
        if(STR_CMP(p_mfp_name, wifi_sec_mfp_map[counter].str_sec_mfp)) {
            *p_mfp_type = wifi_sec_mfp_map[counter].hal_sec_mfp;
            return RETURN_OK;
        }
    }
    return ret;
}

int get_sec_encr_int_from_string(const char *p_sec_encr_name, wifi_encryption_method_t *p_sec_encr_type)
{
    int      ret     = RETURN_ERR;
    uint32_t counter = 0;
    DM_CHECK_NULL_WITH_RC(p_sec_encr_name, ret);
    DM_CHECK_NULL_WITH_RC(p_sec_encr_type, ret);

    wifi_sec_encr_hal_map_t wifi_sec_encr_map[] = {
        { wifi_encryption_none,        "NONE"     },
        { wifi_encryption_tkip,        "TKIP"     },
        { wifi_encryption_aes,         "AES"      },
        { wifi_encryption_aes_tkip,    "AES+TKIP" },
        { wifi_encryption_aes_gcmp256, "AES+GCMP" }
    };

    for (counter = 0 ; counter < (uint32_t)ARRAY_SZ(wifi_sec_encr_map) ; ++counter) {
        if(STR_CMP(p_sec_encr_name, wifi_sec_encr_map[counter].str_sec_encr_type)) {
            *p_sec_encr_type = wifi_sec_encr_map[counter].hal_sec_encr_method;
            return RETURN_OK;
        }
    }
    return ret;
}

int get_sec_encr_string_from_int(wifi_encryption_method_t l_sec_encr_type, char *p_sec_encr_name)
{
    DM_CHECK_NULL_WITH_RC(p_sec_encr_name, 0);

    uint32_t index;
    bool     str_found = false;
    wifi_sec_encr_hal_map_t wifi_sec_encr_map[] = {
        { wifi_encryption_none,        "NONE"     },
        { wifi_encryption_tkip,        "TKIP"     },
        { wifi_encryption_aes,         "AES"      },
        { wifi_encryption_aes_tkip,    "AES+TKIP" },
        { wifi_encryption_aes_gcmp256, "AES+GCMP" }
    };

    for (index = 0 ; index < (uint32_t)ARRAY_SZ(wifi_sec_encr_map) ; index++) {
        if(l_sec_encr_type == wifi_sec_encr_map[index].hal_sec_encr_method) {
            STR_COPY(p_sec_encr_name, wifi_sec_encr_map[index].str_sec_encr_type);
            str_found = true;
        }
    }

    if(str_found == false) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Invalid Security type:%d enum\n",__func__, __LINE__, l_sec_encr_type);
    } else {
        return strlen(p_sec_encr_name) + 1;
    }

    return 0;
}

int get_radio_band_string_from_int(wifi_freq_bands_t l_radio_band, char *p_str_radio_band)
{
    wifi_freq_band_hal_map_t wifi_freq_band[] = {
        { WIFI_FREQUENCY_2_4_BAND, "2.4GHz"},
        { WIFI_FREQUENCY_5_BAND,   "5GHz"},
        { WIFI_FREQUENCY_5L_BAND,  "Low 5GHz"},
        { WIFI_FREQUENCY_5H_BAND,  "High 5Ghz"},
        { WIFI_FREQUENCY_6_BAND,   "6GHz"},
        { WIFI_FREQUENCY_60_BAND,  "60GHz"}
    };
    uint32_t index = 0;
    int ret = RETURN_ERR;

    DM_CHECK_NULL_WITH_RC(p_str_radio_band, ret);

    for (index = 0; index < (uint32_t)ARRAY_SZ(wifi_freq_band); index++) {
        if (l_radio_band == wifi_freq_band[index].hal_wifi_freq_band) {
            STR_COPY(p_str_radio_band, wifi_freq_band[index].str_wifi_freq_band);
            ret = RETURN_OK;
            break;
        }
    }

    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_DMCLI,"%s invalid band input:%d str freq band:%s\n", __func__,
            l_radio_band, p_str_radio_band);
    }

    return ret;
}

int get_radio_band_int_from_string(const char *p_str_radio_band, wifi_freq_bands_t *p_radio_band)
{
    wifi_freq_band_hal_map_t wifi_freq_band[] = {
        { WIFI_FREQUENCY_2_4_BAND, "2.4GHz"},
        { WIFI_FREQUENCY_5_BAND,   "5GHz"},
        { WIFI_FREQUENCY_5L_BAND,  "Low 5GHz"},
        { WIFI_FREQUENCY_5H_BAND,  "High 5Ghz"},
        { WIFI_FREQUENCY_6_BAND,   "6GHz"},
        { WIFI_FREQUENCY_60_BAND,  "60GHz"}
    };
    uint32_t index = 0;
    int ret = RETURN_ERR;

    DM_CHECK_NULL_WITH_RC(p_str_radio_band, ret);
    DM_CHECK_NULL_WITH_RC(p_radio_band, ret);

    for (index = 0; index < (uint32_t)ARRAY_SZ(wifi_freq_band); index++) {
        if (STR_CMP((char *)p_str_radio_band, wifi_freq_band[index].str_wifi_freq_band)) {
            *p_radio_band = wifi_freq_band[index].hal_wifi_freq_band;
            wifi_util_dbg_print(WIFI_DMCLI,"%s input :%s freq band:%d\n", __func__, p_str_radio_band, *p_radio_band);
            return RETURN_OK;
        }
    }

    return ret;
}

int get_radio_bandwidth_int_from_string(const char *p_chan_width_name, wifi_channelBandwidth_t *p_chan_width)
{
    int ret = RETURN_ERR;
    DM_CHECK_NULL_WITH_RC(p_chan_width_name, ret);
    DM_CHECK_NULL_WITH_RC(p_chan_width, ret);

    wifi_chan_width_hal_map_t wifi_chan_width_map[] = {
        { WIFI_CHANNELBANDWIDTH_20MHZ,    "20MHz" },
        { WIFI_CHANNELBANDWIDTH_40MHZ,    "40MHz" },
        { WIFI_CHANNELBANDWIDTH_80MHZ,    "80MHz" },
        { WIFI_CHANNELBANDWIDTH_160MHZ,   "160MHz" },
        { WIFI_CHANNELBANDWIDTH_80_80MHZ, "80+80MHz" },
#ifdef CONFIG_IEEE80211BE
        { WIFI_CHANNELBANDWIDTH_320MHZ,   "320MHz" }
#endif /* CONFIG_IEEE80211BE */
    };
    uint32_t index;

    for (index = 0; index < (uint32_t)ARRAY_SZ(wifi_chan_width_map); index++) {
        if (STR_CMP(p_chan_width_name, wifi_chan_width_map[index].str_wifi_chan_width)) {
            *p_chan_width = wifi_chan_width_map[index].hal_wifi_chan_width;
            return RETURN_OK;
        }
    }

    return ret;
}

int get_radio_bandwidth_string_from_int(wifi_channelBandwidth_t l_chan_width, char *p_chan_width_name)
{
    DM_CHECK_NULL_WITH_RC(p_chan_width_name, 0);

    wifi_chan_width_hal_map_t wifi_chan_width_map[] = {
        { WIFI_CHANNELBANDWIDTH_20MHZ,    "20MHz" },
        { WIFI_CHANNELBANDWIDTH_40MHZ,    "40MHz" },
        { WIFI_CHANNELBANDWIDTH_80MHZ,    "80MHz" },
        { WIFI_CHANNELBANDWIDTH_160MHZ,   "160MHz" },
        { WIFI_CHANNELBANDWIDTH_80_80MHZ, "80+80MHz" },
#ifdef CONFIG_IEEE80211BE
        { WIFI_CHANNELBANDWIDTH_320MHZ,   "320MHz" }
#endif /* CONFIG_IEEE80211BE */
    };
    bool     str_found = false;
    uint32_t index;

    for (index = 0; index < (uint32_t)ARRAY_SZ(wifi_chan_width_map); index++) {
        if (l_chan_width == wifi_chan_width_map[index].hal_wifi_chan_width) {
            STR_COPY(p_chan_width_name, wifi_chan_width_map[index].str_wifi_chan_width);
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d inputBw: %d str bw:[%s]\n",
                __func__, __LINE__, l_chan_width, wifi_chan_width_map[index].str_wifi_chan_width);
            str_found = true;
            break;
        }
    }

    if (str_found == false) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Invalid radio bandwidth:%d\n",__func__, __LINE__, l_chan_width);
    } else {
        return strlen(p_chan_width_name) + 1;
    }

    return 0;
}

int get_radio_guard_interval_int_from_string(const char *p_guard_interval_name, wifi_guard_interval_t *p_guard_interval)
{
    int      ret     = RETURN_ERR;
    uint32_t index = 0;
    DM_CHECK_NULL_WITH_RC(p_guard_interval_name, ret);
    DM_CHECK_NULL_WITH_RC(p_guard_interval, ret);

    wifi_guard_interval_map_t wifi_guard_interval[] ={
        { wifi_guard_interval_400,   "400ns" },
        { wifi_guard_interval_800,   "800ns" },
        { wifi_guard_interval_1600,  "1600ns" },
        { wifi_guard_interval_3200,  "3200ns" },
        { wifi_guard_interval_auto,  "Auto" }
    };

    for (index = 0 ; index < (uint32_t)ARRAY_SZ(wifi_guard_interval) ; index++) {
        if(STR_CMP(p_guard_interval_name, wifi_guard_interval[index].str_guard_interval)) {
            *p_guard_interval = wifi_guard_interval[index].hal_guard_interval;
            return RETURN_OK;
        }
    }
    return ret;
}

int get_radio_guard_interval_string_from_int(wifi_guard_interval_t l_guard_interval, char *p_guard_interval_name)
{
    DM_CHECK_NULL_WITH_RC(p_guard_interval_name, 0);

    uint32_t index;
    bool     str_found = false;
    wifi_guard_interval_map_t wifi_guard_interval[] ={
        { wifi_guard_interval_400,   "400ns" },
        { wifi_guard_interval_800,   "800ns" },
        { wifi_guard_interval_1600,  "1600ns" },
        { wifi_guard_interval_3200,  "3200ns" },
        { wifi_guard_interval_auto,  "Auto" }
    };

    for (index = 0 ; index < (uint32_t)ARRAY_SZ(wifi_guard_interval) ; index++) {
        if(l_guard_interval == wifi_guard_interval[index].hal_guard_interval) {
            STR_COPY(p_guard_interval_name, wifi_guard_interval[index].str_guard_interval);
            str_found = true;
        }
    }

    if(str_found == false) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Invalid guard interval:%d\n",__func__, __LINE__, l_guard_interval);
    } else {
        return strlen(p_guard_interval_name) + 1;
    }

    return 0;
}

int get_radio_variant_string_from_int(wifi_ieee80211Variant_t l_radio_variant, char *p_radio_variant_name)
{
    DM_CHECK_NULL_WITH_RC(p_radio_variant_name, 0);
    
    uint32_t index;
    bool     str_found = false;
    wifi_variant_hal_map_t wifi_variant_map[] = {
        { WIFI_80211_VARIANT_A,  "a" },
        { WIFI_80211_VARIANT_B,  "b" },
        { WIFI_80211_VARIANT_G,  "g" },
        { WIFI_80211_VARIANT_N,  "n" },
        { WIFI_80211_VARIANT_H,  "h" },
        { WIFI_80211_VARIANT_AC, "ac" },
        { WIFI_80211_VARIANT_AD, "ad" },
        { WIFI_80211_VARIANT_AX, "ax" },
#ifdef CONFIG_IEEE80211BE
        { WIFI_80211_VARIANT_BE, "be" }
#endif /* CONFIG_IEEE80211BE */
    };

    for (index = 0 ; index < (uint32_t)ARRAY_SZ(wifi_variant_map) ; index++) {
        if (l_radio_variant & wifi_variant_map[index].hal_radio_variant)
        {
            if (str_found == false) {
                STR_COPY(p_radio_variant_name, wifi_variant_map[index].str_radio_variant);
	    } else {
                STR_CAT(p_radio_variant_name, ",");
                STR_CAT(p_radio_variant_name, wifi_variant_map[index].str_radio_variant);
	    }
            str_found = true;
        }
    }

    if(str_found == false) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Invalid radio variant type:%d enum\n",__func__, __LINE__, l_radio_variant);
    } else {
        return strlen(p_radio_variant_name) + 1;
    }

    return 0;
}

int get_radio_variant_int_from_string(const char *p_radio_variant_name, wifi_ieee80211Variant_t *p_radio_variant)
{
    int ret = RETURN_ERR;
    DM_CHECK_NULL_WITH_RC(p_radio_variant_name, ret);
    DM_CHECK_NULL_WITH_RC(p_radio_variant, ret);

    wifi_variant_hal_map_t wifi_variant_map[] = {
        { WIFI_80211_VARIANT_A,  "a" },
        { WIFI_80211_VARIANT_B,  "b" },
        { WIFI_80211_VARIANT_G,  "g" },
        { WIFI_80211_VARIANT_N,  "n" },
        { WIFI_80211_VARIANT_H,  "h" },
        { WIFI_80211_VARIANT_AC, "ac" },
        { WIFI_80211_VARIANT_AD, "ad" },
        { WIFI_80211_VARIANT_AX, "ax" },
#ifdef CONFIG_IEEE80211BE
        { WIFI_80211_VARIANT_BE, "be" }
#endif /* CONFIG_IEEE80211BE */
    };

    uint32_t index = 0;
    bool is_radio_variant_invalid = true;
    char *token;
    char tmp_input_string[64] = {0};
    
    *p_radio_variant = 0;
    snprintf(tmp_input_string, sizeof(tmp_input_string), "%s", p_radio_variant_name);
    
    token = strtok(tmp_input_string, ",");
    while (token != NULL)
    {
    
        is_radio_variant_invalid = TRUE;
        for (index = 0; index < (uint32_t)ARRAY_SZ(wifi_variant_map); index++)
        {
            if (STR_CMP(token, wifi_variant_map[index].str_radio_variant))
            {
                *p_radio_variant |= wifi_variant_map[index].hal_radio_variant;
                wifi_util_dbg_print(WIFI_DMCLI,"%s input:%s radio_variant:%d\n", __func__,
                    p_radio_variant_name, *p_radio_variant);
                is_radio_variant_invalid = FALSE;
            }   
        }   
        
        if (is_radio_variant_invalid == TRUE)
        {
            wifi_util_error_print(WIFI_DMCLI,"%s Invalid Wifi Standard:%s\n", __func__, p_radio_variant_name);
            return ret;
        }   
        
        token = strtok(NULL, ",");
    }   
    return RETURN_OK;
}

int radio_wifi_channel_is_valid(uint32_t radio_index, uint32_t input_channel)
{
    uint32_t arr_len        = 0;
    uint32_t seq_counter    = 0;
    wifi_radio_capabilities_t *p_radio_cap = NULL;
    uint32_t band_arr_index = 0;
    bool     is_band_found  = false;
    wifi_radio_operationParam_t *p_radio_cfg = NULL;
    wifi_radio_operationParam_t l_pcfg;

    //Get the radio capability for further comparision
    p_radio_cap = getRadioCapability(radio_index);
    if (p_radio_cap == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s Failed for unable to get RadioCapability wlan_Index=%d\n", __func__, radio_index);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_DMCLI,"%s %d for radio_index : %d\n", __func__, __LINE__, radio_index);
    //Get the RadioOperation  structure
    p_radio_cfg = getRadioOperationParam(radio_index);
    if (p_radio_cfg == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s Input radio_index = %d not found for p_radio_cfg\n", __func__, radio_index);
        return RETURN_ERR;
    }
    memcpy(&l_pcfg, p_radio_cfg, sizeof(l_pcfg));
    p_radio_cfg = &l_pcfg;

    //Compare the Band from capability and operation
    for (band_arr_index = 0; band_arr_index < p_radio_cap->numSupportedFreqBand; band_arr_index++) {
        if (p_radio_cap->band[band_arr_index] == p_radio_cfg->band) {
            wifi_util_info_print(WIFI_DMCLI,"%s Band = %d is present at array index of cap:%d\n", __func__,
                p_radio_cfg->band, band_arr_index);
            is_band_found = true;
            break;
        }
    }

    if (is_band_found == false) {
        wifi_util_error_print(WIFI_DMCLI,"%s Input radio_index=%d Band=%d is not found in cap\n", __func__,
            radio_index, p_radio_cfg->band);
        return RETURN_ERR;
    }

    arr_len = p_radio_cap->channel_list[band_arr_index].num_channels;
    for (seq_counter = 0; seq_counter < arr_len; seq_counter++) {
        if (input_channel == (uint32_t)p_radio_cap->channel_list[band_arr_index].channels_list[seq_counter]) {
            wifi_util_info_print(WIFI_DMCLI,"%s %d For radio_index:%d input_channel:%d is supported\n", __func__,
                __LINE__, radio_index, input_channel);
            return RETURN_OK;
        }
    }
    wifi_util_error_print(WIFI_DMCLI,"%s Failed for radio_index:%d for input_channel:%d\n", __func__,
        radio_index, input_channel);
    return RETURN_ERR;
}

bool is_radio_tx_power_valid(char *p_supported_power_list, int l_tx_power)
{
    DM_CHECK_NULL_WITH_RC(p_supported_power_list, false);

    char   power_list[64] = {0} , *tok;
    size_t power_list_size = strlen(p_supported_power_list) + 1;

    if ((power_list_size == 0) || (power_list_size >= sizeof(power_list)))
    {
        wifi_util_error_print(WIFI_DMCLI,"%s: failed to get supported Transmit power list:%d\n", __func__, power_list_size);
        return false;
    }
    strncpy(power_list, p_supported_power_list, power_list_size);
    tok = strtok(power_list, ",");
    while (tok) {
        if (atoi(tok) == l_tx_power) {
            return true;
        }
        tok = strtok(NULL, ",");
    }
    wifi_util_error_print(WIFI_DMCLI,"%s:%d Given Tx power value:%d is not supported and supported values:%s\n",__func__,
        __LINE__, l_tx_power, p_supported_power_list);
    return false;
}

uint32_t get_reg_domain_string_from_int(wifi_countrycode_type_t l_country_code,
    wifi_operating_env_t l_oper_env, char *str_reg_domain)
{
    DM_CHECK_NULL_WITH_RC(str_reg_domain, 0);
    unsigned int i;
    char tmp_country_str[4];
    char tmp_environment[4];

    memset(tmp_country_str, 0, sizeof(tmp_country_str));
    memset(tmp_environment, 0, sizeof(tmp_environment));
    for (i = 0 ; i < (uint32_t)ARRAY_SZ(wifiCountryMapMembers); ++i) {
        if (l_country_code == wifiCountryMapMembers[i].countryCode) {
            strncpy(tmp_country_str, wifiCountryMapMembers[i].countryStr, sizeof(tmp_country_str)-1);
            break;
        }
    }

    for (i = 0; i < (uint32_t)ARRAY_SZ(wifiEnviromentMap); ++i) {
        if (l_oper_env == wifiEnviromentMap[i].operatingEnvironment) {
            strncpy(tmp_environment, wifiEnviromentMap[i].environment, sizeof(wifiEnviromentMap[i].environment)-1);
            break;
        }
    }

    snprintf(str_reg_domain, 4, "%s%s", tmp_country_str, tmp_environment);
    if (strlen(str_reg_domain) == 0) {
        wifi_util_error_print(WIFI_DMCLI,"%s Invalid Country code enum:%d\n", __func__, l_country_code);
        return 0;
    }
    return strlen(str_reg_domain) + 1;
}

int get_reg_domain_int_from_string(const char *p_reg_domain, wifi_countrycode_type_t *p_country_code,
    wifi_operating_env_t *p_oper_env)
{
    int ret = RETURN_ERR;
    DM_CHECK_NULL_WITH_RC(p_reg_domain, ret);
    DM_CHECK_NULL_WITH_RC(p_country_code, ret);
    DM_CHECK_NULL_WITH_RC(p_oper_env, ret);

    uint32_t index = 0;
    bool str_found = false;
    char tmp_reg_domain_str[REG_DOMAIN_SZ+1];
    char environment[ENV_SZ+1] = {'I', '\0'};
    unsigned int len = 0;

    len = strlen(p_reg_domain);
    if ((len > REG_DOMAIN_SZ) || (len < ENV_SZ)) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Invalid country code \n", __func__, __LINE__);
        return ret;
    }

    memset(tmp_reg_domain_str, 0, sizeof(tmp_reg_domain_str));
    strncpy(tmp_reg_domain_str, p_reg_domain, sizeof(tmp_reg_domain_str)-1);
    environment[0] = tmp_reg_domain_str[REG_DOMAIN_SZ-1];
    if (environment[0] == '\0') {
        environment[0] = ' ';
    } else if(environment[0] != 'I' && environment[0] != 'O' && environment[0] != ' ' && environment[0] != 'X') {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Invalid environment \n", __func__, __LINE__);
        return ret;
    }

    tmp_reg_domain_str[REG_DOMAIN_SZ-1] = '\0';

    for (index = 0; index < (uint32_t)ARRAY_SZ(wifiCountryMapMembers); index++) {
        if (STR_CMP(tmp_reg_domain_str, wifiCountryMapMembers[index].countryStr)) {
            *p_country_code = wifiCountryMapMembers[index].countryCode;
            wifi_util_info_print(WIFI_DMCLI,"%s input:%s Countrycode:%d\n", __func__, p_reg_domain, *p_country_code);
            str_found = true;
            break;
        }
    }

    for (index = 0; index < (uint32_t)ARRAY_SZ(wifiEnviromentMap); index++) {
        if (STR_CMP(environment, wifiEnviromentMap[index].environment)) {
            *p_oper_env = wifiEnviromentMap[index].operatingEnvironment;
            wifi_util_info_print(WIFI_DMCLI,"%s input:%s OperatingEnvironment:%d\n", __func__, p_reg_domain, *p_oper_env);
            str_found = true;
            break;
        }
    }

    if (str_found == false) {
        wifi_util_error_print(WIFI_DMCLI,"%s Invalid Regulatory Domain:%s\n", __func__, p_reg_domain);
        return ret;
    }

    return RETURN_OK;
}

int get_wifi_data_tx_rate_int_from_string(const char *p_tx_rate_name, wifi_bitrate_t *p_tx_rate)
{
    int      ret            = RETURN_ERR;
    uint32_t index          = 0;
    char *token;
    bool is_rate_invalid    = true;
    char tmp_input_str[64] = {0};
    DM_CHECK_NULL_WITH_RC(p_tx_rate_name, ret);
    DM_CHECK_NULL_WITH_RC(p_tx_rate, ret);

    wifi_data_tx_rate_hal_map_t wifi_data_tx_rate[] = {
        { WIFI_BITRATE_DEFAULT, "Default" },
        { WIFI_BITRATE_1MBPS,   "1" },
        { WIFI_BITRATE_2MBPS,   "2" },
        { WIFI_BITRATE_5_5MBPS, "5.5" },
        { WIFI_BITRATE_6MBPS,   "6" },
        { WIFI_BITRATE_9MBPS,   "9" },
        { WIFI_BITRATE_11MBPS,  "11" },
        { WIFI_BITRATE_12MBPS,  "12" },
        { WIFI_BITRATE_18MBPS,  "18" },
        { WIFI_BITRATE_24MBPS,  "24" },
        { WIFI_BITRATE_36MBPS,  "36" },
        { WIFI_BITRATE_48MBPS,  "48" },
        { WIFI_BITRATE_54MBPS,  "54" }
    };

    snprintf(tmp_input_str, sizeof(tmp_input_str), "%s", p_tx_rate_name);
    token = strtok(tmp_input_str, ",");
    while (token != NULL) {
        is_rate_invalid = true;
        for (index = 0; index < (uint32_t)ARRAY_SZ(wifi_data_tx_rate); index++) {
            if (STR_CMP(token, wifi_data_tx_rate[index].str_data_tx_rate)) {
                *p_tx_rate |= wifi_data_tx_rate[index].hal_data_tx_rate;
                is_rate_invalid = false;
            }
        }

        if (is_rate_invalid == true) {
            wifi_util_info_print(WIFI_DMCLI,"%s Invalid txrate Token : %s\n", __func__, token);
            return ret;
        }

        token = strtok(NULL, ",");
    }

    return RETURN_OK;
}

uint32_t get_wifi_data_tx_rate_string_from_int(wifi_bitrate_t l_tx_rate, char *p_tx_rate_name)
{
    DM_CHECK_NULL_WITH_RC(p_tx_rate_name, 0);

    uint32_t index;
    bool     str_found = false;
    wifi_data_tx_rate_hal_map_t wifi_data_tx_rate[] = {
        { WIFI_BITRATE_DEFAULT, "Default" },
        { WIFI_BITRATE_1MBPS,   "1" },
        { WIFI_BITRATE_2MBPS,   "2" },
        { WIFI_BITRATE_5_5MBPS, "5.5" },
        { WIFI_BITRATE_6MBPS,   "6" },
        { WIFI_BITRATE_9MBPS,   "9" },
        { WIFI_BITRATE_11MBPS,  "11" },
        { WIFI_BITRATE_12MBPS,  "12" },
        { WIFI_BITRATE_18MBPS,  "18" },
        { WIFI_BITRATE_24MBPS,  "24" },
        { WIFI_BITRATE_36MBPS,  "36" },
        { WIFI_BITRATE_48MBPS,  "48" },
        { WIFI_BITRATE_54MBPS,  "54" }
    };

    for (index = 0 ; index < (uint32_t)ARRAY_SZ(wifi_data_tx_rate) ; index++) {
        if(l_tx_rate & wifi_data_tx_rate[index].hal_data_tx_rate) {
            if (str_found == false) {
                STR_COPY(p_tx_rate_name, wifi_data_tx_rate[index].str_data_tx_rate);
	    } else {
                STR_CAT(p_tx_rate_name, ",");
                STR_CAT(p_tx_rate_name, wifi_data_tx_rate[index].str_data_tx_rate);
            }
            str_found = true;
        }
    }

    if(str_found == false) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Invalid data tx rate:%d\n",__func__, __LINE__, l_tx_rate);
    } else {
        return strlen(p_tx_rate_name) + 1;
    }

    return 0;
}

uint32_t get_beacon_rate_string_from_int(wifi_bitrate_t beacon_type, char *beacon_name)
{
    uint32_t index  = 0;
    wifi_data_tx_rate_hal_map_t wifi_data_tx_rate[] = {
        { WIFI_BITRATE_DEFAULT, "Default" },
        { WIFI_BITRATE_1MBPS,   "1" },
        { WIFI_BITRATE_2MBPS,   "2" },
        { WIFI_BITRATE_5_5MBPS, "5.5" },
        { WIFI_BITRATE_6MBPS,   "6" },
        { WIFI_BITRATE_9MBPS,   "9" },
        { WIFI_BITRATE_11MBPS,  "11" },
        { WIFI_BITRATE_12MBPS,  "12" },
        { WIFI_BITRATE_18MBPS,  "18" },
        { WIFI_BITRATE_24MBPS,  "24" },
        { WIFI_BITRATE_36MBPS,  "36" },
        { WIFI_BITRATE_48MBPS,  "48" },
        { WIFI_BITRATE_54MBPS,  "54" }
    };
    DM_CHECK_NULL_WITH_RC(beacon_name, 0);

    for (index = 0; index < (uint32_t)ARRAY_SZ(wifi_data_tx_rate); index++) {
        if (beacon_type == wifi_data_tx_rate[index].hal_data_tx_rate) {
            char buff[16] = { 0 };
            snprintf(buff, sizeof(buff), "%sMbps", wifi_data_tx_rate[index].str_data_tx_rate);
            STR_COPY(beacon_name, buff);
            return strlen(beacon_name) + 1;
        }
    }

    return 0;
}

int get_beacon_rate_int_from_string(const char *beacon_name, wifi_bitrate_t *beacon_type)
{
    int ret = RETURN_ERR;
    wifi_data_tx_rate_hal_map_t wifi_data_tx_rate[] = {
        { WIFI_BITRATE_DEFAULT, "Default" },
        { WIFI_BITRATE_1MBPS,   "1" },
        { WIFI_BITRATE_2MBPS,   "2" },
        { WIFI_BITRATE_5_5MBPS, "5.5" },
        { WIFI_BITRATE_6MBPS,   "6" },
        { WIFI_BITRATE_9MBPS,   "9" },
        { WIFI_BITRATE_11MBPS,  "11" },
        { WIFI_BITRATE_12MBPS,  "12" },
        { WIFI_BITRATE_18MBPS,  "18" },
        { WIFI_BITRATE_24MBPS,  "24" },
        { WIFI_BITRATE_36MBPS,  "36" },
        { WIFI_BITRATE_48MBPS,  "48" },
        { WIFI_BITRATE_54MBPS,  "54" }
    };

    DM_CHECK_NULL_WITH_RC(beacon_name, ret);
    DM_CHECK_NULL_WITH_RC(beacon_type, ret);
    char temp_beacon_name[16] = { 0 };

    snprintf(temp_beacon_name, sizeof(temp_beacon_name), "%s", beacon_name);
    char * token = strtok(temp_beacon_name, "Mbps");
    DM_CHECK_NULL_WITH_RC(token, ret);

    for (uint32_t index = 0 ; index < (uint32_t)ARRAY_SZ(wifi_data_tx_rate); ++index) {
        if(STR_CMP(token, wifi_data_tx_rate[index].str_data_tx_rate)) {
            *beacon_type = wifi_data_tx_rate[index].hal_data_tx_rate;
            return RETURN_OK;
        }
    }

    return ret;
}

bool is_valid_transmit_rate(char *input_str)
{
    bool is_valid = false;

    DM_CHECK_NULL_WITH_RC(input_str, is_valid);

    int i = 0;
    int len;
    len = strlen(input_str);
    for(i = 0; i < len; i++) {
        if(isdigit(input_str[i]) || input_str[i]==',' || input_str[i]=='.') {
            is_valid = true;
        } else {
            is_valid = false;
            break;
        }
    }

    return is_valid;
}

int read_remote_ip(char *s_ip, int size,char *s_name)
{
    FILE *fp1;
    char buf[1024] = {0};
    char *url_ptr = NULL;
    int ret = RETURN_ERR;

    // Grab the ARM or ATOM RPC IP address

    fp1 = fopen("/etc/device.properties", "r");
    if (fp1 == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d:Error opening properties file!\n",__func__, __LINE__);
        return RETURN_ERR;
    }

    while (fgets(buf, 1024, fp1) != NULL) {
        // Look for ARM_ARPING_IP or ATOM_ARPING_IP
        if (strstr(buf, s_name) != NULL) {
            buf[strcspn(buf, "\r\n")] = 0; // Strip off any carriage returns

            // grab URL from string
            url_ptr = strstr(buf, "=");
            url_ptr++;
            strncpy(s_ip, url_ptr, size);
            ret = RETURN_OK;
            break;
        }
    }

    fclose(fp1);
    return ret;
}

int enable_wifi_telnet(bool enabled)
{
    int ret = RETURN_ERR;

    if (enabled) {
        // Attempt to start the telnet daemon on ATOM
        char np_remote_ip[128]="";

        read_remote_ip(np_remote_ip, 128,"ATOM_ARPING_IP");
        if (np_remote_ip[0] != 0 && strlen(np_remote_ip) > 0) {
            if (get_stubs_descriptor()->v_secure_system_fn("/usr/sbin/telnetd -b %s") != 0) {
                return ret;
            }
        }
    } else {
        // Attempt to kill the telnet daemon on ATOM
        if (get_stubs_descriptor()->v_secure_system_fn("pkill telnetd") != 0 ) {
            return ret;
        }
    }

    return RETURN_OK;
}

int dm_wifi_set_webconfig(char *webconfstr, uint32_t size)
{
    push_event_to_ctrl_queue(webconfstr, size, wifi_event_type_webconfig, wifi_event_webconfig_set_data_webconfig, NULL);

    return RETURN_OK;
}

uint32_t get_total_dbg_log_enable_str_value(char *p_output_str)
{
    const char *exist_dbg_log_str[] = {
        "wifiDbDbg",
        "wifiMgrDbg",
        "wifiWebConfigDbg",
        "wifiCtrlDbg",
        "wifiPasspointDbg",
        "wifiDppDbg",
        "wifiMonDbg",
        "wifiDMCLI",
        "wifiLib",
        "wifiPsm",
        "wifiLibhostapDbg",
        "wifiHalDbg"
    };
    uint32_t index;
    bool     str_found = false;
    size_t   num_strings = (size_t)ARRAY_SZ(exist_dbg_log_str);
    char     temp_buff[32];

    for (index = 0 ; index < num_strings; index++) {
        memset(temp_buff, 0, sizeof(temp_buff));

        snprintf(temp_buff, sizeof(temp_buff), "/nvram/%s", exist_dbg_log_str[index]);
        if(access(temp_buff, F_OK) == 0) {
            if (str_found == false) {
                STR_COPY(p_output_str, exist_dbg_log_str[index]);
            } else {
                STR_CAT(p_output_str, ",");
                STR_CAT(p_output_str, exist_dbg_log_str[index]);
            }
            str_found = true;
        }
    }

    if(str_found == false) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Dbg logs are not enabled\n",__func__, __LINE__);
    } else {
        return strlen(p_output_str) + 1;
    }

    return 0;
}

int disable_dbg_logs(char *p_input_str)
{
    const char *exist_dbg_log_str[] = {
        "wifiDbDbg",
        "wifiMgrDbg",
        "wifiWebConfigDbg",
        "wifiCtrlDbg",
        "wifiPasspointDbg",
        "wifiDppDbg",
        "wifiMonDbg",
        "wifiDMCLI",
        "wifiLib",
        "wifiPsm",
        "wifiLibhostapDbg",
        "wifiHalDbg"
    };
    uint32_t index = 0;
    bool     is_invalid_input = true;
    char     *token;
    char     tmp_input_string[256] = {0};
    char     temp_dbg_log_name[32];
    size_t   num_strings = (size_t)ARRAY_SZ(exist_dbg_log_str);

    if ((p_input_str == NULL) || (strlen(p_input_str) == 0)) {
        wifi_util_error_print(WIFI_DMCLI,"%s input string is not valid\n", __func__);
        return RETURN_ERR;
    }

    snprintf(tmp_input_string, sizeof(tmp_input_string), "%s", p_input_str);

    //validate input string
    token = strtok(tmp_input_string, ",");
    while (token != NULL) {
        is_invalid_input = true;
        for (index = 0; index < num_strings; index++) {
            if (STR_CMP(token, exist_dbg_log_str[index])) {
                wifi_util_dbg_print(WIFI_DMCLI,"%s dbg log name found:%s\n", __func__,
                    exist_dbg_log_str[index]);
                is_invalid_input = false;
            }
        }

        if (is_invalid_input == true) {
            wifi_util_error_print(WIFI_DMCLI,"%s Invalid Wifi Standard:%s\n", __func__, p_input_str);
            return RETURN_ERR;
        }

        token = strtok(NULL, ",");
    }

    snprintf(tmp_input_string, sizeof(tmp_input_string), "%s", p_input_str);
    token = strtok(tmp_input_string, ",");
    while (token != NULL) {
        for (index = 0; index < num_strings; index++) {
            if (STR_CMP(token, exist_dbg_log_str[index])) {
                memset(temp_dbg_log_name, 0, sizeof(temp_dbg_log_name));

                snprintf(temp_dbg_log_name, sizeof(temp_dbg_log_name), "/nvram/%s", exist_dbg_log_str[index]);
                remove(temp_dbg_log_name);
                wifi_util_info_print(WIFI_DMCLI,"%s removed dbg log:%s\n", __func__,
                    temp_dbg_log_name);
            }
        }

        token = strtok(NULL, ",");
    }

    return RETURN_OK;
}

bool is_valid_mac_address(char *mac)
{
    int iter = 0, len = 0;

    len = strlen(mac);
    if (len != MAX_STR_MAC_ADDR_LEN) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d MACAddress:%s:%d is not valid!!!\n", __func__, __LINE__, mac, len);
        return false;
    }
    if (mac[2] == ':' && mac[5] == ':' && mac[8] == ':' && mac[11] == ':' && mac[14] == ':') {
        for (iter = 0; iter < MAX_STR_MAC_ADDR_LEN; iter++) {
            if((iter == 2 || iter == 5 || iter == 8 || iter == 11 || iter == 14)) {
                continue;
            } else if ((mac[iter] > 47 && mac[iter] <= 57) ||
                (mac[iter] > 64 && mac[iter] < 71) ||
                (mac[iter] > 96 && mac[iter] < 103)) {
                continue;
            } else {
                wifi_util_error_print(WIFI_DMCLI,"(%s), MACAdress:%s is not valid:%d\n", __func__, mac, iter);
                return false;
            }
        }
    } else {
        wifi_util_error_print(WIFI_DMCLI,"(%s), MACAdress:%s is not valid\n", __func__, mac);
        return false;
    }

    return true;
}

assoc_dev_data_t *get_sta_assoc_data_map(uint32_t ap_index, uint32_t sta_index)
{
    wifi_vap_info_t *vap_param;
    assoc_dev_data_t *p_assoc_sta_entry;
    hash_map_t *p_assoc_sta_map;

    vap_param = (wifi_vap_info_t *)getVapInfo(ap_index - 1);
    if (vap_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d vap map not found for:[%d]\r\n", __func__,
            __LINE__, ap_index);
        return NULL;
    }

    pthread_mutex_lock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
    //Will be returning the entire stats structure later just returning mac address as of now
    p_assoc_sta_map = (hash_map_t *)get_associated_devices_hash_map(vap_param->vap_index);
    if (p_assoc_sta_map == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d assoc sta is NULL pointer:%d\n", __func__, __LINE__, vap_param->vap_index);
        pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
        return NULL;
    }

    hash_element_t *hash_ele_queue_data = (hash_element_t *)queue_peek(p_assoc_sta_map->queue, sta_index - 1);
    if (hash_ele_queue_data == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d wrong assoc sta entry index:%d\r\n", __func__, __LINE__, sta_index);
        return NULL;
    }
    p_assoc_sta_entry = (assoc_dev_data_t *)hash_ele_queue_data->data;
    pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);

    return p_assoc_sta_entry;
}

int init_dm_params(void)
{
    webconfig_dml_t *webconfig_dml;

    webconfig_dml = (webconfig_dml_t *)get_webconfig_dml();
    if(webconfig_dml == NULL){
        wifi_util_error_print(WIFI_DMCLI, "%s: get_webconfig_dml return NULLL pointer\n", __func__);
        return RETURN_ERR;
    }

    if (init(webconfig_dml) != 0) {
        wifi_util_error_print(WIFI_DMCLI, "%s: Failed to init\n", __func__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int detach_onewifi_main_process(void)
{
    FILE *fd        = NULL;
    char cmd[1024]  = {0};
    fd = fopen("/var/tmp/OneWifi.pid", "w+");
    if ( !fd )
    {
        wifi_util_error_print(WIFI_DMCLI, "Create /var/tmp/OneWifi.pid error. \n");
        return RETURN_ERR;
    }
    else
    {
        sprintf(cmd, "%d", getpid());
        fputs(cmd, fd);
        fclose(fd);
    }
    breakpad_ExceptionHandler();
    /* Inform Webconfig framework if component is coming after crash */
    check_component_crash("/tmp/wifi_initialized");
    /* For some reason, touching the file via system command was not working consistently.
     * We'll fopen the file and dump in a value */
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: Checking wifi_initialized!\n", __func__, __LINE__);
    if ((fd = fopen ("/tmp/wifi_initialized", "w+")) != NULL) {
        fprintf(fd,"1");
        fclose(fd);
    }

    wifi_util_info_print(WIFI_DMCLI,"%s:%d: Semaphore post:%p\n", __func__, __LINE__, sem);
    sem_post(sem);
    sem_close(sem);

    return RETURN_OK;
}

int start_dml_main(void *arg)
{
    int ret;
    wifi_ctrl_t *ctrl =  NULL;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    decode_json_obj(&ctrl->handle, BUS_DML_CONFIG_FILE);
    print_registered_elems(get_bus_mux_reg_cb_map(), 0);

    get_wifidb_obj()->desc.init_data_fn();
    /* Set Wifi Global Parameters */
    init_wifi_global_config();

    init_dm_params();
    ret = detach_onewifi_main_process();
    get_wifidml_obj()->desc.set_dml_init_status_fn(true);

    return ret;
}

int ssp_loop_init(void)
{
    return RETURN_OK;
}

uint32_t get_wifi_wps_method_string_from_int(wifi_onboarding_methods_t l_wps_method, char *p_wps_method_name)
{
    DM_CHECK_NULL_WITH_RC(p_wps_method_name, 0);

    uint32_t index;
    bool     str_found = false;
    wifi_wps_method_hal_map_t wps_method_map[] = {
        { WIFI_ONBOARDINGMETHODS_USBFLASHDRIVE,  "USBFlashDrive" },
        { WIFI_ONBOARDINGMETHODS_ETHERNET,  "Ethernet" },
        { WIFI_ONBOARDINGMETHODS_EXTERNALNFCTOKEN,  "ExternalNFCToken" },
        { WIFI_ONBOARDINGMETHODS_INTEGRATEDNFCTOKEN,  "IntegratedNFCToken" },
        { WIFI_ONBOARDINGMETHODS_NFCINTERFACE,  "NFCInterface" },
        { WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "PushButton" },
        { WIFI_ONBOARDINGMETHODS_PIN, "PIN" }
    };

    for (index = 0 ; index < (uint32_t)ARRAY_SZ(wps_method_map) ; index++) {
        if (l_wps_method & wps_method_map[index].hal_wifi_wps_method)
        {
            if (str_found == false) {
                STR_COPY(p_wps_method_name, wps_method_map[index].str_wifi_wps_method);
            } else {
                STR_CAT(p_wps_method_name, ",");
                STR_CAT(p_wps_method_name, wps_method_map[index].str_wifi_wps_method);
            }
            str_found = true;
        }
    }

    if(str_found == false) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Invalid wifi wps method:%d enum\n",__func__, __LINE__, l_wps_method);
    } else {
        return strlen(p_wps_method_name) + 1;
    }

    return 0;
}

int get_wifi_wps_method_int_from_string(const char *p_wps_method_name, wifi_onboarding_methods_t *p_wps_method)
{
    int ret = RETURN_ERR;
    DM_CHECK_NULL_WITH_RC(p_wps_method_name, ret);
    DM_CHECK_NULL_WITH_RC(p_wps_method, ret);

    wifi_wps_method_hal_map_t wps_method_map[] = {
        { WIFI_ONBOARDINGMETHODS_USBFLASHDRIVE,  "USBFlashDrive" },
        { WIFI_ONBOARDINGMETHODS_ETHERNET,  "Ethernet" },
        { WIFI_ONBOARDINGMETHODS_EXTERNALNFCTOKEN,  "ExternalNFCToken" },
        { WIFI_ONBOARDINGMETHODS_INTEGRATEDNFCTOKEN,  "IntegratedNFCToken" },
        { WIFI_ONBOARDINGMETHODS_NFCINTERFACE,  "NFCInterface" },
        { WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "PushButton" },
        { WIFI_ONBOARDINGMETHODS_PIN, "PIN" }
    };

    uint32_t index = 0;
    bool is_wps_method_invalid = true;
    char *token;
    char tmp_input_string[128] = {0};

    *p_wps_method = 0;
    snprintf(tmp_input_string, sizeof(tmp_input_string), "%s", p_wps_method_name);

    token = strtok(tmp_input_string, ",");
    while (token != NULL) {
        is_wps_method_invalid = true;
        for (index = 0; index < (uint32_t)ARRAY_SZ(wps_method_map); index++) {
            if (STR_CMP(token, wps_method_map[index].str_wifi_wps_method)) {
                *p_wps_method |= wps_method_map[index].hal_wifi_wps_method;
                wifi_util_dbg_print(WIFI_DMCLI,"%s input:%s wps_method:%d\n", __func__,
                    p_wps_method_name, *p_wps_method);
                is_wps_method_invalid = false;
            }
        }

        if (is_wps_method_invalid == true) {
            wifi_util_error_print(WIFI_DMCLI,"%s Invalid Wifi Standard:%s\n", __func__, p_wps_method_name);
            return ret;
        }

        token = strtok(NULL, ",");
    }
    return RETURN_OK;
}

bool validate_def_reporting_period_value(unsigned long period)
{
    uint32_t index;
    unsigned long inst_client_reproting_periods[] = { 0,1,5,15,30,60,300,900,1800,3600,10800,21600,43200,86400 };

    for (index=0; index < (uint32_t)(ARRAY_SZ(inst_client_reproting_periods)); index++) {
        if (inst_client_reproting_periods[index] == period)
            return true;
    }
    return false;
}

bool validate_inst_client_mac_value(char * phys_address)
{

    wifi_util_dbg_print(WIFI_DMCLI,"%s-%d mac is ***%s***\n", __func__, __LINE__, phys_address);
    if (phys_address && phys_address[0]) {
        if (strlen(phys_address) != MIN_STR_MAC_ADDR_LEN) {
            wifi_util_error_print(WIFI_DMCLI,"%s-%d mac:%s length is not 12\n", __func__, __LINE__, phys_address);
            return false;
        }

        if (STR_CMP(phys_address, "000000000000")) {
            wifi_util_error_print(WIFI_DMCLI, "%s-%d mac is all 0\n", __func__, __LINE__);
            return false;
        }

        return true;
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s-%d mac is NULL\n",__func__, __LINE__);
    }
    return false;
}

int is_sec_mode_open_for_private_ap(uint32_t vap_index)
{
    wifi_radio_operationParam_t *p_radio_oper_param = NULL;
    wifi_vap_info_t *p_vap_info = NULL;
    wifi_util_dbg_print(WIFI_DMCLI,"%s for vap_index:%d\n", __func__, vap_index);

    //Check is the Vap is private
    if(isVapPrivate(vap_index) != true) {
        wifi_util_error_print(WIFI_DMCLI,"%s vap_index %d is not private VAP\n", __func__, vap_index);
        return RETURN_ERR;
    }

    p_vap_info = getVapInfo(vap_index);
    if (p_vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s Unable to get VAP info for vap_index : %d\n", __func__, vap_index);
        return RETURN_ERR;
    }

    p_radio_oper_param = getRadioOperationParam(p_vap_info->radio_index);
    if (p_radio_oper_param == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s Input radioIndex = %d not found for radio_oper_param\n", __func__,
            p_vap_info->radio_index);
        return RETURN_ERR;
    }

    //Check for 6Ghz
    if ((p_radio_oper_param->band == WIFI_FREQUENCY_6_BAND)) {
        wifi_util_error_print(WIFI_DMCLI,"%s Input radioIndex = %d with 6G Band doesnot support WPS:%d\n", __func__,
            p_vap_info->radio_index, p_vap_info->u.bss_info.security.mode);
        return RETURN_ERR;
    }

    //Check for open security
    if (p_vap_info->u.bss_info.security.mode == wifi_security_mode_none) {
        wifi_util_error_print(WIFI_DMCLI,"%s Open Security for vap_index : %d, WPS doesnot support \n", __func__,
            vap_index);
        return RETURN_ERR;
    }

    if ((p_vap_info->u.bss_info.security.mode == wifi_security_mode_wpa3_personal) ||
        (p_vap_info->u.bss_info.security.mode == wifi_security_mode_wpa3_enterprise)) {
        wifi_util_error_print(WIFI_DMCLI,"%s Input radioIndex = %d WPS doesnot support WPA3 Mode:%d\n", __func__,
            p_vap_info->radio_index, p_vap_info->u.bss_info.security.mode);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int max_macfilter_number_of_entries(wifi_vap_info_t *vap_param, uint32_t *p_max_macfilter_entries)
{
    int status = RETURN_ERR;
    uint32_t count = 0;

    DM_CHECK_NULL_WITH_RC(vap_param, status);
    DM_CHECK_NULL_WITH_RC(p_max_macfilter_entries, status);
    *p_max_macfilter_entries = 0;

    hash_map_t** acl_device_map = (hash_map_t **)get_acl_hash_map(vap_param);
    queue_t** acl_new_entry_queue = (queue_t **)get_acl_new_entry_queue(vap_param);

    if ((acl_device_map != NULL) && (*acl_device_map != NULL)) {
        count  = hash_map_count(*acl_device_map);
    }

    if ((acl_new_entry_queue != NULL) && (*acl_new_entry_queue != NULL)) {
        count = count + queue_count(*acl_new_entry_queue);
    } else {
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d ERROR NULL queue Pointer \n",__func__, __LINE__);
    }

    *p_max_macfilter_entries = count;

    return RETURN_OK;
}

acl_entry_t *get_macfilter_entry(wifi_vap_info_t *vap_info, uint32_t acl_entry_index)
{
    uint32_t count_hash = 0, count_queue = 0;
    acl_entry_t *acl_entry = NULL;

    DM_CHECK_NULL_WITH_RC(vap_info, NULL);

    if (vap_info->vap_index > MAX_VAP) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d vap_index:%d is out of range\n",__func__,
            __LINE__, vap_info->vap_index);
        return NULL;
    }

    hash_map_t **acl_device_map = (hash_map_t **)get_acl_hash_map(vap_info);
    queue_t **acl_new_entry_queue = (queue_t **)get_acl_new_entry_queue(vap_info);
    if (*acl_new_entry_queue == NULL) {
        *acl_new_entry_queue = queue_create();
    }

    if (*acl_device_map != NULL) {
        count_hash = hash_map_count(*acl_device_map);
    }

    if (*acl_new_entry_queue != NULL) {
        count_queue  = queue_count(*acl_new_entry_queue);
    }

    if (acl_entry_index > (count_hash + count_queue)) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Wrong acl_entry_index\n",__func__, __LINE__);
        return NULL;
    }

    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d vap_index:%d acl_entry_index:%d"
        " count_hash:%d count_queue:%d\n",__func__, __LINE__, vap_info->vap_index,
        acl_entry_index, count_hash, count_queue);
    if ((*acl_device_map != NULL) && (acl_entry_index < count_hash)) {
        uint32_t index = 0;

        acl_entry = hash_map_get_first(*acl_device_map);
        for (index = 0; (index < acl_entry_index) && (acl_entry != NULL); index++) {
            acl_entry = hash_map_get_next(*acl_device_map,acl_entry);
        }
    } else if (*acl_new_entry_queue != NULL) {
        acl_entry = (acl_entry_t *) queue_peek(*acl_new_entry_queue, (acl_entry_index - count_hash));
    }

    return acl_entry;
}

static int sync_bus_macfilter_table_vap_entries(bus_handle_t *handle, wifi_vap_info_t *vap_param)
{
    uint32_t max_acl_cnt = 0;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();

    max_macfilter_number_of_entries(vap_param, &max_acl_cnt);

    wifi_util_info_print(WIFI_DMCLI,"%s:%d max macfilter cnt:%d for vap:%d, dml table_cnt:%d\n", __func__,
        __LINE__, max_acl_cnt, vap_param->vap_index,
        p_dml_param->table_macfilter_index[vap_param->vap_index]);
    if (p_dml_param->table_macfilter_index[vap_param->vap_index] != max_acl_cnt) {
        char buff[64] = { 0 };
        char row_rem_buff[64] = { 0 };
        wifi_bus_desc_t *p_bus_desc = get_bus_descriptor();
        uint32_t index = 0;

        snprintf(buff, sizeof(buff), "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MacFilterTable.", vap_param->vap_index + 1);
        if (p_dml_param->table_macfilter_index[vap_param->vap_index] < max_acl_cnt) {
            index = p_dml_param->table_macfilter_index[vap_param->vap_index] + 1;
            while(index <= max_acl_cnt) {
                if (p_bus_desc->bus_reg_table_row_fn(handle, buff, index, NULL) != bus_error_success) {
                    wifi_util_error_print(WIFI_DMCLI,"%s:%d macfilter table_reg row:%s failed for index:%d\n",
                        __func__, __LINE__, buff, index);
                } else {
                    p_dml_param->table_macfilter_index[vap_param->vap_index]++;
                }
                index++;
            }
        } else {
            index = p_dml_param->table_macfilter_index[vap_param->vap_index];
            while (index > max_acl_cnt) {
                snprintf(row_rem_buff, sizeof(row_rem_buff), "%s%d", buff, index);
                if (p_bus_desc->bus_remove_table_row_fn(handle, row_rem_buff) != bus_error_success) {
                    wifi_util_error_print(WIFI_DMCLI,"%s:%d macfilter table remove row:%s failed\n",
                        __func__, __LINE__, row_rem_buff);
                }
                index--;
            }
        }
    }

    return RETURN_OK;
}

int sync_dml_macfilter_table_entries(void)
{
    uint32_t r_index = 0, v_index = 0;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_vap_info_map_t *vap_map;
    static bool sync_started = false;

    if (sync_started == true) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d sync_dml_macfilter is already started\n",
                        __func__, __LINE__);
        return RETURN_ERR;
    } else {
        sync_started = true;
    }
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    for (r_index = 0; r_index < get_num_radio_dml(); r_index++) {
        vap_map = get_dml_cache_vap_map(r_index);
        for (v_index = 0; v_index < get_max_num_vaps_per_radio_dml(r_index); v_index++) {
            sync_bus_macfilter_table_vap_entries(&ctrl->handle, &vap_map->vap_array[v_index]);
        }
    }

    sync_started = false;
    return RETURN_OK;
}

static int sync_dml_macfilter_index(void *arg)
{
    table_index_timer_arg_t *input_arg = (table_index_timer_arg_t *)arg;
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();
    uint32_t *cur_macfilter_index = &p_dml_param->table_macfilter_index[input_arg->vap_index];
    int vap_index = 0, macfilter_entry_index = 0;
    char new_row_name[64] = { 0 };
    wifi_bus_desc_t *p_bus_desc = get_bus_descriptor();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    sscanf(input_arg->table_row, "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MacFilterTable.%d", &vap_index, &macfilter_entry_index);
    snprintf(input_arg->table_row, sizeof(input_arg->table_row), "Device.WiFi.AccessPoint.%d.X_CISCO_COM_MacFilterTable.", vap_index);
    snprintf(new_row_name, sizeof(new_row_name), "%s%d", input_arg->table_row, *cur_macfilter_index);

    wifi_util_info_print(WIFI_DMCLI,"%s:%d table add:%s = remove:%s for vap:%d remove index:%d add back index:%d \n",
        __func__, __LINE__, input_arg->table_row, new_row_name, input_arg->vap_index, *cur_macfilter_index, macfilter_entry_index);

    if (p_bus_desc->bus_reg_table_row_fn(&ctrl->handle, input_arg->table_row, macfilter_entry_index, NULL) != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d table_reg row:%s failed for index:%d\n",
            __func__, __LINE__, input_arg->table_row, macfilter_entry_index);
    } else {
        if (p_bus_desc->bus_unreg_table_row_fn(&ctrl->handle, new_row_name) != bus_error_success) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d table remove row:%s failed\n",
                __func__, __LINE__, new_row_name);
        } else {
            (*cur_macfilter_index)--;
        }
    }

    if (input_arg != NULL) {
        free(input_arg);
    }

    return TIMER_TASK_COMPLETE;
}

int sync_dml_macfilter_table(uint32_t vap_index, char *table_row_name)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    table_index_timer_arg_t *input_arg = malloc(sizeof(table_index_timer_arg_t));

    DM_CHECK_NULL_WITH_RC(input_arg, RETURN_ERR);
    DM_CHECK_NULL_WITH_RC(table_row_name, RETURN_ERR);

    input_arg->vap_index = vap_index;
    strcpy(input_arg->table_row, table_row_name);

    wifi_util_info_print(WIFI_DMCLI,"%s:%d macfilter table:%s sync start for vap:%d\n",
        __func__, __LINE__, table_row_name, vap_index);
    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, sync_dml_macfilter_index,
        input_arg, (MACFILTER_TABLE_SYNC_TIME_IN_SEC * 1000), 1, FALSE);

    return RETURN_OK;
}

static int sync_bus_sta_assoc_table_vap_entries(bus_handle_t *handle, uint32_t vap_index, uint32_t max_sta_count)
{
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();

    wifi_util_info_print(WIFI_DMCLI,"%s:%d max sta assoc cnt:%d for vap:%d, dml table_cnt:%d\n", __func__,
        __LINE__, max_sta_count, vap_index,
        p_dml_param->table_sta_assoc_index[vap_index]);
    if (p_dml_param->table_sta_assoc_index[vap_index] != max_sta_count) {
        char buff[64] = { 0 };
        char row_rem_buff[64] = { 0 };
        wifi_bus_desc_t *p_bus_desc = get_bus_descriptor();
        uint32_t index = 0;

        snprintf(buff, sizeof(buff), "Device.WiFi.AccessPoint.%d.AssociatedDevice.", vap_index + 1);
        if (p_dml_param->table_sta_assoc_index[vap_index] < max_sta_count) {
            index = p_dml_param->table_sta_assoc_index[vap_index] + 1;
            while(index <= max_sta_count) {
                if (p_bus_desc->bus_reg_table_row_fn(handle, buff, index, NULL) != bus_error_success) {
                    wifi_util_error_print(WIFI_DMCLI,"%s:%d sta assoc table_reg row:%s failed for index:%d\n",
                        __func__, __LINE__, buff, index);
                } else {
                    p_dml_param->table_sta_assoc_index[vap_index]++;
                }
                index++;
            }
        } else {
            index = p_dml_param->table_sta_assoc_index[vap_index];
            while (index > max_sta_count) {
                snprintf(row_rem_buff, sizeof(row_rem_buff), "%s%d", buff, index);
                if (p_bus_desc->bus_unreg_table_row_fn(handle, row_rem_buff) != bus_error_success) {
                    wifi_util_error_print(WIFI_DMCLI,"%s:%d sta assoc table remove row:%s failed\n",
                        __func__, __LINE__, row_rem_buff);
                } else {
                    p_dml_param->table_sta_assoc_index[vap_index]--;
                }
                index--;
            }
        }
    }

    return RETURN_OK;
}

int get_dml_total_associated_devices_count(uint32_t radio_index, uint32_t vap_array_index, uint32_t *count)
{
    int ret = RETURN_ERR;
    if (radio_index < 0 || vap_array_index < 0) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d invalid radio_%d/vap_array_%d index\n", __func__,
            __LINE__, radio_index, vap_array_index);
        return ret;
    }

    pthread_mutex_lock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
    hash_map_t **assoc_dev_hash_map = get_dml_assoc_dev_hash_map(radio_index, vap_array_index);

    if ((assoc_dev_hash_map == NULL) || (*assoc_dev_hash_map == NULL)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s %d No hash_map returning zero\n", __func__, __LINE__);
    } else {
        *count  = (uint32_t)hash_map_count(*assoc_dev_hash_map);
        wifi_util_dbg_print(WIFI_DMCLI,"%s %d returning hash_map count as %d\n", __func__, __LINE__, *count);
        ret = RETURN_OK;
    }
    pthread_mutex_unlock(&((webconfig_dml_t*) get_webconfig_dml())->assoc_dev_lock);
    return ret;
}

int sync_dml_sta_assoc_table_entries(void)
{
    uint32_t r_index = 0, v_index = 0;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    static bool sync_started = false;

    if (sync_started == true) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d sync_dml_macfilter is already started\n",
                        __func__, __LINE__);
        return RETURN_ERR;
    } else {
        sync_started = true;
    }
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    rdk_wifi_radio_t *radio_map;
    uint32_t vap_index = 0;
    uint32_t max_sta_count;

    for (r_index = 0; r_index < get_num_radio_dml(); r_index++) {
        radio_map = get_dml_cache_radio_map_param(r_index);
        for (v_index = 0; v_index < get_max_num_vaps_per_radio_dml(r_index); v_index++) {
            if (get_dml_total_associated_devices_count(r_index, v_index, &max_sta_count) == RETURN_OK) {
                vap_index = radio_map->vaps.rdk_vap_array[v_index].vap_index;
                sync_bus_sta_assoc_table_vap_entries(&ctrl->handle, vap_index, max_sta_count);
            }
        }
    }

    sync_started = false;
    return RETURN_OK;
}

char *getDeviceMac(void)
{
    static char device_mac[MAX_STR_MAC_ADDR_LEN + 1] = { 0 };
#if defined(_COSA_BCM_MIPS_)
#define CPE_MAC_NAMESPACE "Device.DPoE.Mac_address"
#else
#ifdef _SKY_HUB_COMMON_PRODUCT_REQ_
#define CPE_MAC_NAMESPACE "Device.DeviceInfo.X_COMCAST-COM_WAN_MAC"
#else
#define CPE_MAC_NAMESPACE "Device.X_CISCO_COM_CableModem.MACAddress"
#endif
#endif /*_COSA_BCM_MIPS_*/

    if (strlen(device_mac) == 0) {
        wifi_ctrl_t *ctrl;
        ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
        bus_error_t rc = bus_error_success;
        raw_data_t data;
        memset(&data, 0, sizeof(raw_data_t));

        rc = get_bus_descriptor()->bus_data_get_fn(&ctrl->handle, CPE_MAC_NAMESPACE, &data);
        if (rc != bus_error_success || (data.data_type != bus_data_type_string)) {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d bus_data_get_fn failed for [%s]"
                " with error [%d]\n", __func__, __LINE__, CPE_MAC_NAMESPACE, rc);
            get_bus_descriptor()->bus_data_free_fn(&data);
            return NULL;
        }
        strcpy(device_mac, (char *)data.raw_data.bytes);
        wifi_util_info_print(WIFI_DMCLI,"%s:%d device cpe mac[%s]:%d\n", __func__, __LINE__,
            device_mac, data.raw_data_len);
        get_bus_descriptor()->bus_data_free_fn(&data);
    }

    return device_mac;
}

int initparodusTask(void)
{
    return RETURN_OK;
}

void get_cur_time_str(char *str_time, uint32_t str_len)
{
    time_t timer;
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);
    strftime(str_time, str_len, "%Y-%m-%d %H:%M:%S ", tm_info);
}

int get_requestor_string(char *str)
{
    DM_CHECK_NULL_WITH_RC(str, RETURN_ERR);
    strcpy(str, BS_SOURCE_RFC_STR);
    return RETURN_OK;
}

int set_wifi_region_update_source(char *str_input)
{
    DM_CHECK_NULL_WITH_RC(str_input, RETURN_ERR);
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();

    snprintf(p_dml_param->str_wifi_region_update_source,
        sizeof(p_dml_param->str_wifi_region_update_source), "%s", str_input);

    return RETURN_OK;
}

int get_wifi_region_update_source(char *str_output)
{
    DM_CHECK_NULL_WITH_RC(str_output, RETURN_ERR);
    wifi_dml_data_model_t *p_dml_param = get_dml_data_model_param();

    strcpy(str_output, p_dml_param->str_wifi_region_update_source);

    return RETURN_OK;
}

static int write_to_json(char *data, char *file)
{
    FILE *fp;
    fp = fopen(file, "w");
    if (fp == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s : %d Failed to open file %s\n", __func__, __LINE__, file);
        return RETURN_ERR;
    }

    fwrite(data, strlen(data), 1, fp);
    fclose(fp);

    return RETURN_OK;
}

static int update_json_param_legacy(char *p_key, char *partner_id, char *p_value)
{
    cJSON *partner_obj = NULL;
    cJSON *json = NULL;
    FILE *file_read = NULL;
    char *cjson_out = NULL;
    char *data = NULL;
    int len ;
    int config_update_status = -1;

    file_read = fopen(PARTNERS_INFO_FILE, "r");
    if (file_read == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s-%d : Error in opening JSON file\n" , __func__, __LINE__);
        return RETURN_ERR;
    }

    fseek(file_read, 0, SEEK_END);
    len = ftell(file_read);
    if (len < 0) {
        wifi_util_error_print(WIFI_DMCLI,"%s-%d : file_read Negative \n", __func__, __LINE__);
        fclose(file_read);
        return RETURN_ERR;
    }
    fseek(file_read, 0, SEEK_SET);
    data = ( char* )malloc(sizeof(char) * (len + 1));
    if (data != NULL) {
        memset(data, 0, (sizeof(char) * (len + 1)));
        if(1 != fread(data, len, 1, file_read)) {
            fclose(file_read);
            return RETURN_ERR;
        }
        data[len] ='\0';
    } else {
        wifi_util_error_print(WIFI_DMCLI,"%s-%d : Memory allocation failed \n", __func__, __LINE__);
        fclose(file_read);
        return RETURN_ERR;
    }
    fclose(file_read);
    if (data == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s-%d : file_read failed \n", __func__, __LINE__);
        return RETURN_ERR;
    } else if (strlen(data) != 0) {
        json = cJSON_Parse(data);
        if(!json) {
            wifi_util_error_print(WIFI_DMCLI,  "%s : json file parser error : [%d]\n", __func__, __LINE__);
            free(data);
            return RETURN_ERR;
        } else {
            partner_obj = cJSON_GetObjectItem(json, partner_id);
            if (NULL != partner_obj) {
                if (NULL != cJSON_GetObjectItem(partner_obj, p_key)) {
                    cJSON_ReplaceItemInObject(partner_obj, p_key, cJSON_CreateString(p_value));
                    cjson_out = cJSON_Print(json);
                    wifi_util_error_print(WIFI_DMCLI, "Updated json content is %s\n", cjson_out);
                    config_update_status = write_to_json(cjson_out, PARTNERS_INFO_FILE);
                    cJSON_free(cjson_out);
                    if (!config_update_status) {
                        wifi_util_error_print(WIFI_DMCLI, "Updated Value for %s partner\n", partner_id);
                        wifi_util_error_print(WIFI_DMCLI, "Param:%s - Value:%s\n", p_key, p_value);
                    } else {
                        wifi_util_error_print(WIFI_DMCLI, "Failed to update value for %s partner\n", partner_id);
                        wifi_util_error_print(WIFI_DMCLI, "Param:%s\n", p_key);
                        cJSON_Delete(json);
                        return RETURN_ERR;
                    }
                } else {
                    wifi_util_error_print(WIFI_DMCLI,"%s - OBJECT  Value is NULL %s\n", p_key, __func__);
                    cJSON_Delete(json);
                    return RETURN_ERR;
                }

            } else {
                wifi_util_error_print(WIFI_DMCLI,"%s - PARTNER ID OBJECT Value is NULL\n", __func__ );
                cJSON_Delete(json);
                return RETURN_ERR;
            }
            cJSON_Delete(json);
        }
    } else {
        wifi_util_error_print(WIFI_DMCLI,"PARTNERS_INFO_FILE %s is empty\n", PARTNERS_INFO_FILE);
        free(data);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int update_json_param(char *p_key, char *partner_id, char *p_value, char *p_source, char *p_current_time)
{
    cJSON *partner_obj = NULL;
    cJSON *json = NULL;
    FILE *file_read = NULL;
    char * cjson_out = NULL;
    char* data = NULL;
    int len ;
    int config_update_status = -1;

    file_read = fopen(BOOTSTRAP_INFO_FILE, "r");
    if (file_read == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s-%d : Error in opening JSON file\n" , __func__, __LINE__);
        return RETURN_ERR;
    }

    fseek(file_read, 0, SEEK_END);
    len = ftell( file_read );
    if (len < 0) {
        wifi_util_error_print(WIFI_DMCLI,"%s-%d : file_read negative \n", __func__, __LINE__);
        fclose(file_read);
        return RETURN_ERR;
    }
    fseek(file_read, 0, SEEK_SET);
    data = (char *)malloc(sizeof(char) * (len + 1));
    if (data != NULL) {
        memset(data, 0, (sizeof(char) * (len + 1)));
        if (1 != fread(data, len, 1, file_read)) {
            fclose(file_read);
            return RETURN_ERR;
        }
        data[len] ='\0';
    } else {
        wifi_util_error_print(WIFI_DMCLI,"%s-%d : Memory allocation failed \n", __func__, __LINE__);
        fclose(file_read);
        return RETURN_ERR;
    }

    fclose(file_read);
    if (data == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s-%d : file_read failed \n", __func__, __LINE__);
        return RETURN_ERR;
    } else if (strlen(data) != 0) {
        json = cJSON_Parse(data);
        if (!json) {
            wifi_util_error_print(WIFI_DMCLI,  "%s : json file parser error : [%d]\n", __func__,__LINE__);
            free(data);
            return RETURN_ERR;
        } else {
            partner_obj = cJSON_GetObjectItem(json, partner_id);
            if (NULL != partner_obj) {
                cJSON *param_obj = cJSON_GetObjectItem(partner_obj, p_key);
                if (NULL != param_obj) {
                    cJSON_ReplaceItemInObject(param_obj, "ActiveValue", cJSON_CreateString(p_value));
                    cJSON_ReplaceItemInObject(param_obj, "UpdateTime", cJSON_CreateString(p_current_time));
                    cJSON_ReplaceItemInObject(param_obj, "UpdateSource", cJSON_CreateString(p_source));

                    cjson_out = cJSON_Print(json);
                    wifi_util_error_print(WIFI_DMCLI, "Updated json content is %s\n", cjson_out);
                    config_update_status = write_to_json(cjson_out, BOOTSTRAP_INFO_FILE);
                    //Check CLEAR_TRACK_FILE and update in nvram, if needed.
                    unsigned int flags = 0;
                    FILE *fp = fopen(CLEAR_TRACK_FILE, "r");
                    if (fp) {
                        fscanf(fp, "%u", &flags);
                        fclose(fp);
                    }
                    if ((flags & NVRAM_BOOTSTRAP_CLEARED) == 0) {
                        wifi_util_error_print(WIFI_DMCLI, "%s: Updating %s\n", __FUNCTION__, BOOTSTRAP_INFO_FILE_BACKUP);
                        write_to_json(cjson_out, BOOTSTRAP_INFO_FILE_BACKUP);
                    }
                    cJSON_free(cjson_out);
                    if (!config_update_status) {
                        wifi_util_error_print(WIFI_DMCLI, "Bootstrap config update: %s, %s, %s, %s \n", p_key,
                            p_value, partner_id, p_source);
                    } else {
                        wifi_util_error_print(WIFI_DMCLI, "Failed to update value for %s partner\n",partner_id);
                        wifi_util_error_print(WIFI_DMCLI, "Param:%s\n",p_key);
                        cJSON_Delete(json);
                        return RETURN_ERR;
                    }
                } else {
                    wifi_util_error_print(WIFI_DMCLI,"%s - OBJECT  Value is NULL %s\n", p_key, __func__);
                    cJSON_Delete(json);
                    return RETURN_ERR;
                }
            } else {
                wifi_util_error_print(WIFI_DMCLI,"%s - PARTNER ID OBJECT Value is NULL\n", __func__);
                cJSON_Delete(json);
                return RETURN_ERR;
            }
            cJSON_Delete(json);
        }
    } else {
        wifi_util_error_print(WIFI_DMCLI,"BOOTSTRAP_INFO_FILE %s is empty\n", BOOTSTRAP_INFO_FILE);
        free(data);
        return RETURN_ERR;
    }

    update_json_param_legacy(p_key, partner_id, p_value);

    return RETURN_OK;
}

void sendWebpaMsg(char *serviceName, char *dest, char *trans_id, char *traceParent, char *traceState, char *contentType, char *payload, unsigned int payload_len)
{
    wifi_util_info_print(WIFI_DMCLI,"serviceName:%s dest:%s\n", serviceName, dest);
}

int push_data_to_ssp_queue(const void *msg, unsigned int len, uint32_t type, uint32_t sub_type)
{
    return RETURN_OK;
}
