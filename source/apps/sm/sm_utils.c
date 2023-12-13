#include "sm_utils.h"
#include "wifi_util.h"
#include "wifi_mgr.h"

#include <const.h>

typedef struct {
    wifi_freq_bands_t freq_band;
    radio_type_t      radio_type;
} band_to_dpp_radio_t;

static const band_to_dpp_radio_t freq_band_to_radio_type_mapping[] = {
    {WIFI_FREQUENCY_2_4_BAND, RADIO_TYPE_2G},
    {WIFI_FREQUENCY_5_BAND,   RADIO_TYPE_5G},
    {WIFI_FREQUENCY_5L_BAND,  RADIO_TYPE_5GL},
    {WIFI_FREQUENCY_5H_BAND,  RADIO_TYPE_5GU},
    {WIFI_FREQUENCY_6_BAND,   RADIO_TYPE_6G},
};


typedef struct {
    reporting_type_t  report_type;
    report_type_t     dpp_report_type;
} reporting_type_to_dpp_report_type_t;

static const reporting_type_to_dpp_report_type_t report_type_mapping[] = {
    {report_type_raw,         REPORT_TYPE_RAW},
    {report_type_average,     REPORT_TYPE_AVERAGE},
    {report_type_histogram,   REPORT_TYPE_HISTOGRAM},
    {report_type_percentile,  REPORT_TYPE_PERCENTILE},
    {report_type_diff,        REPORT_TYPE_DIFF},
};


typedef struct {
    survey_type_t            survey_type;
    wifi_neighborScanMode_t  scan_mode;
    radio_scan_type_t        dpp_scan_type;
    char                    *description;
} survey_type_to_dpp_scan_type_t;

static const survey_type_to_dpp_scan_type_t scan_type_mapping[] = {
    {survey_type_full,        WIFI_RADIO_SCAN_MODE_FULL,    RADIO_SCAN_TYPE_FULL,    "full"},
    {survey_type_on_channel,  WIFI_RADIO_SCAN_MODE_ONCHAN,  RADIO_SCAN_TYPE_ONCHAN,  "on_channel"},
    {survey_type_off_channel, WIFI_RADIO_SCAN_MODE_OFFCHAN, RADIO_SCAN_TYPE_OFFCHAN, "off_channel"},
};


#define NOISE_FLOOR (-95)

typedef struct {
    char                *str_width;
    radio_chanwidth_t    chan_width;
} str_to_dpp_chan_width_t;

static const str_to_dpp_chan_width_t chan_width_mapping[] = {
    { "11A",             RADIO_CHAN_WIDTH_20MHZ},
    { "11B",             RADIO_CHAN_WIDTH_20MHZ},
    { "11G",             RADIO_CHAN_WIDTH_20MHZ},
    { "11NA_HT20",       RADIO_CHAN_WIDTH_20MHZ},
    { "11NG_HT20",       RADIO_CHAN_WIDTH_20MHZ},
    { "11NA_HT40PLUS",   RADIO_CHAN_WIDTH_40MHZ_ABOVE},
    { "11NA_HT40MINUS",  RADIO_CHAN_WIDTH_40MHZ_BELOW},
    { "11NG_HT40PLUS",   RADIO_CHAN_WIDTH_40MHZ_ABOVE},
    { "11NG_HT40MINUS",  RADIO_CHAN_WIDTH_40MHZ_BELOW},
    { "11NG_HT40",       RADIO_CHAN_WIDTH_40MHZ},
    { "11NA_HT40",       RADIO_CHAN_WIDTH_40MHZ},
    { "11AC_VHT20",      RADIO_CHAN_WIDTH_20MHZ},
    { "11AC_VHT40PLUS",  RADIO_CHAN_WIDTH_40MHZ_ABOVE},
    { "11AC_VHT40MINUS", RADIO_CHAN_WIDTH_40MHZ_BELOW},
    { "11AC_VHT40",      RADIO_CHAN_WIDTH_40MHZ},
    { "11AC_VHT80",      RADIO_CHAN_WIDTH_80MHZ},
    { "160",             RADIO_CHAN_WIDTH_160MHZ},
    { "80+80",           RADIO_CHAN_WIDTH_80_PLUS_80MHZ},
    { "80",              RADIO_CHAN_WIDTH_80MHZ},
    { "40",              RADIO_CHAN_WIDTH_40MHZ},
    { "20",              RADIO_CHAN_WIDTH_20MHZ},
};


radio_type_t freq_band_to_dpp_radio_type(wifi_freq_bands_t freq_band)
{
    for (size_t i = 0; i < ARRAY_SIZE(freq_band_to_radio_type_mapping); i++) {
        if (freq_band == freq_band_to_radio_type_mapping[i].freq_band) {
            return freq_band_to_radio_type_mapping[i].radio_type;
        }
    }
    wifi_util_error_print(WIFI_SM, "%s:%d failed to convert freq_band=%d\n",__func__, __LINE__, freq_band);
    return RADIO_TYPE_NONE;
}


radio_type_t radio_index_to_dpp_radio_type(unsigned int radio_index)
{
    wifi_freq_bands_t freq_band;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;

    if (radio_index >= MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_SM, "%s:%d invalid radio_index=%d\n", __func__, __LINE__, radio_index);
        return RADIO_TYPE_NONE;
    }

    if (convert_radio_index_to_freq_band(wifi_prop, radio_index, (int*)&freq_band)) {
        wifi_util_error_print(WIFI_SM, "%s:%d failed to convert radio_index=%d to freq_band\n", __func__, __LINE__, radio_index);
        return RADIO_TYPE_NONE;
    }

    return freq_band_to_dpp_radio_type(freq_band);
}


report_type_t reporting_type_to_dpp_report_type(reporting_type_t report_type)
{
    for (size_t i = 0; i < ARRAY_SIZE(report_type_mapping); i++) {
        if (report_type == report_type_mapping[i].report_type) {
            return report_type_mapping[i].dpp_report_type;
        }
    }
    wifi_util_error_print(WIFI_SM, "%s:%d failed to convert report_type=%d\n",__func__, __LINE__, report_type);
    return REPORT_TYPE_NONE;
}


radio_scan_type_t survey_type_to_dpp_scan_type(survey_type_t survey_type)
{
    for (size_t i = 0; i < ARRAY_SIZE(scan_type_mapping); i++) {
        if (survey_type == scan_type_mapping[i].survey_type) {
            return scan_type_mapping[i].dpp_scan_type;
        }
    }
    wifi_util_error_print(WIFI_SM, "%s:%d failed to convert survey_type=%d\n",__func__, __LINE__, survey_type);
    return RADIO_SCAN_TYPE_NONE;
}


radio_scan_type_t neighbor_scan_mode_to_dpp_scan_type(wifi_neighborScanMode_t scan_mode)
{
    for (size_t i = 0; i < ARRAY_SIZE(scan_type_mapping); i++) {
        if (scan_mode == scan_type_mapping[i].scan_mode) {
            return scan_type_mapping[i].dpp_scan_type;
        }
    }
    wifi_util_error_print(WIFI_SM, "%s:%d failed to convert scan_mode=%d\n",__func__, __LINE__, scan_mode);
    return RADIO_SCAN_TYPE_NONE;
}


char* survey_type_to_str(survey_type_t survey_type)
{
    for (size_t i = 0; i < ARRAY_SIZE(scan_type_mapping); i++) {
        if (survey_type == scan_type_mapping[i].survey_type) {
            return scan_type_mapping[i].description;
        }
    }
    wifi_util_error_print(WIFI_SM, "%s:%d failed to convert survey_type=%d\n",__func__, __LINE__, survey_type);
    return "unknown";
}

char* radio_index_to_radio_type_str(unsigned int radio_index)
{
    radio_type_t radio_type;

    radio_type = radio_index_to_dpp_radio_type(radio_index);

    return radio_get_name_from_type(radio_type);
}


char* neighbor_scan_mode_to_str(wifi_neighborScanMode_t scan_mode)
{
    for (size_t i = 0; i < ARRAY_SIZE(scan_type_mapping); i++) {
        if (scan_mode == scan_type_mapping[i].scan_mode) {
            return scan_type_mapping[i].description;
        }
    }
    wifi_util_error_print(WIFI_SM, "%s:%d failed to convert scan_mode=%d\n",__func__, __LINE__, scan_mode);
    return "unknown";
}


radio_chanwidth_t str_to_dpp_chan_width(char *str)
{
    for (size_t i = 0; i < ARRAY_SIZE(chan_width_mapping); i++) {
        if (strcmp(str, chan_width_mapping[i].str_width) == 0) {
            return chan_width_mapping[i].chan_width;
        }
    }

    return RADIO_CHAN_WIDTH_20MHZ;
}


size_t get_ds_dlist_len(ds_dlist_t *list)
{
    size_t len = 0;
    void *entry = NULL;
    if (!list) {
        return -1;
    }

    ds_dlist_foreach(list, entry) {
        len++;
    }

    return len;
}


uint64_t get_real_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * MSEC_IN_SEC + ts.tv_nsec / NSEC_IN_MSEC;
}


uint64_t timeval_to_ms(struct timeval *ts)
{
    if (!ts) {
        return 0;
    }
    return (uint64_t)ts->tv_sec * MSEC_IN_SEC + ts->tv_usec / USEC_IN_MSEC;
}


int rssi_to_above_noise_floor(int rssi)
{
    if (rssi >= 0) {
        /* already a right value */
        return rssi;
    }

    rssi -= NOISE_FLOOR;

    if (rssi < 0) {
        /* rssi is lower than the noise floor */
        return 0;
    }

    return rssi;
}


int get_ssid_from_vap_index(unsigned int vap_index, ssid_t ssid)
{
    unsigned num_of_radios;

    if ((num_of_radios = getNumberRadios()) > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_SM, "%s:%d invalid num of radios: %u\n", __func__, __LINE__, num_of_radios);
        return RETURN_ERR;
    }

    for (unsigned i = 0; i < num_of_radios; i++) {
        wifi_vap_info_map_t *vap_map;

        if ((vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i)) == NULL) {
            wifi_util_error_print(WIFI_SM, "%s:%d failed to get vap_map for radio_index:%d\n", __func__, __LINE__, i);
            return RETURN_ERR;
        }

        for (unsigned j = 0; j < vap_map->num_vaps; j++) {
            wifi_vap_info_t *vap = &vap_map->vap_array[j];

            if (vap_index == vap->vap_index) {
                memcpy(ssid, vap->u.bss_info.ssid, sizeof(ssid_t));
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}
