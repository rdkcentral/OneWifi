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

#ifdef CCSP_COMMON
#include <telemetry_busmessage_sender.h>
#include "cosa_wifi_apis.h"
#include "ccsp_psm_helper.h"
#endif // CCSP_COMMON
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include "collection.h"
#include "wifi_hal.h"
#include "wifi_stubs.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"
#include "wifi_whix.h"
#include "wifi_monitor.h"
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/un.h>
#include <assert.h>
#include <limits.h>
#ifdef CCSP_COMMON
#include "ansc_status.h"
#include <sysevent/sysevent.h>
#include "ccsp_base_api.h"
#include "wifi_passpoint.h"
#include "ccsp_trace.h"
#include "safec_lib_common.h"
#include "ccsp_WifiLog_wrapper.h"
#endif // CCSP_COMMON
#include "secure_wrapper.h"

#ifndef  UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(_p_)         (void)(_p_)
#endif

#define CHAN_UTIL_INTERVAL_MS 900000 // 15 mins
#define TELEMETRY_UPDATE_INTERVAL_MS 3600000 // 1 hour
#define CAPTURE_VAP_STATUS_INTERVAL_MS 5*60*1000 // 5 minutes

static unsigned int vap_up_arr[MAX_VAP]={0};
static unsigned char vap_nas_status[MAX_VAP]={0};
static unsigned int vap_iteration=0;
static unsigned int curr_uptime_val = 0;
static unsigned int prev_uptime_val = 0;
static unsigned int skip = 0;
static const char *wifi_health_log = "/rdklogs/logs/wifihealth.txt";


typedef struct {
     wifi_associated_dev3_t assoc_dev_stats[BSS_MAX_NUM_STATIONS];
     size_t   stat_array_size;
} whix_assoc_data_t;

typedef struct {
    whix_assoc_data_t assoc_data[MAX_NUM_VAP_PER_RADIO];
    unsigned int    assoc_stats_vap_presence_mask;
    unsigned int    req_stats_vap_mask;
    unsigned int    is_all_vaps_set;
} whix_assoc_stats_t;

#if 0
whix_assoc_stats_t whix_assoc_stats[MAX_NUM_RADIOS];
#endif

static inline char *to_sta_key    (mac_addr_t mac, sta_key_t key)
{
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}

int radio_health_telemetry_logger_whix(unsigned int radio_index, int ch_util)
{
    char buff[256] = {0}, tmp[128] = {0}, t_string[5] = {0};
    char telemetry_buf[64] = {0};
    unsigned long int itr = 0;
    char *t_str = NULL;

    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    memset(buff, 0, sizeof(buff));
    memset(tmp, 0, sizeof(tmp));
    get_formatted_time(tmp);
    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio_index);
    if (radioOperation != NULL) {
        wifi_util_dbg_print(WIFI_APPS, "Radio operation param is not null\n");
        //Printing the utilization of Radio if and only if the radio is enabled
        if (radioOperation->enable) {
            snprintf(buff, 256, "%s WIFI_BANDUTILIZATION_%d:%d\n", tmp, radio_index+1, ch_util);
            memset(tmp, 0, sizeof(tmp));
            t_str = convert_radio_index_to_band_str_g(radio_index);
            if (t_str != NULL) {
                strncpy(t_string, t_str, sizeof(t_string) - 1);
                for (itr=0; itr<strlen(t_string); itr++) {
                    t_string[itr] = toupper(t_string[itr]);
                }
                snprintf(tmp, sizeof(tmp), "Wifi_%s_utilization_split", t_string);
            } else {
                wifi_util_dbg_print(WIFI_MON, "%s:%d Failed to get band for radio Index %d\n", __func__, __LINE__, radio_index);
                return RETURN_ERR;
            }

            //updating T2 Marker here
            memset(telemetry_buf, 0, sizeof(telemetry_buf));
            snprintf(telemetry_buf, sizeof(telemetry_buf), "%d", ch_util);
            get_stubs_descriptor()->t2_event_s_fn(tmp, telemetry_buf);
        } else {
            snprintf(buff, 256, "%s Radio_%d is down, so not printing WIFI_BANDUTILIZATION marker", tmp, radio_index + 1);
        }

        wifi_util_error_print(WIFI_APPS, "buff is %s\n", buff);
        write_to_file(wifi_health_log, buff);
    }
    return RETURN_OK;
}

int whix_upload_ap_telemetry_data(unsigned int radio_index, int noise_floor)
{
    char buff[1024] = {0};
    char tmp[128] = {0};

    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio_index);
    if (radioOperation != NULL) {
        if (radioOperation->enable) {
            get_formatted_time(tmp);
            snprintf(buff, 1024, "%s WIFI_NOISE_FLOOR_%d:%d\n", tmp, radio_index + 1, noise_floor);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
    }
    return RETURN_OK;
}

static void
get_sub_string(wifi_channelBandwidth_t bandwidth, char *dest)
{
    switch (bandwidth) {
        case WIFI_CHANNELBANDWIDTH_20MHZ:
            strncpy(dest, "20", 3);
        break;
        case WIFI_CHANNELBANDWIDTH_40MHZ:
            strncpy(dest, "40", 3);
        break;
        case WIFI_CHANNELBANDWIDTH_80MHZ:
            strncpy(dest, "80", 3);
        break;
        case WIFI_CHANNELBANDWIDTH_160MHZ:
            strncpy(dest, "160", 4);
        break;
        case WIFI_CHANNELBANDWIDTH_80_80MHZ:
            /* TODO */
            strncpy(dest, "80", 3);
        break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d Bandwidth is not supported\n", __func__, __LINE__);
    }
}

int whix_upload_channel_width_telemetry(unsigned int radio_index)
{
    char buffer[64] = {0};
    char bandwidth[4] = {0};
    char tmp[128] = {0};
    char buff[1024] = {0};
    char t_string[5] = {0};
    CHAR eventName[32] = {0};
    BOOL radioEnabled = FALSE;
    char *t_str = NULL;
    unsigned long int itr = 0;

    wifi_util_dbg_print(WIFI_MON, "Entering %s:%d \n", __FUNCTION__, __LINE__);
    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio_index);

    if (radioOperation == NULL) {
        CcspTraceWarning(("%s : failed to getRadioOperationParam with radio index:%d \n", __FUNCTION__, radio_index));
        radioEnabled = FALSE;
    } else {
        radioEnabled = radioOperation->enable;
    }

    if (radioEnabled) {
        get_sub_string(radioOperation->channelWidth, bandwidth);
        get_formatted_time(tmp);
        t_str = convert_radio_index_to_band_str_g(radio_index);
        if (t_str != NULL) {

            strncpy(t_string, t_str, sizeof(t_string) - 1);
            for (itr=1; itr<strlen(t_string); itr++) {
                t_string[itr] = toupper(t_string[itr]);
            }
            snprintf(buff, 1024, "%s WiFi_config_%s_chan_width_split:%s\n", tmp, t_string, bandwidth);
            write_to_file(wifi_health_log, buff);
        } else {
            wifi_util_dbg_print(WIFI_MON, "%s-%d Failed to get band for radio Index %d\n", __func__, __LINE__, radio_index);
        }

        snprintf(eventName, sizeof(eventName), "WIFI_CWconfig_%d_split", radio_index + 1 );
        get_stubs_descriptor()->t2_event_s_fn(eventName, bandwidth);

        memset(buffer, 0, sizeof(buffer));
        memset(bandwidth, 0, sizeof(bandwidth));
        memset(tmp, 0, sizeof(tmp));
    }
    return RETURN_OK;
}

void calculate_self_bss_chan_statistics (UINT radio, ULLONG Tx_count, ULLONG Rx_count)
{
    ULLONG bss_total = 0;
    UINT Tx_perc = 0;
    UINT Rx_perc = 0;

    bss_total = Tx_count + Rx_count;
    if (bss_total) {
       Tx_perc = (UINT)round( (float) Tx_count / bss_total * 100 );
       Rx_perc = (UINT)round( (float) Rx_count / bss_total * 100 );
    }
    wifi_util_dbg_print(WIFI_APPS, "%s:%d Tx_perc is %d and Rx_perc is %d\n", __func__, __LINE__, Tx_perc, Rx_perc);
    upload_radio_chan_util_telemetry_whix(radio, Tx_perc, Rx_perc);
}

// upload_radio_chan_util_telemetry_whix()  will update the channel stats in telemetry marker
int upload_radio_chan_util_telemetry_whix(UINT radio, UINT Tx_perc, UINT Rx_perc)
{
    UINT bss_Tx_cu = 0 , bss_Rx_cu = 0;
    char tmp[128] = {0};
    char log_buf[1024] = {0};
    char telemetry_buf[1024] = {0};
    errno_t rc = -1;

    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio);
    if (radioOperation != NULL) {
        if (radioOperation->enable) {

            // calculate Self bss Tx and Rx channel utilization
            wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();

            bss_Tx_cu = (UINT)round( (float) monitor_param->radio_data[radio].RadioActivityFactor * Tx_perc / 100 );
            bss_Rx_cu = (UINT)round( (float) monitor_param->radio_data[radio].RadioActivityFactor * Rx_perc / 100 );

            wifi_util_dbg_print(WIFI_MON,"%s: channel Statistics results for Radio %d: Activity: %d AFTX : %d AFRX : %d ChanUtil: %d CSTE: %d\n"
                    ,__func__, radio, monitor_param->radio_data[radio].RadioActivityFactor
                    ,bss_Tx_cu,bss_Rx_cu,monitor_param->radio_data[radio].channelUtil
                    ,monitor_param->radio_data[radio].CarrierSenseThreshold_Exceeded);

            // Telemetry:
            // "header":  "CHUTIL_1_split"
            // "content": "CHUTIL_1_split:"
            // "type": "wifihealth.txt",
            rc = sprintf_s(telemetry_buf, sizeof(telemetry_buf), "%d,%d,%d", bss_Tx_cu, bss_Rx_cu, monitor_param->radio_data[radio].CarrierSenseThreshold_Exceeded);
            if(rc < EOK) {
                ERR_CHK(rc);
            }
            get_formatted_time(tmp);
            rc = sprintf_s(log_buf, sizeof(log_buf), "%s CHUTIL_%d_split:%s\n", tmp, getPrivateApFromRadioIndex(radio) + 1, telemetry_buf);
            if(rc < EOK) {
                ERR_CHK(rc);
            }
            write_to_file(wifi_health_log, log_buf);
            wifi_util_dbg_print(WIFI_MON, "%s", log_buf);

            memset(tmp, 0, sizeof(tmp));
            sprintf(tmp, "CHUTIL_%d_split", getPrivateApFromRadioIndex(radio) + 1);
            get_stubs_descriptor()->t2_event_s_fn(tmp, telemetry_buf);
        }
        else {
            wifi_util_dbg_print(WIFI_MON, "%s : %d Radio : %d is not enabled\n",__func__,__LINE__,radio);
        }
    }
    else {
        wifi_util_error_print(WIFI_MON, "%s : %d Failed to get getRadioOperationParam for rdx : %d\n",__func__,__LINE__,radio);
    }

    return RETURN_OK;
}

int whix_upload_ap_telemetry_pmf()
{
    int i;
    bool bFeatureMFPConfig=false;
    char tmp[128]={0};
    char log_buf[1024]={0};
    char telemetry_buf[1024]={0};
    errno_t rc = -1;
    UINT vap_index;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    wifi_util_dbg_print(WIFI_APPS, "Entering %s:%d \n", __FUNCTION__, __LINE__);
    // Telemetry:
    // "header":  "WIFI_INFO_PMF_ENABLE"
    // "content": "WiFi_INFO_PMF_enable:"
    // "type": "wifihealth.txt",
    get_vap_dml_parameters(MFP_FEATURE_STATUS, &bFeatureMFPConfig);
    rc = sprintf_s(telemetry_buf, sizeof(telemetry_buf), "%s", bFeatureMFPConfig?"true":"false");
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    get_formatted_time(tmp);
    rc = sprintf_s(log_buf, sizeof(log_buf), "%s WIFI_INFO_PMF_ENABLE:%s\n", tmp, (bFeatureMFPConfig?"true":"false"));
    if(rc < EOK)
    {
        ERR_CHK(rc);
    }
    write_to_file(wifi_health_log, log_buf);
    wifi_util_dbg_print(WIFI_MON, "%s", log_buf);
    get_stubs_descriptor()->t2_event_s_fn("WIFI_INFO_PMF_ENABLE", telemetry_buf);
    // Telemetry:
    // "header":  "WIFI_INFO_PMF_CONFIG_1"
    // "content": "WiFi_INFO_PMF_config_ath0:"
    // "type": "wifihealth.txt",
    for(i = 0; i < (int)getTotalNumberVAPs(); i++)
    {
        vap_index = VAP_INDEX(mgr->hal_cap, i);
        if (isVapPrivate(vap_index))
        {
            wifi_vap_security_t *vapSecurity = (wifi_vap_security_t *)Get_wifi_object_bss_security_parameter(vap_index);
            if (vapSecurity != NULL) {

                switch (vapSecurity->mfp)
                {
                    case wifi_mfp_cfg_disabled:
                        snprintf(telemetry_buf, sizeof(telemetry_buf), "Disabled");
                        break;
                    case wifi_mfp_cfg_optional:
                        snprintf(telemetry_buf, sizeof(telemetry_buf), "Optional");
                        break;
                    case wifi_mfp_cfg_required:
                        snprintf(telemetry_buf, sizeof(telemetry_buf), "Required");
                        break;
                    default:
                        wifi_util_dbg_print(WIFI_MON, "%s:%d: unable to find mfp config\n", __func__, __LINE__);
                        break;
                }
                get_formatted_time(tmp);
                rc = sprintf_s(log_buf, sizeof(log_buf), "%s WIFI_INFO_PMF_CONFIG_%d:%s\n", tmp, i+1, telemetry_buf);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }
                write_to_file(wifi_health_log, log_buf);
                wifi_util_dbg_print(WIFI_MON, "%s", log_buf);
                rc = sprintf_s(tmp, sizeof(tmp), "WIFI_INFO_PMF_CONFIG_%d", i+1);
                if(rc < EOK)
                {
                    ERR_CHK(rc);
                }
                get_stubs_descriptor()->t2_event_s_fn(tmp, telemetry_buf);
            }
        }
    }
    wifi_util_dbg_print(WIFI_MON, "Exiting %s:%d \n", __FUNCTION__, __LINE__);
    return RETURN_OK;
}

void upload_client_debug_stats_chan_stats(INT apIndex)
{
    char tmp[128] = {0};
    ULONG channel = 0;
    CHAR eventName[32] = {0};
    unsigned int radio = getRadioIndexFromAp(apIndex);

    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio);
    if (radioOperation != NULL) {
        channel = radioOperation->channel;
        memset(tmp, 0, sizeof(tmp));
        get_formatted_time(tmp);
        write_to_file(wifi_health_log, "\n%s WIFI_CHANNEL_%d:%lu\n", tmp, apIndex + 1, channel);
        snprintf(eventName, sizeof(eventName), "WIFI_CH_%d_split", apIndex +1);
        get_stubs_descriptor()->t2_event_d_fn(eventName, channel);
        if (radio == 1)
        {
            if( 1 == channel )
            {
                //         "header": "WIFI_INFO_UNI3_channel", "content": "WIFI_CHANNEL_2:1", "type": "wifihealth.txt",
                get_stubs_descriptor()->t2_event_d_fn("WIFI_INFO_UNI3_channel", 1);
            } else if (( 3 == channel || 4 == channel)) \
            {
                get_stubs_descriptor()->t2_event_d_fn("WIFI_INFO_UNII_channel", 1);
            }
        }
    } else {
        wifi_util_error_print(WIFI_MON, "%s :Failed to get channel from global db",__func__);
    }
}

static void  upload_client_debug_stats_transmit_power_stats(INT apIndex)
{
    char tmp[128] = {0};
    ULONG txpower = 0;
    ULONG txpwr_pcntg = 0;
    CHAR eventName[32] = {0};
    unsigned int radio = getRadioIndexFromAp(apIndex);

    /* adding transmit power and countrycode */
    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio);
    if (radioOperation != NULL) {
        memset(tmp, 0, sizeof(tmp));
        get_formatted_time(tmp);
        write_to_file(wifi_health_log, "%s WIFI_COUNTRY_CODE_%d:%s\n", tmp, apIndex + 1, wifiCountryMapMembers[radioOperation->countryCode].countryStr);
        wifi_getRadioTransmitPower(radio, &txpower);
        memset(tmp, 0, sizeof(tmp));
        get_formatted_time(tmp);
        write_to_file(wifi_health_log, "%s WIFI_TX_PWR_dBm_%d:%lu\n", tmp, apIndex + 1, txpower);
        //    "header": "WIFI_TXPWR_1_split",   "content": "WIFI_TX_PWR_dBm_1:", "type": "wifihealth.txt",
        //    "header": "WIFI_TXPWR_2_split",   "content": "WIFI_TX_PWR_dBm_2:", "type": "wifihealth.txt",
        snprintf(eventName, sizeof(eventName), "WIFI_TXPWR_%d_split", apIndex + 1);
        get_stubs_descriptor()->t2_event_d_fn(eventName, txpower);
        txpwr_pcntg = radioOperation->transmitPower;
        memset(tmp, 0, sizeof(tmp));
        get_formatted_time(tmp);
        write_to_file(wifi_health_log, "%s WIFI_TX_PWR_PERCENTAGE_%d:%lu\n", tmp, apIndex + 1, txpwr_pcntg);
        snprintf(eventName, sizeof(eventName), "WIFI_TXPWR_PCNTG_%u_split", apIndex + 1);
        get_stubs_descriptor()->t2_event_d_fn("WIFI_TXPWR_PCNTG_1_split", txpwr_pcntg);
    } else {
        wifi_util_error_print(WIFI_MON, "%s: getRadioOperationParam failed for radio %d\n", __FUNCTION__, radio);
    }
}

static void upload_ap_telemetry_anqp_whix (unsigned int vap_index)
{
    char tmp[128] = {0};
    char buff[128] = {0};
    CHAR eventName[128] = {0};
    wifi_vap_info_t *vap_info = getVapInfo(vap_index);
    rdk_wifi_vap_info_t *rdk_vap_info = getRdkVapInfo(vap_index);
    bool public_xfinity_vap_status = false;
    int anqp_request = 0;
    int anqp_response = 0;
    unsigned int radioIndex = getRadioIndexFromAp(vap_index);
    bool status = false;

    if ((rdk_vap_info != NULL) && (vap_info != NULL)) {
        wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radioIndex);
        public_xfinity_vap_status = get_wifi_public_vap_enable_status();
        status = vap_info->u.bss_info.enabled;
        anqp_request = rdk_vap_info->anqp_request_count;
        anqp_response = rdk_vap_info->anqp_response_count;
        if ((public_xfinity_vap_status) && (isVapHotspotSecure(vap_index)) &&
            (radioOperation->band != WIFI_FREQUENCY_2_4_BAND) && (status == TRUE)) {
            get_formatted_time(tmp);
            snprintf(buff, sizeof(buff), "%s XWIFI_ANQP_REQ_%d_split:%d\n", tmp, vap_index+1, anqp_request);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
            snprintf(eventName, sizeof(eventName), "XWIFI_ANQP_REQ_%d_split", vap_index+1);
            get_stubs_descriptor()->t2_event_d_fn(eventName, anqp_request);
            memset(buff, 0, sizeof(buff));
            memset(tmp, 0, sizeof(tmp));
            memset(eventName, 0, sizeof(eventName));
            get_formatted_time(tmp);
            snprintf(buff, sizeof(buff), "%s XWIFI_ANQP_RSP_%d_split:%d\n", tmp, vap_index+1, anqp_response);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
            snprintf(eventName, sizeof(eventName), "XWIFI_ANQP_RSP_%d_split", vap_index+1);
            get_stubs_descriptor()->t2_event_d_fn(eventName, anqp_response);
        }
        //reset counter per telemetry report
        rdk_vap_info->anqp_request_count = 0;
        rdk_vap_info->anqp_response_count = 0;
    }
}

static void upload_client_debug_stats_acs_stats(INT apIndex)
{
    BOOL enable = false;
    char tmp[128] = {0};
    CHAR eventName[32] = {0};
    unsigned int radio = getRadioIndexFromAp(apIndex);
    wifi_global_param_t *global_param = get_wifidb_wifi_global_param();

    if (global_param != NULL) {
        enable = global_param->bandsteering_enable;
    }
    memset(tmp, 0, sizeof(tmp));
    get_formatted_time(tmp);
    write_to_file(wifi_health_log, "%s WIFI_ACL_%d:%d\n", tmp, apIndex + 1, enable);
    enable = false;
    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio);
    if (radioOperation != NULL) {
        enable = radioOperation->autoChannelEnabled;
    }
    if (true == enable)
    {
        memset(tmp, 0, sizeof(tmp));
        get_formatted_time(tmp);
        write_to_file(wifi_health_log, "%s WIFI_ACS_%d:true\n", tmp, apIndex + 1);
        // "header": "WIFI_ACS_1_split",  "content": "WIFI_ACS_1:", "type": "wifihealth.txt",
        // "header": "WIFI_ACS_2_split", "content": "WIFI_ACS_2:", "type": "wifihealth.txt",
        snprintf(eventName, sizeof(eventName), "WIFI_ACS_%d_split", apIndex + 1);
        get_stubs_descriptor()->t2_event_s_fn(eventName, "true");
    }
    else
    {
        memset(tmp, 0, sizeof(tmp));
        get_formatted_time(tmp);
        write_to_file(wifi_health_log, "%s WIFI_ACS_%d:false\n", tmp, apIndex + 1);
        // "header": "WIFI_ACS_1_split",  "content": "WIFI_ACS_1:", "type": "wifihealth.txt",
        // "header": "WIFI_ACS_2_split", "content": "WIFI_ACS_2:", "type": "wifihealth.txt",
        snprintf(eventName, sizeof(eventName), "WIFI_ACS_%d_split", apIndex + 1);
        get_stubs_descriptor()->t2_event_s_fn(eventName,  "false");
    }
}

static void upload_client_debug_stats_sta_fa_info(INT apIndex, sta_data_t *sta)
{
    INT len = 0;
    char *value = NULL;
    char *saveptr = NULL;
    char *ptr = NULL;
    FILE *fp  = NULL;
    char tmp[128] = {0};
    sta_key_t sta_key;
    char buf[CLIENT_STATS_MAX_LEN_BUF] = {0};

    memset (buf, 0, CLIENT_STATS_MAX_LEN_BUF);
    if (sta != NULL) {
        fp = (FILE *)v_secure_popen("r", "dmesg | grep FA_INFO_%s | tail -1", to_sta_key(sta->sta_mac, sta_key));
        if (fp) {
            fgets(buf, CLIENT_STATS_MAX_LEN_BUF, fp);
            v_secure_pclose(fp);
            len = strlen(buf);
            if (len) {
                ptr = buf + len;
                while (len-- && ptr-- && *ptr != ':');
                ptr++;
                value = strtok_r(ptr, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_AID_%d:%s", tmp, apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_TIM_%d:%s", tmp, apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_BMP_SET_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_BMP_CLR_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_TX_PKTS_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                 write_to_file(wifi_health_log,
                        "\n%s WIFI_TX_DISCARDS_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "\n%s WIFI_UAPSD_%d:%s", tmp,
                        apIndex+1, value);
            }
        }
        else {
            wifi_util_error_print(WIFI_MON, " %s Failed to run popen command\n", __FUNCTION__);
        }
    }
    else {
        wifi_util_error_print(WIFI_MON, "%s NULL sta\n", __FUNCTION__);
    }
}

static void upload_client_debug_stats_sta_fa_lmac_data_stats(INT apIndex, sta_data_t *sta)
{
    INT len = 0;
    char *value = NULL;
    char *saveptr = NULL;
    char *ptr = NULL;
    FILE *fp  = NULL;
    char tmp[128] = {0};
    sta_key_t sta_key;
    char buf[CLIENT_STATS_MAX_LEN_BUF] = {0};
    memset (buf, 0, CLIENT_STATS_MAX_LEN_BUF);

    if (sta != NULL) {
        fp = (FILE *)v_secure_popen("r", "dmesg | grep FA_LMAC_DATA_STATS_%s | tail -1", to_sta_key(sta->sta_mac, sta_key));
        if (fp) {
            fgets(buf, CLIENT_STATS_MAX_LEN_BUF, fp);
            v_secure_pclose(fp);
            len = strlen(buf);
            if (len) {
                ptr = buf + len;
                while (len-- && ptr-- && *ptr != ':');
                ptr++;
                value = strtok_r(ptr, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_DATA_QUEUED_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_DATA_DROPPED_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_DATA_DEQUED_TX_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_DATA_DEQUED_DROPPED_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_DATA_EXP_DROPPED_CNT_%d:%s", tmp,
                        apIndex+1, value);
            }
        }
        else {
            wifi_util_error_print(WIFI_MON, "%s Failed to run popen command\n", __FUNCTION__);
        }
    }
    else {
        wifi_util_error_print(WIFI_MON, "%s NULL sta\n", __FUNCTION__);
    }
}

static void upload_client_debug_stats_sta_fa_lmac_mgmt_stats(INT apIndex, sta_data_t *sta)
{
    INT len = 0;
    char *value = NULL;
    char *saveptr = NULL;
    char *ptr = NULL;
    FILE *fp  = NULL;
    sta_key_t sta_key;
    char tmp[128] = {0};
    char buf[CLIENT_STATS_MAX_LEN_BUF] = {0};
    memset (buf, 0, CLIENT_STATS_MAX_LEN_BUF);

    if(sta != NULL) {
        fp = (FILE *)v_secure_popen("r", "dmesg | grep FA_LMAC_MGMT_STATS_%s | tail -1", to_sta_key(sta->sta_mac, sta_key));
        if (fp) {
            fgets(buf, CLIENT_STATS_MAX_LEN_BUF, fp);
            v_secure_pclose(fp);
            len = strlen(buf);
            if (len)
            {
                ptr = buf + len;
                while (len-- && ptr-- && *ptr != ':');
                ptr++;
                value = strtok_r(ptr, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_MGMT_QUEUED_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_MGMT_DROPPED_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_MGMT_DEQUED_TX_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_MGMT_DEQUED_DROPPED_CNT_%d:%s", tmp,
                        apIndex+1, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log,
                        "\n%s WIFI_MGMT_EXP_DROPPED_CNT_%d:%s", tmp,
                        apIndex+1, value);
            }
        }
        else {
            wifi_util_error_print(WIFI_MON, "%s Failed to run popen command\n", __FUNCTION__ );
        }
    }
    else {
        wifi_util_error_print(WIFI_MON, "%s NULL sta\n", __FUNCTION__);
    }
}

static void upload_client_debug_stats_sta_vap_activity_stats(INT apIndex)
{
    INT len = 0;
    char *value = NULL;
    char *saveptr = NULL;
    char *ptr = NULL;
    FILE *fp  = NULL;
    char tmp[128] = {0};
    char buf[CLIENT_STATS_MAX_LEN_BUF] = {0};
    if (0 == apIndex) {
        memset (buf, 0, CLIENT_STATS_MAX_LEN_BUF);
        fp = (FILE *)v_secure_popen("r", "dmesg | grep VAP_ACTIVITY_ath0 | tail -1");
        if (fp)
        {
            fgets(buf, CLIENT_STATS_MAX_LEN_BUF, fp);
            v_secure_pclose(fp);
            len = strlen(buf);
            if (len)
            {
                ptr = buf + len;
                while (len-- && ptr-- && *ptr != ':');
                ptr += 3;
                value = strtok_r(ptr, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "%s WIFI_PS_CLIENTS_1:%s\n", tmp, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "%s WIFI_PS_CLIENTS_DATA_QUEUE_LEN_1:%s\n", tmp,
                        value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "%s WIFI_PS_CLIENTS_DATA_QUEUE_BYTES_1:%s\n", tmp,
                        value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "%s WIFI_PS_CLIENTS_DATA_FRAME_LEN_1:%s\n", tmp,
                        value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "%s WIFI_PS_CLIENTS_DATA_FRAME_COUNT_1:%s\n", tmp,
                        value);
            }
        }
        else {
            wifi_util_error_print(WIFI_MON, "%s Failed to run popen command\n", __FUNCTION__ );
        }
    }
    if (1 == apIndex) {
        memset (buf, 0, CLIENT_STATS_MAX_LEN_BUF);
        fp = (FILE *)v_secure_popen("r", "dmesg | grep VAP_ACTIVITY_ath1 | tail -1");
        if (fp)
        {
            fgets(buf, CLIENT_STATS_MAX_LEN_BUF, fp);
            v_secure_pclose(fp);
            len = strlen(buf);
            if (len)
            {
                ptr = buf + len;
                while (len-- && ptr-- && *ptr != ':');
                ptr += 3;
                value = strtok_r(ptr, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "%s WIFI_PS_CLIENTS_2:%s\n", tmp, value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "%s WIFI_PS_CLIENTS_DATA_QUEUE_LEN_2:%s\n", tmp,
                        value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "%s WIFI_PS_CLIENTS_DATA_QUEUE_BYTES_2:%s\n", tmp,
                        value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "%s WIFI_PS_CLIENTS_DATA_FRAME_LEN_2:%s\n", tmp,
                        value);
                value = strtok_r(NULL, ",", &saveptr);
                memset(tmp, 0, sizeof(tmp));
                get_formatted_time(tmp);
                write_to_file(wifi_health_log, "%s WIFI_PS_CLIENTS_DATA_FRAME_COUNT_2:%s\n", tmp,
                        value);
            }
        }
        else
        {
            wifi_util_error_print(WIFI_MON, "%s Failed to run popen command\n", __FUNCTION__);
        }
    }
}
/*
 * This API will Create telemetry and data model for client activity stats
 * like BytesSent, BytesReceived, RetransCount, FailedRetransCount, etc...
*/
int upload_client_debug_stats_whix(unsigned int num_devs, int vap_index, sta_data_t *sta)
{
    static int vap_status = 0;

    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    vap_status = monitor_param->bssid_data[vap_index].ap_params.ap_status;

    if (NULL == sta && num_devs != 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d sta is NULL and num_devs %u\n", __func__, __LINE__, num_devs);
        return -1;
    }

    if (vap_status) {
        if (isVapPrivate(vap_index)) {
            upload_client_debug_stats_chan_stats(vap_index);
        }
        for (unsigned int i = 0; i < num_devs; i++) {
            upload_client_debug_stats_sta_fa_info(vap_index, &sta[i]);
            upload_client_debug_stats_sta_fa_lmac_data_stats(vap_index, &sta[i]);
            upload_client_debug_stats_sta_fa_lmac_mgmt_stats(vap_index, &sta[i]);
            upload_client_debug_stats_sta_vap_activity_stats(vap_index);
        }
        if (isVapPrivate(vap_index)) {
            upload_client_debug_stats_transmit_power_stats(vap_index);
            upload_client_debug_stats_acs_stats(vap_index);
        }
    }
    return RETURN_OK;
}

int radio_channel_stats_response(wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0;
    radio_index = provider_response->args.radio_index;
    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    unsigned int count = 0;
    radio_chan_data_t *channel_stats = NULL;

    channel_stats = (radio_chan_data_t*) provider_response->stat_pointer;

    wifi_util_dbg_print(WIFI_APPS,"%s:%d radio_index : %d stats_array_size : %d\r\n",__func__, __LINE__, radio_index, provider_response->stat_array_size);

    for (count = 0; count < provider_response->stat_array_size; count++) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d count : %d ch_noise: %d\r\n", __func__, __LINE__, count, channel_stats[count].ch_noise);
        whix_upload_ap_telemetry_data(radio_index, channel_stats[count].ch_noise);
    }
    for (count = 0; count < provider_response->stat_array_size; count++) {
        whix_upload_channel_width_telemetry(radio_index);
    }
    /* calling only once */
    if (radio_index == 0) { 
        whix_upload_ap_telemetry_pmf();
    }
    return RETURN_OK;
}

int radio_channel_util_response(wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0;
    radio_index = provider_response->args.radio_index;
    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    unsigned int count = 0;
    radio_chan_data_t *channel_stats = NULL;

    channel_stats = (radio_chan_data_t*) provider_response->stat_pointer;

    wifi_util_dbg_print(WIFI_APPS,"%s:%d radio_index : %d stats_array_size : %d\r\n",__func__, __LINE__, radio_index, provider_response->stat_array_size);
    for (count = 0; count < provider_response->stat_array_size; count++) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d count : %d ch_utilization: %d\r\n",__func__, __LINE__, count, channel_stats[count].ch_utilization);
        radio_health_telemetry_logger_whix(radio_index, channel_stats[count].ch_utilization);
    }
    for (count = 0; count < provider_response->stat_array_size; count++) {
        calculate_self_bss_chan_statistics(radio_index, channel_stats[count].ch_utilization_busy_tx, channel_stats[count].ch_utilization_busy_self);
    }

    return RETURN_OK;
}

static void get_device_flag(char flag[], int size, char *list_name)
{
    int ret = RETURN_ERR;
    char buf[MAX_BUF_SIZE] = {0};

    ret = get_device_config_list(buf, MAX_BUF_SIZE, list_name);
    wifi_util_dbg_print(WIFI_MON, "\n %s line %d get_device_config_list for %s is %s\n",__func__, __LINE__,list_name, buf);

    if ((ret == RETURN_OK) && (strlen(buf)) ) {
        int buf_int[MAX_VAP] = {0}, i = 0, j = 0;

        for (i = 0; buf[i] != '\0' && j < MAX_VAP; i++)
        {
            if (buf[i] == ',')
            {
                j++;
            } else if (buf[i] == '"') {
                continue;
            }
            else
            {
                buf_int[j] = buf_int[j] * 10 + (buf[i] - 48);
            }
        }

        for(i = 0; i < MAX_VAP && i < size; i ++)
        {
            if(buf_int[i] < size && buf_int[i] >= 0)
            {
                flag[(buf_int[i] - 1)] = 1;
            }
            else
            {
                wifi_util_error_print(WIFI_MON, "%s():%d for vap(%u) failed.\n",
                        __func__, __LINE__, buf_int[i]);
            }
        }
    } else {
        flag[0] = 1;
        flag[1] = 1;
    }
}

/* Log VAP status on percentage basis */
static void logVAPUpStatus()
{
    int i=0;
    int vapup_percentage=0;
    unsigned int vap_iter = 0;
    char log_buf[1024]={0};
    char telemetry_buf[1024]={0};
    char vap_buf[16]={0};
    char tmp[128]={0};
    errno_t rc = -1;
    UINT vap_index = 0;

    wifi_mgr_t *mgr = get_wifimgr_obj();

    wifi_util_dbg_print(WIFI_MON, "Entering %s:%d \n",__FUNCTION__,__LINE__);
    get_formatted_time(tmp);
    rc = sprintf_s(log_buf, sizeof(log_buf), "%s WIFI_VAP_PERCENT_UP:",tmp);
    if(rc < EOK) {
        ERR_CHK(rc);
    }

    curr_uptime_val = get_sys_uptime();
    vap_iter = (curr_uptime_val - prev_uptime_val)/(60*5); /*One iteration per 5 mins*/
    /* syncing the vap_iteration to the upload period */
    if ((vap_iter > vap_iteration) || (vap_iteration == 0)) {
        capture_vapup_status();
        skip = 1;
    }
    for(i = 0; i < (int)getTotalNumberVAPs(); i++)
    {
        vap_index = VAP_INDEX(mgr->hal_cap, i);
        wifi_util_dbg_print(WIFI_APPS, "vap_index is %d vap_iteration is %d and vap_up_arr value is %d\n", vap_index, vap_iteration, vap_up_arr[vap_index]);
        vapup_percentage = (vap_up_arr[vap_index]*100)/vap_iteration;

        char delimiter = (i+1) < ((int)getTotalNumberVAPs()+1) ?';':' ';
        rc = sprintf_s(vap_buf, sizeof(vap_buf), "%d,%d%c",(vap_index + 1),vapup_percentage, delimiter);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        rc = strcat_s(log_buf, sizeof(log_buf), vap_buf);
        ERR_CHK(rc);
        rc = strcat_s(telemetry_buf, sizeof(telemetry_buf), vap_buf);
        ERR_CHK(rc);
    }
    rc = strcat_s(log_buf, sizeof(log_buf), "\n");
    ERR_CHK(rc);
    write_to_file(wifi_health_log,log_buf);
    wifi_util_dbg_print(WIFI_MON, "%s", log_buf);
    get_stubs_descriptor()->t2_event_s_fn("WIFI_VAPPERC_split", telemetry_buf);
    prev_uptime_val = curr_uptime_val;
    vap_iteration = 0;
    memset(vap_up_arr, 0,sizeof(vap_up_arr));
    wifi_util_dbg_print(WIFI_MON, "Exiting %s:%d \n",__FUNCTION__,__LINE__);
}

void print_sta_client_telemetry_data(unsigned int num_devs, int vap_index, sta_data_t *sta_data)
{
    char l_temp[128];
    char l_buff[512];
    unsigned int i = 0;

    memset(l_temp, 0, sizeof(l_temp));
    memset(l_buff, 0, sizeof(l_buff));

    get_formatted_time(l_temp);
    snprintf(l_buff, sizeof(l_buff), "%s WIFI_OPERATING_STANDARD_%d:", l_temp, vap_index + 1);
     for(i = 0; i < num_devs; i++) {
        if (sta_data[i].dev_stats.cli_Active == true) {
            snprintf(l_temp, sizeof(l_temp), "%s,", sta_data[i].dev_stats.cli_OperatingStandard);
            strncat(l_buff, l_temp, sizeof(l_buff) - strlen(l_buff) - 1);
        }
    }
    strncat(l_buff, "\n", sizeof(l_buff) - strlen(l_buff) - 1);
    if(0 != num_devs) {
        write_to_file(wifi_health_log, l_buff);
    }
    wifi_util_dbg_print(WIFI_MON, "sta_OperatingStandard %s\r\n", l_buff);
}

#define CLIENT_TELEMETRY_PARAM_MAX_LEN 64
#define MAX_BUFF_SIZE   BSS_MAX_NUM_STATIONS * CLIENT_TELEMETRY_PARAM_MAX_LEN

int upload_client_telemetry_data(unsigned int num_devs, unsigned int vap_index, sta_data_t *sta)
{
    sta_key_t    sta_key;
    char buff[MAX_BUFF_SIZE];
    char telemetryBuff[MAX_BUFF_SIZE];
    char tmp[128];
    int rssi;
    BOOL sendIndication = false;
    char trflag[MAX_VAP] = {0};
    char nrflag[MAX_VAP] = {0};
    char stflag[MAX_VAP] = {0};
    char snflag[MAX_VAP] = {0};
    CHAR eventName[32] = {0};
    unsigned int itr = 0, i = 0;
    char *t_str =  NULL;
    char t_string[5] = {0};
    wifi_vap_info_t *vap_info = NULL;
    bool is_managed_wifi = false;
    unsigned int vap_array_index;
    unsigned int radioIndex = getRadioIndexFromAp(vap_index);
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();

    if (NULL == sta && num_devs != 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d sta is NULL and num_devs %u\n", __func__, __LINE__, num_devs);
        return RETURN_ERR;
    }

    vap_info = getVapInfo(vap_index);
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL rdk_vap_info pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if (strlen(vap_info->repurposed_vap_name) != 0) {
        wifi_util_info_print(WIFI_APPS,"Managed wifi is enabled on the device\n");
        is_managed_wifi =  true;
    }
    wifi_util_dbg_print(WIFI_APPS," %s:%d vap_index=%d and repurposed_vap_name=%s\n",__func__,__LINE__,vap_index,vap_info->repurposed_vap_name);

        wifi_global_param_t *global_param = get_wifidb_wifi_global_param();
        BOOL sWiFiDmlvApStatsFeatureEnableCfg = global_param->vap_stats_feature;
        get_device_flag(trflag, sizeof(trflag), WIFI_TxRx_RATE_LIST);
        get_device_flag(nrflag, sizeof(nrflag), WIFI_NORMALIZED_RSSI_LIST);
        get_device_flag(stflag, sizeof(stflag), WIFI_CLI_STAT_LIST);
        UNREFERENCED_PARAMETER(sWiFiDmlvApStatsFeatureEnableCfg);
        // see if list has changed
        // Use memcmp() and memcpy() here as it's an array of bits for each VAP, not string.
        if (monitor_param->cliStatsList[vap_index] != stflag[vap_index]) {
                monitor_param->cliStatsList[vap_index] = stflag[vap_index];
                // check if we should enable of disable detailed client stats collection on XB3
                if (monitor_param->radio_presence[radioIndex] == false) {
                    return RETURN_ERR;
                }
                wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radioIndex);
                if (radioOperation == NULL) {
                    CcspTraceWarning(("%s : failed to getRadioOperationParam with radio index \n", __FUNCTION__));
                    return RETURN_ERR;
                }

                BOOL enableRadioDetailStats = stflag[vap_index];
                switch (radioOperation->band)
                {
                    case WIFI_FREQUENCY_2_4_BAND:
                        wifi_util_dbg_print(WIFI_MON, "%s:%d: vap:%u client detailed stats collection for 2.4GHz radio set to %s\n", __func__, __LINE__,
                                vap_index, (enableRadioDetailStats == TRUE)?"enabled":"disabled");
                    break;
                    case WIFI_FREQUENCY_5_BAND:
                        wifi_util_dbg_print(WIFI_MON, "%s:%d: vap:%u client detailed stats collection for 5GHz radio set to %s\n", __func__, __LINE__,
                                vap_index, (enableRadioDetailStats == TRUE)?"enabled":"disabled");
                    break;
                    case WIFI_FREQUENCY_5L_BAND:
                        wifi_util_dbg_print(WIFI_MON, "%s:%d: vap:%u client detailed stats collection for 5GHz Low radio set to %s\n", __func__, __LINE__,
                                vap_index, (enableRadioDetailStats == TRUE)?"enabled":"disabled");
                    break;
                    case WIFI_FREQUENCY_5H_BAND:
                        wifi_util_dbg_print(WIFI_MON, "%s:%d: vap:%u client detailed stats collection for 5GHz High radio set to %s\n", __func__, __LINE__,
                                vap_index, (enableRadioDetailStats == TRUE)?"enabled":"disabled");
                    break;
                    case WIFI_FREQUENCY_6_BAND:
                        wifi_util_dbg_print(WIFI_MON, "%s:%d: vap:%u client detailed stats collection for 6GHz radio set to %s\n", __func__, __LINE__,
                                vap_index, (enableRadioDetailStats == TRUE)?"enabled":"disabled");
                    break;
                    default:
                    break;
                }
            }
        get_device_flag(snflag, sizeof(snflag), WIFI_SNR_LIST);
        memset(buff, 0, MAX_BUFF_SIZE);
        getVAPArrayIndexFromVAPIndex(vap_index, &vap_array_index);
        memset(telemetryBuff, 0, MAX_BUFF_SIZE);
        get_formatted_time(tmp);
        snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_MAC_%d:", tmp, vap_index + 1);
        for( i = 0; i < num_devs; i++) {
            if (sta[i].dev_stats.cli_Active == true) {
                snprintf(tmp, 32, "%s,", to_sta_key(sta[i].sta_mac, sta_key));
                strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
            }
        }
        strncat(buff, "\n", 2);
        if (0 != num_devs) {
            write_to_file(wifi_health_log, buff);
        }
        print_sta_client_telemetry_data(num_devs, vap_index, sta);
        /*
          "header": "2GclientMac_split", "content": "WIFI_MAC_1:", "type": "wifihealth.txt",
          "header": "5GclientMac_split", "content": "WIFI_MAC_2:", "type": "wifihealth.txt",
          "header": "xh_mac_3_split",    "content": "WIFI_MAC_3:", "type": "wifihealth.txt",
          "header": "xh_mac_4_split",    "content": "WIFI_MAC_4:", "type": "wifihealth.txt",
          "header": "MG_mac_7_split",    "content": "WIFI_MAC_7:", "type": "wifihealth.txt",
          "header": "MG_mac_8_split",    "content": "WIFI_MAC_8:", "type": "wifihealth.txt",
          */
        t_str = convert_radio_index_to_band_str_g(radioIndex);
        if (t_str != NULL) {
            strncpy(t_string, t_str, sizeof(t_string) - 1);
            for (itr=1; itr<strlen(t_string); itr++) {
                t_string[itr] = toupper(t_string[itr]);
            }
            if (isVapPrivate(vap_index)) {
                snprintf(eventName, sizeof(eventName), "%sclientMac_split", t_string);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            } else if (isVapXhs(vap_index)) {
                snprintf(eventName, sizeof(eventName), "xh_mac_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
                snprintf(eventName, sizeof(eventName), "MG_mac_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            }
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_MAC_%d_TOTAL_COUNT:%d\n", tmp, vap_index + 1, num_devs);
            write_to_file(wifi_health_log, buff);
            //    "header": "Total_2G_clients_split", "content": "WIFI_MAC_1_TOTAL_COUNT:", "type": "wifihealth.txt",
            //    "header": "Total_5G_clients_split", "content": "WIFI_MAC_2_TOTAL_COUNT:","type": "wifihealth.txt",
            //    "header": "xh_cnt_1_split","content": "WIFI_MAC_3_TOTAL_COUNT:","type": "wifihealth.txt",
            //    "header": "xh_cnt_2_split","content": "WIFI_MAC_4_TOTAL_COUNT:","type": "wifihealth.txt",
            if (isVapPrivate(vap_index)) {
                if (0 == num_devs) {
                    snprintf(eventName, sizeof(eventName), "WIFI_INFO_Zero_%s_Clients", t_string);
                    get_stubs_descriptor()->t2_event_d_fn(eventName, 1);
                } else {
                    snprintf(eventName, sizeof(eventName), "Total_%s_clients_split", t_string);
                    get_stubs_descriptor()->t2_event_d_fn(eventName, num_devs);
                }
            } else if (isVapXhs(vap_index)) {
                snprintf(eventName, sizeof(eventName), "xh_cnt_%d_split", radioIndex + 1);
                get_stubs_descriptor()->t2_event_d_fn(eventName, num_devs);
            } else if (isVapMesh(vap_index)) {
                snprintf(eventName, sizeof(eventName), "Total_%s_PodClients_split", t_string);
                get_stubs_descriptor()->t2_event_d_fn(eventName, num_devs);
            } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
                snprintf(eventName, sizeof(eventName), "MG_cnt_%s_split", t_string);
                get_stubs_descriptor()->t2_event_d_fn(eventName, num_devs);
            }
        } else {
            wifi_util_dbg_print(WIFI_MON, "%s-%d Failed to get band for radio Index %d\n", __func__,
                __LINE__, radioIndex);
        }
        /* If number of device connected is 0, then dont print the markers */
        if (0 == num_devs) {
            return RETURN_OK;
        }
        wifi_util_dbg_print(WIFI_MON, "%s", buff);
        get_formatted_time(tmp);
        memset(telemetryBuff, 0, MAX_BUFF_SIZE);
#if !defined(_XB7_PRODUCT_REQ_) && !defined(_PLATFORM_TURRIS_) && !defined(_HUB4_PRODUCT_REQ_) && !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_SCER11BEL_PRODUCT_REQ_)
        int vap_status = 0;
        wifi_VAPTelemetry_t telemetry;
        //TODO
        vap_status = monitor_param->bssid_data[vap_index].ap_params.ap_status;
        wifi_getVAPTelemetry(vap_index, &telemetry);
        if (vap_status) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WiFi_TX_Overflow_SSID_%d:%u\n", tmp, vap_index + 1, telemetry.txOverflow);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
#endif
        memset(buff, 0, MAX_BUFF_SIZE);
        snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_RSSI_%d:", tmp, vap_index + 1);
        for (i = 0; i < num_devs; i++) {
            if (sta[i].dev_stats.cli_Active == true) {
                snprintf(tmp, 32, "%d,", sta[i].dev_stats.cli_RSSI);
                strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
            }
        }
        strncat(buff, "\n", 2);
        write_to_file(wifi_health_log, buff);
        if (isVapPrivate(vap_index)) {
            t_str = convert_radio_index_to_band_str_g(getRadioIndexFromAp(vap_index));
            if (t_str != NULL) {
                strncpy(t_string, t_str, sizeof(t_string) - 1);
                for (itr=1; itr<strlen(t_string); itr++) {
                    t_string[itr] = toupper(t_string[itr]);

                }
                snprintf(eventName, sizeof(eventName), "%sRSSI_split", t_string);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            } else {
                wifi_util_dbg_print(WIFI_MON, "%s-%d Failed to get band for radio Index %d\n", __func__, __LINE__, radioIndex);
            }
        } else if (isVapXhs(vap_index)) {
            snprintf(eventName, sizeof(eventName), "xh_rssi_%u_split", vap_index + 1);
            get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
        } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
            snprintf(eventName, sizeof(eventName), "MG_rssi_%u_split", vap_index + 1);
            get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
        }
        wifi_util_dbg_print(WIFI_MON, "%s", buff);
        get_formatted_time(tmp);
        memset(buff, 0, MAX_BUFF_SIZE);
        memset(telemetryBuff, 0, MAX_BUFF_SIZE);
        snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_CHANNEL_WIDTH_%d:", tmp, vap_index + 1);
        for (i = 0 ; i < num_devs; i++) {
            if (sta[i].dev_stats.cli_Active == true) {
                snprintf(tmp, CLIENT_TELEMETRY_PARAM_MAX_LEN, "%s,", sta[i].dev_stats.cli_OperatingChannelBandwidth);
                strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
            }
        }
        strncat(buff, "\n", 2);
        write_to_file(wifi_health_log, buff);
        if (isVapPrivate(vap_index)) {
            snprintf(eventName, sizeof(eventName), "WIFI_CW_%d_split", vap_index + 1);
            get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
        } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
            snprintf(eventName, sizeof(eventName), "MG_CW_%d_split", vap_index + 1);
            get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
        }
        wifi_util_dbg_print(WIFI_MON, "%s", buff);
        if (nrflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_NORMALIZED_RSSI_%d:", tmp, vap_index + 1);
            for (i= 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%d,", sta[i].dev_stats.cli_SignalStrength);
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (snflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            memset(telemetryBuff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_SNR_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%d,", sta[i].dev_stats.cli_SNR);
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                    strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            if (isVapPrivate(vap_index)) {
                snprintf(eventName, sizeof(eventName), "WIFI_SNR_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
                snprintf(eventName, sizeof(eventName), "MG_SNR_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            }
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        get_formatted_time(tmp);
        memset(buff, 0, MAX_BUFF_SIZE);
        memset(telemetryBuff, 0, MAX_BUFF_SIZE);
        snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_TXCLIENTS_%d:", tmp, vap_index + 1);
        for (i = 0; i < num_devs; i++) {
            if (sta[i].dev_stats.cli_Active == true) {
                snprintf(tmp, 32, "%d,", sta[i].dev_stats.cli_LastDataDownlinkRate);
                strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
            }
        }
        strncat(buff, "\n", 2);
        write_to_file(wifi_health_log, buff);
        if (isVapPrivate(vap_index)) {
            snprintf(eventName, sizeof(eventName), "WIFI_TX_%d_split", vap_index + 1);
            get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
        } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
            snprintf(eventName, sizeof(eventName), "MG_TX_%d_split", vap_index + 1);
            get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
        }
        wifi_util_dbg_print(WIFI_MON, "%s", buff);
        get_formatted_time(tmp);
        memset(buff, 0, MAX_BUFF_SIZE);
        memset(telemetryBuff, 0, MAX_BUFF_SIZE);
        snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_RXCLIENTS_%d:", tmp, vap_index + 1);
        for (i = 0; i < num_devs; i++) {
            if (sta[i].dev_stats.cli_Active == true) {
                snprintf(tmp, 32, "%d,", sta[i].dev_stats.cli_LastDataUplinkRate);
                strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
            }
        }
        strncat(buff, "\n", 2);
        write_to_file(wifi_health_log, buff);
        //  "header": "WIFI_RX_1_split", "content": "WIFI_RXCLIENTS_1:", "type": "wifihealth.txt",
        if (isVapPrivate(vap_index)) {
            snprintf(eventName, sizeof(eventName), "WIFI_RX_%d_split", vap_index + 1);
            get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
        } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
            snprintf(eventName, sizeof(eventName), "MG_RX_%d_split", vap_index + 1);
            get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
        }
        wifi_util_dbg_print(WIFI_MON, "%s", buff);

        if (trflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            memset(telemetryBuff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_MAX_TXCLIENTS_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%u,", sta[i].dev_stats.cli_MaxDownlinkRate);
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                    strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            if (isVapPrivate(vap_index)) {
                snprintf(eventName, sizeof(eventName), "MAXTX_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
                snprintf(eventName, sizeof(eventName), "MG_MAXTX_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            }
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (trflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            memset(telemetryBuff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_MAX_RXCLIENTS_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%u,", sta[i].dev_stats.cli_MaxUplinkRate);
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                    strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            if (isVapPrivate(vap_index)) {
                snprintf(eventName, sizeof(eventName), "MAXRX_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
                snprintf(eventName, sizeof(eventName), "MG_MAXRX_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            }
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (trflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_RXTXCLIENTDELTA_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%u,", (sta[i].dev_stats.cli_LastDataDownlinkRate - sta[i].dev_stats.cli_LastDataUplinkRate));
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (stflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_BYTESSENTCLIENTS_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%lu,", sta[i].dev_stats.cli_BytesSent - sta[i].dev_stats_last.cli_BytesSent);
                    sta[i].dev_stats_last.cli_BytesSent = sta[i].dev_stats.cli_BytesSent;
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (stflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_BYTESRECEIVEDCLIENTS_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%lu,", sta[i].dev_stats.cli_BytesReceived - sta[i].dev_stats_last.cli_BytesReceived);
                    sta[i].dev_stats_last.cli_BytesReceived = sta[i].dev_stats.cli_BytesReceived;
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (stflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            memset(telemetryBuff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_PACKETSSENTCLIENTS_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%lu,", sta[i].dev_stats.cli_PacketsSent - sta[i].dev_stats_last.cli_PacketsSent);
                    sta[i].dev_stats_last.cli_PacketsSent = sta[i].dev_stats.cli_PacketsSent;
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                    strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            if (isVapPrivate(vap_index)) {
                snprintf(eventName, sizeof(eventName), "WIFI_PACKETSSENTCLIENTS_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
                snprintf(eventName, sizeof(eventName), "MG_PACKETSSENTCLIENTS_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            }
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (stflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_PACKETSRECEIVEDCLIENTS_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%lu,", sta[i].dev_stats.cli_PacketsReceived - sta[i].dev_stats_last.cli_PacketsReceived);
                    sta[i].dev_stats_last.cli_PacketsReceived = sta[i].dev_stats.cli_PacketsReceived;
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (stflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            memset(telemetryBuff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_ERRORSSENT_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%lu,", sta[i].dev_stats.cli_ErrorsSent - sta[i].dev_stats_last.cli_ErrorsSent);
                    sta[i].dev_stats_last.cli_ErrorsSent = sta[i].dev_stats.cli_ErrorsSent;
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                    strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            if (isVapPrivate(vap_index))
            {
                snprintf(eventName, sizeof(eventName), "WIFI_ERRORSSENT_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
                snprintf(eventName, sizeof(eventName), "MG_ERRORSSENT_%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            }
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (stflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            memset(telemetryBuff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_RETRANSCOUNT_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%lu,", sta[i].dev_stats.cli_RetransCount - sta[i].dev_stats_last.cli_RetransCount);
                    sta[i].dev_stats_last.cli_RetransCount = sta[i].dev_stats.cli_RetransCount;
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                    strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            if (isVapPrivate(vap_index))
            {
                snprintf(eventName, sizeof(eventName), "WIFIRetransCount%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
                snprintf(eventName, sizeof(eventName), "MG_RetransCount%d_split", vap_index + 1);
                get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
            }
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (stflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_FAILEDRETRANSCOUNT_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%lu,", sta[i].dev_stats.cli_FailedRetransCount - sta[i].dev_stats_last.cli_FailedRetransCount);
                    sta[i].dev_stats_last.cli_FailedRetransCount = sta[i].dev_stats.cli_FailedRetransCount;
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (stflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_RETRYCOUNT_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%lu,", sta[i].dev_stats.cli_RetryCount - sta[i].dev_stats_last.cli_RetryCount);
                    sta[i].dev_stats_last.cli_RetryCount = sta[i].dev_stats.cli_RetryCount;
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        if (stflag[vap_index]) {
            get_formatted_time(tmp);
            memset(buff, 0, MAX_BUFF_SIZE);
            snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_MULTIPLERETRYCOUNT_%d:", tmp, vap_index + 1);
            for (i = 0; i < num_devs; i++) {
                if (sta[i].dev_stats.cli_Active == true) {
                    snprintf(tmp, 32, "%lu,", sta[i].dev_stats.cli_MultipleRetryCount - sta[i].dev_stats_last.cli_MultipleRetryCount);
                    sta[i].dev_stats_last.cli_MultipleRetryCount = sta[i].dev_stats.cli_MultipleRetryCount;
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                }
            }
            strncat(buff, "\n", 2);
            write_to_file(wifi_health_log, buff);
            wifi_util_dbg_print(WIFI_MON, "%s", buff);
        }
        // Every hour, for private SSID(s) we need to calculate the good rssi time and bad rssi time
        // and write into wifi log in following format
        // WIFI_GOODBADRSSI_$apindex: $MAC,$GoodRssiTime,$BadRssiTime; $MAC,$GoodRssiTime,$BadRssiTime; ....
        get_formatted_time(tmp);
        memset(buff, 0, MAX_BUFF_SIZE);
        memset(telemetryBuff, 0, MAX_BUFF_SIZE);
        snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_GOODBADRSSI_%d:", tmp, vap_index + 1);

       for (i = 0; i < num_devs; i++) {
            if (sta[i].dev_stats.cli_Active == true) {
                snprintf(tmp, 128, "%s,%d,%d;", to_sta_key(sta[i].sta_mac, sta_key), (sta[i].good_rssi_time)/60, (sta[i].bad_rssi_time)/60);
                strncat(buff, tmp, 128);
                strncat(telemetryBuff, tmp, 128);
            }
        }
        strncat(buff, "\n", 2);
        write_to_file(wifi_health_log, buff);
        if (isVapPrivate(vap_index)) {
            snprintf(eventName, sizeof(eventName), "GB_RSSI_%d_split", vap_index + 1);
            get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
        } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
            snprintf(eventName, sizeof(eventName), "MG_GB_RSSI_%d_split", vap_index + 1);
            get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
        }
        wifi_util_dbg_print(WIFI_MON, "%s", buff);
        // check if failure indication is enabled in TR swicth
        wifi_front_haul_bss_t *vap_bss_info = Get_wifi_object_bss_parameter(vap_index);
        if(vap_bss_info != NULL) {
            sendIndication = vap_bss_info->rapidReconnectEnable;
            wifi_util_dbg_print(WIFI_MON, "%s: sendIndication:%d vapIndex:%d \n", __FUNCTION__, sendIndication, vap_index);
        } else {
            wifi_util_dbg_print(WIFI_MON, "%s: wrong vapIndex:%d \n", __FUNCTION__, vap_index);
        }
        if (sendIndication == true) {
            BOOLEAN bReconnectCountEnable = 0;
            // check whether Reconnect Count is enabled or not fro individual vAP
            get_multi_vap_dml_parameters(vap_index, RECONNECT_COUNT_STATUS, &bReconnectCountEnable);
            if (bReconnectCountEnable == true)
            {
                get_formatted_time(tmp);
                memset(buff, 0, MAX_BUFF_SIZE);
                memset(telemetryBuff, 0, MAX_BUFF_SIZE);
                snprintf(buff, MAX_BUFF_SIZE - 1, "%s WIFI_RECONNECT_%d:", tmp, vap_index + 1);
                for (i = 0; i < num_devs; i++) {
                    snprintf(tmp, CLIENT_TELEMETRY_PARAM_MAX_LEN, "%s,%d;", to_sta_key(sta[i].sta_mac, sta_key), sta[i].rapid_reconnects);
                    strncat(buff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                    strncat(telemetryBuff, tmp, MAX_BUFF_SIZE - strlen(buff) - 1);
                    sta[i].rapid_reconnects = 0;
                }
                strncat(buff, "\n", 2);
                write_to_file(wifi_health_log, buff);
                if (isVapPrivate(vap_index))
                {
                    snprintf(eventName, sizeof(eventName), "WIFI_REC_%d_split", vap_index + 1);
                    get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
                } else if (isVapLnfPsk(vap_index) && is_managed_wifi) {
                    snprintf(eventName, sizeof(eventName), "MG_REC_%d_split", vap_index + 1);
                    get_stubs_descriptor()->t2_event_s_fn(eventName, telemetryBuff);
                }
                wifi_util_dbg_print(WIFI_MON, "%s", buff);
            }
        }

    // update thresholds if changed
    if (get_vap_dml_parameters(RSSI_THRESHOLD, &rssi) == ANSC_STATUS_SUCCESS) {
        monitor_param->sta_health_rssi_threshold = rssi;
    }

    if (monitor_param->radio_presence[radioIndex] == false) {
        return RETURN_OK;
    }
    // update rapid reconnect time limit if changed
    if(vap_bss_info != NULL) {
        monitor_param->bssid_data[vap_array_index].ap_params.rapid_reconnect_threshold = vap_bss_info->rapidReconnThreshold;
        wifi_util_dbg_print(WIFI_MON, "%s:rapidReconnThreshold:%d vapIndex:%d \n", __FUNCTION__, vap_bss_info->rapidReconnThreshold, vap_index);
    } else {
        wifi_util_error_print(WIFI_MON, "%s: wrong vapIndex:%d \n", __FUNCTION__, vap_index);
    }

    return RETURN_OK;
}

void update_clientdiagdata(unsigned int num_devs, int vap_idx, sta_data_t *assoc_stats)
{
    //add code of events_update_clientdiagdata
    wifi_util_dbg_print(WIFI_APPS, "Entering %s for vap_idx : %d dev_count: %d\n", __func__, vap_idx, num_devs);

    //check call
    upload_client_debug_stats_whix(num_devs, vap_idx, assoc_stats);
    if (isVapHotspotSecure(vap_idx)) {
        upload_ap_telemetry_anqp_whix (vap_idx);
    }
    upload_client_telemetry_data(num_devs, vap_idx, assoc_stats);
    if (vap_idx == 0) {
       logVAPUpStatus();
    }
    return;
}

int associated_device_stats_response(wifi_provider_response_t *provider_response)
{
    unsigned int vap_index = 0;
    vap_index = provider_response->args.vap_index;
    sta_data_t *assoc_stats = NULL;
    wifi_monitor_data_t *data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));

    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);

    assoc_stats = (sta_data_t *) provider_response->stat_pointer;

    wifi_util_dbg_print(WIFI_APPS,"%s:%d: vap_index : %d stats_array_size : %d\r\n",__func__, __LINE__, vap_index, provider_response->stat_array_size);
    update_clientdiagdata(provider_response->stat_array_size, vap_index, assoc_stats);

    if (data != NULL) {
        data->ap_index = vap_index;
        push_event_to_monitor_queue(data, wifi_event_monitor_clear_sta_counters, NULL);
        free(data);
    }

    return RETURN_OK;
}


int associated_device_diagnostics_response(wifi_provider_response_t *provider_response)
{
#if 0
    unsigned int vap_index = 0;
    unsigned int radio_index = 0;
    radio_index = provider_response->args.radio_index;
    vap_index = provider_response->args.vap_index;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    char vap_name[32];
    unsigned int r_index = 0;
    int v_array_index = 0;
    unsigned int radio_set = 1;
    rdk_wifi_vap_map_t *rdk_vap_map = NULL;

    sta_data_t *assoc_stats = NULL;
    wifi_util_dbg_print(WIFI_APPS, "%s:%d Entering \n", __func__, __LINE__);

    if (convert_vap_index_to_name(&wifi_mgr->hal_cap.wifi_prop, vap_index, vap_name) != RETURN_OK) {
        wifi_util_error_print(WIFI_APPS,"%s:%d: convert_vap_index_to_name failed for vap_index : %d\r\n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    v_array_index = convert_vap_name_to_array_index(&wifi_mgr->hal_cap.wifi_prop, vap_name);
    if (v_array_index == -1) {
        wifi_util_error_print(WIFI_APPS,"%s:%d: convert_vap_name_to_array_index failed for vap_name: %s\r\n",__func__, __LINE__, vap_name);
        return RETURN_ERR;
    }

    assoc_stats = (sta_data_t *) provider_response->stat_pointer;

    memset(whix_assoc_stats[radio_index].assoc_data[v_array_index].assoc_dev_stats, 0, sizeof(whix_assoc_stats[radio_index].assoc_data[v_array_index].assoc_dev_stats));
    memcpy(whix_assoc_stats[radio_index].assoc_data[v_array_index].assoc_dev_stats, &assoc_stats->dev_stats, (sizeof(wifi_associated_dev3_t)*provider_response->stat_array_size));
    whix_assoc_stats[radio_index].assoc_data[v_array_index].stat_array_size = provider_response->stat_array_size;

    whix_assoc_stats[radio_index].assoc_stats_vap_presence_mask |= (1 << vap_index);

    if ((whix_assoc_stats[radio_index].assoc_stats_vap_presence_mask == whix_assoc_stats[radio_index].req_stats_vap_mask)) {
        whix_assoc_stats[radio_index].is_all_vaps_set = 1;
    }

    for (r_index = 0; r_index < getNumberRadios(); r_index++) {
        radio_set &= whix_assoc_stats[r_index].is_all_vaps_set;
    }

    if (radio_set == 1) {
        for (r_index = 0; r_index < getNumberRadios(); r_index++) {
            rdk_vap_map = getRdkWifiVap(r_index);
            if (rdk_vap_map == NULL) {
                wifi_util_error_print(WIFI_APPS,"%s:%d: getRdkWifiVap failed for radio_index : %d\r\n",__func__, __LINE__, r_index);
                return RETURN_ERR;
            }
            for (v_array_index = 0; v_array_index < (int )rdk_vap_map->num_vaps; v_array_index++) {
                events_update_clientdiagdata(whix_assoc_stats[r_index].assoc_data[v_array_index].stat_array_size, rdk_vap_map->rdk_vap_array[v_array_index].vap_index,
                        whix_assoc_stats[r_index].assoc_data[v_array_index].assoc_dev_stats);
            }
            whix_assoc_stats[r_index].assoc_stats_vap_presence_mask = 0;
            whix_assoc_stats[r_index].is_all_vaps_set = 0;
            wifi_util_dbg_print(WIFI_APPS,"%s:%d: events update for radio_index : %d\r\n",__func__, __LINE__, r_index);
        }
    }
#endif
    return RETURN_OK;
}

#if defined (DUAL_CORE_XB3)
static BOOL erouterGetIpAddress()
{
    FILE *f;
    char ptr[32];
    char *cmd = "deviceinfo.sh -eip";

    memset (ptr, 0, sizeof(ptr));

    if ((f = popen(cmd, "r")) == NULL) {
        return false;
    } else {
        *ptr = 0;
        fgets(ptr,32,f);
        pclose(f);
    }

    if ((ptr[0] >= '1') && (ptr[0] <= '9')) {
        memset(erouterIpAddrStr, 0, sizeof(erouterIpAddrStr));
        /*CID: 159695 BUFFER_SIZE_WARNING*/
        strncpy((char*)erouterIpAddrStr, ptr, sizeof(erouterIpAddrStr)-1);
        erouterIpAddrStr[sizeof(erouterIpAddrStr)-1] = '\0';
        return true;
    } else {
        return false;
    }
}
#endif

static unsigned char updateNasIpStatus (int apIndex)
{
#if defined (DUAL_CORE_XB3)

    static unsigned char erouterIpInitialized = 0;
    if(isVapHotspotSecure(apIndex)) {
        if (!erouterIpInitialized) {
            if (FALSE == erouterGetIpAddress()) {
                return 0;
            } else {
                erouterIpInitialized = 1;
                return wifi_pushSecureHotSpotNASIP(apIndex, erouterIpAddrStr);
            }
        } else {
                return wifi_pushSecureHotSpotNASIP(apIndex, erouterIpAddrStr);
        }
    } else {
        return 1;
    }
#else
    UNREFERENCED_PARAMETER(apIndex);
    return 1;
#endif
}

int capture_vapup_status()
{
    int i = 0, vap_status = 0;
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    wifi_mgr_t *mgr = get_wifimgr_obj();

    if (skip == 1) {
        wifi_util_dbg_print(WIFI_APPS, "Skipping as the calculation already made while syncing\n");
        skip = 0;
        return RETURN_OK;
    }

    for(i = 0; i < (int)getTotalNumberVAPs(); i++) {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, i);
        vap_status = monitor_param->bssid_data[vap_index].ap_params.ap_status;
        if (vap_status) {
            vap_up_arr[vap_index] = vap_up_arr[vap_index]+1;
            if (!vap_nas_status[vap_index]) {
                vap_nas_status[vap_index] = updateNasIpStatus(vap_index);
            }
        } else {
            vap_nas_status[vap_index] = 0;
        }
    }
    vap_iteration++;
    return RETURN_OK;
}

int handle_whix_provider_response(wifi_app_t *app, wifi_event_t *event)
{
    // Handle the response for stats, radio confs
    wifi_provider_response_t    *provider_response;
    provider_response = (wifi_provider_response_t *)event->u.provider_response;
    int ret = RETURN_ERR;
    unsigned int radio = 0;
    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    if (provider_response == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d input event is NULL\r\n", __func__, __LINE__);
        return ret;
    }

    radio = provider_response->args.radio_index;
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();

    if (monitor_param->radio_presence[radio] == false) {
        wifi_util_error_print(WIFI_APPS,"%s:%d Radio is not present\r\n", __func__, __LINE__);
        return ret;
    }

    switch (provider_response->args.app_info) {
        case whix_app_event_type_chan_stats:
            wifi_util_error_print(WIFI_APPS, "collect channel stats %s\n", __func__);
            ret = radio_channel_stats_response(provider_response);
        break;
        case whix_app_event_type_chan_util:
            wifi_util_error_print(WIFI_APPS, "collect channel utils %s\n", __func__);
            ret = radio_channel_util_response(provider_response);
        break;
        case whix_app_event_type_assoc_dev_stats:
            ret = associated_device_stats_response(provider_response);
        break;
        case whix_app_event_type_assoc_dev_diagnostics:
            ret = associated_device_diagnostics_response(provider_response);
        break;
        default:
            wifi_util_error_print(WIFI_MON, "%s:%d Data type %d is not supported.\n", __func__,__LINE__, provider_response->args.app_info);
            return RETURN_ERR;
    }
    return RETURN_OK;
}

int monitor_whix_event(wifi_app_t *app, wifi_event_t *event)
{
    int ret = RETURN_ERR;

    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    if (event == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d input event is NULL\r\n", __func__, __LINE__);
        return ret;
    }

    switch (event->sub_type) {
        case wifi_event_monitor_provider_response:
            wifi_util_dbg_print(WIFI_APPS, "Inside wifi_event_monitor_data_collection_response %s\n", __func__);
            ret = handle_whix_provider_response(app, event);
        break;
        default:
            wifi_util_error_print(WIFI_APPS, "%s:%d Inside default\n", __func__, __LINE__);
        break;
    }
    return ret;
}

static void whix_route(wifi_event_route_t *route)
{
    memset(route, 0, sizeof(wifi_event_route_t));
    route->dst = wifi_sub_component_mon;
    route->u.inst_bit_map = wifi_app_inst_whix;
}

static void whix_common_config_to_monitor_queue(wifi_monitor_data_t *data, bool is_channel_util)
{
    data->u.mon_stats_config.inst = wifi_app_inst_whix;

    wifi_global_param_t *global_param = get_wifidb_wifi_global_param();
    if ((global_param != NULL) && (global_param->whix_chutility_loginterval != 0) && (global_param->whix_log_interval != 0)) {
        if (is_channel_util) {
            data->u.mon_stats_config.interval_ms = (global_param->whix_chutility_loginterval) * 1000;
        } else {
            data->u.mon_stats_config.interval_ms = (global_param->whix_log_interval) * 1000;
        }
    } else {
        if (is_channel_util) {
            data->u.mon_stats_config.interval_ms = CHAN_UTIL_INTERVAL_MS;
        } else {
            data->u.mon_stats_config.interval_ms = TELEMETRY_UPDATE_INTERVAL_MS;
        }
    }
    wifi_util_dbg_print(WIFI_APPS, "%s:%d Interval is %lu\n", __func__, __LINE__, data->u.mon_stats_config.interval_ms);
}

static void config_radio_channel_util(wifi_monitor_data_t *data)
{
    unsigned int radioIndex = 0;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_event_route_t route;
    wifi_util_error_print(WIFI_APPS, "Entering %s\n", __func__);
    whix_route(&route);
    whix_common_config_to_monitor_queue(data, true);

    data->u.mon_stats_config.data_type = mon_stats_type_radio_channel_stats;
    data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_ONCHAN;
    /* Request to get channel utilization */
    data->u.mon_stats_config.args.app_info = whix_app_event_type_chan_util;
    for (radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        data->u.mon_stats_config.args.radio_index = wifi_mgr->radio_config[radioIndex].vaps.radio_index;
        wifi_util_error_print(WIFI_APPS, "pushing the event to collect chan_util\n");
        push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
    }
}

static void config_radio_channel_stats(wifi_monitor_data_t *data)
{
    unsigned int radioIndex = 0;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_event_route_t route;
    wifi_util_error_print(WIFI_APPS, "Entering %s\n", __func__);
    whix_route(&route);
    whix_common_config_to_monitor_queue(data, false);

    /* Request to collect other channel stats */
    data->u.mon_stats_config.data_type = mon_stats_type_radio_channel_stats;
    data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_ONCHAN;
    data->u.mon_stats_config.args.app_info = whix_app_event_type_chan_stats;

    //for each vap push the event to monitor queue
    for (radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        data->u.mon_stats_config.args.radio_index = wifi_mgr->radio_config[radioIndex].vaps.radio_index;
        wifi_util_error_print(WIFI_APPS, "pushing the event %s\n", __func__);
        push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
    }
}

static void config_associated_device_stats(wifi_monitor_data_t *data)
{
    unsigned int radio_index;
    unsigned int vapArrayIndex = 0;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_event_route_t route;
    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    whix_route(&route);
    whix_common_config_to_monitor_queue(data, false);

    data->u.mon_stats_config.data_type = mon_stats_type_associated_device_stats;
    data->u.mon_stats_config.args.app_info = whix_app_event_type_assoc_dev_stats;

    for (radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        //for each vap push the event to monitor queue
        for (vapArrayIndex = 0; vapArrayIndex < getNumberVAPsPerRadio(radio_index); vapArrayIndex++) {
            data->u.mon_stats_config.args.vap_index = wifi_mgr->radio_config[radio_index].vaps.rdk_vap_array[vapArrayIndex].vap_index;
            if (!isVapSTAMesh(data->u.mon_stats_config.args.vap_index)) {
                push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
            }
        }
    }
}

static int push_whix_config_event_to_monitor_queue(wifi_mon_stats_request_state_t state, wifi_app_t *app)
{
    // Send appropriate configs to monitor queue(stats, radio)
    wifi_monitor_data_t *data;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_error_print(WIFI_APPS, "Entering %s\n", __func__);
    data = (wifi_monitor_data_t *)malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (app->data.u.whix.sched_handler_id != 0) {
        wifi_util_dbg_print(WIFI_APPS, "Cancelling scheduler\n");
        scheduler_cancel_timer_task(ctrl->sched,  app->data.u.whix.sched_handler_id);
        app->data.u.whix.sched_handler_id = 0;
        vap_iteration = 0;
        memset(vap_up_arr, 0, sizeof(vap_up_arr));
    }
    /* Add a scheduler task to calculate vapup status */
    scheduler_add_timer_task(ctrl->sched, FALSE, &(app->data.u.whix.sched_handler_id),
                    capture_vapup_status, NULL, CAPTURE_VAP_STATUS_INTERVAL_MS, 0);

    memset(data, 0, sizeof(wifi_monitor_data_t));
    data->u.mon_stats_config.req_state = state;

    config_radio_channel_stats(data);
    config_radio_channel_util(data);

    memset(data, 0, sizeof(wifi_monitor_data_t));
    data->u.mon_stats_config.req_state = state;
    config_associated_device_stats(data);

    if (NULL != data) {
        free(data);
        data = NULL;
    }

    return RETURN_OK;
}

void reconfigure_whix_interval(wifi_app_t *app, wifi_event_t *event)
{
    int whix_log_interval = 0, whix_chutil_interval = 0;
    //copy the log interval from webconfig
    webconfig_subdoc_data_t *webconfig_data = NULL;
    webconfig_data = event->u.webconfig_data;
    whix_log_interval = webconfig_data->u.decoded.config.global_parameters.whix_log_interval;
    whix_chutil_interval = webconfig_data->u.decoded.config.global_parameters.whix_chutility_loginterval;
    wifi_util_dbg_print(WIFI_APPS,"%s:%d Intervals are %d %d\n", __func__, __LINE__, whix_log_interval, whix_chutil_interval);
    if (whix_log_interval && whix_chutil_interval) {
        push_whix_config_event_to_monitor_queue(mon_stats_request_state_start, app);
    }
}

static void wps_enable_telemetry(wifi_app_t *app, wifi_event_t *event)
{
    bool enable = 0;
    unsigned int radio_index = 0;
    unsigned int vap_index = 0;
    int vap_array_index = 0;
    int band = 0;
    char tmp[128];
    FILE *wifihealth_fp = NULL;
    webconfig_subdoc_data_t *webconfig_data = NULL;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    if (app == NULL || event == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: app or event is NULL\n", __func__, __LINE__);
        return;
    }

    if (wifi_mgr == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Failed to get wifi manager object\n", __func__, __LINE__);
        return;
    }

    webconfig_data = event->u.webconfig_data;
    if (webconfig_data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: webconfig_data\n", __func__, __LINE__);
        return;
    }

    wifihealth_fp = fopen("/rdklogs/logs/wifihealth.txt", "a+");
    if (wifihealth_fp == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d: Failed to open file /rdklogs/logs/wifihealth.txt\n", __func__, __LINE__);
        return;
    }

    unsigned int numRadios = getNumberRadios();
    for (radio_index = 0; radio_index < numRadios; radio_index++) {
        if (convert_radio_index_to_freq_band(&wifi_mgr->hal_cap.wifi_prop, radio_index, &band) == RETURN_ERR) {
            wifi_util_error_print(WIFI_APPS,"%s:%d failed to convert radio_index=%d to freq_band\n", __func__, __LINE__, radio_index);
            continue;
        }
        else{
             if (band == WIFI_FREQUENCY_6_BAND) {
                 continue;
             }
             vap_index = getPrivateApFromRadioIndex(radio_index);
             vap_array_index = convert_vap_index_to_vap_array_index(&wifi_mgr->hal_cap.wifi_prop, vap_index);

             if (vap_array_index == RETURN_ERR) {
                 wifi_util_error_print(WIFI_APPS,"%s:%d: Failed to get vap_array_index for vap index %u and radio index %u\n", __func__, __LINE__, vap_index, radio_index);
                 continue;
             }
             enable = webconfig_data->u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index].u.bss_info.wps.enable;
             wifi_util_dbg_print(WIFI_APPS,"%s:%d WPS current enable value and previous enable value for radio %u is %d and %d\n", __func__, __LINE__, radio_index, enable, app->data.u.whix.wps_enabled[radio_index]);
             if (app->data.u.whix.wps_enabled[radio_index] != enable) {
                 get_formatted_time(tmp);
                 fprintf(wifihealth_fp, "%s RDKB_WPS_ENABLED_%d %s\n", tmp, radio_index+1, enable ? "TRUE":"FALSE");
                 app->data.u.whix.wps_enabled[radio_index] = enable;
             }
        }
    }
    fclose(wifihealth_fp);
}

void handle_whix_command_event(wifi_app_t *app, wifi_event_t *event)
{
    switch(event->sub_type) {
        case wifi_event_type_start_inst_msmt:
            push_whix_config_event_to_monitor_queue(mon_stats_request_state_stop, app);
            break;
        case wifi_event_type_stop_inst_msmt:
            push_whix_config_event_to_monitor_queue(mon_stats_request_state_start, app);
            break;
        case wifi_event_type_notify_monitor_done:
            /* Send the event to monitor queue */
            push_whix_config_event_to_monitor_queue(mon_stats_request_state_start, app);
            break;
        default:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Not Processing\n", __func__, __LINE__);
            break;
    }
}

void handle_whix_webconfig_event(wifi_app_t *app, wifi_event_t *event)
{
    switch(event->sub_type) {
        case wifi_event_webconfig_set_data_dml:
            reconfigure_whix_interval(app, event);
            if (event->u.webconfig_data->type == webconfig_subdoc_type_private){
                wps_enable_telemetry(app, event);
            }
            break;
        default:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Not Processing\n", __func__, __LINE__);
            break;
    }
}

void radius_eap_failure_event_marker(wifi_app_t *app, void *data)
{
    char tmp[128]={0};
    char eventName[1024]={0};
    char telemetry_buf[1024]={0};
    radius_eap_data_t *radius_eap_data = (radius_eap_data_t *) data;

    get_formatted_time(tmp);

    if (radius_eap_data->failure_reason == RADIUS_ACCESS_REJECT) {
        if (isVapHotspotSecure5g(radius_eap_data->apIndex) || \
            isVapHotspotSecure6g(radius_eap_data->apIndex) || \
            isVapHotspotOpen5g(radius_eap_data->apIndex) || \
            isVapHotspotOpen6g(radius_eap_data->apIndex)) {
            app->data.u.whix.radius_failure_count[radius_eap_data->apIndex]++;
            snprintf(telemetry_buf, sizeof(telemetry_buf), "XWIFI_Radius_Failures_%d_split", (radius_eap_data->apIndex)+1);
            get_stubs_descriptor()->t2_event_d_fn(telemetry_buf, app->data.u.whix.radius_failure_count[radius_eap_data->apIndex]);
            snprintf(eventName, sizeof(eventName), "%s XWIFI_Radius_Failures_%d_split:%d\n", tmp, (radius_eap_data->apIndex)+1, app->data.u.whix.radius_failure_count[radius_eap_data->apIndex]);
            write_to_file("/rdklogs/logs/wifihealth.txt", eventName);
        }
    } else if (radius_eap_data->failure_reason == EAP_FAILURE) {
        if (isVapHotspotSecure5g(radius_eap_data->apIndex) || isVapHotspotSecure6g(radius_eap_data->apIndex)) {
            app->data.u.whix.eap_failure_count[radius_eap_data->apIndex]++;
            snprintf(telemetry_buf, sizeof(telemetry_buf), "XWIFI_EAP_Failures_%d_split", (radius_eap_data->apIndex)+1);
            get_stubs_descriptor()->t2_event_d_fn(telemetry_buf, app->data.u.whix.eap_failure_count[radius_eap_data->apIndex]);
            snprintf(eventName, sizeof(eventName), "%s XWIFI_EAP_Failures_%d_split:%d\n", tmp, (radius_eap_data->apIndex)+1, app->data.u.whix.eap_failure_count[radius_eap_data->apIndex]);
            write_to_file("/rdklogs/logs/wifihealth.txt", eventName);
        }
    }
}

void handle_whix_hal_ind_event(wifi_app_t *app, wifi_event_t *event)
{
    switch(event->sub_type) {
        case wifi_event_radius_eap_failure:
            radius_eap_failure_event_marker(app, event->u.core_data.msg);
        break;
        default:
        break;
     }
}

#ifdef ONEWIFI_WHIX_APP_SUPPORT
int whix_event(wifi_app_t *app, wifi_event_t *event)
{
    switch(event->event_type) {
        case wifi_event_type_webconfig:
            handle_whix_webconfig_event(app, event);
        break;
        case wifi_event_type_monitor:
            monitor_whix_event(app, event);
        break;
        case wifi_event_type_command:
            handle_whix_command_event(app,event);
        break;
        case wifi_event_type_hal_ind:
            handle_whix_hal_ind_event(app, event);
        break;
        default:
        break;
    }
    return RETURN_OK;
}
#endif

#if 0
int whix_generate_vap_mask_for_radio_index(unsigned int radio_index)
{
   rdk_wifi_vap_map_t *rdk_vap_map = NULL;
   unsigned int count = 0;
   rdk_vap_map = getRdkWifiVap(radio_index);
   if (rdk_vap_map == NULL) {
       wifi_util_error_print(WIFI_APPS,"%s:%d: getRdkWifiVap failed for radio_index : %d\r\n",__func__, __LINE__, radio_index);
       return RETURN_ERR;
   }
   for (count = 0; count < rdk_vap_map->num_vaps; count++) {
       if (!isVapSTAMesh(rdk_vap_map->rdk_vap_array[count].vap_index)) {
           whix_assoc_stats[radio_index].req_stats_vap_mask |= (1 << rdk_vap_map->rdk_vap_array[count].vap_index);
       }
   }
   whix_assoc_stats[radio_index].is_all_vaps_set = 0;

   return RETURN_OK;
}
#endif

#ifdef ONEWIFI_WHIX_APP_SUPPORT
int whix_init(wifi_app_t *app, unsigned int create_flag)
{
    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    unsigned int radio_index = 0;
    unsigned int vap_index = 0;
    int vap_array_index = 0;
    int band = 0;
    wifi_mgr_t *wifi_mgr = (wifi_mgr_t*)get_wifimgr_obj();

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

#if 0
    memset(whix_assoc_stats, 0, sizeof(whix_assoc_stats));

    for (radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        whix_generate_vap_mask_for_radio_index(radio_index);
    }
#endif
    unsigned int numRadios = getNumberRadios();
    for (radio_index = 0; radio_index < numRadios; radio_index++) {
        if (convert_radio_index_to_freq_band(&wifi_mgr->hal_cap.wifi_prop, radio_index, &band) == RETURN_ERR) {
            wifi_util_error_print(WIFI_APPS,"%s:%d Failed to convert radio_index=%d to freq_band\n", __func__, __LINE__, radio_index);
            continue;
        }
        else{
             if (band == WIFI_FREQUENCY_6_BAND) {
                 continue;
             }
             vap_index = getPrivateApFromRadioIndex(radio_index);
             vap_array_index = convert_vap_index_to_vap_array_index(&wifi_mgr->hal_cap.wifi_prop, vap_index);

             if (vap_array_index == RETURN_ERR) {
                 wifi_util_error_print(WIFI_APPS,"%s:%d: Failed to get vap_array_index for vap index %u\n", __func__, __LINE__, vap_index);
                 continue;
             }
             app->data.u.whix.wps_enabled[radio_index] = wifi_mgr->radio_config[radio_index].vaps.vap_map.vap_array[vap_array_index].u.bss_info.wps.enable;
        }
    }
    app->data.u.whix.sched_handler_id = 0;

    return RETURN_OK;
}

int whix_deinit(wifi_app_t *app)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    push_whix_config_event_to_monitor_queue(mon_stats_request_state_stop, app);

    if (app->data.u.whix.sched_handler_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched,  &(app->data.u.whix.sched_handler_id));
        app->data.u.whix.sched_handler_id = 0;
    }

    return RETURN_OK;
}
#endif

