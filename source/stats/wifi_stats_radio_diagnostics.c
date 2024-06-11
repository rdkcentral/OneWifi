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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "wifi_monitor.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"


int validate_radio_diagnostic_args(wifi_mon_stats_args_t *args)
{
    if (args == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p\n",__func__,__LINE__, args);
        return RETURN_ERR;
    }

    if (args->radio_index > getNumberRadios()) {
        wifi_util_error_print(WIFI_MON, "%s:%d invalid radio index : %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int generate_radio_diagnostic_clctr_stats_key(wifi_mon_stats_args_t *args, char *key_str, size_t key_len)
{
    if ((args == NULL) || (key_str == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p key = %p\n",__func__,__LINE__, args, key_str);
        return RETURN_ERR;
    }

    memset(key_str, 0, key_len);

    snprintf(key_str, key_len, "%02d-%02d", mon_stats_type_radio_diagnostic_stats, args->radio_index);

    wifi_util_dbg_print(WIFI_MON, "%s:%d collector stats key: %s\n", __func__,__LINE__, key_str);
    return RETURN_OK;
}


int generate_radio_diagnostic_provider_stats_key(wifi_mon_stats_config_t *config, char *key_str, size_t key_len)
{
    if ((config == NULL) || (key_str == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL config : %p key = %p\n",__func__,__LINE__, config, key_str);
        return RETURN_ERR;
    }

    memset(key_str, 0, key_len);

    snprintf(key_str, key_len, "%04d-%02d-%02d-%08d", config->inst, mon_stats_type_radio_diagnostic_stats, config->args.radio_index, config->args.app_info);

    wifi_util_dbg_print(WIFI_MON, "%s:%d: provider stats key: %s\n", __func__,__LINE__, key_str);

    return RETURN_OK;
}


//int execute_radio_diagnostic_stats_api(wifi_mon_stats_args_t *args, void **stats, unsigned int *stat_array_size)
int execute_radio_diagnostic_stats_api(wifi_mon_collector_element_t *c_elem, wifi_monitor_t *mon_data, unsigned long task_interval_ms)
{
    int ret = RETURN_OK;
    wifi_radio_operationParam_t* radioOperation = NULL;
    wifi_radioTrafficStats2_t *radioTrafficStats = NULL;
    radio_data_t *radio_data = NULL;
    char str[64] = {0};
    wifi_freq_bands_t band_enum;
    wifi_mon_stats_args_t *args = NULL;

    if (c_elem == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p\n",__func__,__LINE__, c_elem);
        return RETURN_ERR;
    }

    args = c_elem->args;
    if (args == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p\n",__func__,__LINE__, args);
        return RETURN_ERR;
    }

    if (mon_data->radio_presence[args->radio_index] == false) {
        wifi_util_info_print(WIFI_MON, "%s:%d radio_presence is false for radio : %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_OK;
    }

    radioOperation = getRadioOperationParam(args->radio_index);
    if (radioOperation == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d radioOperationParam is NULL for radio_index : %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }

    radioTrafficStats = (wifi_radioTrafficStats2_t *)calloc(1, sizeof(wifi_radioTrafficStats2_t));
    if (radioTrafficStats == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d radioTrafficStats is NULL for radio_index : %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }

    memset(radioTrafficStats, 0, sizeof(wifi_radioTrafficStats2_t));

    if (radioOperation->enable == true) {
        ret = wifi_getRadioTrafficStats2(args->radio_index, radioTrafficStats);
        if (ret != RETURN_OK) {
            wifi_util_error_print(WIFI_MON, "%s : %d  Failed to get radio traffic statistics for index %d\n",__func__,__LINE__, args->radio_index);
            if (radioTrafficStats != NULL) {
                free(radioTrafficStats);
                radioTrafficStats = NULL;
            }
            return RETURN_ERR;
        }
    } else {
        memset(radioTrafficStats, 0, sizeof(wifi_radioTrafficStats2_t));
    }
    radio_data = (radio_data_t *)&mon_data->radio_data[args->radio_index];
    if (radio_data == NULL) {
        wifi_util_error_print(WIFI_MON, "%s : %d radio_data is NULL for %d\n",
                __func__, __LINE__, args->radio_index);
        if (radioTrafficStats != NULL) {
            free(radioTrafficStats);
            radioTrafficStats = NULL;
        }
        return RETURN_ERR;
    }

    radio_data->NoiseFloor = radioTrafficStats->radio_NoiseFloor;
    radio_data->RadioActivityFactor = radioTrafficStats->radio_ActivityFactor;
    radio_data->CarrierSenseThreshold_Exceeded = radioTrafficStats->radio_CarrierSenseThreshold_Exceeded;
    radio_data->channelUtil = radioTrafficStats->radio_ChannelUtilization;
    radio_data->radio_BytesSent = radioTrafficStats->radio_BytesSent;
    radio_data->radio_BytesReceived = radioTrafficStats->radio_BytesReceived;
    radio_data->radio_PacketsSent = radioTrafficStats->radio_PacketsSent;
    radio_data->radio_PacketsReceived = radioTrafficStats->radio_PacketsReceived;
    radio_data->radio_ErrorsSent = radioTrafficStats->radio_ErrorsSent;
    radio_data->radio_ErrorsReceived = radioTrafficStats->radio_ErrorsReceived;
    radio_data->radio_DiscardPacketsSent = radioTrafficStats->radio_DiscardPacketsSent;
    radio_data->radio_DiscardPacketsReceived = radioTrafficStats->radio_DiscardPacketsReceived;
    radio_data->radio_InvalidMACCount = radioTrafficStats->radio_InvalidMACCount;
    radio_data->radio_PacketsOtherReceived = radioTrafficStats->radio_PacketsOtherReceived;
    radio_data->radio_RetransmissionMetirc = radioTrafficStats->radio_RetransmissionMetirc;
    radio_data->radio_PLCPErrorCount = radioTrafficStats->radio_PLCPErrorCount;
    radio_data->radio_FCSErrorCount = radioTrafficStats->radio_FCSErrorCount;
    radio_data->radio_MaximumNoiseFloorOnChannel = radioTrafficStats->radio_MaximumNoiseFloorOnChannel;
    radio_data->radio_MinimumNoiseFloorOnChannel = radioTrafficStats->radio_MinimumNoiseFloorOnChannel;
    radio_data->radio_MedianNoiseFloorOnChannel = radioTrafficStats->radio_MedianNoiseFloorOnChannel;
    radio_data->radio_StatisticsStartTime = radioTrafficStats->radio_StatisticsStartTime;
    radio_data->primary_radio_channel = radioOperation->channel;

    memset(str, 0, sizeof(str));
    band_enum = radioOperation->band;
    if (freq_band_conversion(&band_enum, (char *)str, sizeof(str), ENUM_TO_STRING) != RETURN_OK)
    {
        wifi_util_error_print(WIFI_MON,"%s:%d: frequency band conversion failed\n", __func__, __LINE__);
    } else {
        strncpy((char *)radio_data->frequency_band, str, sizeof(str));
        radio_data->frequency_band[sizeof(radio_data->frequency_band)-1] = '\0';
    }

    memset(str, 0, sizeof(str));
    if (radioOperation->channelWidth == WIFI_CHANNELBANDWIDTH_20MHZ) {
        snprintf(str, sizeof(str), "%s", "20MHz");
    } else if (radioOperation->channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ) {
        snprintf(str, sizeof(str), "%s", "40MHz");
    } else if (radioOperation->channelWidth == WIFI_CHANNELBANDWIDTH_80MHZ) {
        snprintf(str, sizeof(str), "%s", "80MHz");
    } else if (radioOperation->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ) {
        snprintf(str, sizeof(str), "%s", "160MHz");
    }
#ifdef CONFIG_IEEE80211BE
    else if (radioOperation->channelWidth == WIFI_CHANNELBANDWIDTH_320MHZ) {
        snprintf(str, sizeof(str), "%s", "320MHz");
    }
#endif /* CONFIG_IEEE80211BE */

    strncpy((char *)radio_data->channel_bandwidth, str, sizeof(radio_data->channel_bandwidth));

    if (radioTrafficStats != NULL) {
        free(radioTrafficStats);
        radioTrafficStats = NULL;
    }
    return RETURN_OK;
}

int copy_radio_diagnostic_stats_from_cache(wifi_mon_provider_element_t *p_elem, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache)
{
    radio_data_t *radio_data = NULL, *mon_radio_data = NULL;
    wifi_mon_stats_args_t *args;

    if ((p_elem == NULL) || (mon_cache == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d Invalid args p_elem : %p mon_cache = %p\n",
                __func__,__LINE__, p_elem, mon_cache);
        return RETURN_ERR;
    }
    if (p_elem->mon_stats_config == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d  p_elem->mon_stats_config NULL\n",
                __func__,__LINE__, p_elem, mon_cache);
        return RETURN_ERR;
    }
    args = &(p_elem->mon_stats_config->args);

    mon_radio_data = (radio_data_t *)&mon_cache->radio_data[args->radio_index];
    if (mon_radio_data == NULL) {
        wifi_util_error_print(WIFI_MON, "%s : %d monitor radio cache is NULL for radio : %d\n",
                __func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }

    radio_data = (radio_data_t *)calloc(1, sizeof(radio_data_t));
    if (radio_data == NULL) {
        wifi_util_error_print(WIFI_MON, "%s : %d calloc failed for radio_index : %d\n",
                __func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }

    memcpy(radio_data, mon_radio_data, sizeof(radio_data_t));

    *stats = radio_data;
    *stat_array_size = 1;

    return RETURN_OK;
}

