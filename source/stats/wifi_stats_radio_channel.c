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

int validate_radio_channel_args(wifi_mon_stats_args_t *args)
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

int generate_radio_channel_clctr_stats_key(wifi_mon_stats_args_t *args, char *key_str, size_t key_len)
{
    if ((args == NULL) || (key_str == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p key = %p\n",__func__,__LINE__, args, key_str);
        return RETURN_ERR;
    }

    memset(key_str, 0, key_len);

    snprintf(key_str, key_len, "%02d-%02d", mon_stats_type_radio_channel_stats, args->radio_index);

    wifi_util_dbg_print(WIFI_MON, "%s:%d collector stats key: %s\n", __func__,__LINE__, key_str);
    return RETURN_OK;
}


int generate_radio_channel_provider_stats_key(wifi_mon_stats_config_t *config, char *key_str, size_t key_len)
{
    if ((config == NULL) || (key_str == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL config : %p key = %p\n",__func__,__LINE__, config, key_str);
        return RETURN_ERR;
    }
    snprintf(key_str, key_len, "%04d-%02d-%02d-%02d-%02d", config->inst, mon_stats_type_radio_channel_stats, 
            config->args.radio_index, config->args.scan_mode, config->args.app_info);
    wifi_util_dbg_print(WIFI_MON, "%s:%d: provider stats key: %s\n", __func__,__LINE__, key_str);

    return RETURN_OK;
}

void copy_chanstats_to_chandata(radio_chan_data_t *chan_data, wifi_channelStats_t *chan_stats)
{
    struct timeval tv_now;
    gettimeofday(&tv_now, NULL);

    ULONG currentTime = tv_now.tv_sec;

    chan_data->ch_in_pool = chan_stats->ch_in_pool;
    chan_data->ch_radar_noise = chan_stats->ch_radar_noise;
    chan_data->ch_number = chan_stats->ch_number;
    chan_data->ch_noise = chan_stats->ch_noise;
    chan_data->ch_max_80211_rssi = chan_stats->ch_max_80211_rssi;
    chan_data->ch_non_80211_noise = chan_stats->ch_non_80211_noise;
    chan_data->ch_utilization = chan_stats->ch_utilization;
    chan_data->ch_utilization_busy_tx = chan_stats->ch_utilization_busy_tx;
    chan_data->ch_utilization_busy_self = chan_stats->ch_utilization_busy_self;
    chan_data->ch_utilization_total = chan_stats->ch_utilization_total;
    chan_data->ch_utilization_busy = chan_stats->ch_utilization_busy;
    chan_data->ch_utilization_busy_rx = chan_stats->ch_utilization_busy_rx;
    chan_data->ch_utilization_busy_ext = chan_stats->ch_utilization_busy_ext;
    chan_data->LastUpdatedTime = currentTime;
    chan_data->LastUpdatedTimeUsec = tv_now.tv_usec;
    return;
}

int execute_radio_channel_stats_api(wifi_mon_stats_args_t *args, wifi_monitor_t *mon_data, unsigned long task_interval_ms)
{
    int ret = RETURN_OK;
    wifi_channelStats_t *chan_stats = NULL;
    unsigned int chan_count = 0;
    wifi_radio_capabilities_t *wifi_cap = NULL;
    int   num_channels = 0;
    radio_chan_stats_data_t *radio_chan_stats_data;
    int channels[64] = {0};
    wifi_radio_operationParam_t* radioOperation = NULL;


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
        wifi_util_error_print(WIFI_MON,"%s:%d NULL radioOperation pointer for radio : %d\n", __func__, __LINE__, args->radio_index);
        return RETURN_ERR;
    }

    wifi_cap = getRadioCapability(args->radio_index);

    if (get_allowed_channels(radioOperation->band, wifi_cap, channels, &num_channels, radioOperation->DfsEnabled) != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s:%d get allowed channels failed for the radio : %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }


    chan_stats = (wifi_channelStats_t *) calloc(num_channels, sizeof(wifi_channelStats_t));
    if (chan_stats == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d Failed to alloc memory for the radio : %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }

    for (chan_count = 0; chan_count < (unsigned int)num_channels; chan_count++) {
        chan_stats[chan_count].ch_number = channels[chan_count];
        chan_stats[chan_count].ch_in_pool= TRUE;
    }

#if CCSP_WIFI_HAL
    ret = wifi_getRadioChannelStats(args->radio_index, chan_stats, chan_count);
#endif
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s : %d  Failed to get radio channel statistics for scan mode %d radio index %d\n",__func__,__LINE__, args->scan_mode, args->radio_index);
        if (chan_stats != NULL) {
            free(chan_stats);
            chan_stats = NULL;
        }
        return RETURN_ERR;
    }

    radio_chan_stats_data = (radio_chan_stats_data_t *)&mon_data->radio_chan_stats_data[args->radio_index];
    if (radio_chan_stats_data == NULL) {
        wifi_util_error_print(WIFI_MON, "%s : %d radio_chan_stats_data is NULL for %d\n",
                __func__, __LINE__, args->radio_index);
        if (chan_stats != NULL) {
            free(chan_stats);
            chan_stats = NULL;
        }
        return RETURN_ERR;
    }

    if (radio_chan_stats_data->chan_data == NULL) {
        radio_chan_stats_data->chan_data = (radio_chan_data_t *) calloc(num_channels, sizeof(radio_chan_data_t));
        if (radio_chan_stats_data->chan_data == NULL) {
            wifi_util_error_print(WIFI_MON, "%s:%d Failed to alloc memory for radio : %d\n",__func__,__LINE__, args->radio_index);
            if (chan_stats != NULL) {
                free(chan_stats);
                chan_stats = NULL;
            }
            return RETURN_ERR;
        }
    } else if (radio_chan_stats_data->num_channels < num_channels) {
        free(radio_chan_stats_data->chan_data);
        radio_chan_stats_data->chan_data = (radio_chan_data_t *) calloc(num_channels, sizeof(radio_chan_data_t));
        if (radio_chan_stats_data->chan_data == NULL) {
            wifi_util_error_print(WIFI_MON, "%s:%d Failed to alloc memory for radio : %d\n",__func__,__LINE__, args->radio_index);
            if (chan_stats != NULL) {
                free(chan_stats);
                chan_stats = NULL;
            }
            return RETURN_ERR;
        }
    }

    for (chan_count = 0; chan_count < (unsigned int)num_channels; chan_count++) {
        copy_chanstats_to_chandata(&radio_chan_stats_data->chan_data[chan_count], &chan_stats[chan_count]);
    }
    radio_chan_stats_data->num_channels = num_channels;

    if (chan_stats != NULL) {
        free(chan_stats);
        chan_stats = NULL;
    }

    return RETURN_OK;
}

radio_chan_data_t *get_wifi_channelStats_t(radio_chan_stats_data_t *stats_data, int channel)
{
    int count = 0;

    if (stats_data == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: stats_data is NULL\n", __func__,__LINE__);
        return NULL;
    }

    if (stats_data->chan_data == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: chan_data is NULL for channel : %d\n", __func__,__LINE__, channel);
        return NULL;
    }

    for (count = 0; count < stats_data->num_channels; count++) {
        if (stats_data->chan_data[count].ch_number == channel) {
            return &stats_data->chan_data[count];
        }
    }
    return NULL;
}

int copy_radio_channel_stats_from_cache(wifi_mon_stats_args_t *args, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache)
{
    radio_chan_data_t   *chan_data;
    radio_chan_data_t    *radio_chan_data = NULL;
    radio_chan_stats_data_t *radio_chan_stats_data;
    int chan_count = 0, i;

    if ((args == NULL) || (mon_cache == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s : %d Invalid args args : %p mon_cache = %p\n",
                __func__,__LINE__, args, mon_cache);
        return RETURN_ERR;
    }

    radio_chan_stats_data = (radio_chan_stats_data_t *)&mon_cache->radio_chan_stats_data[args->radio_index];
    if (radio_chan_stats_data == NULL) {
        wifi_util_error_print(WIFI_MON, "%s : %d radio_chan_stats_data is NULL\n",
                __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(args->radio_index);
    if (radioOperation == NULL) {
        wifi_util_error_print(WIFI_MON,"%s:%d NULL radioOperation pointer for radio : %d\n", __func__, __LINE__, args->radio_index);
        return RETURN_ERR;
    }

    if (args->channel_list.num_channels == 0) {
        chan_count = 1;

        chan_data = (radio_chan_data_t *) calloc(chan_count, sizeof(radio_chan_data_t));
        if (chan_data == NULL) {
            wifi_util_error_print(WIFI_MON,"%s:%d NULL chan_data pointer for radio : %d\n", __func__, __LINE__, args->radio_index);
            return RETURN_ERR;
        }
        radio_chan_data = (radio_chan_data_t *)get_wifi_channelStats_t(radio_chan_stats_data, radioOperation->channel);
        if (radio_chan_data == NULL) {
            free(chan_data);
            return RETURN_ERR;
        }
        memcpy(chan_data, radio_chan_data, sizeof(radio_chan_data_t));
        *stats = chan_data;
        *stat_array_size = chan_count;
        return RETURN_OK;
    } else {
        chan_data = (radio_chan_data_t *) calloc(args->channel_list.num_channels, sizeof(radio_chan_data_t));
        if (chan_data == NULL) {
            wifi_util_error_print(WIFI_MON,"%s:%d NULL chan_data pointer for radio : %d\n", __func__, __LINE__, args->radio_index);
            return RETURN_ERR;
        }
        chan_count = 0;
        for (i = 0; i < args->channel_list.num_channels; i++) {
            if (args->scan_mode == WIFI_RADIO_SCAN_MODE_OFFCHAN && radioOperation->channel == (unsigned int) args->channel_list.channels_list[i]) {
                //skip current channel for offchan request
                continue;
            }
            if (!radioOperation->DfsEnabled && is_5g_20M_channel_in_dfs(args->channel_list.channels_list[i])) {
                //skip dfs channel since dfs is disabled
                continue;
            }
            radio_chan_data = (radio_chan_data_t *)get_wifi_channelStats_t(radio_chan_stats_data, args->channel_list.channels_list[i]);
            if (radio_chan_data == NULL) {
                free(chan_data);
                return RETURN_ERR;
            }
            memcpy(&chan_data[chan_count], radio_chan_data, sizeof(radio_chan_data_t));
            chan_count++;
        }
        *stats = chan_data;
        *stat_array_size = chan_count;
        return RETURN_OK;
    }

    return RETURN_ERR;

}

