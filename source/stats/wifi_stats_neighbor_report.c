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

#define STATS_COLLECTOR_NEIGHBOR_SCAN_RESULT_INTERVAL 200 //200 ms
#define MAX_SCAN_RESULTS_RETRIES 150 //30 seconds

int validate_neighbor_ap_args(wifi_mon_stats_args_t *args)
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

int generate_neighbor_ap_clctr_stats_key(wifi_mon_stats_args_t *args, char *key_str, size_t key_len)
{
    if ((args == NULL) || (key_str == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p key = %p\n",__func__,__LINE__, args, key_str);
        return RETURN_ERR;
    }

    memset(key_str, 0, key_len);

    snprintf(key_str, key_len, "%02d-%02d-%02d", mon_stats_type_neighbor_stats, args->radio_index, args->scan_mode);

    wifi_util_dbg_print(WIFI_MON, "%s:%d collector stats key: %s\n", __func__,__LINE__, key_str);
    return RETURN_OK;
}


int generate_neighbor_ap_provider_stats_key(wifi_mon_stats_config_t *config, char *key_str, size_t key_len)
{
    if ((config == NULL) || (key_str == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL config : %p key = %p\n",__func__,__LINE__, config, key_str);
        return RETURN_ERR;
    }

    memset(key_str, 0, key_len);
    snprintf(key_str, key_len, "%04d-%02d", config->inst, config->args.app_info);

    return RETURN_OK;
}


int copy_neighborstats_to_cache(void *arg)
{
    wifi_neighbor_ap2_t *temp_neigh_stats = NULL;
    int ret = RETURN_OK;
    unsigned int ap_count = 0;
    wifi_neighbor_ap2_t *neigh_stats = NULL;
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    neighscan_diag_cfg_t *neighscan_stats_data = NULL;
    wifi_mon_stats_args_t *args = arg;
#if CCSP_WIFI_HAL
    ret = wifi_getNeighboringWiFiStatus(args->radio_index, &neigh_stats, &ap_count);
#endif
    if (ret != RETURN_OK) {
        if (errno == EAGAIN && mon_data->scan_results_retries[args->radio_index] < MAX_SCAN_RESULTS_RETRIES) {
            mon_data->scan_results_retries[args->radio_index]++;
            scheduler_add_timer_task(mon_data->sched, FALSE, NULL, copy_neighborstats_to_cache, args,
                STATS_COLLECTOR_NEIGHBOR_SCAN_RESULT_INTERVAL, 1, FALSE);
            
            wifi_util_dbg_print(WIFI_MON, "%s : %d  Neighbor wifi status for index %d not ready. Retry (%d)\n",__func__,__LINE__, args->radio_index, mon_data->scan_results_retries[args->radio_index]);
            return RETURN_OK;
        }
        wifi_util_error_print(WIFI_MON, "%s : %d  Failed to get Neighbor wifi status for scan mode %d radio index %d\n",__func__,__LINE__, args->scan_mode, args->radio_index);
        mon_data->scan_status[args->radio_index] = 0;
        return RETURN_ERR;
    }
    mon_data->scan_status[args->radio_index] = 0;
    neighscan_stats_data = (neighscan_diag_cfg_t *)&mon_data->neighbor_scan_cfg;

    pthread_mutex_lock(&mon_data->data_lock);
    wifi_util_dbg_print(WIFI_MON, "%s : %d  radio index %d scan_mode %d, found %d neighbors\n",__func__,__LINE__, args->radio_index, args->scan_mode, ap_count);
    if (args->scan_mode == WIFI_RADIO_SCAN_MODE_FULL) {
        temp_neigh_stats = neighscan_stats_data->pResult[args->radio_index];
        neighscan_stats_data->pResult[args->radio_index] = neigh_stats;
        neighscan_stats_data->resultCountPerRadio[args->radio_index] = ap_count;
        if (temp_neigh_stats != NULL) {
            free(temp_neigh_stats);
            temp_neigh_stats = NULL;
        }
    } else if (args->scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) {
        temp_neigh_stats = neighscan_stats_data->pResult_onchannel[args->radio_index];
        neighscan_stats_data->pResult_onchannel[args->radio_index] = neigh_stats;
        neighscan_stats_data->resultCountPerRadio_onchannel[args->radio_index] = ap_count;
        if (temp_neigh_stats != NULL) {
            free(temp_neigh_stats);
            temp_neigh_stats = NULL;
        }
    } else { //if (args->scan_mode == WIFI_RADIO_SCAN_MODE_OFFCHAN) 
        temp_neigh_stats = neighscan_stats_data->pResult_offchannel[args->radio_index];
        neighscan_stats_data->pResult_offchannel[args->radio_index] = neigh_stats;
        neighscan_stats_data->resultCountPerRadio_offchannel[args->radio_index] = ap_count;
        if (temp_neigh_stats != NULL) {
            free(temp_neigh_stats);
            temp_neigh_stats = NULL;
        }
    }
    pthread_mutex_unlock(&mon_data->data_lock);
    return RETURN_OK;
}

int execute_neighbor_ap_stats_api(wifi_mon_stats_args_t *args, wifi_monitor_t *mon_data, unsigned long task_interval_ms)
{
    int ret = RETURN_OK;
    wifi_radio_operationParam_t* radioOperation = NULL;
    wifi_radio_capabilities_t *wifi_cap = NULL;
    wifi_channels_list_t    channel_list;

#if CCSP_WIFI_HAL
    unsigned int private_vap_index;
    int dwell_time;
#endif

    if (args == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p\n",__func__,__LINE__, args);
        return RETURN_ERR;
    }
    if (mon_data->radio_presence[args->radio_index] == false) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d radio_presence is false for radio : %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_OK;
    }

    radioOperation = getRadioOperationParam(args->radio_index);
    if (radioOperation == NULL) {
        wifi_util_error_print(WIFI_MON,"%s:%d NULL radioOperation pointer for radio : %d\n", __func__, __LINE__, args->radio_index);
        return RETURN_ERR;
    }

#if CCSP_WIFI_HAL
    if (args->scan_mode == WIFI_RADIO_SCAN_MODE_FULL && radioOperation->band == WIFI_FREQUENCY_6_BAND) {
        dwell_time = 110;
    } else {
        if (args->dwell_time == 0) {
            dwell_time = 10;
        } else {
            dwell_time = args->dwell_time;
        }
    }
#endif

    if (args->scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) {
        channel_list.num_channels = 1;
        channel_list.channels_list[0] = radioOperation->channel;
    } else if (args->scan_mode == WIFI_RADIO_SCAN_MODE_FULL) {
        wifi_cap = getRadioCapability(args->radio_index);

        if (get_allowed_channels(radioOperation->band, wifi_cap, channel_list.channels_list, &(channel_list.num_channels), radioOperation->DfsEnabled) != RETURN_OK) {
            wifi_util_error_print(WIFI_MON, "%s:%d get allowed channels failed for the radio : %d\n",__func__,__LINE__, args->radio_index);
            return RETURN_ERR;
        }
    } else {
        int i;
        channel_list.num_channels = 0;
        for(i=0;i<args->channel_list.num_channels;i++)
        {
            if (radioOperation->channel != (unsigned int) args->channel_list.channels_list[i]) {
                channel_list.channels_list[channel_list.num_channels] = args->channel_list.channels_list[i];
                channel_list.num_channels++;
            }
        }
    }
    wifi_util_dbg_print(WIFI_MON, "%s : %d  Start scan radio index %d scan_mode %d\n",__func__,__LINE__, args->radio_index, args->scan_mode);

    mon_data->scan_status[args->radio_index] = 1;
    mon_data->scan_results_retries[args->radio_index] = 0;
    
#if CCSP_WIFI_HAL
    private_vap_index = getPrivateApFromRadioIndex(args->radio_index);
    ret = wifi_startNeighborScan(private_vap_index, args->scan_mode, dwell_time, channel_list.num_channels, (unsigned int *)channel_list.channels_list);
#endif
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s : %d  Failed to get Neighbor scan for index %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }
    scheduler_add_timer_task(mon_data->sched, FALSE, NULL, copy_neighborstats_to_cache, args,
            STATS_COLLECTOR_NEIGHBOR_SCAN_RESULT_INTERVAL, 1, FALSE);
    return RETURN_OK;
}


int copy_neighbor_ap_stats_from_cache(wifi_mon_stats_args_t *args, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache)
{
    wifi_neighbor_ap2_t *neigh_stat = NULL;
    unsigned int ap_count;
    wifi_neighbor_ap2_t *results;
    neighscan_diag_cfg_t *neighscan_stats_data = NULL;
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();

    if ((args == NULL) || (mon_cache == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s : %d Invalid args args : %p mon_cache = %p\n",
                __func__,__LINE__, args, mon_cache);
        return RETURN_ERR;
    }
    
    neighscan_stats_data = (neighscan_diag_cfg_t *)&mon_data->neighbor_scan_cfg;
    if (args->scan_mode == WIFI_RADIO_SCAN_MODE_FULL) {
        results = neighscan_stats_data->pResult[args->radio_index];
        ap_count = neighscan_stats_data->resultCountPerRadio[args->radio_index];
    } else if (args->scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) {
        results = neighscan_stats_data->pResult_onchannel[args->radio_index];
        ap_count = neighscan_stats_data->resultCountPerRadio_onchannel[args->radio_index];
    } else { //if (args->scan_mode == WIFI_RADIO_SCAN_MODE_OFFCHAN)
        results = neighscan_stats_data->pResult_offchannel[args->radio_index];
        ap_count = neighscan_stats_data->resultCountPerRadio_offchannel[args->radio_index];
    }

    if (ap_count > 0) {
        neigh_stat = (wifi_neighbor_ap2_t *) calloc(ap_count, sizeof(wifi_neighbor_ap2_t));
        if (neigh_stat == NULL) {
            wifi_util_error_print(WIFI_MON, "%s:%d Failed to alloc memory for radio %d\n",__func__,__LINE__, args->radio_index);
            return RETURN_ERR;
        }

        memcpy(neigh_stat, results, ap_count*sizeof(wifi_neighbor_ap2_t));

        *stats = (wifi_neighbor_ap2_t *)neigh_stat;
        *stat_array_size = ap_count;
        wifi_util_dbg_print(WIFI_MON, "%s : %d  radio index %d, send %d neighbors\n",__func__,__LINE__, args->radio_index, ap_count);

    } else {
        *stats = NULL;
        *stat_array_size = 0;
        wifi_util_dbg_print(WIFI_MON, "%s : %d  radio index %d, send 0 neighbors\n",__func__,__LINE__, args->radio_index);
    }
    return RETURN_OK;

}

