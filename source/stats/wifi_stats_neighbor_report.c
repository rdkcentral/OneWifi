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
#include "wifi_util.h"


static void convert_stat_channels_to_string(const wifi_channels_list_t *chan_list, char *buff, size_t max_len)
{
    char chan_buf[MON_STATS_KEY_LEN_16];
    int i;
    int res = 0;
    int len = 0;
    char tmp[MON_STATS_KEY_LEN_32] = {0};

    if (chan_list->num_channels > 0) {
        memset(chan_buf, 0, sizeof(chan_buf));
        for (i = 0; i < chan_list->num_channels - 1; i++) {
            res = snprintf(&chan_buf[len], (MON_STATS_KEY_LEN_16-len), "%d,", chan_list->channels_list[i]);
            len += res;
        }
        chan_buf[len-1] = '\0';
        snprintf(tmp, sizeof(tmp), "%s-%s", buff, chan_buf);
        memcpy(buff, tmp, max_len);
    }
}

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

    snprintf(key_str, key_len, "%02d-%02d", mon_stats_type_neighbor_stats, args->radio_index);

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

    snprintf(key_str, key_len, "%04d-%02d-%02d-%08lu", config->inst, mon_stats_type_neighbor_stats, config->args.radio_index, config->interval_ms);

    convert_stat_channels_to_string(&config->args.channel_list, key_str, key_len);

    return RETURN_OK;
}


int execute_neighbor_ap_stats_api(wifi_mon_stats_args_t *args, wifi_monitor_t *mon_data, unsigned long task_interval_ms)
{
    wifi_neighbor_ap2_t *temp_neigh_stats = NULL;
    int ret = RETURN_OK;
    unsigned int ap_count = 0;
    wifi_neighbor_ap2_t *neigh_stats = NULL;
    neighscan_diag_cfg_t *neighscan_stats_data = NULL;

    if (args == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p\n",__func__,__LINE__, args);
        return RETURN_ERR;
    }

    if (mon_data->radio_presence[args->radio_index] == false) {
        wifi_util_info_print(WIFI_MON, "%s:%d radio_presence is false for radio : %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_OK;
    }

#if CCSP_WIFI_HAL
    ret = wifi_getNeighboringWiFiStatus(args->radio_index, &neigh_stats, &ap_count);
#endif
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s : %d  Failed to get Neighbor wifi status for index %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }

    neighscan_stats_data = (neighscan_diag_cfg_t *)&mon_data->neighbor_scan_cfg;
    if (neighscan_stats_data == NULL) {
        wifi_util_error_print(WIFI_MON, "%s : %d neighscan_stats_data is NULL for %d\n",
                __func__, __LINE__, args->radio_index);
        if (neigh_stats != NULL) {
            free(neigh_stats);
            neigh_stats = NULL;
        }
        return RETURN_ERR;
    }

    temp_neigh_stats = neighscan_stats_data->pResult[args->radio_index];
    neighscan_stats_data->pResult[args->radio_index] = neigh_stats;
    neighscan_stats_data->resultCountPerRadio[args->radio_index] = ap_count;
    if (temp_neigh_stats != NULL) {
        free(temp_neigh_stats);
        temp_neigh_stats = NULL;
    }

    return RETURN_OK;
}

int copy_neighbor_ap_stats_from_cache(wifi_mon_stats_args_t *args, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache)
{
    wifi_neighbor_ap2_t *neigh_stat = NULL;

    if ((args == NULL) || (mon_cache == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s : %d Invalid args args : %p mon_cache = %p\n",
                __func__,__LINE__, args, mon_cache);
        return RETURN_ERR;
    }

    if (mon_cache->neighbor_scan_cfg.pResult[args->radio_index] == NULL) {
        wifi_util_error_print(WIFI_MON, "%s : %d neighbor scan results is NULL for %d\n",
                __func__, __LINE__, args->radio_index);
        return RETURN_ERR;
    }

    neigh_stat = (wifi_neighbor_ap2_t *) calloc(mon_cache->neighbor_scan_cfg.resultCountPerRadio[args->radio_index], sizeof(wifi_neighbor_ap2_t));
    if (neigh_stat == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d Failed to alloc memory for radio %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }

    memcpy(neigh_stat, mon_cache->neighbor_scan_cfg.pResult[args->radio_index], mon_cache->neighbor_scan_cfg.resultCountPerRadio[args->radio_index]*sizeof(wifi_neighbor_ap2_t));

    *stats = (wifi_neighbor_ap2_t *)neigh_stat;
    *stat_array_size = mon_cache->neighbor_scan_cfg.resultCountPerRadio[args->radio_index];

    return RETURN_OK;

}

