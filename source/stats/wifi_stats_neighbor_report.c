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


int copy_neighbor_ap_stats_from_cache(wifi_mon_provider_element_t *p_elem, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache)
{
    wifi_neighbor_ap2_t *neigh_stat = NULL, *neigh_stat_tmp = NULL;
    unsigned int ap_count = 0, ap_count_total = 0;
    wifi_neighbor_ap2_t *results;
    neighscan_diag_cfg_t *neighscan_stats_data = NULL;
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    wifi_mon_stats_args_t *args;

    if ((p_elem == NULL) || (mon_cache == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s : %d Invalid args p_elem : %p mon_cache = %p\n",
                __func__,__LINE__, p_elem, mon_cache);
        return RETURN_ERR;
    }
    if (p_elem->mon_stats_config == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d  p_elem->mon_stats_config NULL\n",
                __func__,__LINE__, p_elem, mon_cache);
        return RETURN_ERR;
    }
    args = &(p_elem->mon_stats_config->args);

    pthread_mutex_lock(&mon_data->data_lock);
    neighscan_stats_data = (neighscan_diag_cfg_t *)&mon_data->neighbor_scan_cfg;
    if (args->scan_mode == WIFI_RADIO_SCAN_MODE_OFFCHAN) {
        int i, j;
        int updated[MAX_CHANNELS];
        memset(updated, 0, sizeof(int)*MAX_CHANNELS);
        for (i=0;i<args->channel_list.num_channels;i++) {
            for (j=0;j<MAX_CHANNELS;j++) {
                if (args->channel_list.channels_list[i] == neighscan_stats_data->channel[args->radio_index][j]) {
                    if (neighscan_stats_data->last_update_time_offchannel[args->radio_index][j].tv_sec != p_elem->u.neighbour_data.last_update_time_offchannel[j].tv_sec) {
                        p_elem->u.neighbour_data.last_update_time_offchannel[j].tv_sec = neighscan_stats_data->last_update_time_offchannel[args->radio_index][j].tv_sec;
                        updated[j] = 1;
                        ap_count_total = ap_count_total + neighscan_stats_data->resultCountPerRadio_offchannel[args->radio_index][j];
                        wifi_util_dbg_print(WIFI_MON, "%s:%d  radio index %d, %d neighbours on channel %d updated\n",__func__,__LINE__, args->radio_index, 
                            neighscan_stats_data->resultCountPerRadio_offchannel[args->radio_index][j], neighscan_stats_data->channel[args->radio_index][j]);
                    }
                    break;
                }
            }
        }
        if (ap_count_total > 0) {
            wifi_util_dbg_print(WIFI_MON, "%s:%d  radio index %, ap count total %d\n",__func__,__LINE__, args->radio_index, ap_count_total);
            neigh_stat = (wifi_neighbor_ap2_t *) calloc(ap_count_total, sizeof(wifi_neighbor_ap2_t));
            if (neigh_stat == NULL) {
                wifi_util_error_print(WIFI_MON, "%s:%d Failed to alloc memory for radio %d\n",__func__,__LINE__, args->radio_index);
                pthread_mutex_unlock(&mon_data->data_lock);
                return RETURN_ERR;
            }
            neigh_stat_tmp = neigh_stat;
            for (j=0;j<MAX_CHANNELS;j++) {
                if (updated[j] == 1) {
                    results = neighscan_stats_data->pResult_offchannel[args->radio_index][j];
                    ap_count = neighscan_stats_data->resultCountPerRadio_offchannel[args->radio_index][j];
                    if (ap_count > 0) {
                        memcpy(neigh_stat_tmp, results, ap_count*sizeof(wifi_neighbor_ap2_t));
                        neigh_stat_tmp = neigh_stat_tmp + ap_count;
                    }
                }
            }

            *stats = (wifi_neighbor_ap2_t *)neigh_stat;
            *stat_array_size = ap_count_total;
            wifi_util_dbg_print(WIFI_MON, "%s : %d  radio index %d, send %d neighbors\n",__func__,__LINE__, args->radio_index, ap_count_total);

        } else {
            *stats = NULL;
            *stat_array_size = 0;
            wifi_util_dbg_print(WIFI_MON, "%s : %d  radio index %d, send 0 neighbors\n",__func__,__LINE__, args->radio_index);
        }

    } else {
        if (args->scan_mode == WIFI_RADIO_SCAN_MODE_FULL) {
            results = neighscan_stats_data->pResult[args->radio_index];
            ap_count = neighscan_stats_data->resultCountPerRadio[args->radio_index];
        } else if (args->scan_mode == WIFI_RADIO_SCAN_MODE_ONCHAN) {
            results = neighscan_stats_data->pResult_onchannel[args->radio_index];
            ap_count = neighscan_stats_data->resultCountPerRadio_onchannel[args->radio_index];
        }

        if (ap_count > 0) {
            neigh_stat = (wifi_neighbor_ap2_t *) calloc(ap_count, sizeof(wifi_neighbor_ap2_t));
            if (neigh_stat == NULL) {
                wifi_util_error_print(WIFI_MON, "%s:%d Failed to alloc memory for radio %d\n",__func__,__LINE__, args->radio_index);
                pthread_mutex_unlock(&mon_data->data_lock);
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
    }
    pthread_mutex_unlock(&mon_data->data_lock);
    return RETURN_OK;

}

