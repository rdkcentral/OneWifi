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

int validate_vap_args(wifi_mon_stats_args_t *args)  
{
    wifi_platform_property_t *wifi_prop = get_wifi_hal_cap_prop();
    if (args == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p\n",__func__,__LINE__, args);
        return RETURN_ERR;
    }

    if (args->vap_index >= wifi_prop->numRadios * MAX_NUM_VAP_PER_RADIO) {
        wifi_util_error_print(WIFI_MON,"RDK_LOG_ERROR, %s Input apIndex = %d not found, Out of range\n", __FUNCTION__, args->vap_index);
        return RETURN_ERR;
    }

    if (args->radio_index >= getNumberRadios()) {
        wifi_util_error_print(WIFI_MON, "%s:%d invalid radio index : %d\n",__func__,__LINE__, args->radio_index);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int generate_vap_clctr_stats_key(wifi_mon_stats_args_t *args, char *key_str, size_t key_len)  
{  
    if ((args == NULL) || (key_str == NULL)) {  
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p key = %p\n", __func__, __LINE__, args, key_str);  
        return RETURN_ERR;  
    }  
    memset(key_str, 0, key_len);  
    snprintf(key_str, key_len, "%02d-%02d", mon_stats_type_vap_stats, args->vap_index);  
    wifi_util_dbg_print(WIFI_MON, "%s:%d collector stats key: %s\n", __func__, __LINE__, key_str);  
    return RETURN_OK;  
}

int generate_vap_provider_stats_key(wifi_mon_stats_config_t *config, char *key_str, size_t key_len)  
{  
    if ((config == NULL) || (key_str == NULL)) {  
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL config : %p key = %p\n", __func__, __LINE__, config, key_str);  
        return RETURN_ERR;  
    }  
    memset(key_str, 0, key_len);  
    snprintf(key_str, key_len, "%04d-%02d-%02d-%08d", config->inst, mon_stats_type_vap_stats,  
            config->args.vap_index, config->args.app_info);  
    wifi_util_dbg_print(WIFI_MON, "%s:%d: provider stats key: %s\n", __func__, __LINE__, key_str);  
    return RETURN_OK;  
}


int execute_vap_stats_api(wifi_mon_collector_element_t *c_elem, wifi_monitor_t *mon_data,  
                          unsigned long task_interval_ms)  
{  
    wifi_mon_stats_args_t *args;  
    vap_traffic_stats_t *vap_stats;
    unsigned int vap_array_index;
   
    if ((c_elem == NULL) || (mon_data == NULL) || (c_elem->args == NULL)) {  
        wifi_util_error_print(WIFI_MON, "%s:%d invalid arguments\n", __func__, __LINE__);  
        return RETURN_ERR;  
    }  
    args = c_elem->args;  
    vap_stats = (vap_traffic_stats_t *)calloc(1, sizeof(vap_traffic_stats_t));  
    if (vap_stats == NULL) {  
        wifi_util_error_print(WIFI_MON, "%s:%d calloc failed\n", __func__, __LINE__);
        return RETURN_ERR;  
    }

    /*
    if (wifi_getxxx(args->vap_index, vap_stats) != RETURN_OK) {  
        wifi_util_error_print(WIFI_MON, "%s:%d wifi_getxxx failed for vap_index %d\n",  
            __func__, __LINE__, args->vap_index);  
        free(vap_stats);  
        return RETURN_ERR;  
    } */
    getVAPArrayIndexFromVAPIndex(args->vap_index, &vap_array_index);

    pthread_mutex_lock(&mon_data->data_lock);  
    memcpy(&mon_data->bssid_data[vap_array_index].vap_traffic, vap_stats, sizeof(vap_traffic_stats_t));
    pthread_mutex_unlock(&mon_data->data_lock);  
  
    if (c_elem->stats_clctr.is_event_subscribed == true &&  
        (c_elem->stats_clctr.stats_type_subscribed & 1 << mon_stats_type_vap_stats)) {
        vap_traffic_stats_t *copy = (vap_traffic_stats_t *)malloc(sizeof(vap_traffic_stats_t));  
        if (copy == NULL) {  
            wifi_util_error_print(WIFI_MON, "%s:%d malloc copy failed\n", __func__, __LINE__);  
            free(vap_stats);  
            return RETURN_ERR;  
        }
        memcpy(copy, vap_stats, sizeof(vap_traffic_stats_t));  
  
        wifi_provider_response_t *collect_stats = (wifi_provider_response_t *)malloc(sizeof(wifi_provider_response_t));  
        if (collect_stats == NULL) {  
            wifi_util_error_print(WIFI_MON, "%s:%d malloc response failed\n", __func__, __LINE__);  
            free(copy);  
            free(vap_stats);  
            return RETURN_ERR;  
        }  
        collect_stats->data_type = mon_stats_type_vap_stats;  
        collect_stats->args.vap_index = args->vap_index;
        collect_stats->args.radio_index = args->radio_index;  
        collect_stats->stat_pointer = copy;
        collect_stats->stat_array_size = 1;  
  
        wifi_util_dbg_print(WIFI_MON, "%s:%d sending VAP stats for vap_index %d\n", __func__, __LINE__, args->vap_index);  
        push_monitor_response_event_to_ctrl_queue(collect_stats, sizeof(wifi_provider_response_t),  
            wifi_event_type_monitor, wifi_event_type_collect_stats, NULL);  
        free(copy);  
        free(collect_stats);
    }

    free(vap_stats);  
    wifi_util_dbg_print(WIFI_MON, "%s:%d executed VAP stats for vap_index %d\n", __func__, __LINE__, args->vap_index);  
    return RETURN_OK;  
}

int copy_vap_stats_from_cache(wifi_mon_provider_element_t *p_elem, void **stats,  
                              unsigned int *stat_array_size, wifi_monitor_t *mon_cache)  
{
    vap_traffic_stats_t *out;
    unsigned int vap_array_index;
    if ((p_elem == NULL) || (mon_cache == NULL) || (p_elem->mon_stats_config == NULL)) {  
        wifi_util_error_print(WIFI_MON, "%s:%d invalid arguments\n", __func__, __LINE__);  
        return RETURN_ERR;  
    }

    wifi_util_dbg_print(WIFI_MON, "%s:%d copy_vap_stats_from_cache for vap index: %d\n", __func__, __LINE__, 
    p_elem->mon_stats_config->args.vap_index);

    pthread_mutex_lock(&mon_cache->data_lock);  
    out = calloc(1, sizeof(vap_traffic_stats_t));  
    if (out == NULL) {  
        pthread_mutex_unlock(&mon_cache->data_lock);  
        return RETURN_ERR;  
    }

    getVAPArrayIndexFromVAPIndex(p_elem->mon_stats_config->args.vap_index, &vap_array_index);
    memcpy(out, &mon_cache->bssid_data[vap_array_index].vap_traffic, sizeof(vap_traffic_stats_t));
    pthread_mutex_unlock(&mon_cache->data_lock);  

    *stats = out;
    *stat_array_size = 1;  
    return RETURN_OK;
}
