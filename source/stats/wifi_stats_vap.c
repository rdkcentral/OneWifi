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
#include "wifi_hal.h"

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
    if (getVAPArrayIndexFromVAPIndex(args->vap_index, &vap_array_index) != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s:%d invalid vap_index %d\n", __func__, __LINE__,
            args->vap_index);
        return RETURN_ERR;
    }

    vap_stats = (vap_traffic_stats_t *)calloc(1, sizeof(vap_traffic_stats_t));  
    if (vap_stats == NULL) {  
        wifi_util_error_print(WIFI_MON, "%s:%d calloc failed\n", __func__, __LINE__);
        return RETURN_ERR;  
    }

    wifi_ssidTrafficStats2_t hal_stats;
    memset(&hal_stats, 0, sizeof(hal_stats));
    if (wifi_getSSIDTrafficStats2(args->vap_index, &hal_stats) != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s:%d wifi_getSSIDTrafficStats2 failed for vap_index %d\n",
            __func__, __LINE__, args->vap_index);
        free(vap_stats);
        return RETURN_ERR;
    }
    vap_stats->ssid_BytesSent = hal_stats.ssid_BytesSent;
    vap_stats->ssid_BytesReceived = hal_stats.ssid_BytesReceived;
    vap_stats->ssid_PacketsSent = hal_stats.ssid_PacketsSent;
    vap_stats->ssid_PacketsReceived = hal_stats.ssid_PacketsReceived;
    vap_stats->ssid_ErrorsSent = hal_stats.ssid_ErrorsSent;
    vap_stats->ssid_ErrorsReceived = hal_stats.ssid_ErrorsReceived;
    vap_stats->ssid_UnicastPacketsSent = hal_stats.ssid_UnicastPacketsSent;
    vap_stats->ssid_UnicastPacketsReceived = hal_stats.ssid_UnicastPacketsReceived;
    vap_stats->ssid_DiscardPacketsSent = hal_stats.ssid_DiscardedPacketsSent;
    vap_stats->ssid_DiscardPacketsReceived = hal_stats.ssid_DiscardedPacketsReceived;
    vap_stats->ssid_MulticastPacketsSent = hal_stats.ssid_MulticastPacketsSent;
    vap_stats->ssid_MulticastPacketsReceived = hal_stats.ssid_MulticastPacketsReceived;
    vap_stats->ssid_BroadcastPacketsSent = hal_stats.ssid_BroadcastPacketsSent;
    vap_stats->ssid_BroadcastPacketsReceived = hal_stats.ssid_BroadcastPacketsRecevied;
    vap_stats->ssid_UnknownProtoPacketsReceived = hal_stats.ssid_UnknownPacketsReceived;
    vap_stats->ssid_RetransCount = hal_stats.ssid_RetransCount;
    vap_stats->ssid_FailedRetransCount = hal_stats.ssid_FailedRetransCount;
    vap_stats->ssid_RetryCount = hal_stats.ssid_RetryCount;
    vap_stats->ssid_MultipleRetryCount = hal_stats.ssid_MultipleRetryCount;
    vap_stats->ssid_ACKFailureCount = hal_stats.ssid_ACKFailureCount;
    vap_stats->ssid_AggregatedPacketCount = hal_stats.ssid_AggregatedPacketCount;
    /* ssid_{Unicast,Multicast,Broadcast}Bytes{Sent,Received} stay 0: wifi_getSSIDTrafficStats2()
     * has no per-cast byte fields to source them from. */

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
    if ((p_elem == NULL) || (stats == NULL) || (stat_array_size == NULL) || (mon_cache == NULL) ||
        (p_elem->mon_stats_config == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d invalid arguments\n", __func__, __LINE__);  
        return RETURN_ERR;  
    }

    wifi_util_dbg_print(WIFI_MON, "%s:%d copy_vap_stats_from_cache for vap index: %d\n", __func__, __LINE__, 
    p_elem->mon_stats_config->args.vap_index);

    if (getVAPArrayIndexFromVAPIndex(p_elem->mon_stats_config->args.vap_index, &vap_array_index) !=
        RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s:%d invalid vap_index %d\n", __func__, __LINE__,
            p_elem->mon_stats_config->args.vap_index);
        return RETURN_ERR;
    }

    pthread_mutex_lock(&mon_cache->data_lock);  
    out = calloc(1, sizeof(vap_traffic_stats_t));  
    if (out == NULL) {  
        pthread_mutex_unlock(&mon_cache->data_lock);  
        return RETURN_ERR;  
    }

    memcpy(out, &mon_cache->bssid_data[vap_array_index].vap_traffic, sizeof(vap_traffic_stats_t));
    pthread_mutex_unlock(&mon_cache->data_lock);  

    *stats = out;
    *stat_array_size = 1;  
    return RETURN_OK;
}
