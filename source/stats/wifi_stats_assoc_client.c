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

static inline char *to_sta_key(mac_addr_t mac, sta_key_t key)
{
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}


int validate_assoc_client_args(wifi_mon_stats_args_t *args)
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
    if (isVapSTAMesh(args->vap_index)) {
        wifi_util_error_print(WIFI_MON, "%s:%d input vap_index %d is STA mesh interface\n",__func__,__LINE__, args->vap_index);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int generate_assoc_client_clctr_stats_key(wifi_mon_stats_args_t *args, char *key_str, size_t key_len)
{
    if ((args == NULL) || (key_str == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p key = %p\n",__func__,__LINE__, args, key_str);
        return RETURN_ERR;
    }

    memset(key_str, 0, key_len);

    snprintf(key_str, key_len, "%02d-%02d", mon_stats_type_associated_device_diag, args->vap_index);

    wifi_util_dbg_print(WIFI_MON, "%s:%d collector stats key: %s\n", __func__,__LINE__, key_str);

    return RETURN_OK;
}

int generate_assoc_client_provider_stats_key(wifi_mon_stats_config_t *config, char *key_str, size_t key_len)
{
    if ((config == NULL) || (key_str == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL config : %p key = %p\n",__func__,__LINE__, config, key_str);
        return RETURN_ERR;
    }

    memset(key_str, 0, key_len);

    snprintf(key_str, key_len, "%04d-%02d-%02d", config->inst, mon_stats_type_associated_device_diag, config->args.vap_index);

    wifi_util_dbg_print(WIFI_MON, "%s:%d: provider stats key: %s\n", __func__,__LINE__, key_str);

    return RETURN_OK;
}

int execute_assoc_client_stats_api(wifi_mon_stats_args_t *args, wifi_monitor_t *mon_data, unsigned long task_interval_ms)
{
    wifi_front_haul_bss_t *bss_param = NULL;
    wifi_associated_dev3_t *dev_array = NULL;
    unsigned int num_devs = 0;
    unsigned int vap_array_index;
    wifi_associated_dev3_t  *hal_sta;
    sta_key_t   sta_key;
    unsigned int i = 0;
    hash_map_t *sta_map;
    sta_data_t *sta = NULL,  *tmp_sta = NULL;
    unsigned long temp_time = 0;
    int ret = RETURN_OK;

    if (args == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p\n",__func__,__LINE__, args);
        return RETURN_ERR;
    }

    bss_param = Get_wifi_object_bss_parameter(args->vap_index);
    if (bss_param == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d Failed to get bss info for vap index %d\n",
                __func__, __LINE__, args->vap_index);
        return RETURN_ERR;
    }

    getVAPArrayIndexFromVAPIndex(args->vap_index, &vap_array_index);

    if (bss_param->enabled == false) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d vap_index %d enabled is false, clearing the sta_map\n",
                __func__, __LINE__, args->vap_index);
        if (mon_data->bssid_data[vap_array_index].sta_map != NULL) {
            sta = hash_map_get_first(mon_data->bssid_data[vap_array_index].sta_map);
            while (sta != NULL) {
                to_sta_key(sta->sta_mac, sta_key);
                sta = hash_map_get_next(mon_data->bssid_data[vap_array_index].sta_map, sta);
                tmp_sta = hash_map_remove(mon_data->bssid_data[vap_array_index].sta_map, sta_key);
                if (tmp_sta != NULL) {
                    free(tmp_sta);
                }
            }
            hash_map_destroy(mon_data->bssid_data[vap_array_index].sta_map);
            mon_data->bssid_data[vap_array_index].sta_map =  NULL;
        }
        return RETURN_OK;
    }

#if CCSP_WIFI_HAL
    ret = wifi_getApAssociatedDeviceDiagnosticResult3(args->vap_index, &dev_array, &num_devs);
#endif
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s : %d  Failed to get AP Associated Devices statistics for vap index %d \r\n",
                __func__, __LINE__, args->vap_index);
        return RETURN_ERR;
    }


    if (mon_data->bssid_data[vap_array_index].sta_map == NULL) {
        mon_data->bssid_data[vap_array_index].sta_map = hash_map_create();
        if (mon_data->bssid_data[vap_array_index].sta_map == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: hash map create failed for sta_map for vap_index : %d\n", __func__, __LINE__, args->vap_index);
            if (dev_array != NULL) {
                free(dev_array);
                dev_array = NULL;
            }
            return RETURN_ERR;
        }
    }

    sta_map = mon_data->bssid_data[vap_array_index].sta_map;

    hal_sta = dev_array;
    if (hal_sta != NULL) {
        for (i = 0; i < num_devs; i++) {
            to_sta_key(hal_sta->cli_MACAddress, sta_key);
            str_tolower(sta_key);
            sta = (sta_data_t *)hash_map_get(sta_map, sta_key);
            if (sta == NULL) {
                sta = (sta_data_t *)calloc(1, sizeof(sta_data_t));
                memset(sta, 0, sizeof(sta_data_t));
                memcpy(sta->sta_mac, hal_sta->cli_MACAddress, sizeof(mac_addr_t));
                hash_map_put(sta_map, strdup(sta_key), sta);
            }
            memcpy((unsigned char *)&sta->dev_stats_last, (unsigned char *)&sta->dev_stats, sizeof(wifi_associated_dev3_t));
            memcpy((unsigned char *)&sta->dev_stats, (unsigned char *)hal_sta, sizeof(wifi_associated_dev3_t));
            sta->updated = true;
            sta->dev_stats.cli_Active = true;
            sta->dev_stats.cli_SignalStrength = hal_sta->cli_SignalStrength;

            if (sta->dev_stats.cli_SignalStrength >= mon_data->sta_health_rssi_threshold) {
                temp_time = ((sta->good_rssi_time * 1000) + task_interval_ms)/1000;
                sta->good_rssi_time = temp_time;
            } else {
                temp_time = ((sta->bad_rssi_time * 1000) + task_interval_ms)/1000;
                sta->bad_rssi_time = temp_time;
            }
            temp_time = ((sta->connected_time * 1000) + task_interval_ms)/1000;
            sta->connected_time = temp_time;
            hal_sta++;
        }
    }
    sta = hash_map_get_first(sta_map);
    while (sta != NULL) {
        if (sta->updated == true) {
            sta->updated = false;
        } else {
            // this was not present in hal record
            temp_time = ((sta->disconnected_time * 1000) + task_interval_ms)/1000;
            sta->disconnected_time = temp_time;
            sta->dev_stats.cli_Active = false;
            wifi_util_dbg_print(WIFI_MON, "[%s:%d] Device:%s is disassociated from ap:%d, for %d amount of time, assoc status:%d\n",
                    __func__, __LINE__, to_sta_key(sta->sta_mac, sta_key), args->vap_index, sta->disconnected_time, sta->dev_stats.cli_Active);
            if ((sta->disconnected_time > mon_data->bssid_data[vap_array_index].ap_params.rapid_reconnect_threshold) &&  (sta->dev_stats.cli_Active == false)) {
                tmp_sta = sta;
            }
        }
        sta = hash_map_get_next(sta_map, sta);
        if (tmp_sta != NULL) {
            wifi_util_info_print(WIFI_MON, "[%s:%d] Device:%s being removed from map of ap:%d, and being deleted\n", __func__, __LINE__, to_sta_key(tmp_sta->sta_mac, sta_key), args->vap_index);
            wifi_util_info_print(WIFI_MON, "[%s:%d] Station info for, vap:%d ClientMac:%s\n", __func__, __LINE__,
                    (args->vap_index + 1), to_sta_key(tmp_sta->dev_stats.cli_MACAddress, sta_key));
            send_wifi_disconnect_event_to_ctrl(tmp_sta->sta_mac, args->vap_index);
            memset(sta_key, 0, sizeof(sta_key_t));
            to_sta_key(tmp_sta->sta_mac, sta_key);
            hash_map_remove(sta_map, sta_key);
            free(tmp_sta);
            tmp_sta = NULL;
        }
    }
    if (dev_array != NULL) {
        free(dev_array);
        dev_array = NULL;
    }

    return RETURN_OK;
}

int copy_assoc_client_stats_from_cache(wifi_mon_stats_args_t *args, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache)
{
    hash_map_t *sta_map = NULL;
    sta_data_t *temp_sta = NULL, *sta = NULL;
    unsigned int sta_count = 0, count = 0, vap_array_index = 0;
    wifi_front_haul_bss_t *bss_param = NULL;
    sta_key_t   sta_key;

    if ((args == NULL) || (mon_cache == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s : %d Invalid args args : %p mon_cache = %p\n",
                __func__,__LINE__, args, mon_cache);
        return RETURN_ERR;
    }
    bss_param = Get_wifi_object_bss_parameter(args->vap_index);
    if (bss_param == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d Failed to get bss info for vap index %d\n",
                __func__, __LINE__, args->vap_index);
        return RETURN_ERR;
    }

    getVAPArrayIndexFromVAPIndex(args->vap_index, &vap_array_index);

    if (bss_param->enabled == false) {
        wifi_util_error_print(WIFI_MON, "%s:%d vap_index %d enabled is false \n",
                __func__, __LINE__, args->vap_index);
        *stats = NULL;
        *stat_array_size = 0;
        return RETURN_OK;
    }

    sta_map = mon_cache->bssid_data[vap_array_index].sta_map ;
    if(sta_map != NULL) {
        *stats = NULL;
        *stat_array_size = 0;
        return RETURN_OK;
    }

    sta_count = hash_map_count(sta_map);
    sta = (sta_data_t *)calloc(sta_count, sizeof(sta_data_t));
    if (sta == NULL) {
        wifi_util_error_print(WIFI_MON, "%s : %d Failed to allocate memory for sta structure for %d\n",
                __func__,__LINE__, args->vap_index);
        return RETURN_ERR;
    }

    temp_sta = hash_map_get_first(sta_map);
    while(temp_sta != NULL) {
        memset(sta_key, 0, sizeof(sta_key_t));
        to_sta_key(temp_sta->sta_mac, sta_key);
        wifi_util_error_print(WIFI_MON, "%s:%d vap_index %d count : %d sta_key : %s\n",
                __func__, __LINE__, args->vap_index, count, sta_key);
        memcpy(&sta[count], temp_sta, sizeof(sta_data_t));
        count++;
        temp_sta = hash_map_get_next(sta_map, temp_sta);
    }

    *stats = sta;
    *stat_array_size = sta_count;

    return RETURN_OK;
}
