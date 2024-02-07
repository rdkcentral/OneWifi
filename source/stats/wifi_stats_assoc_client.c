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

#define MAC_ARG(arg) \
    arg[0], \
    arg[1], \
    arg[2], \
    arg[3], \
    arg[4], \
    arg[5]

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

#ifdef CCSP_COMMON
    snprintf(key_str, key_len, "%02d-%02d", mon_stats_type_associated_device_stats, args->vap_index);
#else
    snprintf(key_str, key_len, "%02d-%02d-%02x:%02x:%02x:%02x:%02x:%02x", mon_stats_type_associated_device_stats, args->vap_index, MAC_ARG(args->target_mac));
#endif

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

    snprintf(key_str, key_len, "%04d-%02d-%02d-%08lu", config->inst, mon_stats_type_associated_device_stats, config->args.vap_index, config->interval_ms);

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
    wifi_platform_property_t *wifi_prop = get_wifi_hal_cap_prop();
#ifndef CCSP_WIFI_HAL
    char *radio_type = NULL;
    int nf = 0;
    int sleep_mode = 0;
#endif

    if (args == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p\n",__func__,__LINE__, args);
        return RETURN_ERR;
    }

    UINT radio = get_radio_index_for_vap_index(wifi_prop, args->vap_index);

    if ((unsigned)RETURN_ERR == radio) {
        wifi_util_error_print(WIFI_MON, "%s:%d Error in getting wifi_prop\n", __func__,__LINE__);
        return RETURN_ERR;
    }

    if (mon_data->radio_presence[radio] == false) {
        wifi_util_info_print(WIFI_MON, "%s:%d radio_presence is false for radio : %d\n",__func__,__LINE__, radio);
        return RETURN_OK;
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
        }
        return RETURN_OK;
    }

#if CCSP_WIFI_HAL
    ret = wifi_getApAssociatedDeviceDiagnosticResult3(args->vap_index, &dev_array, &num_devs);
#else //CCSP_WIFI_HAL
    radio_type = mon_data->radio_data[radio].frequency_band;
    nf = mon_data->radio_data[radio].NoiseFloor;
    dev_array = (wifi_associated_dev3_t *) malloc (sizeof(wifi_associated_dev3_t));
    if (dev_array == NULL) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d dev_array is NULL\n", __func__,__LINE__);
        return RETURN_ERR;
    }
    memset(dev_array, 0,sizeof(wifi_associated_dev3_t));
    ret = ow_mesh_ext_get_device_stats(args->vap_index, radio_type, nf, args->target_mac, dev_array, &sleep_mode);

    dev_array->cli_MACAddress[0] = args->target_mac[0];
    dev_array->cli_MACAddress[1] = args->target_mac[1];
    dev_array->cli_MACAddress[2] = args->target_mac[2];
    dev_array->cli_MACAddress[3] = args->target_mac[3];
    dev_array->cli_MACAddress[4] = args->target_mac[4];
    dev_array->cli_MACAddress[5] = args->target_mac[5];

    num_devs = 1;
#endif

    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s : %d  Failed to get AP Associated Devices statistics for vap index %d \r\n",
                __func__, __LINE__, args->vap_index);
        return RETURN_ERR;
    }

#if CCSP_WIFI_HAL
    wifi_util_dbg_print(WIFI_MON, "%s:%d: diag result: number of devs: %d\n",
        __func__, __LINE__, num_devs);
    for (i = 0; i < num_devs; i++) {
        wifi_util_dbg_print(WIFI_MON, "cli_MACAddress: %s\ncli_AuthenticationState: %d\n"
            "cli_LastDataDownlinkRate: %d\ncli_LastDataUplinkRate: %d\ncli_SignalStrength: %d\n"
            "cli_Retransmissions: %d\ncli_Active: %d\ncli_OperatingStandard: %s\n"
            "cli_OperatingChannelBandwidth: %s\ncli_SNR: %d\ncli_InterferenceSources: %s\n"
            "cli_DataFramesSentAck: %d\ncli_DataFramesSentNoAck: %d\ncli_BytesSent: %d\n"
            "cli_BytesReceived: %d\ncli_RSSI: %d\ncli_MinRSSI: %d\ncli_MaxRSSI: %d\n"
            "cli_Disassociations: %d\ncli_AuthenticationFailures: %d\ncli_Associations: %llu\n"
            "cli_PacketsSent: %d\ncli_PacketsReceived: %d\ncli_ErrorsSent: %d\n"
            "cli_RetransCount: %d\ncli_FailedRetransCount: %d\ncli_RetryCount: %d\n"
            "cli_MultipleRetryCount: %d\ncli_MaxDownlinkRate: %d\ncli_MaxUplinkRate: %d\n"
            "cli_activeNumSpatialStreams: %d\ncli_TxFrames: %llu\ncli_RxRetries: %llu\n"
            "cli_RxErrors: %llu\n", to_sta_key(dev_array[i].cli_MACAddress, sta_key),
            dev_array[i].cli_AuthenticationState, dev_array[i].cli_LastDataDownlinkRate,
            dev_array[i].cli_LastDataUplinkRate, dev_array[i].cli_SignalStrength,
            dev_array[i].cli_Retransmissions, dev_array[i].cli_Active,
            dev_array[i].cli_OperatingStandard, dev_array[i].cli_OperatingChannelBandwidth,
            dev_array[i].cli_SNR, dev_array[i].cli_InterferenceSources,
            dev_array[i].cli_DataFramesSentAck, dev_array[i].cli_DataFramesSentNoAck,
            dev_array[i].cli_BytesSent, dev_array[i].cli_BytesReceived, dev_array[i].cli_RSSI,
            dev_array[i].cli_MinRSSI, dev_array[i].cli_MaxRSSI, dev_array[i].cli_Disassociations,
            dev_array[i].cli_AuthenticationFailures, dev_array[i].cli_Associations,
            dev_array[i].cli_PacketsSent, dev_array[i].cli_PacketsReceived,
            dev_array[i].cli_ErrorsSent, dev_array[i].cli_RetransCount,
            dev_array[i].cli_FailedRetransCount, dev_array[i].cli_RetryCount,
            dev_array[i].cli_MultipleRetryCount, dev_array[i].cli_MaxDownlinkRate,
            dev_array[i].cli_MaxUplinkRate, dev_array[i].cli_activeNumSpatialStreams,
            dev_array[i].cli_TxFrames, dev_array[i].cli_RxRetries,
            dev_array[i].cli_RxErrors);
    }
#endif

#ifdef CCSP_COMMON
    events_update_clientdiagdata(num_devs, args->vap_index, dev_array);
#endif
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
            wifi_util_dbg_print(WIFI_MON, "Polled station info for, vap:%d ClientMac:%s Uplink rate:%d Downlink rate:%d Packets Sent:%d Packets Received:%d Errors Sent:%d Retrans:%d\n",
                    (args->vap_index)+1, to_sta_key(sta->dev_stats.cli_MACAddress, sta_key), sta->dev_stats.cli_LastDataUplinkRate, sta->dev_stats.cli_LastDataDownlinkRate,
                    sta->dev_stats.cli_PacketsSent, sta->dev_stats.cli_PacketsReceived, sta->dev_stats.cli_ErrorsSent, sta->dev_stats.cli_RetransCount);
            wifi_util_dbg_print(WIFI_MON, "%s:%d cli_TxFrames : %llu cli_RxRetries : %llu cli_RxErrors : %llu  \n",
                            __func__, __LINE__, hal_sta->cli_TxFrames, hal_sta->cli_RxRetries, hal_sta->cli_RxErrors);
#ifndef CCSP_WIFI_HAL
            sta->sleep_mode = sleep_mode;
            wifi_util_dbg_print(WIFI_MON, "%s:%d Value of Sleep mode is %d \n", __func__,__LINE__, sta->sleep_mode);
#endif
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
            tmp_sta = hash_map_remove(sta_map, sta_key);
            if (tmp_sta != NULL) {
                free(tmp_sta);
                tmp_sta = NULL;
            }
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
        wifi_util_dbg_print(WIFI_MON, "%s:%d vap_index %d enabled is false \n",
                __func__, __LINE__, args->vap_index);
        *stats = NULL;
        *stat_array_size = 0;
        return RETURN_OK;
    }

    sta_map = mon_cache->bssid_data[vap_array_index].sta_map ;
    if(sta_map == NULL) {
        *stats = NULL;
        *stat_array_size = 0;
        return RETURN_OK;
    }

    sta_count = hash_map_count(sta_map);
    if (sta_count == 0) {
        *stats = NULL;
        *stat_array_size = 0;
        return RETURN_OK;
    }

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
        wifi_util_dbg_print(WIFI_MON, "%s:%d vap_index %d count : %d sta_key : %s\n",
                __func__, __LINE__, args->vap_index, count, sta_key);
        memcpy(&sta[count], temp_sta, sizeof(sta_data_t));
        count++;
        temp_sta = hash_map_get_next(sta_map, temp_sta);
    }

    *stats = sta;
    *stat_array_size = sta_count;

    return RETURN_OK;
}

