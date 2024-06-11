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
#include "timespec_macro.h"

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

    snprintf(key_str, key_len, "%04d-%02d-%02d-%08d", config->inst, mon_stats_type_associated_device_stats, config->args.vap_index, config->args.app_info);

    wifi_util_dbg_print(WIFI_MON, "%s:%d: provider stats key: %s\n", __func__,__LINE__, key_str);

    return RETURN_OK;
}

int execute_assoc_client_stats_api(wifi_mon_collector_element_t *c_elem, wifi_monitor_t *mon_data, unsigned long task_interval_ms)
{
    wifi_front_haul_bss_t *bss_param = NULL;
    wifi_associated_dev3_t *dev_array = NULL;
    wifi_mon_stats_args_t *args = NULL;
    unsigned int num_devs = 0;
    unsigned int vap_array_index;
    wifi_associated_dev3_t  *hal_sta;
    sta_key_t   sta_key;
    sta_key_t   mld_sta_key;
    unsigned int i = 0;
    hash_map_t *sta_map;
    sta_data_t *sta = NULL,  *tmp_sta = NULL;
    int ret = RETURN_OK;
    int mld_mac_present = 0;
    mac_address_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    wifi_platform_property_t *wifi_prop = get_wifi_hal_cap_prop();
    struct timespec tv_now, t_diff, t_tmp;
    unsigned int disconnected_time;

    if (c_elem == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d input arguments are NULL args : %p\n",__func__,__LINE__, c_elem);
        return RETURN_ERR;
    }

    args = c_elem->args;
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

    ret = wifi_getApAssociatedDeviceDiagnosticResult3(args->vap_index, &dev_array, &num_devs);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s : %d  Failed to get AP Associated Devices statistics for vap index %d \r\n",
                __func__, __LINE__, args->vap_index);
        if (dev_array != NULL) {
            free(dev_array);
            dev_array = NULL;
        }
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_MON, "%s:%d: diag result: number of devs: %d\n",
        __func__, __LINE__, num_devs);
    for (i = 0; i < num_devs; i++) {
        wifi_util_dbg_print(WIFI_MON, "cli_MACAddress: %s\ncli_MLDAddr: %s\ncli_MLDEnable: %d\ncli_AuthenticationState: %d\n"
            "cli_LastDataDownlinkRate: %d\ncli_LastDataUplinkRate: %d\ncli_SignalStrength: %d\n"
            "cli_Retransmissions: %d\ncli_Active: %d\ncli_OperatingStandard: %s\n"
            "cli_OperatingChannelBandwidth: %s\ncli_SNR: %d\ncli_InterferenceSources: %s\n"
            "cli_DataFramesSentAck: %lu\ncli_DataFramesSentNoAck: %lu\ncli_BytesSent: %lu\n"
            "cli_BytesReceived: %lu\ncli_RSSI: %d\ncli_MinRSSI: %d\ncli_MaxRSSI: %d\n"
            "cli_Disassociations: %d\ncli_AuthenticationFailures: %d\ncli_Associations: %llu\n"
            "cli_PacketsSent: %lu\ncli_PacketsReceived: %lu\ncli_ErrorsSent: %lu\n"
            "cli_RetransCount: %lu\ncli_FailedRetransCount: %lu\ncli_RetryCount: %lu\n"
            "cli_MultipleRetryCount: %lu\ncli_MaxDownlinkRate: %d\ncli_MaxUplinkRate: %d\n"
            "cli_activeNumSpatialStreams: %d\ncli_TxFrames: %llu\ncli_RxRetries: %llu\n"
            "cli_RxErrors: %llu\n", to_sta_key(dev_array[i].cli_MACAddress, sta_key),
            to_sta_key(dev_array[i].cli_MLDAddr, mld_sta_key), dev_array[i].cli_MLDEnable,
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

    clock_gettime(CLOCK_MONOTONIC, &tv_now);
    sta_map = mon_data->bssid_data[vap_array_index].sta_map;

    if (num_devs != 0) {
        wifi_util_dbg_print(WIFI_MON,"%s:%d ap_index:%d num_devs:%d\r\n", __func__, __LINE__, args->vap_index, num_devs);
    }

    hal_sta = dev_array;

    if (hal_sta != NULL) {
        for (i = 0; i < num_devs; i++) {
            if (memcmp(hal_sta->cli_MLDAddr, zero_mac, sizeof(mac_address_t)) == 0) {
                to_sta_key(hal_sta->cli_MACAddress, sta_key);
                mld_mac_present = 0;
            } else {
                to_sta_key(hal_sta->cli_MLDAddr, sta_key);
                mld_mac_present = 1;
            }
            str_tolower(sta_key);
            sta = (sta_data_t *)hash_map_get(sta_map, sta_key);
            if (sta == NULL) {
                sta = (sta_data_t *)calloc(1, sizeof(sta_data_t));
                if (sta == NULL) {
                    wifi_util_error_print(WIFI_MON, "%s:%d Failed to allocate memory:sta:%s\n", __func__, __LINE__, sta_key);
                    break;
                }
                memset(sta, 0, sizeof(sta_data_t));
                if (mld_mac_present == 0) {
                    memcpy(sta->sta_mac, hal_sta->cli_MACAddress, sizeof(mac_address_t));
                } else {
                    wifi_util_dbg_print(WIFI_MON, "%s:%d mld mac %s\n", __func__, __LINE__, to_sta_key(hal_sta->cli_MLDAddr, mld_sta_key));
                    memcpy(sta->sta_mac, hal_sta->cli_MLDAddr, sizeof(mac_address_t));
                    memcpy(sta->link_mac, hal_sta->cli_MACAddress, sizeof(mac_address_t));
                    memcpy(hal_sta->cli_MACAddress, hal_sta->cli_MLDAddr, sizeof(mac_address_t));
                    sta->primary_link = 0;
                }
                hash_map_put(sta_map, strdup(sta_key), sta);
                sta->last_connected_time.tv_sec = tv_now.tv_sec;
                sta->last_connected_time.tv_nsec = tv_now.tv_nsec;
            } else {
                if (mld_mac_present != 0) {
                    memcpy(hal_sta->cli_MACAddress, hal_sta->cli_MLDAddr, sizeof(mac_address_t));
                }
            }
            memcpy((unsigned char *)&sta->dev_stats_last, (unsigned char *)&sta->dev_stats, sizeof(wifi_associated_dev3_t));
            memcpy((unsigned char *)&sta->dev_stats, (unsigned char *)hal_sta, sizeof(wifi_associated_dev3_t));
            sta->updated = true;
            sta->dev_stats.cli_Active = true;
            sta->dev_stats.cli_SignalStrength = hal_sta->cli_SignalStrength;

            if (timespeccmp(&(sta->last_connected_time), &(mon_data->bssid_data[vap_array_index].last_sta_update_time), >)) {//sta disconnected before counter update
                timespecsub(&tv_now, &(sta->last_connected_time), &t_diff);
            } else {
                timespecsub(&tv_now, &(mon_data->bssid_data[vap_array_index].last_sta_update_time), &t_diff);
            }

            if (sta->dev_stats.cli_SignalStrength >= mon_data->sta_health_rssi_threshold) {
                sta->good_rssi_time += t_diff.tv_sec;
            } else {
                sta->bad_rssi_time += t_diff.tv_sec;
            }

            t_tmp.tv_sec = sta->total_connected_time.tv_sec;
            t_tmp.tv_nsec = sta->total_connected_time.tv_nsec;
            timespecadd(&t_tmp, &t_diff, &(sta->total_connected_time));

            wifi_util_dbg_print(WIFI_MON, "%s:%d mac %s\n", __func__, __LINE__, to_sta_key(sta->dev_stats.cli_MACAddress, sta_key));
            wifi_util_dbg_print(WIFI_MON, "%s:%d total_connected_time %lld ms\n", __func__, __LINE__, (long long)(sta->total_connected_time.tv_sec*1000)+(sta->total_connected_time.tv_nsec/1000000));
            wifi_util_dbg_print(WIFI_MON, "%s:%d total_disconnected_time %lld ms\n", __func__, __LINE__, (long long)(sta->total_disconnected_time.tv_sec*1000)+(sta->total_disconnected_time.tv_nsec/1000000));

            wifi_util_dbg_print(WIFI_MON, "Polled station info for, vap:%d ClientMac:%s Uplink rate:%d Downlink rate:%d Packets Sent:%d Packets Received:%d Errors Sent:%d Retrans:%d\n",
                    (args->vap_index)+1, to_sta_key(sta->dev_stats.cli_MACAddress, sta_key), sta->dev_stats.cli_LastDataUplinkRate, sta->dev_stats.cli_LastDataDownlinkRate,
                    sta->dev_stats.cli_PacketsSent, sta->dev_stats.cli_PacketsReceived, sta->dev_stats.cli_ErrorsSent, sta->dev_stats.cli_RetransCount);
            wifi_util_dbg_print(WIFI_MON, "%s:%d cli_TxFrames : %llu cli_RxRetries : %llu cli_RxErrors : %llu  \n",
                            __func__, __LINE__, hal_sta->cli_TxFrames, hal_sta->cli_RxRetries, hal_sta->cli_RxErrors);
            hal_sta++;
            if (hal_sta == NULL) {
                wifi_util_error_print(WIFI_MON, "%s:%d hal_sta is NULL: ap_index:%d index:%d num_devs:%d\n", __func__, __LINE__, args->vap_index, i, num_devs);
                break;
            }
        }
    }
    sta = hash_map_get_first(sta_map);
    while (sta != NULL) {
        int send_disconnect_event = 1;
        if (sta->updated == true) {
            sta->updated = false;
        } else {
            
            if (timespecisset(&(sta->total_connected_time))) {
                if (sta->dev_stats.cli_Active == true) {
                    sta->last_disconnected_time.tv_sec = tv_now.tv_sec;
                    sta->last_disconnected_time.tv_nsec = tv_now.tv_nsec;
                    t_diff.tv_sec = 0;
                    t_diff.tv_nsec = 0;
                } else if (timespeccmp(&(sta->last_disconnected_time), &(mon_data->bssid_data[vap_array_index].last_sta_update_time), >)) {//sta disconnected before counter update
                    timespecsub(&tv_now, &(sta->last_disconnected_time), &t_diff);
                } else {
                    timespecsub(&tv_now, &(mon_data->bssid_data[vap_array_index].last_sta_update_time), &t_diff);
                }
                t_tmp.tv_sec = sta->total_disconnected_time.tv_sec;
                t_tmp.tv_nsec = sta->total_disconnected_time.tv_nsec;
                timespecadd(&t_tmp, &t_diff, &(sta->total_disconnected_time));
                
                wifi_util_dbg_print(WIFI_MON, "%s:%d mac %s\n", __func__, __LINE__, to_sta_key(sta->dev_stats.cli_MACAddress, sta_key));
                wifi_util_dbg_print(WIFI_MON, "%s:%d total_connected_time %lu ms\n", __func__, __LINE__, (sta->total_connected_time.tv_sec*1000)+(sta->total_connected_time.tv_nsec/1000000));
                wifi_util_dbg_print(WIFI_MON, "%s:%d total_disconnected_time %lu ms\n", __func__, __LINE__, (sta->total_disconnected_time.tv_sec*1000)+(sta->total_disconnected_time.tv_nsec/1000000));

                disconnected_time = (tv_now.tv_sec - sta->last_disconnected_time.tv_sec);
                sta->dev_stats.cli_Active = false;
                wifi_util_dbg_print(WIFI_MON, "[%s:%d] Device:%s is disassociated from ap:%d, for %d amount of time, assoc status:%d\n",
                        __func__, __LINE__, to_sta_key(sta->sta_mac, sta_key), args->vap_index, disconnected_time, sta->dev_stats.cli_Active);
                if ((disconnected_time > mon_data->bssid_data[vap_array_index].ap_params.rapid_reconnect_threshold) &&  (sta->dev_stats.cli_Active == false)) {
                    tmp_sta = sta;
                }
            } else {
                //client never connected, only storing the assoc request.
                if (tv_now.tv_sec - sta->assoc_frame_data.frame_timestamp > 5) {
                    //remove this entry after 5 seconds, should not trigger a disconnect event.
                    send_disconnect_event = 0;
                    tmp_sta = sta;
                }
            }
        }
        sta = hash_map_get_next(sta_map, sta);
        if (tmp_sta != NULL) {
            wifi_util_info_print(WIFI_MON, "[%s:%d] Device:%s being removed from map of ap:%d, and being deleted\n", __func__, __LINE__, to_sta_key(tmp_sta->sta_mac, sta_key), args->vap_index);
            wifi_util_info_print(WIFI_MON, "[%s:%d] Station info for, vap:%d ClientMac:%s\n", __func__, __LINE__,
                    (args->vap_index + 1), to_sta_key(tmp_sta->dev_stats.cli_MACAddress, sta_key));
            if (send_disconnect_event) {
                send_wifi_disconnect_event_to_ctrl(tmp_sta->sta_mac, args->vap_index);
            }
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

    mon_data->bssid_data[vap_array_index].last_sta_update_time.tv_sec = tv_now.tv_sec;
    mon_data->bssid_data[vap_array_index].last_sta_update_time.tv_nsec = tv_now.tv_nsec;

    return RETURN_OK;
}

int copy_assoc_client_stats_from_cache(wifi_mon_provider_element_t *p_elem, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache)
{
    hash_map_t *sta_map = NULL;
    sta_data_t *temp_sta = NULL, *sta = NULL;
    unsigned int sta_count = 0, count = 0, vap_array_index = 0;
    wifi_front_haul_bss_t *bss_param = NULL;
    sta_key_t   sta_key;
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

