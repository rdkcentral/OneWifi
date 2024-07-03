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
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_stubs.h"
#include "wifi_util.h"
#include "wifi_apps_mgr.h"
#include "wifi_cac.h"
#include "wifi_hal_rdk_framework.h"
#include "wifi_monitor.h"
#include <rbus.h>

void cac_print(char *format, ...)
{
    char buff[256] = {0};
    va_list list;
    FILE *fpg = NULL;

    get_formatted_time(buff);
    strncat(buff, " ", strlen(buff));

    va_start(list, format);
    vsprintf(&buff[strlen(buff)], format, list);
    va_end(list);

    fpg = fopen("/rdklogs/logs/wifiConnAdmissionCtrl.txt", "a+");
    if (fpg == NULL) {
        return;
    }
    fputs(buff, fpg);
    fflush(fpg);
    fclose(fpg);
}

void telemetry_event_cac(char *deny_type,int index, char *deny_reason,char *mac,int threshold ,int value)
{
    char telemetry_buff[64] = {0};
    char telemetry_val[128] = {0};

    if (!deny_type || !deny_reason || !mac ) {
        return;
    }

    memset(telemetry_buff, 0, sizeof(telemetry_buff));
    memset(telemetry_val, 0, sizeof(telemetry_val));

    if (isVapHotspotSecure5g(index)) {
        snprintf(telemetry_buff,sizeof(telemetry_buff),"XWIFIS_%s_accum",deny_type);
        snprintf(telemetry_val,sizeof(telemetry_val),"%s,%s,%d,%d",deny_reason,mac,threshold,value);
    } else if (isVapHotspotOpen5g(index)) {
        snprintf(telemetry_buff,sizeof(telemetry_buff),"XWIFI_%s_accum",deny_type);
        snprintf(telemetry_val,sizeof(telemetry_val),"%s,%s,%d,%d",deny_reason,mac,threshold,value);
    } else if (isVapHotspotSecure6g(index)) {
        snprintf(telemetry_buff,sizeof(telemetry_buff),"XWIFIS_6G%s_accum",deny_type);
        snprintf(telemetry_val,sizeof(telemetry_val),"%s,%s,%d,%d",deny_reason,mac,threshold,value);
    } else if (isVapHotspotOpen6g(index)) {
        snprintf(telemetry_buff,sizeof(telemetry_buff),"XWIFI_6G%s_accum",deny_type);
        snprintf(telemetry_val,sizeof(telemetry_val),"%s,%s,%d,%d",deny_reason,mac,threshold,value);
    } else {
        return;
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d telemetry_buff=%s and telemetry_val=%s\n", __func__, __LINE__,telemetry_buff,telemetry_val);
    get_stubs_descriptor()->t2_event_s_fn(telemetry_buff, telemetry_val);
}

int cac_event_exec_start(wifi_app_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

int cac_event_exec_stop(wifi_app_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

typedef struct wifi_params_mcsindex_rate {
  char  *oper_standard;      /* Operating standard - n/ac/ax */
  char  *bw;                 /* bandwidth 20/40/80/160 */
  int   gi;                  /* guard interval 400nsec/Auto = 1 800nsec = -1*/
  int   mcs_index;           /* mcs_index*/
  int   rate;                /* Max uplink/downlink rate */
} wifi_params_mcsindex_rate_t;

wifi_params_mcsindex_rate_t mcsindex_rate_tbl[] = {
  /* Standard,  BW, GI, MCSIndex,  Rate */
  {"n",   "20", 1,  0,  7},
  {"n",   "20", 1,  1,  14},
  {"n",   "20", 1,  2,  22},
  {"n",   "20", 1,  3,  29},
  {"n",   "20", 1,  4,  43},
  {"n",   "20", 1,  5,  58},
  {"n",   "20", 1,  6,  65},
  {"n",   "20", 1,  7,  72},

  {"n",   "20", -1,  0,  7},
  {"n",   "20", -1,  1,  13},
  {"n",   "20", -1,  2,  20},
  {"n",   "20", -1,  3,  26},
  {"n",   "20", -1,  4,  39},
  {"n",   "20", -1,  5,  52},
  {"n",   "20", -1,  6,  59},
  {"n",   "20", -1,  7,  65},

  {"n",   "40", 1,  0,  15},
  {"n",   "40", 1,  1,  30},
  {"n",   "40", 1,  2,  45},
  {"n",   "40", 1,  3,  60},
  {"n",   "40", 1,  4,  90},
  {"n",   "40", 1,  5,  120},
  {"n",   "40", 1,  6,  135},
  {"n",   "40", 1,  7,  150},

  {"n",   "40", -1, 0,  14},
  {"n",   "40", -1, 1,  27},
  {"n",   "40", -1, 2,  41},
  {"n",   "40", -1, 3,  54},
  {"n",   "40", -1, 4,  81},
  {"n",   "40", -1, 5,  108},
  {"n",   "40", -1, 6,  122},
  {"n",   "40", -1, 7,  135},

  {"ac",    "20", 1,  0,  7},
  {"ac",    "20", 1,  1,  14},
  {"ac",    "20", 1,  2,  22},
  {"ac",    "20", 1,  3,  29},
  {"ac",    "20", 1,  4,  43},
  {"ac",    "20", 1,  5,  58},
  {"ac",    "20", 1,  6,  65},
  {"ac",    "20", 1,  7,  72},
  {"ac",    "20", -1, 0,  7},
  {"ac",    "20", -1, 1,  13},
  {"ac",    "20", -1, 2,  20},
  {"ac",    "20", -1, 3,  26},
  {"ac",    "20", -1, 4,  39},
  {"ac",    "20", -1, 5,  52},
  {"ac",    "20", -1, 6,  59},
  {"ac",    "20", -1, 7,  65},

  {"ac",    "40", 1,  0,  15},
  {"ac",    "40", 1,  1,  30},
  {"ac",    "40", 1,  2,  45},
  {"ac",    "40", 1,  3,  60},
  {"ac",    "40", 1,  4,  90},
  {"ac",    "40", 1,  5,  120},
  {"ac",    "40", 1,  6,  135},
  {"ac",    "40", 1,  7,  150},

  {"ac",    "40", -1, 0,  14},
  {"ac",    "40", -1, 1,  27},
  {"ac",    "40", -1, 2,  41},
  {"ac",    "40", -1, 3,  54},
  {"ac",    "40", -1, 4,  81},
  {"ac",    "40", -1, 5,  108},
  {"ac",    "40", -1, 6,  122},
  {"ac",    "40", -1, 7,  135},

  {"ac",    "80", 1,  0,  33},
  {"ac",    "80", 1,  1,  65},
  {"ac",    "80", 1,  2,  98},
  {"ac",    "80", 1,  3,  130},
  {"ac",    "80", 1,  4,  195},
  {"ac",    "80", 1,  5,  260},
  {"ac",    "80", 1,  6,  293},
  {"ac",    "80", 1,  7,  325},
  {"ac",    "80", -1, 0,  29},
  {"ac",    "80", -1, 1,  59},
  {"ac",    "80", -1, 2,  88},
  {"ac",    "80", -1, 3,  117},
  {"ac",    "80", -1, 4,  176},
  {"ac",    "80", -1, 5,  234},
  {"ac",    "80", -1, 6,  263},
  {"ac",    "80", -1, 7,  293},

  {"ac",    "160",  1,  0,  65},
  {"ac",    "160",  1,  1,  130},
  {"ac",    "160",  1,  2,  195},
  {"ac",    "160",  1,  3,  260},
  {"ac",    "160",  1,  4,  390},
  {"ac",    "160",  1,  5,  520},
  {"ac",    "160",  1,  6,  585},
  {"ac",    "160",  1,  7,  650},

  {"ac",    "160",  -1, 0,  56},
  {"ac",    "160",  -1, 1,  117},
  {"ac",    "160",  -1, 2,  176},
  {"ac",    "160",  -1, 3,  234},
  {"ac",    "160",  -1, 4,  351},
  {"ac",    "160",  -1, 5,  468},
  {"ac",    "160",  -1, 6,  527},
  {"ac",    "160",  -1, 7,  585},

  {"ax",    "20", 1,  0,  9},
  {"ax",    "20", 1,  1,  17},
  {"ax",    "20", 1,  2,  26},
  {"ax",    "20", 1,  3,  34},
  {"ax",    "20", 1,  4,  52},
  {"ax",    "20", 1,  5,  69},
  {"ax",    "20", 1,  6,  77},
  {"ax",    "20", 1,  7,  86},

  {"ax",    "40", 1,  0,  17},
  {"ax",    "40", 1,  1,  34},
  {"ax",    "40", 1,  2,  52},
  {"ax",    "40", 1,  3,  69},
  {"ax",    "40", 1,  4,  103},
  {"ax",    "40", 1,  5,  138},
  {"ax",    "40", 1,  6,  155},
  {"ax",    "40", 1,  7,  172},
  {"ax",    "80", 1,  0,  36},
  {"ax",    "80", 1,  1,  72},
  {"ax",    "80", 1,  2,  108},
  {"ax",    "80", 1,  3,  144},
  {"ax",    "80", 1,  4,  216},
  {"ax",    "80", 1,  5,  288},
  {"ax",    "80", 1,  6,  324},
  {"ax",    "80", 1,  7,  360},

  {"ax",    "160",  1,  0,  72},
  {"ax",    "160",  1,  1,  144},
  {"ax",    "160",  1,  2,  216},
  {"ax",    "160",  1,  3,  288},
  {"ax",    "160",  1,  4,  432},
  {"ax",    "160",  1,  5,  577},
  {"ax",    "160",  1,  6,  649},
  {"ax",    "160",  1,  7,  721},

};

int get_minrate_from_mcs( char *cli_OperatingStandard, char *cli_OperatingChannelBandwidth, int mcs)
{
    int i = 0 , gi = 0;
    int tbl_size = sizeof(mcsindex_rate_tbl) / sizeof(mcsindex_rate_tbl[0]);
    gi = 1;  //Guard interval is Auto for both 2.4G and 5G radio

    for (i = 0; i < tbl_size; i++) {
      if (!strcmp(mcsindex_rate_tbl[i].oper_standard, cli_OperatingStandard) &&
        !strcmp(mcsindex_rate_tbl[i].bw, cli_OperatingChannelBandwidth) &&
        mcsindex_rate_tbl[i].gi == gi && mcsindex_rate_tbl[i].mcs_index == mcs) {
        return mcsindex_rate_tbl[i].rate;
      }
    }
    return 0;
}

int cac_event_exec_timeout(wifi_app_t *apps, void *arg)
{
    hash_map_t *assoc_map = apps->data.u.cac.assoc_req_map;
    hash_map_t *sta_map = apps->data.u.cac.sta_map;
    cac_sta_info_t *elem;
    cac_sta_info_t *tmp_elem;
    cac_associated_devices_t *client;
    wifi_postassoc_control_t wifidb_postassoc_conf = { 0 };
    wifi_preassoc_control_t wifidb_preassoc_conf = { 0 };
    int *preassoc_basic_rates={0};
    char basic_buf[32] = {0};
    wifi_radioTrafficStats2_t chan_stats;
    char vap_name[32];
    int radio_index = 0;
    int chan_util = 0;
    cac_status_t status = status_ok;
    assoc_dev_data_t *assoc_dev_data = NULL;
    int itr, itrj;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    bool found = false;
    char *str;
    int rssi_conf = 0, snr_conf = 0, cu_conf = 0, mcs_conf = 0, min_rate = 0;
    float min_mbr_rate = 0;
    bool rssi_enabled, snr_enabled, chan_util_enabled, mcs_enabled, mbr_enabled;
    bool threshold_breached = false;

    mac_addr_str_t mac_str = { 0 };

    if (assoc_map != NULL) {
        elem = hash_map_get_first(assoc_map);

        while (elem != NULL) {
            elem->seconds_alive--;

            if(elem->seconds_alive == 0) {
                memset(mac_str, 0, sizeof(mac_str));
                strncpy(mac_str, elem->mac_addr, sizeof(mac_str));
                elem = hash_map_get_next(assoc_map, elem);
                tmp_elem = hash_map_remove(assoc_map, mac_str);

                if (tmp_elem != NULL) {
                    free(tmp_elem);
                }
            } else {
                elem = hash_map_get_next(assoc_map, elem);
            }
        }
    }

    if (sta_map != NULL) {
        client = hash_map_get_first(sta_map);

        while (client != NULL) {
            convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, client->ap_index, vap_name);
            wifidb_get_postassoc_ctrl_config(vap_name, &wifidb_postassoc_conf);
            wifidb_get_preassoc_ctrl_config(vap_name, &wifidb_preassoc_conf);
            radio_index = convert_vap_name_to_radio_array_index(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
            if (radio_index < 0) {
                client = hash_map_get_next(sta_map, client);
                continue;
            }
            get_radio_channel_utilization(radio_index, &chan_util);

            if (strcmp(wifidb_postassoc_conf.rssi_up_threshold, "disabled") == 0) {
                rssi_enabled = false;
            } else {
                rssi_enabled = true;
                rssi_conf = atoi(wifidb_postassoc_conf.rssi_up_threshold);
            }

            if (strcmp(wifidb_postassoc_conf.snr_threshold, "disabled") == 0) {
                snr_enabled = false;
            } else {
                snr_enabled = true;
                snr_conf = atoi(wifidb_postassoc_conf.snr_threshold);
            }

            if (strcmp(wifidb_postassoc_conf.cu_threshold, "disabled") == 0) {
                chan_util_enabled = false;
            } else {
                chan_util_enabled = true;
                cu_conf = atoi(wifidb_postassoc_conf.cu_threshold);
            }

            if (strcmp(wifidb_preassoc_conf.minimum_advertised_mcs, "disabled") == 0) {
                mcs_enabled = false;
            } else {
                mcs_enabled = true;
                mcs_conf = atoi(wifidb_preassoc_conf.minimum_advertised_mcs);
            }
            if ((strlen (wifidb_preassoc_conf.basic_data_transmit_rates) > 0) && strcmp(wifidb_preassoc_conf.basic_data_transmit_rates, "disabled")) {
                mbr_enabled = true;
                snprintf(basic_buf, sizeof(basic_buf), "%s", wifidb_preassoc_conf.basic_data_transmit_rates);
                convert_string_to_int(&preassoc_basic_rates, basic_buf);
            } else {
                mbr_enabled = false;
            }

            get_min_rate(preassoc_basic_rates, &min_mbr_rate);
            if(preassoc_basic_rates) {
                free(preassoc_basic_rates);
                preassoc_basic_rates = NULL;
            }

            if (!rssi_enabled && !snr_enabled && !chan_util_enabled && !mcs_enabled && !mbr_enabled) {
                client = hash_map_get_next(sta_map, client);
                continue;
            }

            client->sampling_interval--;

            if (client->sampling_interval == 0 && client->sampling_count != 0) {
                for (itr=0; itr<MAX_NUM_RADIOS; itr++) {
                    for (itrj=0; itrj<MAX_NUM_VAP_PER_RADIO; itrj++) {
                        if (mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_map != NULL && !found) {
                            assoc_dev_data = hash_map_get_first(mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_map);
                            while (assoc_dev_data != NULL) {
                                get_sta_stats_info(assoc_dev_data);
                                if (((unsigned int)assoc_dev_data->ap_index == client->ap_index) &&
                                    (memcmp(client->sta_mac,assoc_dev_data->dev_stats.cli_MACAddress,sizeof(mac_address_t))== 0 )) {
                                    found = true;
                                    break;
                                }
                                assoc_dev_data = hash_map_get_next(mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_map, assoc_dev_data);
                            }
                        }
                    }
                }

                found = false;

                get_radio_data(radio_index, &chan_stats);
                if (assoc_dev_data != NULL) {
                    client->rssi_avg = EXP_WEIGHT * client->rssi_avg + (1 - EXP_WEIGHT) * assoc_dev_data->dev_stats.cli_RSSI;
                    client->snr_avg = EXP_WEIGHT * client->snr_avg + (1 - EXP_WEIGHT) * (assoc_dev_data->dev_stats.cli_RSSI - chan_stats.radio_NoiseFloor);
                    client->uplink_rate_avg = EXP_WEIGHT * client->uplink_rate_avg + (1 - EXP_WEIGHT) * assoc_dev_data->dev_stats.cli_LastDataUplinkRate;
                    min_rate = get_minrate_from_mcs(assoc_dev_data->dev_stats.cli_OperatingStandard, assoc_dev_data->dev_stats.cli_OperatingChannelBandwidth, mcs_conf);
                }

                client->sampling_count--;

                if (client->sampling_count == 0) {

                    threshold_breached = false;

                    memset(mac_str, 0, sizeof(mac_str));
                    str = to_mac_str(client->sta_mac, mac_str);
                    wifi_util_dbg_print(WIFI_APPS,"%s:%d client rssi = %d, rssi threshold = %d mac_str=%s\r\n", __func__, __LINE__,
                                    client->rssi_avg, rssi_conf,mac_str);
                    if (rssi_enabled && (client->rssi_avg < rssi_conf)) {
                        threshold_breached = true;
                        cac_print("%s:%d, POSTASSOC DENY: %d,RSSI,%s,%d,%d\n", __func__, __LINE__, (client->ap_index + 1), str, rssi_conf, client->rssi_avg);
                        status = status_deny;
                        notify_force_disassociation(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, client->ap_index, "RSSI", str, rssi_conf, client->rssi_avg);
                        telemetry_event_cac("POSTDENY",client->ap_index, "RSSI", str, rssi_conf, client->rssi_avg);
                    }

                    wifi_util_dbg_print(WIFI_APPS,"%s:%d client snr = %d, snr threshold = %d\r\n", __func__, __LINE__,
                                    client->snr_avg, snr_conf);
                    if (!(threshold_breached) && snr_enabled && (client->snr_avg < snr_conf)) {
                        threshold_breached = true;
                        cac_print("%s:%d, POSTASSOC DENY: %d,SNR,%s,%d,%d\n", __func__, __LINE__, (client->ap_index + 1), str, snr_conf, client->snr_avg);
                        status = status_deny;
                        notify_force_disassociation(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, client->ap_index , "SNR", str, snr_conf, client->snr_avg);
                        telemetry_event_cac("POSTDENY",client->ap_index, "SNR", str, snr_conf, client->snr_avg);
                    }

                    wifi_util_dbg_print(WIFI_APPS,"%s:%d client cu = %d, cu threshold = %d\r\n", __func__, __LINE__,
                                    chan_util, cu_conf);
                    if (!(threshold_breached) && chan_util_enabled && (chan_util > cu_conf)) {
                        threshold_breached = true;
                        cac_print("%s:%d, POSTASSOC DENY: %d,CU,%s,%d,%d\n", __func__, __LINE__, (client->ap_index + 1), str, cu_conf, chan_util);
                        status = status_deny;
                        notify_force_disassociation(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, client->ap_index, "CU", str, cu_conf, chan_util);
                        telemetry_event_cac("POSTDENY", client->ap_index, "CU", str, cu_conf, chan_util);
                    }

                    wifi_util_info_print(WIFI_APPS,"%s:%d  client avg rate= %d, mcs_conf = %d min_mbr_rate:%.1f min_rate:%d\r\n", __func__, __LINE__,client->uplink_rate_avg,mcs_conf,min_mbr_rate,min_rate);

                    if(!(threshold_breached) && mcs_enabled && min_rate > 0 && (client->uplink_rate_avg < min_rate)) {
                        threshold_breached = true;
                        cac_print("%s:%d, POSTASSOC DENY: %d,MCS,%s,%d,%d\n", __func__, __LINE__, (client->ap_index + 1), str, mcs_conf, client->uplink_rate_avg);
                        status = status_deny;
                        notify_force_disassociation(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, client->ap_index, "MCS", str, mcs_conf, client->uplink_rate_avg);
                        telemetry_event_cac("POSTDENY",client->ap_index, "MCS", str,mcs_conf, client->uplink_rate_avg);
                    }
                    if(!(threshold_breached) && mbr_enabled && min_mbr_rate > 0 && (client->uplink_rate_avg < min_mbr_rate)) {
                        cac_print("%s:%d, POSTASSOC DENY: %d,MBR,%s,%d,%d\n", __func__, __LINE__, (client->ap_index + 1), str, (int)min_mbr_rate, client->uplink_rate_avg);
                        status = status_deny;
                        notify_force_disassociation(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, client->ap_index, "MBR", str, (int)min_mbr_rate, client->uplink_rate_avg);
                        telemetry_event_cac("POSTDENY",client->ap_index, "MBR", str, (int)min_mbr_rate, client->uplink_rate_avg);
                    }

                    if (status == status_deny) {
                        wifi_hal_disassoc(client->ap_index, WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS, client->sta_mac);
                    } else {
                        client->sampling_count = atoi(wifidb_postassoc_conf.sampling_count);
                    }
                }
                client->sampling_interval = atoi(wifidb_postassoc_conf.sampling_interval);
            }

            client = hash_map_get_next(sta_map, client);
        }
    }

    return RETURN_OK;
}

int exec_event_cac(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case wifi_event_exec_start:
            cac_event_exec_start(apps, arg);
            break;

        case wifi_event_exec_stop:
            cac_event_exec_stop(apps, arg);
            break;

        case wifi_event_exec_timeout:
            cac_event_exec_timeout(apps, arg);
            break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, sub_type);
            break;
    }
    return RETURN_OK;
}

void cac_mgmt_frame_event(wifi_app_t *app, frame_data_t *msg, int type)
{
    mac_addr_str_t mac_str = { 0 };
    wifi_preassoc_control_t wifidb_preassoc_conf;
    wifi_radioTrafficStats2_t chan_stats;
    int radio_index;
    char *str;
    cac_sta_info_t *elem;
    char vap_name[32];
    int ret;
    int snr, chan_util;
    float sta_phy_rate;
    int rssi_conf = 0;
    int snr_conf = 0;
    int cu_conf = 0;
    float min_mbr_rate = 0;
    int *preassoc_basic_rates={0};
    char basic_buf[32] = {0};
    cac_status_t rssi_status, snr_status, chan_util_status, mbr_status;
    bool rssi_enabled, snr_enabled, chan_util_enabled, mbr_enabled;
    hash_map_t *req_map = app->data.u.cac.assoc_req_map;
    bool threshold_breached = false;

    memset(vap_name, 0, sizeof(vap_name));

    if (!is_vap_hotspot(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, msg->frame.ap_index)) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d cac frame hook is used for hotspot vap, ap_index = :%d \n", __func__, __LINE__, msg->frame.ap_index);
        return;
    }

    str = to_mac_str(msg->frame.sta_mac, mac_str);
    if (str == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d mac str convert failure\r\n", __func__, __LINE__);
        return;
    }

    if (strcmp(str, "ff:ff:ff:ff:ff:ff") == 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d bad sta mac \n", __func__, __LINE__);
        return;
    }

    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d src mac:%s rssi:%d phy_rate:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, str, msg->frame.sig_dbm, msg->frame.phy_rate);

    ret = convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, msg->frame.ap_index, vap_name);

    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_APPS, "%s:%d wrong ap index:%d \n", __func__, __LINE__, msg->frame.ap_index);
        return;
    }

    radio_index = convert_vap_name_to_radio_array_index(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);

    if (radio_index < 0) {
        wifi_util_error_print(WIFI_APPS, "%s:%d radio index %d is invalid \n", __func__, __LINE__, radio_index);
        return;
    }

    ret = wifidb_get_preassoc_ctrl_config(vap_name, &wifidb_preassoc_conf);

    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_APPS, "%s:%d config not found for ap index:%d \n", __func__, __LINE__, msg->frame.ap_index);
        return;
    }

    if (strcmp(wifidb_preassoc_conf.rssi_up_threshold, "disabled") == 0) {
        rssi_enabled = false;
        rssi_status = status_ok;
    } else {
        rssi_enabled = true;
        rssi_conf = atoi(wifidb_preassoc_conf.rssi_up_threshold);
    }

    if (strcmp(wifidb_preassoc_conf.snr_threshold, "disabled") == 0) {
        snr_enabled = false;
        snr_status = status_ok;
    } else {
        snr_enabled = true;
        snr_conf = atoi(wifidb_preassoc_conf.snr_threshold);
    }

    if (strcmp(wifidb_preassoc_conf.cu_threshold, "disabled") == 0) {
        chan_util_enabled = false;
        chan_util_status = status_ok;
    } else {
        chan_util_enabled = true;
        cu_conf = atoi(wifidb_preassoc_conf.cu_threshold);
    }
    if ((strlen (wifidb_preassoc_conf.basic_data_transmit_rates) > 0) && strcmp(wifidb_preassoc_conf.basic_data_transmit_rates, "disabled")) {
        mbr_enabled = true;
        snprintf(basic_buf, sizeof(basic_buf), "%s", wifidb_preassoc_conf.basic_data_transmit_rates);
        convert_string_to_int(&preassoc_basic_rates, basic_buf);
    } else {
        mbr_enabled = false;
        mbr_status = status_ok;
    }
    get_min_rate(preassoc_basic_rates, &min_mbr_rate);
    if(preassoc_basic_rates) {
        free(preassoc_basic_rates);
        preassoc_basic_rates = NULL;
    }
    if (!rssi_enabled && !snr_enabled && !chan_util_enabled && !mbr_enabled) {
        return;
    }

    get_radio_data(radio_index, &chan_stats);
    snr = msg->frame.sig_dbm - chan_stats.radio_NoiseFloor;
    chan_util = chan_stats.radio_ChannelUtilization;
    sta_phy_rate = (float)msg->frame.phy_rate/10;

    if ((elem = (cac_sta_info_t *)hash_map_get(req_map, mac_str)) == NULL) {
        threshold_breached = false;
        if(mbr_enabled) {
            if (sta_phy_rate >= min_mbr_rate) {
                mbr_status = status_ok;
            } else {
                threshold_breached = true;
                mbr_status = status_deny;
                if (msg->frame.type == WIFI_MGMT_FRAME_TYPE_PROBE_REQ) {
                    wifi_util_info_print(WIFI_APPS,"%s:%d, PROBE DENY %s due to lower phy rate\n", __func__, __LINE__, str);
                } else {
                    cac_print("%s:%d, PRE DENY: %d,MBR,%s,%d,%d\n" , __func__, __LINE__, (msg->frame.ap_index + 1), str, (int)min_mbr_rate, (int)sta_phy_rate);
                }
                notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, msg->frame.ap_index , "MBR", str, (int)min_mbr_rate, (int)sta_phy_rate);
                telemetry_event_cac("PREDENY", msg->frame.ap_index , "MBR", str, (int)min_mbr_rate, (int)sta_phy_rate);
            }
        }
        if (mbr_status == status_ok && msg->frame.type == WIFI_MGMT_FRAME_TYPE_PROBE_REQ) {
            wifi_hal_send_mgmt_frame_response(msg->frame.ap_index,
              type, CAC_STATUS_OK, WLAN_STATUS_SUCCESS,
              msg->data, msg->frame.sta_mac,
              msg->frame.len, msg->frame.sig_dbm);
            return;
        }

        if (!(threshold_breached) && rssi_enabled) {
            if (msg->frame.sig_dbm > (rssi_conf + DBM_DEVIATION)) {
                rssi_status = status_ok;
            } else if (msg->frame.sig_dbm < (rssi_conf - DBM_DEVIATION)) {
                threshold_breached = true;
                rssi_status = status_deny;
                cac_print("%s:%d, PRE DENY: %d,RSSI,%s,%d,%d\n" , __func__, __LINE__, (msg->frame.ap_index + 1), str, rssi_conf, msg->frame.sig_dbm);
                notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, msg->frame.ap_index , "RSSI", str, rssi_conf, msg->frame.sig_dbm);
                telemetry_event_cac("PREDENY",msg->frame.ap_index , "RSSI", str, rssi_conf, msg->frame.sig_dbm);
            } else {
                rssi_status = status_wait;
            }
        }

        if (!(threshold_breached) && snr_enabled) {
            if (snr > (snr_conf + DBM_DEVIATION)) {
                snr_status = status_ok;
            } else if (snr < (snr_conf - DBM_DEVIATION)) {
                threshold_breached = true;
                snr_status = status_deny;
                cac_print("%s:%d, PRE DENY: %d,SNR,%s,%d,%d\n" , __func__, __LINE__, (msg->frame.ap_index + 1), str, snr_conf, snr);
                notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, msg->frame.ap_index , "SNR", str, snr_conf, snr);
                telemetry_event_cac("PREDENY", msg->frame.ap_index , "SNR", str, snr_conf, snr);
            } else {
                snr_status = status_wait;
            }
        }

        if (!(threshold_breached) && chan_util_enabled) {
            if (chan_util <= cu_conf) {
                chan_util_status = status_ok;
            } else {
                threshold_breached = true;
                chan_util_status = status_deny;
                cac_print("%s:%d, PRE DENY: %d,CU,%s,%d,%d\n" , __func__, __LINE__, (msg->frame.ap_index + 1), str, cu_conf, chan_util);
                notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, msg->frame.ap_index, "CU", str, cu_conf, chan_util);
                telemetry_event_cac("PREDENY",msg->frame.ap_index, "CU", str, cu_conf, chan_util);
            }
        }

        if (rssi_status == status_ok &&
             snr_status == status_ok &&
             chan_util_status == status_ok &&
             mbr_status == status_ok) {
            wifi_util_info_print(WIFI_APPS,"%s:%d: send status ok\n",__func__, __LINE__);
            cac_print("%s:%d, ASSOC ACCEPT\n", __func__, __LINE__);
            wifi_hal_send_mgmt_frame_response(msg->frame.ap_index,
                            type, CAC_STATUS_OK, WLAN_STATUS_SUCCESS,
                            msg->data, msg->frame.sta_mac,
                            msg->frame.len, msg->frame.sig_dbm);
            return;
        }

        if (rssi_status == status_deny ||
             snr_status == status_deny ||
             mbr_status == status_deny) {
            wifi_util_info_print(WIFI_APPS,"%s:%d: send status failure\n",__func__, __LINE__);
            wifi_hal_send_mgmt_frame_response(msg->frame.ap_index, 
                            type, CAC_STATUS_DENY, 
                            WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS, 
                            msg->data, msg->frame.sta_mac, 
                            msg->frame.len, msg->frame.sig_dbm);
            return;
        }

        if (chan_util_status == status_deny) {
            wifi_util_info_print(WIFI_APPS,"%s:%d: send status failure\n",__func__, __LINE__);
            wifi_hal_send_mgmt_frame_response(msg->frame.ap_index, 
                            type, CAC_STATUS_DENY, 
                            WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA, 
                            msg->data, msg->frame.sta_mac, 
                            msg->frame.len, msg->frame.sig_dbm);
            return;
        }

        elem = (cac_sta_info_t *)malloc(sizeof(cac_sta_info_t));
        memset(elem, 0, sizeof(cac_sta_info_t));
        strncpy(elem->mac_addr, mac_str, sizeof(elem->mac_addr));
        elem->ap_index = msg->frame.ap_index;
        elem->rssi_avg = msg->frame.sig_dbm;
        elem->snr_avg = snr;
        elem->uplink_rate_avg = 0;
        elem->num_frames = 1;
        elem->seconds_alive = 5;
        hash_map_put(req_map, strdup(mac_str), elem);
    } else {
        threshold_breached = false;
        elem->num_frames++;
        elem->rssi_avg = EXP_WEIGHT * elem->rssi_avg + (1 - EXP_WEIGHT) * msg->frame.sig_dbm;
        elem->snr_avg = EXP_WEIGHT * elem->snr_avg + (1 - EXP_WEIGHT) * snr;

        if (elem->num_frames == MAX_NUM_FRAME_TO_WAIT) {
            if (!(threshold_breached) && rssi_enabled) {
                if (elem->rssi_avg >= rssi_conf) {
                    rssi_status = status_ok;
                } else {
                    threshold_breached = true;
                    rssi_status = status_deny;
                    cac_print("%s:%d, PRE DENY: %d,RSSI,%s,%d,%d\n" , __func__, __LINE__, (elem->ap_index + 1), str, rssi_conf, elem->rssi_avg);
                    notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, elem->ap_index , "RSSI", str, rssi_conf, elem->rssi_avg);
                    telemetry_event_cac("PREDENY", elem->ap_index , "RSSI", str, rssi_conf, elem->rssi_avg);
                }
            }

            if (!(threshold_breached) && snr_enabled) {
                if (elem->snr_avg >= snr_conf) {
                    snr_status = status_ok;
                } else {
                    threshold_breached = true;
                    snr_status = status_deny;
                    cac_print("%s:%d, PRE DENY: %d,SNR,%s,%d,%d\n" , __func__, __LINE__, (elem->ap_index + 1), str, snr_conf, elem->snr_avg);
                    notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, elem->ap_index , "SNR", str, snr_conf, elem->snr_avg);
                    telemetry_event_cac("PREDENY",elem->ap_index , "SNR", str, snr_conf, elem->snr_avg);
                }
            }

            if (!(threshold_breached) && chan_util_enabled) {
                if (chan_util <= cu_conf) {
                    chan_util_status = status_ok;
                } else {
                    threshold_breached = true;
                    chan_util_status = status_deny;
                    cac_print("%s:%d, PRE DENY: %d,CU,%s,%d,%d\n" , __func__, __LINE__, (elem->ap_index + 1), str, cu_conf, chan_util);
                    notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, elem->ap_index , "CU", str, cu_conf, chan_util);
                    telemetry_event_cac("PREDENY",elem->ap_index , "CU", str, cu_conf, chan_util);
                }
            }
            if(!(threshold_breached) && mbr_enabled) {
                if (sta_phy_rate >= min_mbr_rate) {
                    mbr_status = status_ok;
                } else {
                    threshold_breached = true;
                    mbr_status = status_deny;
                    if (msg->frame.type == WIFI_MGMT_FRAME_TYPE_PROBE_REQ) {
                        wifi_util_info_print(WIFI_APPS,"%s:%d, PROBE DENY %s due to lower phy rate\n", __func__, __LINE__, str);
                    } else {
                        cac_print("%s:%d, PRE DENY: %d,MBR,%s,%d,%d\n" , __func__, __LINE__, (elem->ap_index + 1), str, (int)min_mbr_rate, (int)sta_phy_rate);
                    }
                    notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, elem->ap_index, "MBR", str, (int)min_mbr_rate, (int)sta_phy_rate);
                    telemetry_event_cac("PREDENY",elem->ap_index, "MBR", str, (int)min_mbr_rate, (int)sta_phy_rate);
                }
            }
        } else {
            if (!(threshold_breached) && rssi_enabled) {
                if (elem->rssi_avg > (rssi_conf + DBM_DEVIATION)) {
                    rssi_status = status_ok;
                } else if (elem->rssi_avg < (rssi_conf - DBM_DEVIATION)) {
                    threshold_breached = true;
                    rssi_status = status_deny;
                    cac_print("%s:%d, PRE DENY: %d,RSSI,%s,%d,%d\n" , __func__, __LINE__, (elem->ap_index + 1), str, rssi_conf, elem->rssi_avg);
                    notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, elem->ap_index , "RSSI", str, rssi_conf, elem->rssi_avg);
                    telemetry_event_cac("PREDENY",elem->ap_index , "RSSI", str, rssi_conf, elem->rssi_avg);
                } else {
                    elem->seconds_alive = 5;
                    rssi_status = status_wait;
                }
            }

            if (!(threshold_breached) && snr_enabled) {
                if (elem->snr_avg > (snr_conf + DBM_DEVIATION)) {
                    snr_status = status_ok;
                } else if (elem->snr_avg < (snr_conf - DBM_DEVIATION)) {
                    threshold_breached = true;
                    snr_status = status_deny;
                    cac_print("%s:%d, PRE DENY: %d,SNR,%s,%d,%d\n" , __func__, __LINE__, (elem->ap_index + 1), str, snr_conf, elem->snr_avg);
                    notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, elem->ap_index, "SNR", str, snr_conf, elem->snr_avg);
                    telemetry_event_cac("PREDENY",elem->ap_index, "SNR", str, snr_conf, elem->snr_avg);
                } else {
                    elem->seconds_alive = 5;
                    snr_status = status_wait;
                }
            }

            if (!(threshold_breached) && chan_util_enabled) {
                if (chan_util <= cu_conf) {
                    chan_util_status = status_ok;
                } else {
                    threshold_breached = true;
                    chan_util_status = status_deny;
                    cac_print("%s:%d, PRE DENY: %d,CU,%s,%d,%d\n" , __func__, __LINE__, (elem->ap_index + 1), str, cu_conf, chan_util);
                    notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, elem->ap_index , "CU", str, cu_conf, chan_util);
                    telemetry_event_cac("PREDENY",elem->ap_index, "CU", str, cu_conf, chan_util);
                }
            }
            if(!(threshold_breached) && mbr_enabled) {
                if (sta_phy_rate >= min_mbr_rate) {
                    mbr_status = status_ok;
                } else {
                    threshold_breached = true;
                    mbr_status = status_deny;
                    if (msg->frame.type == WIFI_MGMT_FRAME_TYPE_PROBE_REQ) {
                        wifi_util_info_print(WIFI_APPS,"%s:%d, PROBE DENY %s due to lower phy rate\n", __func__, __LINE__, str);
                    } else {
                        cac_print("%s:%d, PRE DENY: %d,MBR,%s,%d,%d\n" , __func__, __LINE__, (elem->ap_index + 1), str, (int)min_mbr_rate, (int)sta_phy_rate);
                        notify_deny_association(&((wifi_mgr_t *)get_wifimgr_obj())->ctrl, elem->ap_index , "MBR", str, (int)min_mbr_rate, (int)sta_phy_rate);
                        telemetry_event_cac("PREDENY", elem->ap_index , "MBR", str, (int)min_mbr_rate, (int)sta_phy_rate);
                    }
                }
            }
        }

        if (mbr_status == status_ok && msg->frame.type == WIFI_MGMT_FRAME_TYPE_PROBE_REQ) {
            wifi_hal_send_mgmt_frame_response(msg->frame.ap_index,
                    type, CAC_STATUS_OK, WLAN_STATUS_SUCCESS,
                    msg->data, msg->frame.sta_mac,
                    msg->frame.len, msg->frame.sig_dbm);
            return;
        }

        if (rssi_status == status_ok && 
             snr_status == status_ok && 
             chan_util_status == status_ok &&
             mbr_status == status_ok) {
            wifi_util_info_print(WIFI_APPS,"%s:%d: send status ok\n",__func__, __LINE__);
            cac_print("%s:%d, ASSOC ACCEPT %s\n", __func__, __LINE__, str);
            wifi_hal_send_mgmt_frame_response(msg->frame.ap_index, 
                            type, CAC_STATUS_OK, WLAN_STATUS_SUCCESS,
                            msg->data, msg->frame.sta_mac, 
                            msg->frame.len, msg->frame.sig_dbm);
            elem = hash_map_remove(req_map, mac_str);

            if (elem != NULL) {
                free(elem);
            }
            return;
        }

        if (rssi_status == status_deny ||
             snr_status == status_deny ||
             mbr_status == status_deny) {
            wifi_util_info_print(WIFI_APPS,"%s:%d: send status failure\n",__func__, __LINE__);
            wifi_hal_send_mgmt_frame_response(msg->frame.ap_index, 
                            type, CAC_STATUS_DENY, 
                            WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS, 
                            msg->data, msg->frame.sta_mac,
                            msg->frame.len, msg->frame.sig_dbm);
            elem = hash_map_remove(req_map, mac_str);

            if (elem != NULL) {
                free(elem);
            }
            return;
        }

        if (chan_util_status == status_deny) {
            wifi_util_info_print(WIFI_APPS,"%s:%d: send status failure\n",__func__, __LINE__);
            wifi_hal_send_mgmt_frame_response(msg->frame.ap_index, 
                            type, CAC_STATUS_DENY, 
                            WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA, 
                            msg->data, msg->frame.sta_mac,
                            msg->frame.len, msg->frame.sig_dbm);
            elem = hash_map_remove(req_map, mac_str);

            if (elem != NULL) {
                free(elem);
            }
            return;
        }
    }
}

int cac_event_webconfig_set_data(wifi_app_t *apps, webconfig_subdoc_data_t *doc, wifi_event_subtype_t sub_type)
{
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;

    if (doc == NULL) {
       /*Note : This is not error case, but this check is used to denote webconfig_set_data event
        * is received by the handle_webconfig_event() function and decode is not happened yet
        * to determine the subdoc type.
        */
        return RETURN_OK;
    }

    decoded_params = &doc->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d: decoded data is NULL : %p\n", __func__, __LINE__, decoded_params);
        return RETURN_ERR;
    }

    switch (doc->type) {
        case webconfig_subdoc_type_private:
        case webconfig_subdoc_type_home:
        case webconfig_subdoc_type_xfinity:
        case webconfig_subdoc_type_lnf:
        case webconfig_subdoc_type_mesh_backhaul:
        case webconfig_subdoc_type_mesh_sta:
        case webconfig_subdoc_type_mesh_backhaul_sta:
        case webconfig_subdoc_type_radio:
        case webconfig_subdoc_type_cac:
            break;
        default:
            break;
    }

    return RETURN_OK;
}


int webconfig_event_cac(wifi_app_t *apps, wifi_event_subtype_t sub_type, webconfig_subdoc_data_t *doc)
{
    switch (sub_type) {
        case wifi_event_webconfig_set_data:
            break;
        case wifi_event_webconfig_set_data_dml:
            break;
        case wifi_event_webconfig_set_data_webconfig:
            break;
        case wifi_event_webconfig_set_data_ovsm:
            break;
        case wifi_event_webconfig_data_resched_to_ctrl_queue:
            break;
        case wifi_event_webconfig_data_to_hal_apply:
            break;
        case wifi_event_webconfig_data_to_apply_pending_queue:
            cac_event_webconfig_set_data(apps, doc, sub_type);
            break;
        case wifi_event_webconfig_set_status:
            break;
        case wifi_event_webconfig_hal_result:
            break;
        case wifi_event_webconfig_get_data:
            break;
        case wifi_event_webconfig_set_data_tunnel:
            break;
        case wifi_event_webconfig_data_req_from_dml:
            break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, sub_type);
            break;
    }

    return RETURN_OK;
}

int cac_event_hal_assoc_device(wifi_app_t *apps, void *arg)
{
    int ret = 0;
    char vap_name[32];
    char client_mac[32];
    char temp_str[64];
    hash_map_t           *sta_map;
    cac_associated_devices_t *sta_info;
    wifi_postassoc_control_t wifidb_postassoc_conf = { 0 };
    int sampling_interval_conf, sampling_count_conf;

    memset(client_mac, 0, sizeof(client_mac));
    memset(temp_str, 0, sizeof(temp_str));

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;

    if (!is_vap_hotspot(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, assoc_data->ap_index)) {
        wifi_util_info_print(WIFI_APPS, "%s:%d cac postassoc is used for hotspot vap, ap_index = :%d \n", __func__, __LINE__, assoc_data->ap_index);
        return RETURN_OK;
    }

    ret = convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, assoc_data->ap_index, vap_name);

    if (ret != RETURN_OK) {
        wifi_util_info_print(WIFI_APPS, "%s:%d wrong ap index:%d \n", __func__, __LINE__, assoc_data->ap_index);
        return NL_OK; 
    }

    ret = wifidb_get_postassoc_ctrl_config(vap_name, &wifidb_postassoc_conf);

    if (ret != RETURN_OK) {
        wifi_util_info_print(WIFI_APPS, "%s:%d config not found for ap index:%d \n", __func__, __LINE__, assoc_data->ap_index);
        return NL_OK;
    }

    sampling_interval_conf = atoi(wifidb_postassoc_conf.sampling_interval);
    sampling_count_conf = atoi(wifidb_postassoc_conf.sampling_count);

    to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);

    str_tolower(client_mac);

    snprintf(temp_str, sizeof(temp_str), "\"%s\" vap index:%d", client_mac, (assoc_data->ap_index + 1));

    cac_print("%s:%d connected %s\n", __func__, __LINE__, temp_str);

    sta_map = apps->data.u.cac.sta_map;

    if ((sta_info = (cac_associated_devices_t *)hash_map_get(sta_map, client_mac)) == NULL) {
        sta_info = malloc(sizeof(cac_associated_devices_t));
        sta_info->ap_index = assoc_data->ap_index;
        sta_info->sampling_count = sampling_count_conf;
        sta_info->sampling_interval = sampling_interval_conf;
        sta_info->rssi_avg = assoc_data->dev_stats.cli_RSSI;
        sta_info->snr_avg = assoc_data->dev_stats.cli_SNR;
        sta_info->uplink_rate_avg = assoc_data->dev_stats.cli_LastDataUplinkRate;
        memcpy(sta_info->sta_mac, assoc_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
        hash_map_put(sta_map, strdup(client_mac), sta_info);
    } else {
        sta_info->ap_index = assoc_data->ap_index;
        memcpy(sta_info->sta_mac, assoc_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
    }

    return RETURN_OK;
}

int cac_event_hal_disassoc_device(wifi_app_t *apps, void *arg)
{
    char client_mac[32];
    char temp_str[64];
    hash_map_t            *sta_map;
    cac_associated_devices_t  *sta_info;
    memset(client_mac, 0, sizeof(client_mac));
    memset(temp_str, 0, sizeof(temp_str));

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;

    sta_map = apps->data.u.cac.sta_map;

    (char *)to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);
    str_tolower(client_mac);
    snprintf(temp_str, sizeof(temp_str), "\"%s\" vap index:%d reason:%d", client_mac, (assoc_data->ap_index + 1), assoc_data->reason);
    cac_print("%s:%d disconnected %s\n", __func__, __LINE__, temp_str);

    sta_info = (cac_associated_devices_t *)hash_map_get(sta_map, client_mac);
    if (sta_info != NULL) {
        sta_info = hash_map_remove(sta_map, client_mac);
        if (sta_info != NULL) {
            free(sta_info);
        }
    }

    return RETURN_OK;
}

int hal_event_cac(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    //wifi_util_info_print(WIFI_APPS,"%s:%d: event handled[%d]\r\n",__func__, __LINE__, sub_type);
    switch (sub_type) {
        case wifi_event_hal_unknown_frame:
            break;
        case wifi_event_hal_mgmt_frames:
            break;
        case wifi_event_hal_probe_req_frame:
            cac_mgmt_frame_event(apps, (frame_data_t *)arg, WLAN_FC_STYPE_PROBE_REQ);
            break;
        case wifi_event_hal_auth_frame:
            break;
        case wifi_event_hal_assoc_req_frame:
            cac_mgmt_frame_event(apps, (frame_data_t *)arg, WLAN_FC_STYPE_ASSOC_RESP);
            break;
        case wifi_event_hal_assoc_rsp_frame:
            break;
        case wifi_event_hal_reassoc_req_frame:
            cac_mgmt_frame_event(apps, (frame_data_t *)arg, WLAN_FC_STYPE_REASSOC_RESP);
            break;
        case wifi_event_hal_reassoc_rsp_frame:
            break;
        case wifi_event_hal_sta_conn_status:
            break;
        case wifi_event_hal_assoc_device:
            cac_event_hal_assoc_device(apps, arg);
            break;
        case wifi_event_hal_disassoc_device:
            cac_event_hal_disassoc_device(apps, arg);
            break;
        case wifi_event_scan_results:
            break;
        case wifi_event_hal_channel_change:
            break;
        case wifi_event_radius_greylist:
            break;
        case wifi_event_hal_potential_misconfiguration:
            break;
        case wifi_event_hal_analytics:
            break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, sub_type);
            break;
    }

    return RETURN_OK;
}

#ifdef ONEWIFI_CAC_APP_SUPPORT
int cac_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
        case wifi_event_type_webconfig:
            webconfig_event_cac(app, event->sub_type, (webconfig_subdoc_data_t *)event->u.core_data.msg);
            break;

        case wifi_event_type_exec:
            exec_event_cac(app, event->sub_type, NULL);
            break;

        case wifi_event_type_hal_ind:
            hal_event_cac(app, event->sub_type, event->u.core_data.msg);
            break;

        default:
            break;
    }

    return RETURN_OK;
}

int cac_mgmt_frame_hook(int ap_index, wifi_mgmtFrameType_t type)
{
    int ret = 0;
    char vap_name[32];
    wifi_preassoc_control_t wifidb_preassoc_conf = { 0 };

    wifi_util_dbg_print(WIFI_APPS, "%s:%d received mgmt frame hook for ap index:%d type:%d \n", __func__, __LINE__, ap_index, type);

    if (!is_vap_hotspot(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, ap_index)) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d cac frame hook is used for hotspot vap, ap_index = :%d \n", __func__, __LINE__, ap_index);
        return NL_OK;
    }

    if (type != WIFI_MGMT_FRAME_TYPE_PROBE_REQ &&
        type != WIFI_MGMT_FRAME_TYPE_ASSOC_REQ &&
        type != WIFI_MGMT_FRAME_TYPE_REASSOC_REQ) {
        return NL_OK;
    }

    ret = convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, ap_index, vap_name);

    if (ret != RETURN_OK) {
        wifi_util_info_print(WIFI_APPS, "%s:%d wrong ap index:%d \n", __func__, __LINE__, ap_index);
        return NL_OK; 
    }

    ret = wifidb_get_preassoc_ctrl_config(vap_name, &wifidb_preassoc_conf);

    if (ret != RETURN_OK) {
        wifi_util_info_print(WIFI_APPS, "%s:%d config not found for ap index:%d \n", __func__, __LINE__, ap_index);
        return NL_OK;
    }

    if((type == WIFI_MGMT_FRAME_TYPE_PROBE_REQ) && (strlen (wifidb_preassoc_conf.basic_data_transmit_rates) <= 0) && (strcmp(wifidb_preassoc_conf.basic_data_transmit_rates, "disabled") == 0)) {
        return NL_OK;
    }

    if ((strcmp(wifidb_preassoc_conf.rssi_up_threshold, "disabled") != 0) ||
         (strcmp(wifidb_preassoc_conf.snr_threshold, "disabled") != 0) ||
         (strcmp(wifidb_preassoc_conf.cu_threshold, "disabled") != 0) ||
         ((strlen (wifidb_preassoc_conf.basic_data_transmit_rates) > 0) && (strcmp(wifidb_preassoc_conf.basic_data_transmit_rates, "disabled") != 0))) {
        return NL_SKIP;
    }
    return NL_OK;
}

int cac_init(wifi_app_t *app, unsigned int create_flag)
{
    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    app->data.u.cac.assoc_req_map = hash_map_create();
    app->data.u.cac.sta_map = hash_map_create();

    return 0;
}

int cac_deinit(wifi_app_t *app)
{
    hash_map_destroy(app->data.u.cac.assoc_req_map);
    hash_map_destroy(app->data.u.cac.sta_map);
    return RETURN_OK;
}
#endif
