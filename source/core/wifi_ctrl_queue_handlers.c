#include <stdio.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "ansc_platform.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_monitor.h"
#include "webconfig_framework.h"
#include "scheduler.h"
#include <unistd.h>
#include <pthread.h>
#include <rbus.h>
#include "wifi_hal_rdk_framework.h"
#include "safec_lib_common.h"

#define NEIGHBOR_SCAN_RESULT_INTERVAL 5000 //5sec
static int neighbor_scan_task_id = -1;




void process_scan_results_event(wifi_bss_info_t *bss, unsigned int len)
{
    unsigned int i, num = len/sizeof(wifi_bss_info_t);
    wifi_bss_info_t *tmp_bss = bss;
    wifi_ctrl_t *ctrl;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    mac_addr_str_t bssid_str;
    unsigned int band = 0;

    ctrl = &mgr->ctrl;

    if(num && (tmp_bss->freq >= 2412 && tmp_bss->freq <= 2484)) {
        band = WIFI_FREQUENCY_2_4_BAND;
    } else if (num && (tmp_bss->freq >= 5160 && tmp_bss->freq <= 5885)) {
        band = WIFI_FREQUENCY_5_BAND;
    }

    if(ctrl->network_mode == rdk_dev_mode_type_ext) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d Extender Mode num of scan results:%d, conn_state:%d\n",__FUNCTION__,__LINE__, num, ctrl->conn_state);
        if(ctrl->conn_state == connection_state_disconnected && num) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d Copy scanresults and initiate sta connection\n",__FUNCTION__,__LINE__);

            scan_list_t *scan_list;

            if (ctrl->scan_list != NULL) {
                scan_list = (scan_list_t *) realloc(ctrl->scan_list, ((num + ctrl->scan_count) * sizeof(scan_list_t)));
                if(scan_list == NULL) {
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi scan result list realloc failure:%d\r\n",
                                            __func__, __LINE__, ((num + ctrl->scan_count) * sizeof(scan_list_t)));
                    return;
                }
                //memset(scan_list, 0, (num + ctrl->scan_count) * sizeof(scan_list_t));
                //memcpy(scan_list, ctrl->scan_list, (ctrl->scan_count * sizeof(scan_list_t)));
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d scan count:%d:num:%d scan_list:%p\n",__func__,__LINE__, ctrl->scan_count, num, scan_list);
                ctrl->scan_list = scan_list;
                scan_list += ctrl->scan_count;
                ctrl->scan_count += num;

                wifi_util_dbg_print(WIFI_CTRL, "%s:%d scan count:%d:num:%d scan_list:%p\n",__func__,__LINE__, ctrl->scan_count, num, scan_list);
                //memset(scan_list, 0, num * sizeof(scan_list_t));
                for (i = 0; i < num; i++) {
                    memcpy(&scan_list->external_ap, tmp_bss, sizeof(wifi_bss_info_t));
                    scan_list->conn_attempt = connection_attempt_wait;
                    scan_list->conn_retry_attempt = 0;
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: AP with ssid:%s, bssid:%s, rssi:%d, freq:%d\n",
                                __func__, __LINE__, tmp_bss->ssid, to_mac_str(tmp_bss->bssid, bssid_str), tmp_bss->rssi, tmp_bss->freq);
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: AP with ssid:%s, bssid:%s, rssi:%d, freq:%d\n",
                                __func__, __LINE__, scan_list->external_ap.ssid, to_mac_str(scan_list->external_ap.bssid, bssid_str), scan_list->external_ap.rssi, scan_list->external_ap.freq);
                    tmp_bss++;
                    scan_list++;
                }
            } else {
                scan_list = (scan_list_t *) malloc(num * sizeof(scan_list_t));
                if(ctrl->scan_list != NULL) {
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: candidate_list is present ctrl->scan_list:%p\n", __func__, __LINE__, ctrl->scan_list);
                }

                memset(scan_list, 0, num * sizeof(scan_list_t));
                ctrl->scan_list = scan_list;
                ctrl->scan_count = num;

                wifi_util_dbg_print(WIFI_CTRL, "%s:%d scan count:%d:num:%d scan_list:%p\n",__func__,__LINE__, ctrl->scan_count, num, scan_list);
                for (i = 0; i < num; i++) {
                    memcpy(&scan_list->external_ap, tmp_bss, sizeof(wifi_bss_info_t));
                    scan_list->conn_attempt = connection_attempt_wait;
                    scan_list->conn_retry_attempt = 0;
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: AP with ssid:%s, bssid:%s, rssi:%d, freq:%d\n",
                                __func__, __LINE__, tmp_bss->ssid, to_mac_str(tmp_bss->bssid, bssid_str), tmp_bss->rssi, tmp_bss->freq);
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: AP with ssid:%s, bssid:%s, rssi:%d, freq:%d\n",
                                __func__, __LINE__, scan_list->external_ap.ssid, to_mac_str(scan_list->external_ap.bssid, bssid_str), scan_list->external_ap.rssi, scan_list->external_ap.freq);
                    tmp_bss++;
                    scan_list++;
                }
            }

            if (band == WIFI_FREQUENCY_5_BAND) {
                ctrl->scan_wifi_state |= received_5g_wifi_scan;
            } else if (band == WIFI_FREQUENCY_2_4_BAND) {
                ctrl->scan_wifi_state |= received_2g_wifi_scan;
            }

            if (ctrl->scan_wifi_state == received_both_wifi_scan) {
                ctrl->conn_state = connection_state_in_progress;
                ctrl->scan_wifi_state = received_none_wifi_scan;
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: candidate_list is present, start connecting\n", __func__, __LINE__);
                sta_pending_connection_retry(ctrl);
            }
        } else if ((ctrl->conn_state == connection_state_disconnected) && (!num)) {
            if (band == WIFI_FREQUENCY_5_BAND) {
                ctrl->scan_wifi_state |= received_5g_wifi_scan;
            } else if (band == WIFI_FREQUENCY_2_4_BAND) {
                ctrl->scan_wifi_state |= received_2g_wifi_scan;
            }

            if ((ctrl->scan_count != 0) && (ctrl->scan_wifi_state == received_both_wifi_scan)) {
                ctrl->conn_state = connection_state_in_progress;
                ctrl->scan_wifi_state = received_none_wifi_scan;
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: candidate_list is present, start connecting\n", __func__, __LINE__);
                sta_pending_connection_retry(ctrl);
            }
        }
    }
}
int remove_greylist_acl_entries(bool remove_all_greylist_entry)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d  Enter \n", __FUNCTION__, __LINE__);
    acl_entry_t *tmp_acl_entry = NULL, *acl_entry = NULL;
    rdk_wifi_vap_info_t *l_rdk_vap_array = NULL;
    unsigned int itr = 0, itrj = 0;
    mac_addr_str_t mac_str;
    struct timeval tv_now;
    int vap_index = 0;
    int ret = 0;
    char macfilterkey[128];
    wifi_vap_info_map_t *wifi_vap_map = NULL;

    memset(macfilterkey, 0, sizeof(macfilterkey));
    gettimeofday(&tv_now, NULL);

    for (itr = 0; itr < getNumberRadios(); itr++) {
        wifi_vap_map = get_wifidb_vap_map(itr);
        for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
            vap_index = wifi_vap_map->vap_array[itrj].vap_index;
            l_rdk_vap_array = get_wifidb_rdk_vap_info(vap_index);

            if (l_rdk_vap_array->acl_map != NULL) {
                acl_entry = hash_map_get_first(l_rdk_vap_array->acl_map);

                while(acl_entry != NULL) {

                    if ((acl_entry->reason == WLAN_RADIUS_GREYLIST_REJECT) &&
                        ((acl_entry->expiry_time <= tv_now.tv_sec) || remove_all_greylist_entry)) {

                        to_mac_str(acl_entry->mac, mac_str);
                        ret = wifi_delApAclDevice(l_rdk_vap_array->vap_index, mac_str);
                        if (ret != RETURN_OK) {

                            wifi_util_dbg_print(WIFI_MGR, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
                             __func__, __LINE__, l_rdk_vap_array->vap_index, mac_str);
                            ret = RETURN_ERR;
                        }

                        if (ret == RETURN_OK || remove_all_greylist_entry) {
                            tmp_acl_entry = hash_map_remove(l_rdk_vap_array->acl_map, mac_str);
                            snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", l_rdk_vap_array->vap_name, mac_str);
                            wifidb_update_wifi_macfilter_config(macfilterkey, tmp_acl_entry, false);
                        }
                    }
                    acl_entry = hash_map_get_next(l_rdk_vap_array->acl_map, acl_entry);
                }
            }
       }
    }
    return RETURN_OK;
}


void process_mgmt_ctrl_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->ap_index, msg->len, msg->type, msg->dir);
}

void send_hotspot_status(char* vap_name, bool up)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL ctrl object\n", __func__,__LINE__);
        return;
    }

    rbusValue_t value;
    rbusObject_t data;

    rbusValue_Init(&value);
    rbusValue_SetString(value, vap_name);

    char *evt_name = up ? WIFI_RBUS_HOTSPOT_UP : WIFI_RBUS_HOTSPOT_DOWN;

    rbusObject_Init(&data, NULL);
    rbusObject_SetValue(data, evt_name, value);

    rbusEvent_t event;
    event.name = evt_name;
    event.data = data;
    event.type = RBUS_EVENT_GENERAL;

    int rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
    if(rc != RBUS_ERROR_SUCCESS){
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d rbusEvent_Publish %s failed for %s\n", __func__, __LINE__, event.name, vap_name);
    }

    rbusValue_Release(value);
    rbusObject_Release(data);
}
/* process_xfinity_vaps()  vap_enable param can take values 0,1 and 2
    0 ---To disable xfinityvaps,
    1 --To enable xfinty vaps
    0 and 1 are  used for TunnelUp/Down event
    2 --- To not change the enable param of xfinityvaps
    This is used in case of Radius greylist, station disconnect
*/

void process_xfinity_vaps(int vap_enable, bool hs_evt)
{
    vap_svc_t  *pub_svc = NULL;
    wifi_ctrl_t *ctrl;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    bool open_2g_enabled = false, open_5g_enabled = false,sec_2g_enabled = false,sec_5g_enabled = false;
    uint8_t num_radios = getNumberRadios();
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

    pub_svc = get_svc_by_type(ctrl, vap_svc_type_public);
    for(int radio_indx = 0; radio_indx < num_radios; ++radio_indx) {
        wifi_vap_info_map_t *wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(radio_indx);
        for(unsigned int j = 0; j < wifi_vap_map->num_vaps; ++j) {
            if(strstr(wifi_vap_map->vap_array[j].vap_name, "hotspot") == NULL) {
                continue;
            }

            wifi_vap_info_map_t tmp_vap_map;
            memset((unsigned char *)&tmp_vap_map, 0, sizeof(wifi_vap_info_map_t));
            tmp_vap_map.num_vaps = 1;
            memcpy((unsigned char *)&tmp_vap_map.vap_array[0], (unsigned char *)&wifi_vap_map->vap_array[j], sizeof(wifi_vap_info_t));
            if(vap_enable == 0 ) {
                tmp_vap_map.vap_array[0].u.bss_info.enabled = false;
            }
            if(vap_enable == 1 ) {
              if (rfc_param) {
                  open_2g_enabled = rfc_param->hotspot_open_2g_last_enabled;
                  open_5g_enabled = rfc_param->hotspot_open_5g_last_enabled;
                  sec_2g_enabled = rfc_param->hotspot_secure_2g_last_enabled;
                  sec_5g_enabled = rfc_param->hotspot_secure_5g_last_enabled;
              }
              wifi_util_dbg_print(WIFI_CTRL," vap_name is %s and bool is %d:%d:%d:%d\n",tmp_vap_map.vap_array[0].vap_name,open_2g_enabled,open_5g_enabled,sec_2g_enabled,sec_5g_enabled);
              if ((strcmp(wifi_vap_map->vap_array[0].vap_name,"hotspot_open_2g") == 0) && open_2g_enabled)
                  tmp_vap_map.vap_array[0].u.bss_info.enabled = true;
              else if ((strcmp(wifi_vap_map->vap_array[0].vap_name,"hotspot_open_5g") == 0) && open_5g_enabled)
                  tmp_vap_map.vap_array[0].u.bss_info.enabled = true;
              else if((strcmp(wifi_vap_map->vap_array[0].vap_name,"hotspot_secure_2g") == 0) && sec_2g_enabled)
                  tmp_vap_map.vap_array[0].u.bss_info.enabled = true;
              else if((strcmp(wifi_vap_map->vap_array[0].vap_name,"hotspot_secure_5g") == 0) && sec_5g_enabled)
                  tmp_vap_map.vap_array[0].u.bss_info.enabled = true;
              wifi_util_dbg_print(WIFI_CTRL,"enabled is %d\n",tmp_vap_map.vap_array[0].u.bss_info.enabled);
            }

            if(pub_svc->update_fn(pub_svc,radio_indx, &tmp_vap_map) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d Unable to create vaps\n", __func__,__LINE__);
                if(hs_evt) {
                    send_hotspot_status(wifi_vap_map->vap_array[j].vap_name, false);
               }
            } else {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d Able to create vaps\n", __func__,__LINE__);
                wifidb_print("%s:%d radio_index:%d create vap %s successful\n", __func__,__LINE__, radio_indx, wifi_vap_map->vap_array[j].vap_name);
                if(hs_evt) {
                    send_hotspot_status(wifi_vap_map->vap_array[j].vap_name, true);
                }

            }
        }
    }
}

void convert_freq_to_channel(unsigned int freq, unsigned char *channel)
{
    if ((freq >= 2407) && (freq <= 2484)) {
        freq = freq - 2407;
        *channel = (freq / 5);
    } else if ((freq >= 5000) && (freq <= 5980)) {
        freq = freq - 5000;
        *channel = (freq / 5);
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d frequency out of range:%d\r\n", __func__,__LINE__, freq);
        return;
    }
}

void update_global_cache_radio_channel(unsigned int freq)
{
    wifi_radio_operationParam_t *wifi_radio_oper_param = NULL;
    unsigned char radio_index = 0;
    unsigned char channel = 0;
    int ret;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if ((freq >= 2407) && (freq <= 2484)) {
        radio_index = 0;
    } else if ((freq >= 5000) && (freq <= 5980)) {
        radio_index = 1;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d frequency out of range:%d\r\n", __func__,__LINE__, freq);
        return;
    }

    convert_freq_to_channel(freq, &channel);

    wifi_radio_oper_param = (wifi_radio_operationParam_t *)get_wifidb_radio_map(radio_index);
    if (wifi_radio_oper_param != NULL) {
        if (wifi_radio_oper_param->channel != channel) {
            wifi_radio_oper_param->channel = channel;
            ctrl->webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d channel updated to global cache:%d\r\n", __func__,__LINE__, channel);
            ret = wifi_hal_setRadioOperatingParameters(radio_index, wifi_radio_oper_param);
            if (ret != RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL,"%s: wifi radio parameter set failure: radio_index:%d\n",__FUNCTION__, radio_index);
                return;
            } else {
                wifi_util_dbg_print(WIFI_CTRL,"%s: wifi radio parameter set success: radio_index:%d\n",__FUNCTION__, radio_index);
            }
        } else {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d global cache channel:%d current channel:%d\r\n", __func__,__LINE__, wifi_radio_oper_param->channel, channel);
	}
    }
}

void process_sta_conn_status_event(rdk_sta_data_t *sta_data, unsigned int len)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    char name[64];
    unsigned int index, i;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_vap_info_map_t *vap_map;
    wifi_ctrl_t *ctrl;
    wifi_vap_info_t *temp_vap_info = NULL;
    bool scan = true;
    mac_addr_str_t bssid_str;
    unsigned int rbus_send_connected = 0;

    ctrl = &mgr->ctrl;

    /* first update the internal cache */
    index = (sta_data->stats.vap_index == 14) ? 1:2;
    vap_map = &mgr->radio_config[(index - 1)].vaps.vap_map;

    for (i = 0; i < vap_map->num_vaps; i++) {
        if (vap_map->vap_array[i].vap_index == sta_data->stats.vap_index) {
            vap_map->vap_array[i].u.sta_info.conn_status = sta_data->stats.connect_status;
            memset(vap_map->vap_array[i].u.sta_info.bssid, 0, sizeof(vap_map->vap_array[i].u.sta_info.bssid));
            temp_vap_info = &vap_map->vap_array[i];
            break;
        }
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d connect_status:%d\n",__FUNCTION__, __LINE__, sta_data->stats.connect_status);
    if (sta_data->stats.connect_status == wifi_connection_status_connected) {
        if (temp_vap_info != NULL) {
            memcpy (temp_vap_info->u.sta_info.bssid, sta_data->bss_info.bssid, sizeof(temp_vap_info->u.sta_info.bssid));
        }

        if(ctrl->conn_state == connection_state_in_progress) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d sending STA connected event over RBUS\n",__FUNCTION__, __LINE__);
            rbus_send_connected = 1;
        }

        ctrl->conn_state = connection_state_connected;

        ctrl->disconnected_time = 0;
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d reset disconnected_time\n",__FUNCTION__, __LINE__);

        ctrl->connected_vap_index = sta_data->stats.vap_index;
        memcpy(&ctrl->connected_external_ap, &sta_data->bss_info, sizeof(wifi_bss_info_t));
        update_global_cache_radio_channel(sta_data->bss_info.freq);
        if(ctrl->network_mode == rdk_dev_mode_type_ext) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d Mode: Extender, sta connected, delete scan candidates\n",__FUNCTION__, __LINE__);
        } else {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d Mode: Gateway, delete scan candidates and disconnect sta on vap:%d\n",__FUNCTION__, __LINE__, sta_data->stats.vap_index);
            wifi_hal_disconnect(sta_data->stats.vap_index);
            ctrl->conn_state = connection_state_disconnected;
        }
        if(ctrl->scan_list != NULL) {
            free(ctrl->scan_list);
            ctrl->scan_list = NULL;
            ctrl->scan_count = 0;
        }
    } else if (sta_data->stats.connect_status == wifi_connection_status_ap_not_found || sta_data->stats.connect_status == wifi_connection_status_disconnected) {
        if(ctrl->network_mode == rdk_dev_mode_type_ext) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d Mode: Extender, conn_state:%d\n",__FUNCTION__, __LINE__, ctrl->conn_state);
            if (ctrl->conn_state == connection_state_in_progress) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d Mode: Extender, sta not connected, conn_state:%d\n",__FUNCTION__, __LINE__, ctrl->conn_state);
                scan_list_t *scan_list;
                scan_list = ctrl->scan_list;

                if (scan_list != NULL) {

                    for(i = 0; i < ctrl->scan_count; i++) {
                        wifi_util_dbg_print(WIFI_CTRL,"%s:%d bssid:%s scan_list->conn_attempt:%d\n",__FUNCTION__, __LINE__,
                                to_mac_str(scan_list->external_ap.bssid, bssid_str), scan_list->conn_attempt);
                        if(scan_list->conn_attempt == connection_attempt_in_progress) {
                            scan_list->conn_attempt = connection_attempt_failed;
                        }

                        if(scan_list->conn_attempt == connection_attempt_wait) {
                            scan = false;
                        }

                        scan_list++;
                    }

                    if(scan) {
                        ctrl->conn_state = connection_state_disconnected;
                        if (ctrl->scan_list != NULL) {
                            free(ctrl->scan_list);
                            ctrl->scan_list = NULL;
                            ctrl->scan_count = 0;
                        }

                        start_scan();
                    }
                } else {
                    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi_scan list not present, start scanning\r\n",__func__, __LINE__);
                    ctrl->conn_state = connection_state_disconnected;
                    start_scan();
                }
            } else {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d Mode: Extender, sta connected, change it to disconnected, conn_state:%d\n",
                                    __FUNCTION__, __LINE__, ctrl->conn_state);

                ctrl->conn_state = connection_state_disconnected;

                if (ctrl->connected_external_ap.freq) {
                   mac_addr_str_t bssid_str;
                   wifi_util_dbg_print(WIFI_CTRL,"%s:%d connecting to ssid:%s bssid:%s rssi:%d frequency:%d on vap:%d\n",
                                    __func__, __LINE__, ctrl->connected_external_ap.ssid, to_mac_str(ctrl->connected_external_ap.bssid, bssid_str),
                                    ctrl->connected_external_ap.rssi, ctrl->connected_external_ap.freq, ctrl->connected_vap_index);
                   if (wifi_hal_connect(ctrl->connected_vap_index, &ctrl->connected_external_ap) == RETURN_ERR) {
                      wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi_hal_connect failed\n",__FUNCTION__, __LINE__);
                      memset(&ctrl->connected_external_ap, 0, sizeof(wifi_bss_info_t));
                   } else {
                      ctrl->conn_state = connection_state_in_progress;
                      wifi_util_dbg_print(WIFI_CTRL,"%s:%d start wifi_hal_connect\n",__FUNCTION__, __LINE__);
                      ctrl->last_connected_time = get_current_ms_time();
                   }
                }
            }
         }
    }

    /* publish connection status over rbus */
    if (rbus_send_connected || sta_data->stats.connect_status == wifi_connection_status_disconnected) {
        ctrl->webconfig_state |= ctrl_webconfig_state_sta_conn_status_rsp_pending;
        sprintf(name, "Device.WiFi.STA.%d.Connection.Status", index+1);

        wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus name:%s:connection status:%d\r\n", __func__, __LINE__,
                                       name, sta_data->stats.connect_status);
        rbusValue_Init(&value);
        rbusObject_Init(&rdata, NULL);

        rbusObject_SetValue(rdata, name, value);
        rbusValue_SetBytes(value, (uint8_t *)&sta_data->stats.connect_status, sizeof(sta_data->stats.connect_status));
        event.name = name;
        event.data = rdata;
        event.type = RBUS_EVENT_GENERAL;

        if (rbusEvent_Publish(ctrl->rbus_handle, &event) != RBUS_ERROR_SUCCESS) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed\n", __func__, __LINE__);
            return;
        }

        rbusValue_Release(value);
        rbusObject_Release(rdata);
    }
}

void process_sta_connect_command(bool connect)
{
    unsigned int i, j, sta_vap_index;
    wifi_channel_t channel;
    ssid_t sta_ssid;
    wifi_bss_info_t *bss_array, *tmp_bss, target_bss;
    unsigned int num_bss;
    bool found_sta_ssid = false;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    uint8_t num_of_radios = getNumberRadios();
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: sta connect command:%d\n", __func__, __LINE__, connect);
    if (connect == false) {
        // disconnect from STA and return
        for (i = 0; i < num_of_radios; i++) {
            vap_map = &mgr->radio_config[i].vaps.vap_map;
            for (j = 0; j < vap_map->num_vaps; ++j) {
                if (!strncmp(vap_map->vap_array[j].vap_name, "mesh_sta", strlen("mesh_sta"))) {
                    break;
                }
            }
            vap = &vap_map->vap_array[j];
            if ((vap->vap_mode == wifi_vap_mode_sta) &&
                    (vap->u.sta_info.conn_status == wifi_connection_status_connected)) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi disconnect :%d\n", __func__, __LINE__, vap->vap_index);
                wifi_hal_disconnect(vap->vap_index);
            }
        }
        process_xfinity_vaps(1, false); //reenable public vaps
        return;
    }

    process_xfinity_vaps(0, false); // disable public vaps
    // try finding STA bssid on 2.4 first and then on 5GHz
    for (i = 0; i < num_of_radios; i++) {
        if (get_sta_ssid_from_radio_config_by_radio_index(i, sta_ssid) == -1) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Could not find sta ssid for radio index:%d\n",
                            __func__, __LINE__, i);
            continue;
        }
        radio = find_radio_config_by_index(i);
        channel.band = radio->oper.band;
        channel.channel = radio->oper.channel;
        sta_vap_index = get_sta_vap_index_for_radio(&mgr->hal_cap.wifi_prop, i);
        if (wifi_hal_findNetworks(sta_vap_index, &channel, &bss_array, &num_bss) == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_hal_findNetworks failed for radio index:%d\n",
                        __func__, __LINE__, i);
            continue;
        }

        tmp_bss = bss_array;
        for (j = 0; j < num_bss; j++) {
            if (strcmp(tmp_bss->ssid, sta_ssid) == 0) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: ssid match found for radio index:%d\n",
                        __func__, __LINE__, i);
                found_sta_ssid = true;
                memcpy(&target_bss, tmp_bss, sizeof(wifi_bss_info_t));
                break;
            }
            tmp_bss++;
        }

        free(bss_array);

        if (found_sta_ssid == true) {
            break;
        }
    }

    if (found_sta_ssid == true) {
        wifi_hal_connect(sta_vap_index, &target_bss);
    } else {
    // start a scan procedure for 2.4 and 5 Ghz Radio
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d start scan on 2.4GHz and 5GHz radios\n",__func__, __LINE__);
        wifi_hal_startScan(0, WIFI_RADIO_SCAN_MODE_ONCHAN, 0, 0, NULL);
	wifi_hal_startScan(1, WIFI_RADIO_SCAN_MODE_ONCHAN, 0, 0, NULL);
    }
}

bool  IsClientConnected(rdk_wifi_vap_info_t* rdk_vap_info, char *check_mac)
{
    int itr;
    assoc_dev_data_t *assoc_dev_data = NULL;
    mac_address_t mac;

    if((check_mac == NULL) || (rdk_vap_info == NULL)){
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d Null arguments\n",__func__, __LINE__);
        return false;
    }

    to_mac_bytes(check_mac, mac);
    queue_t *associated_devices_queue;
    associated_devices_queue = rdk_vap_info->associated_devices_queue;
    if (associated_devices_queue == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return false;
    }

    int count  = queue_count(associated_devices_queue);
    for (itr=0; itr<count; itr++) {
        assoc_dev_data = (assoc_dev_data_t *)queue_peek(associated_devices_queue, itr);
        if (memcmp(assoc_dev_data->dev_stats.cli_MACAddress, mac, sizeof(mac_address_t)) == 0){
            return true;
        }
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Client is not connected to vap_index\n", __func__, __LINE__);
    return false;
}

int process_maclist_timeout(void *arg)
{
    if (arg == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return TIMER_TASK_ERROR;
    }
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Inside \n", __func__, __LINE__);

    char *str_str, *cptr, *str_dup;
    int filtermode;
    kick_details_t *kick = NULL;
    wifi_vap_info_t *vap_info = NULL;
    kick = (kick_details_t *)arg;
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d kick list is %s\n", __func__, __LINE__, kick->kick_list);

    vap_info = getVapInfo(kick->vap_index);
    if (vap_info == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL vap_info Pointer\n", __func__, __LINE__);
        return TIMER_TASK_ERROR;
    }
    
    rdk_vap_info = get_wifidb_rdk_vap_info(kick->vap_index);
    if (rdk_vap_info == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL rdk_vap_info Pointer\n", __func__, __LINE__);
        return TIMER_TASK_ERROR;
    }

    str_dup = strdup(kick->kick_list);
    if (str_dup == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return TIMER_TASK_ERROR;
    }

    str_str = strtok_r(str_dup, ",", &cptr);
    while (str_str != NULL) {
        if ((rdk_vap_info->kick_device_config_change) && (!vap_info->u.bss_info.mac_filter_enable)){
            if (wifi_delApAclDevice(kick->vap_index, str_str) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
                        __func__, __LINE__, kick->vap_index, str_str);
            }
        } else {
            if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                if (wifi_delApAclDevice(kick->vap_index, str_str) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
                            __func__, __LINE__, kick->vap_index, str_str);
                }
            } else if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
                if (wifi_addApAclDevice(kick->vap_index, str_str) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_addApAclDevice failed. vap_index %d, mac %s \n",
                            __func__, __LINE__, kick->vap_index, str_str);
                }
            }
        }
        str_str = strtok_r(NULL, ",", &cptr);
    }

    if (rdk_vap_info->kick_device_task_counter > 0) {
        rdk_vap_info->kick_device_task_counter--;
    }

    if ((rdk_vap_info->kick_device_task_counter == 0) && (rdk_vap_info->kick_device_config_change)) {
        if (vap_info->u.bss_info.mac_filter_enable == TRUE) {
            if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                filtermode = 2;
            } else {
                filtermode = 1;
            }
        } else {
            filtermode  = 0;
        }
        if (wifi_setApMacAddressControlMode(kick->vap_index, filtermode) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_setApMacAddressControlMode failed vap_index %d", __func__, __LINE__);
        }
        rdk_vap_info->kick_device_config_change = FALSE;
    }

    if (str_dup) {
        free(str_dup);
    }
    if ((kick != NULL) && (kick->kick_list != NULL)) {
        free(kick->kick_list);
        kick->kick_list = NULL;
    }

    if (kick != NULL) {
        free(kick);
        kick = NULL;
    }
    return TIMER_TASK_COMPLETE;
}

void kick_all_macs(int vap_index, int timeout, rdk_wifi_vap_info_t* rdk_vap_info, wifi_ctrl_t *ctrl, wifi_vap_info_t *vap_info)
{
    int itr;
    assoc_dev_data_t *assoc_dev_data = NULL;
    queue_t *associated_devices_queue = NULL;
    mac_address_t kick_all = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    char *assoc_maclist;
    mac_addr_str_t mac_str;
    kick_details_t *kick_details = NULL;
    //Code to kick all mac
    if (wifi_hal_kickAssociatedDevice(vap_index, kick_all) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d Failed to kick all mac from ap_index %d\n", __func__, __LINE__, vap_index);
        return;
    }
    associated_devices_queue = rdk_vap_info->associated_devices_queue;
    if (associated_devices_queue ==  NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL queue pointer \n", __func__, __LINE__);
        return;
    }
    kick_details = (kick_details_t *)malloc(sizeof(kick_details_t));
    if (kick_details == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL data Pointer\n", __func__, __LINE__);
    }

    memset(kick_details, 0, sizeof(kick_details_t));
    assoc_maclist =  (char*)malloc(2048);
    if (assoc_maclist == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }

    memset(assoc_maclist, 0, 2048);
    int count  = queue_count(associated_devices_queue);
    for (itr=0; itr<count; itr++) {
        assoc_dev_data = (assoc_dev_data_t *)queue_peek(associated_devices_queue, itr);
        if (assoc_dev_data == NULL) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: NULL pointer for iteration %d\n", __func__, __LINE__, itr);
            continue;
        }
        memset(mac_str, 0, sizeof(mac_addr_str_t));
        to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, mac_str);
        if (rdk_vap_info->kick_device_config_change == TRUE) {
            if (wifi_addApAclDevice(vap_index, mac_str) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_addApAclDevice failed. vap_index %d\n",
                        __func__, __LINE__, vap_index);
            }
        } else {
            if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                if (wifi_addApAclDevice(vap_index, mac_str) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_addApAclDevice failed. vap_index %d\n",
                            __func__, __LINE__, vap_index);
                }
            } else if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
                if (wifi_delApAclDevice(vap_index, mac_str) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_delApAclDevice failed. vap_index %d\n",
                            __func__, __LINE__, vap_index);
                }
            }
        }
        strcat(assoc_maclist, mac_str);
        strcat(assoc_maclist, ",");
    }
    int len = strlen(assoc_maclist);
    if (len > 0) {
        assoc_maclist[len-1] = '\0';
    }
    kick_details->kick_list = assoc_maclist;
    kick_details->vap_index = vap_index;
    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, process_maclist_timeout, kick_details,
            timeout*1000, 1);
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Scheduled task for vap_index %d\n", __func__, __LINE__, vap_index);

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Exit\n", __func__, __LINE__);
    return;
}

void process_kick_assoc_devices_event(void *data)
{
    wifi_util_dbg_print(WIFI_CTRL,"Inside %s\n", __func__);
    char *str_str, *cptr, *str_dup;
    int itr = 0, timeout = 0, vap_index = 0;
    wifi_ctrl_t *ctrl;
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    wifi_vap_info_t *vap_info = NULL;
    char *str, s_vapindex[10], s_maclist[2048], s_timeout[520], *assoc_maclist;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    kick_details_t *kick_details = NULL;
    ctrl = &p_wifi_mgr->ctrl;
    mac_address_t kick_all = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    mac_address_t mac_bytes;

    if (data == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NUll data Pointer\n", __func__, __LINE__);
        return;
    }


    str = (char *)data;

    str_dup = strdup(str);
    if (str_dup ==  NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }

    memset(s_vapindex, 0, sizeof(s_vapindex));
    memset(s_maclist, 0, sizeof(s_maclist));
    memset(s_timeout, 0, sizeof(s_timeout));

    str_str = strtok_r(str_dup, "-", &cptr);
    while (str_str != NULL) {
        if (itr > 2) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d Invalid input not kicking Macs\n", __func__, __LINE__);
            if (str_dup) {
                free(str_dup);
            }
            return;
        }

        if (itr == 0) {
            strncpy(s_vapindex, str_str, sizeof(s_vapindex) - 1);
        } else if (itr == 1) {
            strncpy(s_maclist, str_str, sizeof(s_maclist) - 1);
        } else if (itr == 2) {
            strncpy(s_timeout, str_str, sizeof(s_timeout) - 1);
        }

        str_str = strtok_r(NULL, "-", &cptr);
        itr++;
    }
    if (str_dup) {
        free(str_dup);
    }

    if (itr < 3) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d Invalid input not kicking Macs\n", __func__, __LINE__);
        return;
    }

    //Code to change the maclist and add to scheduler.
    vap_index = atoi(s_vapindex);
    vap_info = getVapInfo(vap_index);
    rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
    if ((vap_info == NULL) || (rdk_vap_info == NULL)){
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL vap_info Pointer\n", __func__, __LINE__);
        return;
    }

    str_dup = strdup(s_maclist);
    if (str_dup == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    timeout = atoi(s_timeout);

    if (vap_info->u.bss_info.mac_filter_enable == FALSE) {
        if (wifi_setApMacAddressControlMode(vap_index, 2) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_setApMacAddressControlMode failed vap_index %d", __func__, __LINE__, vap_index);
            return;
        }
        rdk_vap_info->kick_device_config_change = TRUE;
        rdk_vap_info->kick_device_task_counter++;
    }
    str_str = strtok_r(str_dup, ",", &cptr);
    if (str_str == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d No Maclist\n", __func__, __LINE__);
        if (str_dup) {
            free(str_dup);
        }
        return;
    }
    to_mac_bytes(str_str, mac_bytes);
    if (memcmp(mac_bytes, kick_all, sizeof(mac_address_t)) == 0) {
        kick_all_macs(vap_index, timeout, rdk_vap_info, ctrl, vap_info);
        if (str_dup) {
            free(str_dup);
        }
        return;
    }

    assoc_maclist =  (char*)malloc(2048);
    if (assoc_maclist == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL Pointer\n", __func__, __LINE__);
        if (str_dup) {
            free(str_dup);
        }
        return;
    }
    kick_details = (kick_details_t *)malloc(sizeof(kick_details_t));
    if (kick_details == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL Pointer\n", __func__, __LINE__);

        if (str_dup) {
            free(str_dup);
        }
        return;
    }

    memset(assoc_maclist, 0, 2048);
    memset(kick_details, 0, sizeof(kick_details_t));

    while(str_str != NULL) {
        to_mac_bytes(str_str, mac_bytes);
        if (memcmp(mac_bytes, kick_all, sizeof(mac_address_t)) == 0) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: ff mac\n", __func__, __LINE__);
            continue;
        }
        if (IsClientConnected(rdk_vap_info, str_str)) {
            //Client is associated.
            //Hal code for kick assoc dev in particular access Point
            if (wifi_hal_kickAssociatedDevice(vap_index, mac_bytes) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_hal_kickAssociatedDevice failed for mac %s\n", __func__, __LINE__, str_str);
            }

            if (rdk_vap_info->kick_device_config_change == TRUE) {
                if (wifi_addApAclDevice(vap_index, str_str) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_addApAclDevice failed. vap_index %d, mac %s \n",
                            __func__, __LINE__, vap_index, str_str);
                }
            } else {
                if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                    if (wifi_addApAclDevice(vap_index, str_str) != RETURN_OK) {
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_addApAclDevice failed. vap_index %d, mac %s \n",
                                __func__, __LINE__, vap_index, str_str);
                    }
                } else if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
                    if (wifi_delApAclDevice(vap_index, str_str) != RETURN_OK) {
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
                                __func__, __LINE__, vap_index, str_str);
                    }
                }
            }
        }
        strcat(assoc_maclist, str_str);
        strcat(assoc_maclist, ",");
        str_str = strtok_r(NULL, ",", &cptr);
    }
    if (str_dup) {
        free(str_dup);
    }
    int assoc_len = strlen(assoc_maclist);
    if (assoc_len > 0) {
        assoc_maclist[assoc_len-1] = '\0';
    }
    kick_details->kick_list = assoc_maclist;
    kick_details->vap_index = vap_index;
    timeout = atoi(s_timeout);
    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, process_maclist_timeout, kick_details,
            timeout*1000, 1); 

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d vap_index is %s mac_list is %s timeout is %s\n", __func__, __LINE__, s_vapindex, s_maclist, s_timeout);
    return;
}
void process_greylist_mac_filter(void *data)
{
    long int  expiry_time = 0;
    struct timeval tv_now;
    unsigned int itr = 0, itrj = 0;
    int reason = 0;
    int vap_index = 0;
    const char *wifi_health_log = "/rdklogs/logs/wifihealth.txt";
    char log_buf[1024] = {0};
    char time_str[20] = {0};
    time_t now;
    struct tm *time_info;
    bool greylist_client_added = false;

    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    mac_address_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    acl_entry_t *acl_entry = NULL;
    acl_entry_t *temp_acl_entry = NULL;
    mac_address_t new_mac;
    mac_addr_str_t new_mac_str;
    char macfilterkey[128];
    wifi_vap_info_map_t *wifi_vap_map = NULL;

    memset(macfilterkey, 0, sizeof(macfilterkey));

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Enter \n", __FUNCTION__, __LINE__);
    greylist_data_t *grey_data = (greylist_data_t *) data;
    reason = grey_data->reason;

    wifi_util_dbg_print(WIFI_CTRL,"Disassociation reason is %d\n",reason);
    if (reason != WLAN_RADIUS_GREYLIST_REJECT){
        wifi_util_dbg_print(WIFI_CTRL,"This Not a Greylisted disassoc device\n");
        return;
    }

    memcpy(new_mac, grey_data->sta_mac, sizeof(mac_address_t));
    gettimeofday(&tv_now, NULL);
    expiry_time = tv_now.tv_sec + GREYLIST_TIMEOUT_IN_SECONDS;
    wifi_util_dbg_print(WIFI_CTRL," time now %d and expiry_time %d\n",tv_now.tv_sec,expiry_time);

    for (itr = 0; itr < getNumberRadios(); itr++) {
        wifi_vap_map = get_wifidb_vap_map(itr);
        for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
            vap_index = wifi_vap_map->vap_array[itrj].vap_index;
            rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);

            if (rdk_vap_info == NULL) {
                 return;
            }

            if ((strstr(rdk_vap_info->vap_name, "hotspot") == NULL)) {
                continue;
            }

            if (rdk_vap_info->acl_map == NULL) {
                wifi_util_dbg_print(WIFI_CTRL,"GreyList acl_map is NULL\n");
                rdk_vap_info->acl_map = hash_map_create();
            }

            if (memcmp(new_mac, zero_mac, sizeof(mac_address_t)) == 0){
                wifi_util_dbg_print(WIFI_CTRL,"GreyList new_mac is zero mac \n");
                return ;
            }

            to_mac_str(new_mac, new_mac_str);
            temp_acl_entry = hash_map_get(rdk_vap_info->acl_map,strdup(new_mac_str));

            if (temp_acl_entry != NULL) {
                wifi_util_dbg_print(WIFI_CTRL,"Mac is already present in macfilter \n");
                return;
            }

            acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
            memcpy(acl_entry->mac, new_mac, sizeof(mac_address_t));
            to_mac_str(acl_entry->mac, new_mac_str);
            acl_entry->reason = WLAN_RADIUS_GREYLIST_REJECT;
            acl_entry->expiry_time = expiry_time;

            if (wifi_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_MGR, "%s:%d: wifi_addApAclDevice failed. vap_index %d, MAC %s \n",
                   __func__, __LINE__, rdk_vap_info->vap_index, new_mac_str);
                return;
            }

            hash_map_put(rdk_vap_info->acl_map, strdup(new_mac_str), acl_entry);

            snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", rdk_vap_info->vap_name, new_mac_str);
            wifidb_update_wifi_macfilter_config(macfilterkey, acl_entry, true);
            greylist_client_added = true;
        }
    }
    //Add time and Mac address to wifihealth.txt
    if (greylist_client_added) {
        time(&now);
        time_info = localtime(&now);
        to_mac_str(new_mac, new_mac_str);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", time_info);
        sprintf(log_buf,"%s Client added to grey list from RADIUS:%s\n",time_str,new_mac_str);
        write_to_file(wifi_health_log, log_buf);
        wifi_util_dbg_print(WIFI_CTRL,"%s",log_buf);
   }
}

void process_wifi_host_sync()
{

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Inside \n", __func__, __LINE__);
    LM_wifi_hosts_t hosts;
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    mac_addr_str_t mac_str;
    char ssid[256];
    char assoc_device[256];
    unsigned int itr, itrj=0, count;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    assoc_dev_data_t *assoc_dev_data = NULL;

    memset(&hosts, 0, sizeof(LM_wifi_hosts_t));
    memset(ssid, 0, sizeof(ssid));
    memset(assoc_device, 0, sizeof(assoc_device));

    for (itr=0; itr<getTotalNumberVAPs(); itr++) {
        if ((isVapPrivate(itr)) || (isVapXhs(itr))) {
            rdk_vap_info = get_wifidb_rdk_vap_info(itr);
            if (rdk_vap_info == NULL) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d ERROR Null Pointer\n", __func__, __LINE__);
                continue;
            }

            if (hosts.count > LM_MAX_HOSTS_NUM) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d has reached LM_MAX_HOSTS_NUM\n", __func__, __LINE__);
                break;
            }

            if (rdk_vap_info->associated_devices_queue != NULL) {
                count = queue_count(rdk_vap_info->associated_devices_queue);
                for (itrj=0; itrj<count; itrj++) {
                    assoc_dev_data = (assoc_dev_data_t *)queue_peek(rdk_vap_info->associated_devices_queue, itrj);
                    if (assoc_dev_data == NULL) {
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL Pointer\n", __func__, __LINE__);
                        continue;
                    }

                    snprintf(ssid, sizeof(ssid), "Device.WiFi.SSID.%d", rdk_vap_info->vap_index+1);
                    strncpy((char *)hosts.host[hosts.count].ssid, ssid, sizeof(hosts.host[hosts.count].ssid));
                    to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, mac_str);
                    strncpy((char *)hosts.host[hosts.count].phyAddr, mac_str, sizeof(hosts.host[hosts.count].phyAddr));
                    snprintf(assoc_device, sizeof(assoc_device), "Device.WiFi.AccessPoint.%d.AssociatedDevice.%d", rdk_vap_info->vap_index+1, itrj+1);
                    strncpy((char *)hosts.host[hosts.count].AssociatedDevice, assoc_device, sizeof(hosts.host[hosts.count].AssociatedDevice));
                    if (assoc_dev_data->dev_stats.cli_Active) {
                        hosts.host[hosts.count].Status = TRUE;
                    } else {
                        hosts.host[hosts.count].Status = FALSE;
                    }
                    hosts.host[hosts.count].RSSI = assoc_dev_data->dev_stats.cli_RSSI;
                    (hosts.count)++;
                }
                if (notify_associated_entries(&p_wifi_mgr->ctrl, rdk_vap_info->vap_index, count, 0) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
                }

            }
        }
    }
    if (notify_LM_Lite(&p_wifi_mgr->ctrl, &hosts, false) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d Unable to send notification to LMLite", __func__, __LINE__);
    }

}

void lm_notify_disassoc(assoc_dev_data_t *assoc_dev_data, unsigned int vap_index)
{
    char ssid[256]= {0};
    mac_addr_str_t mac_str;
    LM_wifi_hosts_t hosts;
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();

    if (assoc_dev_data == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    memset(ssid, 0, sizeof(ssid));
    snprintf(ssid, sizeof(ssid), "Device.WiFi.SSID.%d", vap_index +1);

    memset(&hosts, 0, sizeof(LM_wifi_hosts_t));
    strncpy((char *)hosts.host[0].ssid, ssid, sizeof(hosts.host[0].ssid));

    to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, mac_str);
    strncpy((char *)hosts.host[0].phyAddr, mac_str, sizeof(hosts.host[0].phyAddr));
    hosts.host[0].Status = FALSE;
    hosts.host[0].RSSI = 0;

    if (isVapHotspot(vap_index)) {
        if (notify_hotspot(&p_wifi_mgr->ctrl, assoc_dev_data) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d Unable to send notification to Hotspot\n", __func__, __LINE__);
        }
    } else if ((isVapPrivate(vap_index)) || (isVapXhs(vap_index))) {
        //Code to Publish to LMLite
        if (notify_LM_Lite(&p_wifi_mgr->ctrl, &hosts, true) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d Unable to send notification to LMLite", __func__, __LINE__);
        }
    }
}

void process_disassoc_device_event(void *data)
{
    unsigned int count = 0, i = 0;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    assoc_dev_data_t *assoc_dev_data = NULL;
    mac_address_t disassoc_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    mac_address_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    ULONG old_count = 0, new_count = 0;

    if (data == NULL) {
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;

    rdk_vap_info = get_wifidb_rdk_vap_info(assoc_data->ap_index);
    if (rdk_vap_info == NULL) {
        return;
    }

    if (rdk_vap_info->associated_devices_queue == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }

    if ((memcmp(assoc_data->dev_stats.cli_MACAddress, disassoc_mac, sizeof(mac_address_t)) == 0) ||
           (memcmp(assoc_data->dev_stats.cli_MACAddress, zero_mac, sizeof(mac_address_t)) == 0)) {
        if (rdk_vap_info->associated_devices_queue !=  NULL) {
            old_count  = queue_count(rdk_vap_info->associated_devices_queue);
            do {
                assoc_dev_data = (assoc_dev_data_t *)queue_pop(rdk_vap_info->associated_devices_queue);
                if (assoc_dev_data != NULL) {
                    lm_notify_disassoc(assoc_dev_data, rdk_vap_info->vap_index);
                    free(assoc_dev_data);
                }
            } while (assoc_dev_data != NULL);
            new_count  = 0;
            if (((isVapPrivate(rdk_vap_info->vap_index)) || (isVapXhs(rdk_vap_info->vap_index)))){
                if (notify_associated_entries(&p_wifi_mgr->ctrl, rdk_vap_info->vap_index, new_count, old_count) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
                }
            }
        }
        return;
    }

    count = queue_count(rdk_vap_info->associated_devices_queue);
    for (i = 0; i < count; i++) {
        assoc_dev_data = (assoc_dev_data_t *)queue_peek(rdk_vap_info->associated_devices_queue, i);
        if (assoc_dev_data == NULL) {
            continue;
        }

        if (memcmp(assoc_data->dev_stats.cli_MACAddress, assoc_dev_data->dev_stats.cli_MACAddress, 6) == 0)
        {
            old_count = queue_count(rdk_vap_info->associated_devices_queue);
            assoc_dev_data = (assoc_dev_data_t*)queue_remove(rdk_vap_info->associated_devices_queue, i);
            if (assoc_dev_data != NULL) {
                lm_notify_disassoc(assoc_dev_data, rdk_vap_info->vap_index);
                free(assoc_dev_data);
            }
            new_count = old_count - 1;
            if (((isVapPrivate(rdk_vap_info->vap_index)) || (isVapXhs(rdk_vap_info->vap_index)))){
                if (notify_associated_entries(&p_wifi_mgr->ctrl, rdk_vap_info->vap_index, new_count, old_count) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
                }
            }

            p_wifi_mgr->ctrl.webconfig_state |= ctrl_webconfig_state_associated_clients_cfg_rsp_pending;
            break;
        }
    }
}

void process_assoc_device_event(void *data)
{
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    assoc_dev_data_t* assoc_data_to_queue = NULL;
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    mac_addr_str_t mac_str;
    char ssid[256]= {0};
    char assoc_device[256] = {0};
    ULONG old_count = 0, new_count = 0;
    assoc_dev_data_t *p_assoc_data;
    int itr = 0, itrj = 0;

    if (data == NULL) {
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;

    rdk_vap_info = get_wifidb_rdk_vap_info(assoc_data->ap_index);
    if (rdk_vap_info == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL rdk_vap_info pointer\n", __func__, __LINE__);
        return;
    }

    assoc_data_to_queue = (assoc_dev_data_t *)malloc(sizeof(assoc_dev_data_t));
    if (assoc_data_to_queue ==  NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL  assoc_data_to_queue pointer \n", __func__, __LINE__);
        return;
    }

    memset(assoc_data_to_queue, 0, sizeof(assoc_dev_data_t));
    memcpy(assoc_data_to_queue, assoc_data, sizeof(assoc_dev_data_t));

    if (rdk_vap_info->associated_devices_queue) {
        old_count = queue_count(rdk_vap_info->associated_devices_queue);
        queue_push(rdk_vap_info->associated_devices_queue, assoc_data_to_queue);
        p_wifi_mgr->ctrl.webconfig_state |= ctrl_webconfig_state_associated_clients_cfg_rsp_pending;
        new_count  = old_count + 1;

        if (((isVapPrivate(rdk_vap_info->vap_index)) || (isVapXhs(rdk_vap_info->vap_index)))){
            if (notify_associated_entries(&p_wifi_mgr->ctrl, rdk_vap_info->vap_index, new_count, old_count) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
            }
        }
        if (isVapHotspot(rdk_vap_info->vap_index)) {
            if (notify_hotspot(&p_wifi_mgr->ctrl, assoc_data_to_queue) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d Unable to send notification to Hotspot\n", __func__, __LINE__);
            }
        }
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL assoc_device_queue\n", __func__,__LINE__);
        free(assoc_data_to_queue);
    }

    //Code to publish event to LMLite.
    if ((isVapPrivate(rdk_vap_info->vap_index)) || (isVapXhs(rdk_vap_info->vap_index))) {
        snprintf(ssid, sizeof(ssid), "Device.WiFi.SSID.%d", rdk_vap_info->vap_index+1);
        LM_wifi_hosts_t hosts;
        memset(&hosts, 0, sizeof(LM_wifi_hosts_t));
        strncpy((char *)hosts.host[0].ssid, ssid, sizeof(hosts.host[0].ssid));
        int count  = queue_count(rdk_vap_info->associated_devices_queue);

        for (itr = 0; itr<count; itr++) {
            p_assoc_data = (assoc_dev_data_t *)queue_peek(rdk_vap_info->associated_devices_queue, itr);
            if (p_assoc_data == NULL) {
                continue;
            }
            to_mac_str(p_assoc_data->dev_stats.cli_MACAddress, mac_str);
            strncpy((char *)hosts.host[0].phyAddr, mac_str, sizeof(hosts.host[0].phyAddr));
            snprintf(assoc_device, sizeof(assoc_device), "Device.WiFi.AccessPoint.%d.AssociatedDevice.%d", rdk_vap_info->vap_index+1, itrj+1);
            strncpy((char *)hosts.host[0].AssociatedDevice, assoc_device, sizeof(hosts.host[0].AssociatedDevice));
            if (p_assoc_data->dev_stats.cli_Active) {
                hosts.host[0].Status = TRUE;
            } else {
                hosts.host[0].Status = FALSE;
            }
            hosts.host[0].RSSI = p_assoc_data->dev_stats.cli_RSSI;

            if (notify_LM_Lite(&p_wifi_mgr->ctrl, &hosts, true) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d Unable to send notification to LMLite", __func__, __LINE__);
            }
            itrj++;
        }
    }
}

void process_factory_reset_command(bool type)
{
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    p_wifi_mgr->ctrl.factory_reset = type;
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d and type is %d\n",__func__,__LINE__,type);
    system("killall -9 wifidb-server");
    system("rm -f /nvram/wifi/rdkb-wifi.db");
    wifidb_cleanup();
    start_wifidb();
    wifi_util_dbg_print(WIFI_DB,"WIFI Factory reset started wifi db %d\n",__LINE__);
    init_wifidb_tables();
    wifidb_init_default_value();
    wifi_util_dbg_print(WIFI_DB,"WIFI Factory reset initiated default value %d\n",__LINE__);
    start_wifi_services();
    wifi_util_dbg_print(WIFI_DB,"WIFI Factory reset started wifidb monitor %d\n",__LINE__);
    start_wifidb_monitor();
    p_wifi_mgr->ctrl.webconfig_state |= ctrl_webconfig_state_factoryreset_cfg_rsp_pending;
}

void process_radius_grey_list_rfc(bool type)
{
    bool public_xfinity_vap_status = false;
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();

    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    rfc_param->radiusgreylist_rfc = type;
    wifidb_update_rfc_config(0, rfc_param);
    g_wifi_mgr->rfc_dml_parameters.radiusgreylist_rfc = type;

    public_xfinity_vap_status = get_wifi_public_vap_enable_status();

    if (public_xfinity_vap_status) {
        wifi_util_dbg_print(WIFI_CTRL,"public xfinity vaps are up and running\n");
        process_xfinity_vaps(2,false);
    }

    if (!rfc_param->radiusgreylist_rfc) {
        wifi_util_dbg_print(WIFI_CTRL,"Greylist RFC is disabled remove all greylisted entries from DB\n");
        remove_greylist_acl_entries(true);
    }
}

void process_wifi_passpoint_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->wifipasspoint_rfc = type;
    wifidb_update_rfc_config(0, rfc_param);
}

void process_xfinity_open_2g_enabled(bool open_2g)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,open_2g);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->hotspot_open_2g_last_enabled = open_2g;
    wifidb_update_rfc_config(0, rfc_param);
}
void process_xfinity_open_5g_enabled(bool open_5g)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,open_5g);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->hotspot_open_5g_last_enabled = open_5g;
    wifidb_update_rfc_config(0, rfc_param);
}
void process_xfinity_sec_2g_enabled(bool secure_2g)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,secure_2g);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->hotspot_secure_2g_last_enabled = secure_2g;
    wifidb_update_rfc_config(0, rfc_param);
}
void process_xfinity_sec_5g_enabled(bool secure_5g)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,secure_5g);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->hotspot_secure_5g_last_enabled = secure_5g;
    wifidb_update_rfc_config(0, rfc_param);
}
void process_wifi_interworking_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->wifiinterworking_rfc = type;
    wifidb_update_rfc_config(0, rfc_param);
}

void process_wpa3_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->wpa3_rfc = type;
    wifidb_update_rfc_config(0, rfc_param);
}

void process_dfs_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
	rfc_param->dfs_rfc = type;
    wifidb_update_rfc_config(0, rfc_param);
}

void process_dfs_atbootup_rfc(bool type)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->dfsatbootup_rfc = type;
    wifidb_update_rfc_config(0, rfc_param);
}

void process_twoG80211axEnable_rfc(bool type)
{
    int ret = 0;
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();

    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    ret = wifi_allow2G80211ax(type);
    if (ret == 0) {
        rfc_param->twoG80211axEnable_rfc = type;
        ret = wifidb_update_rfc_config(0, rfc_param);
        if (ret == 0) {
            g_wifi_mgr->rfc_dml_parameters.twoG80211axEnable_rfc = type;
        }
    }
}

void process_wps_command_event(unsigned int vap_index)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi wps test vap index = %d\n",__func__, __LINE__, vap_index);
    wifi_hal_setApWpsButtonPush(vap_index);
}

void process_device_mode_command_event(int device_mode)
{
    wifi_global_param_t *global_param = get_wifidb_wifi_global_param();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    ctrl->network_mode = device_mode;

    if (global_param->device_network_mode != device_mode) {
        global_param->device_network_mode = device_mode;
        update_wifi_global_config(global_param);
        if (device_mode == rdk_dev_mode_type_ext) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: disable all vaps and start station mode, scan_count:%d\r\n", __func__, __LINE__, ctrl->scan_count);
            stop_gateway_vaps();
            start_extender_vaps();
        } else if (device_mode == rdk_dev_mode_type_gw) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: disable station, delete all scan results and start accesspoint mode\r\n", __func__, __LINE__);
            stop_extender_vaps();
            start_gateway_vaps();
            if(ctrl->conn_state == connection_state_connected) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d disconnect sta on vap:%d\n",__FUNCTION__, __LINE__, ctrl->connected_vap_index);
                wifi_hal_disconnect(ctrl->connected_vap_index);
		ctrl->conn_state = connection_state_disconnected;
            }
        }
    }
    if(device_mode == rdk_dev_mode_type_gw) {
        ctrl->webconfig_state |= ctrl_webconfig_state_vap_all_cfg_rsp_pending;
    } else if (device_mode == rdk_dev_mode_type_ext) {
        /* Null out VIF table by sending NULL subdoc */
        ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_cfg_rsp_pending;
    }
}

void process_channel_change_event(wifi_channel_change_event_t *ch_chg)
{
    wifi_radio_operationParam_t *radio_params = NULL;
    wifi_mgr_t *g_wifidb;
    g_wifidb = get_wifimgr_obj();

    radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(ch_chg->radioIndex);
    if (radio_params == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s: wrong index for radio map: %d\n",__FUNCTION__, ch_chg->radioIndex);
        return;
    }
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d channel change on radio:%d old channel:%d new channel:%d channel change event type:%d op_class:%d\n",
                       __func__, __LINE__, ch_chg->radioIndex, radio_params->channel, ch_chg->channel, ch_chg->event, ch_chg->op_class);
    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    radio_params->channel = ch_chg->channel;
    radio_params->channelWidth = ch_chg->channelWidth;
    radio_params->op_class = ch_chg->op_class;
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);
    g_wifidb->ctrl.webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
    update_wifi_radio_config(ch_chg->radioIndex, radio_params);
}

void process_neighbor_scan_command_event()
{
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    wifi_radio_operationParam_t *wifi_radio_oper_param = NULL;
    wifi_neighborScanMode_t scan_mode = WIFI_RADIO_SCAN_MODE_FULL;
    int dwell_time = 20;

    if(strcmp(monitor_param->neighbor_scan_cfg.DiagnosticsState, "Requested") == 0) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Scan already in Progress!!!\n", __func__, __LINE__);
    } else {
        strcpy_s(monitor_param->neighbor_scan_cfg.DiagnosticsState, sizeof(monitor_param->neighbor_scan_cfg.DiagnosticsState) , "Requested");

        for(UINT rIdx = 0; rIdx < getNumberRadios(); rIdx++)
        {
            wifi_radio_oper_param = (wifi_radio_operationParam_t *)get_wifidb_radio_map(rIdx);
            wifi_startNeighborScan(rIdx, scan_mode, ((wifi_radio_oper_param->band == WIFI_FREQUENCY_6_BAND) ? (dwell_time=110) : dwell_time), 0, NULL);
        }
        scheduler_add_timer_task(monitor_param->sched, FALSE, &neighbor_scan_task_id, get_neighbor_scan_results, NULL,
                    NEIGHBOR_SCAN_RESULT_INTERVAL, 1);
    }
}

void handle_command_event(void *data, unsigned int len, ctrl_event_subtype_t subtype)
{
    switch (subtype) {
        case ctrl_event_type_command_sta_connect:
            process_sta_connect_command(*(bool *)data);
            break;

        case ctrl_event_type_command_factory_reset:
            process_factory_reset_command(*(bool *)data);
            break;
        case ctrl_event_type_radius_grey_list_rfc:
            process_radius_grey_list_rfc(*(bool *)data);
            break;
        case ctrl_event_type_wifi_passpoint_rfc:
            process_wifi_passpoint_rfc(*(bool *)data);
            break;
        case ctrl_event_type_wifi_interworking_rfc:
            process_wifi_interworking_rfc(*(bool *)data);
            break;
        case ctrl_event_type_wpa3_rfc:
            process_wpa3_rfc(*(bool *)data);
            break;
        case ctrl_event_type_dfs_rfc:
            process_dfs_rfc(*(bool *)data);
            break;
        case ctrl_event_type_dfs_atbootup_rfc:
            process_dfs_atbootup_rfc(*(bool *)data);
            break;
        case ctrl_event_type_twoG80211axEnable_rfc:
            process_twoG80211axEnable_rfc(*(bool *)data);
            break;

        case ctrl_event_type_command_kickmac:
            break;

        case ctrl_event_type_xfinity_tunnel_up:
            process_xfinity_vaps(1, true);
            break;

        case ctrl_event_type_xfinity_tunnel_down:
            process_xfinity_vaps(0, true);
            break;
        case ctrl_event_type_command_kick_assoc_devices:
            process_kick_assoc_devices_event(data);
            break;

        case ctrl_event_type_command_wps:
            process_wps_command_event(*(unsigned int *)data);
            break;

        case ctrl_event_type_command_wifi_host_sync:
            process_wifi_host_sync();
            break;

        case ctrl_event_type_device_network_mode:
            process_device_mode_command_event(*(int *)data);
            break;
        
        case ctrl_event_type_command_wifi_neighborscan:
            process_neighbor_scan_command_event();
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL,"[%s]:WIFI hal handler not supported this event %d\r\n",__FUNCTION__, subtype);
            break;
    }

}

void handle_hal_indication(void *data, unsigned int len, ctrl_event_subtype_t subtype)
{
    switch (subtype) {
        case ctrl_event_hal_mgmt_farmes:
            process_mgmt_ctrl_frame_event(data, len);
            break;

        case ctrl_event_hal_sta_conn_status:
            process_sta_conn_status_event(data, len);
            break;

        case ctrl_event_hal_assoc_device:
            process_assoc_device_event(data);
            break;

        case ctrl_event_hal_disassoc_device:
            process_disassoc_device_event(data);
            break;

        case ctrl_event_radius_greylist:
            process_greylist_mac_filter(data);
            break;

        case ctrl_event_scan_results:
            process_scan_results_event(data, len);
            break;

        case ctrl_event_hal_channel_change:
            process_channel_change_event(data);
            break;

        default:

            wifi_util_dbg_print(WIFI_CTRL,"[%s]:WIFI hal handler not supported this event %d\r\n",__FUNCTION__, subtype);
            break;
    }
}

void handle_webconfig_event(wifi_ctrl_t *ctrl, const char *raw, unsigned int len, ctrl_event_subtype_t subtype)
{
    webconfig_t *config;
    webconfig_subdoc_data_t data = {0};
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    config = &ctrl->webconfig;

    switch (subtype) {
        case ctrl_event_webconfig_set_data:
            memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));
            webconfig_decode(config, &data, raw);
            break;

        case ctrl_event_webconfig_set_data_tunnel:
            webconfig_decode(config, &data, raw);
            break;

        case ctrl_event_webconfig_get_data:
            // copy the global config
            memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&mgr->global_config, sizeof(wifi_global_config_t));

            // copy the radios and vaps data
            memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));

            //copy HAL Cap data
            memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));
            data.u.decoded.num_radios = getNumberRadios();

            // tell webconfig to encode
            webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_dml);
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL,"[%s]:WIFI webconfig handler not supported this event %d\r\n",__FUNCTION__, subtype);
            break;

    }
}


void handle_wifiapi_event(void *data, unsigned int len, ctrl_event_subtype_t subtype)
{
    switch (subtype) {
        case ctrl_event_type_wifiapi_execution:
            process_wifiapi_command((char *)data, len);
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL,"[%s]: wifi_api handler does not support this event %d\r\n",__FUNCTION__, subtype);
            break;
    }

}
