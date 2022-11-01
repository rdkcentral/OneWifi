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




void process_scan_results_event(scan_results_t *results, unsigned int len)
{
    wifi_ctrl_t *ctrl;
    vap_svc_t *ext_svc;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    ctrl = &mgr->ctrl;

    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        ext_svc->event_fn(ext_svc, ctrl_event_type_hal_ind, ctrl_event_scan_results, vap_svc_event_none, results);
    }
}
int remove_xfinity_acl_entries(bool remove_all_greylist_entry,bool prefer_private)
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
            if ((vap_svc_is_public(vap_index) == false)) {
                continue;
            }

            l_rdk_vap_array = get_wifidb_rdk_vap_info(vap_index);

            if (l_rdk_vap_array->acl_map != NULL) {
                acl_entry = hash_map_get_first(l_rdk_vap_array->acl_map);

                while (acl_entry != NULL) {
                    if ((prefer_private && (acl_entry->reason == PREFER_PRIVATE_RFC_REJECT)) || ((acl_entry->reason == WLAN_RADIUS_GREYLIST_REJECT) &&
                        ((acl_entry->expiry_time <= tv_now.tv_sec) || remove_all_greylist_entry))) {

                        to_mac_str(acl_entry->mac, mac_str);
                        ret = wifi_delApAclDevice(l_rdk_vap_array->vap_index, mac_str);
                        if (ret != RETURN_OK) {

                            wifi_util_error_print(WIFI_MGR, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
                             __func__, __LINE__, l_rdk_vap_array->vap_index, mac_str);
                            ret = RETURN_ERR;
                        }
                           acl_entry = hash_map_get_next(l_rdk_vap_array->acl_map, acl_entry);

                            tmp_acl_entry = hash_map_remove(l_rdk_vap_array->acl_map, mac_str);
                            snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", l_rdk_vap_array->vap_name, mac_str);
                            wifidb_update_wifi_macfilter_config(macfilterkey, tmp_acl_entry, false);
                    }
                    else {
                       acl_entry = hash_map_get_next(l_rdk_vap_array->acl_map, acl_entry);
                    }
                }
            }
       }
    }
    return RETURN_OK;
}

void process_mgmt_ctrl_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
    send_app_event(ctrl_event_type_hal_ind, msg);
}

void send_hotspot_status(char* vap_name, bool up)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL ctrl object\n", __func__,__LINE__);
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
        wifi_util_error_print(WIFI_CTRL,"%s:%d rbusEvent_Publish %s failed for %s\n", __func__, __LINE__, event.name, vap_name);
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

              if ((strcmp(tmp_vap_map.vap_array[0].vap_name,"hotspot_open_2g") == 0) && open_2g_enabled)
                  tmp_vap_map.vap_array[0].u.bss_info.enabled = true;

              else if ((strcmp(tmp_vap_map.vap_array[0].vap_name,"hotspot_open_5g") == 0) && open_5g_enabled)
                  tmp_vap_map.vap_array[0].u.bss_info.enabled = true;

              else if ((strcmp(tmp_vap_map.vap_array[0].vap_name,"hotspot_secure_2g") == 0) && sec_2g_enabled)
                  tmp_vap_map.vap_array[0].u.bss_info.enabled = true;

              else if ((strcmp(tmp_vap_map.vap_array[0].vap_name,"hotspot_secure_5g") == 0) && sec_5g_enabled)
                  tmp_vap_map.vap_array[0].u.bss_info.enabled = true;

              wifi_util_dbg_print(WIFI_CTRL,"enabled is %d\n",tmp_vap_map.vap_array[0].u.bss_info.enabled);
            }

            if(pub_svc->update_fn(pub_svc,radio_indx, &tmp_vap_map) != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL, "%s:%d Unable to create vaps\n", __func__,__LINE__);
                if(hs_evt) {
                    send_hotspot_status(wifi_vap_map->vap_array[j].vap_name, false);
               }
            } else {
                wifi_util_info_print(WIFI_CTRL, "%s:%d Able to create vaps. vap_enable %d\n", __func__,__LINE__, vap_enable);
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
        wifi_util_error_print(WIFI_CTRL, "%s:%d frequency out of range:%d\r\n", __func__,__LINE__, freq);
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
        wifi_util_error_print(WIFI_CTRL, "%s:%d frequency out of range:%d\r\n", __func__,__LINE__, freq);
        return;
    }

    convert_freq_to_channel(freq, &channel);

    wifi_radio_oper_param = (wifi_radio_operationParam_t *)get_wifidb_radio_map(radio_index);
    if (wifi_radio_oper_param != NULL) {
        if (wifi_radio_oper_param->channel != channel) {
            wifi_radio_oper_param->channel = channel;
            ctrl->webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
            wifi_util_info_print(WIFI_CTRL, "%s:%d channel updated to global cache:%d\r\n", __func__,__LINE__, channel);
            ret = wifi_hal_setRadioOperatingParameters(radio_index, wifi_radio_oper_param);
            if (ret != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL,"%s: wifi radio parameter set failure: radio_index:%d\n",__FUNCTION__, radio_index);
                return;
            } else {
                wifi_util_info_print(WIFI_CTRL,"%s: wifi radio parameter set success: radio_index:%d\n",__FUNCTION__, radio_index);
            }
        } else {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d global cache channel:%d current channel:%d\r\n", __func__,__LINE__, wifi_radio_oper_param->channel, channel);
        }
    }
}

void process_sta_conn_status_event(rdk_sta_data_t *sta_data, unsigned int len)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    vap_svc_t *ext_svc;

    ctrl->webconfig_state |= ctrl_webconfig_state_sta_conn_status_rsp_pending;

    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);

    if(ctrl->network_mode == rdk_dev_mode_type_ext) {
        ext_svc->event_fn(ext_svc, ctrl_event_type_hal_ind, ctrl_event_hal_sta_conn_status, vap_svc_event_none, sta_data);
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
                wifi_util_info_print(WIFI_CTRL, "%s:%d: wifi disconnect :%d\n", __func__, __LINE__, vap->vap_index);
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
            wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi_hal_findNetworks failed for radio index:%d\n",
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
        wifi_util_info_print(WIFI_CTRL,"%s:%d start scan on 2.4GHz and 5GHz radios\n",__func__, __LINE__);
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
        wifi_util_error_print(WIFI_CTRL, "%s:%d Null arguments\n",__func__, __LINE__);
        return false;
    }

    str_to_mac_bytes(check_mac, mac);
    queue_t *associated_devices_queue;
    associated_devices_queue = rdk_vap_info->associated_devices_queue;
    if (associated_devices_queue == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer \n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer \n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL vap_info Pointer\n", __func__, __LINE__);
        return TIMER_TASK_ERROR;
    }
    
    rdk_vap_info = get_wifidb_rdk_vap_info(kick->vap_index);
    if (rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL rdk_vap_info Pointer\n", __func__, __LINE__);
        return TIMER_TASK_ERROR;
    }

    str_dup = strdup(kick->kick_list);
    if (str_dup == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return TIMER_TASK_ERROR;
    }

    str_str = strtok_r(str_dup, ",", &cptr);
    while (str_str != NULL) {
        if ((rdk_vap_info->kick_device_config_change) && (!vap_info->u.bss_info.mac_filter_enable)){
            if (wifi_delApAclDevice(kick->vap_index, str_str) != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
                        __func__, __LINE__, kick->vap_index, str_str);
            }
        } else {
            if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                if (wifi_delApAclDevice(kick->vap_index, str_str) != RETURN_OK) {
                    wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
                            __func__, __LINE__, kick->vap_index, str_str);
                }
            } else if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
                if (wifi_addApAclDevice(kick->vap_index, str_str) != RETURN_OK) {
                    wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi_addApAclDevice failed. vap_index %d, mac %s \n",
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
            wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi_setApMacAddressControlMode failed vap_index %d", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL queue pointer \n", __func__, __LINE__);
        return;
    }
    kick_details = (kick_details_t *)malloc(sizeof(kick_details_t));
    if (kick_details == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL data Pointer\n", __func__, __LINE__);
    }

    memset(kick_details, 0, sizeof(kick_details_t));
    assoc_maclist =  (char*)malloc(2048);
    if (assoc_maclist == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer\n", __func__, __LINE__);
        free(kick_details);
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
    wifi_util_info_print(WIFI_CTRL, "%s:%d Scheduled task for vap_index %d\n", __func__, __LINE__, vap_index);

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
        wifi_util_error_print(WIFI_CTRL, "%s:%d NUll data Pointer\n", __func__, __LINE__);
        return;
    }


    str = (char *)data;

    str_dup = strdup(str);
    if (str_dup ==  NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }

    memset(s_vapindex, 0, sizeof(s_vapindex));
    memset(s_maclist, 0, sizeof(s_maclist));
    memset(s_timeout, 0, sizeof(s_timeout));

    str_str = strtok_r(str_dup, "-", &cptr);
    while (str_str != NULL) {
        if (itr > 2) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d Invalid input not kicking Macs\n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_CTRL, "%s:%d Invalid input not kicking Macs\n", __func__, __LINE__);
        return;
    }

    //Code to change the maclist and add to scheduler.
    vap_index = atoi(s_vapindex);
    vap_info = getVapInfo(vap_index);
    rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
    if ((vap_info == NULL) || (rdk_vap_info == NULL)){
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL vap_info Pointer\n", __func__, __LINE__);
        return;
    }

    str_dup = strdup(s_maclist);
    if (str_dup == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    timeout = atoi(s_timeout);

    if (vap_info->u.bss_info.mac_filter_enable == FALSE) {
        if (wifi_setApMacAddressControlMode(vap_index, 2) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi_setApMacAddressControlMode failed vap_index %d", __func__, __LINE__, vap_index);
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
    str_to_mac_bytes(str_str, mac_bytes);
    if (memcmp(mac_bytes, kick_all, sizeof(mac_address_t)) == 0) {
        kick_all_macs(vap_index, timeout, rdk_vap_info, ctrl, vap_info);
        if (str_dup) {
            free(str_dup);
        }
        return;
    }

    assoc_maclist =  (char*)malloc(2048);
    if (assoc_maclist == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer\n", __func__, __LINE__);
        if (str_dup) {
            free(str_dup);
        }
        return;
    }
    kick_details = (kick_details_t *)malloc(sizeof(kick_details_t));
    if (kick_details == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer\n", __func__, __LINE__);

        if (str_dup) {
            free(str_dup);
        }
        return;
    }

    memset(assoc_maclist, 0, 2048);
    memset(kick_details, 0, sizeof(kick_details_t));

    while(str_str != NULL) {
        str_to_mac_bytes(str_str, mac_bytes);
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
                    wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi_addApAclDevice failed. vap_index %d, mac %s \n",
                            __func__, __LINE__, vap_index, str_str);
                }
            } else {
                if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list) {
                    if (wifi_addApAclDevice(vap_index, str_str) != RETURN_OK) {
                        wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi_addApAclDevice failed. vap_index %d, mac %s \n",
                                __func__, __LINE__, vap_index, str_str);
                    }
                } else if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_white_list) {
                    if (wifi_delApAclDevice(vap_index, str_str) != RETURN_OK) {
                        wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
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

    wifi_util_info_print(WIFI_CTRL, "%s:%d vap_index is %s mac_list is %s timeout is %s\n", __func__, __LINE__, s_vapindex, s_maclist, s_timeout);
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
                wifi_util_error_print(WIFI_CTRL, "%s:%d ERROR Null Pointer\n", __func__, __LINE__);
                continue;
            }

            if (hosts.count > LM_MAX_HOSTS_NUM) {
                wifi_util_info_print(WIFI_CTRL, "%s:%d has reached LM_MAX_HOSTS_NUM\n", __func__, __LINE__);
                break;
            }

            if (rdk_vap_info->associated_devices_queue != NULL) {
                count = queue_count(rdk_vap_info->associated_devices_queue);
                for (itrj=0; itrj<count; itrj++) {
                    assoc_dev_data = (assoc_dev_data_t *)queue_peek(rdk_vap_info->associated_devices_queue, itrj);
                    if (assoc_dev_data == NULL) {
                        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL Pointer\n", __func__, __LINE__);
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
                    wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
                }

            }
        }
    }
    if (notify_LM_Lite(&p_wifi_mgr->ctrl, &hosts, false) != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification to LMLite", __func__, __LINE__);
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
            wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification to Hotspot\n", __func__, __LINE__);
        }
    } else if ((isVapPrivate(vap_index)) || (isVapXhs(vap_index))) {
        //Code to Publish to LMLite
        if (notify_LM_Lite(&p_wifi_mgr->ctrl, &hosts, true) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification to LMLite", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL Pointer\n", __func__, __LINE__);
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
                    wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
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
                    wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
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
    vap_svc_t  *pub_svc;
    mac_addr_t prefer_private_mac;
    wifi_global_param_t *pcfg = (wifi_global_param_t *) get_wifidb_wifi_global_param();

    if (data == NULL) {
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;

    rdk_vap_info = get_wifidb_rdk_vap_info(assoc_data->ap_index);
    if (rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL rdk_vap_info pointer\n", __func__, __LINE__);
        return;
    }

    assoc_data_to_queue = (assoc_dev_data_t *)malloc(sizeof(assoc_dev_data_t));
    if (assoc_data_to_queue ==  NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL  assoc_data_to_queue pointer \n", __func__, __LINE__);
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
                wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification for associated entries\n", __func__, __LINE__);
            }
        }
        if (isVapHotspot(rdk_vap_info->vap_index)) {
            if (notify_hotspot(&p_wifi_mgr->ctrl, assoc_data_to_queue) != RETURN_OK) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification to Hotspot\n", __func__, __LINE__);
            }
        }
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL assoc_device_queue\n", __func__,__LINE__);
        free(assoc_data_to_queue);
    }
    if ((isVapPrivate(rdk_vap_info->vap_index))) {
        if (pcfg != NULL && pcfg->prefer_private) {
            pub_svc = get_svc_by_type(&p_wifi_mgr->ctrl, vap_svc_type_public);
            if (pub_svc->event_fn != NULL) {
                memcpy(prefer_private_mac, assoc_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
                pub_svc->event_fn(pub_svc, ctrl_event_type_command, ctrl_event_type_prefer_private_rfc,
                                    add_prefer_private_acl_to_public, &prefer_private_mac);
            }
        }
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
                wifi_util_error_print(WIFI_CTRL,"%s:%d Unable to send notification to LMLite", __func__, __LINE__);
            }
            itrj++;
        }
    }
}

void process_factory_reset_command(bool type)
{
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    p_wifi_mgr->ctrl.factory_reset = type;
    wifi_util_info_print(WIFI_CTRL,"%s:%d and type is %d\n",__func__,__LINE__,type);
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

    wifi_util_info_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *)get_ctrl_rfc_parameters();
    rfc_param->radiusgreylist_rfc = type;
    wifidb_update_rfc_config(0, rfc_param);
    g_wifi_mgr->rfc_dml_parameters.radiusgreylist_rfc = type;

    public_xfinity_vap_status = get_wifi_public_vap_enable_status();

    if (public_xfinity_vap_status) {
        wifi_util_info_print(WIFI_CTRL,"public xfinity vaps are up and running\n");
        process_xfinity_vaps(2,false);
    }

    if (!rfc_param->radiusgreylist_rfc) {
        wifi_util_info_print(WIFI_CTRL,"Greylist RFC is disabled remove all greylisted entries from DB\n");
        remove_xfinity_acl_entries(true,false);
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

void process_mgmt_frame_rbus_enable_event(bool status)
{
    wifi_util_dbg_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,status);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_ctrl_rfc_parameters();
    rfc_param->mgmt_frame_rbus_enabled_rfc = status;
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

    wifi_util_info_print(WIFI_DB,"WIFI Enter RFC Func %s: %d : bool %d\n",__FUNCTION__,__LINE__,type);
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
void process_prefer_private_rfc(bool type)
{
    wifi_mgr_t *p_wifi_mgr = get_wifimgr_obj();
    vap_svc_t  *pub_svc;

    if (!type) {
        wifi_util_dbg_print(WIFI_CTRL,"Prefer private is set to false\n");
        remove_xfinity_acl_entries(false,true);
    }
    pub_svc = get_svc_by_type(&p_wifi_mgr->ctrl, vap_svc_type_public);
    if (pub_svc->event_fn != NULL) {
        pub_svc->event_fn(pub_svc, ctrl_event_type_command, ctrl_event_type_prefer_private_rfc,
                            add_macmode_to_public, &type);
    }
}
void process_wps_command_event(unsigned int vap_index)
{
    wifi_util_info_print(WIFI_CTRL,"%s:%d wifi wps test vap index = %d\n",__func__, __LINE__, vap_index);
    wifi_hal_setApWpsButtonPush(vap_index);
}

void marker_list_config_event(char *data, marker_list_t list_type)
{
    int ret = -1;
    wifi_global_param_t *global_param = get_wifidb_wifi_global_param();

    switch (list_type) {

        case normalized_rssi_list_type:
            if (strcmp(global_param->normalized_rssi_list, data) != 0) {
                strncpy(global_param->normalized_rssi_list, data, sizeof(global_param->normalized_rssi_list)-1);
                global_param->normalized_rssi_list[sizeof(global_param->normalized_rssi_list)-1]= '\0';
            }
            break;

        case snr_list_type:
            if (strcmp(global_param->snr_list, data) != 0 ) {
                strncpy(global_param->snr_list, data, sizeof(global_param->snr_list)-1);
                global_param->snr_list[sizeof(global_param->snr_list)-1]= '\0';
            }
            break;

        case cli_stat_list_type:
            if (strcmp(global_param->cli_stat_list, data) != 0) {
                strncpy(global_param->cli_stat_list, data, sizeof(global_param->cli_stat_list)-1);
                global_param->cli_stat_list[sizeof(global_param->cli_stat_list)-1]= '\0';
            }
            break;

        case txrx_rate_list_type:
            if (strcmp(global_param->txrx_rate_list, data) != 0) {
                strncpy(global_param->txrx_rate_list, data, sizeof(global_param->txrx_rate_list)-1);
                global_param->txrx_rate_list[sizeof(global_param->txrx_rate_list)-1]= '\0';
            }
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL,"[%s]: List type not supported this event %x\r\n",__FUNCTION__, list_type);
            return;
    }

    ret = update_wifi_global_config(global_param);
    if ( ret < 0 ) {
        wifi_util_dbg_print(WIFI_CTRL,"[%s]: Failed to update global config for type  %x\r\n",__FUNCTION__, list_type);
    }
    return;

}

void process_device_mode_command_event(int device_mode)
{
    vap_svc_t *ext_svc;
    wifi_global_param_t *global_param = get_wifidb_wifi_global_param();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    ctrl->network_mode = device_mode;

    if (global_param->device_network_mode != device_mode) {
        global_param->device_network_mode = device_mode;
        update_wifi_global_config(global_param);
        if (device_mode == rdk_dev_mode_type_ext) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: disable all vaps and start station mode\r\n", __func__, __LINE__);
            stop_gateway_vaps();
            start_extender_vaps();
        } else if (device_mode == rdk_dev_mode_type_gw) {
            wifi_util_info_print(WIFI_CTRL, "%s:%d: disable station, delete all scan results and start accesspoint mode\r\n", __func__, __LINE__);
            stop_extender_vaps();
            start_gateway_vaps();
            ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);

            if(ext_svc->u.ext.conn_state == connection_state_connected) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d disconnect sta on vap:%d\n",__FUNCTION__, __LINE__, ext_svc->u.ext.connected_vap_index);
                wifi_hal_disconnect(ext_svc->u.ext.connected_vap_index);
                ext_svc->u.ext.conn_state = connection_state_disconnected_scan_list_none;
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
        wifi_util_error_print(WIFI_CTRL,"%s: wrong index for radio map: %d\n",__FUNCTION__, ch_chg->radioIndex);
        return;
    }
    wifi_util_info_print(WIFI_CTRL,"%s:%d channel change on radio:%d old channel:%d new channel:%d channel change event type:%d op_class:%d\n",
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

int wifidb_vap_status_update(bool status)
{
    wifi_vap_name_t backhauls[MAX_NUM_RADIOS];
    int count;
    wifi_vap_info_t vap_config;
    memset(&vap_config, 0, sizeof(vap_config));

    /* get a list of mesh backhaul names of all radios */
    count = get_list_of_mesh_backhaul(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, sizeof(backhauls)/sizeof(wifi_vap_name_t), backhauls);

    for (int i = 0; i < count; i++) {
        if (wifidb_get_wifi_vap_info(&backhauls[i][0], &vap_config) == RETURN_OK) {
            vap_config.u.bss_info.enabled = status;
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi mesh backhaul status save:%d\n", __func__, __LINE__, status);
            update_wifi_vap_info(&backhauls[i][0], &vap_config);
        }
    }

    return RETURN_OK;
}

void process_mesh_status_command(bool mesh_enable_status)
{
    vap_svc_t *mesh_gw_svc;
    unsigned int value;
    wifi_ctrl_t *ctrl;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    mesh_gw_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_gw);

    // start mesh gateway if mesh is enabled
    value = get_wifi_mesh_vap_enable_status();
    if ((value != true) && (mesh_enable_status == true)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Mesh_service start\n", __func__, __LINE__);
        mesh_gw_svc->start_fn(mesh_gw_svc, WIFI_ALL_RADIO_INDICES, NULL);
        wifidb_vap_status_update(mesh_enable_status);
        ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending;
    } else if ((value == true) && (mesh_enable_status == false)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Mesh_service stop\n", __func__, __LINE__);
        mesh_gw_svc->stop_fn(mesh_gw_svc, WIFI_ALL_RADIO_INDICES, NULL);
        wifidb_vap_status_update(mesh_enable_status);
        ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending;
    }
}

void handle_command_event(wifi_ctrl_t *ctrl, void *data, unsigned int len, ctrl_event_subtype_t subtype)
{
    wifi_apps_t     *analytics = NULL;

    analytics = get_app_by_type(ctrl, wifi_apps_type_analytics);

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
        case ctrl_event_type_prefer_private_rfc:
            process_prefer_private_rfc(*(bool *)data);
            break;

        case ctrl_event_type_command_mesh_status:
            process_mesh_status_command(*(bool *)data);
            break;

        case ctrl_event_type_normalized_rssi:
            marker_list_config_event((char *)data, normalized_rssi_list_type);
            break;

        case ctrl_event_type_snr:
            marker_list_config_event((char *)data, snr_list_type);
            break;

        case ctrl_event_type_cli_stat:
            marker_list_config_event((char *)data, cli_stat_list_type);
            break;

        case ctrl_event_type_txrx_rate:
            marker_list_config_event((char *)data, txrx_rate_list_type);
            break;

        case ctrl_event_type_mgmt_frame_rbus_rfc:
            process_mgmt_frame_rbus_enable_event(*(bool *)data);
            break;

        default:
            wifi_util_error_print(WIFI_CTRL,"[%s]:WIFI hal handler not supported this event %d\r\n",__FUNCTION__, subtype);
            break;
    }

    if (analytics->event_fn != NULL) {
        analytics->event_fn(analytics, ctrl_event_type_command, subtype, data);
    }
}

void handle_hal_indication(wifi_ctrl_t *ctrl, void *data, unsigned int len, ctrl_event_subtype_t subtype)
{
    wifi_apps_t     *analytics = NULL;

    analytics = get_app_by_type(ctrl, wifi_apps_type_analytics);

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

            wifi_util_error_print(WIFI_CTRL,"[%s]:WIFI hal handler not supported this event %d\r\n",__FUNCTION__, subtype);
            break;
    }

    if (analytics->event_fn != NULL) {
        analytics->event_fn(analytics, ctrl_event_type_hal_ind, subtype, data);
    }
}

void handle_webconfig_event(wifi_ctrl_t *ctrl, const char *raw, unsigned int len, ctrl_event_subtype_t subtype)
{
    webconfig_t *config;
    webconfig_subdoc_data_t data = {0};
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_apps_t    *analytics = NULL;

    config = &ctrl->webconfig;
    analytics = get_app_by_type(ctrl, wifi_apps_type_analytics);

    switch (subtype) {
        case ctrl_event_webconfig_set_data:
        case ctrl_event_webconfig_set_data_dml:
        case ctrl_event_webconfig_set_data_webconfig:
        case ctrl_event_webconfig_set_data_ovsm:
            memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));
            if (analytics->event_fn != NULL) {
                analytics->event_fn(analytics, ctrl_event_type_webconfig, subtype, NULL);
            }
            webconfig_decode(config, &data, raw);
            if (analytics->event_fn != NULL) {
                analytics->event_fn(analytics, ctrl_event_type_webconfig, subtype, &data);
            }
            break;

        case ctrl_event_webconfig_set_data_tunnel:
            memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));
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
            wifi_util_error_print(WIFI_CTRL,"[%s]:WIFI webconfig handler not supported this event %d\r\n",__FUNCTION__, subtype);
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
            wifi_util_error_print(WIFI_CTRL,"[%s]: wifi_api handler does not support this event %d\r\n",__FUNCTION__, subtype);
            break;
    }

}
