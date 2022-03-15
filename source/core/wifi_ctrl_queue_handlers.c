#include <stdio.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "ansc_platform.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "webconfig_framework.h"
#include "scheduler.h"
#include <unistd.h>
#include <pthread.h>
#include <rbus.h>

void process_scan_results_event(wifi_bss_info_t *bss, unsigned int len)
{
    unsigned int i, num = len/sizeof(wifi_bss_info_t);
    wifi_bss_info_t *tmp_bss = bss;
    wifi_ctrl_t *ctrl;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    unsigned int vap_index = 0, band = 0;
    bool found_sta_ssid = false;
    wifi_bss_info_t target_bss;
    int radio_index = 0;
    ssid_t sta_ssid;

    ctrl = &mgr->ctrl;

    if (num && (ctrl->scan_result_for_connect_pending == true)) {
        if (tmp_bss->freq >= 2412 && tmp_bss->freq <= 2484) {
            band = WIFI_FREQUENCY_2_4_BAND;
        } else if (tmp_bss->freq >= 5180 && tmp_bss->freq <= 5980) {
            band = WIFI_FREQUENCY_5_BAND;
        }

        convert_freq_band_to_radio_index(band, &radio_index);

        if (get_sta_ssid_from_radio_config_by_radio_index(radio_index, sta_ssid) == -1) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Could not find sta ssid for radio index:%d\n",
                                     __func__, __LINE__, radio_index);
            return;
        }

        for (i = 0; i < num; i++) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: ssid:%s rssi:%d frequency:%d\n", __func__, __LINE__,
                                        tmp_bss->ssid, tmp_bss->rssi, tmp_bss->freq);
            if (strcmp(tmp_bss->ssid, sta_ssid) == 0) {
                vap_index = get_sta_vap_index_for_radio(radio_index);
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: ssid:%s match found for radio index:%d vap:%d\n",
                            __func__, __LINE__, tmp_bss->ssid, radio_index, vap_index);
                found_sta_ssid = true;
                memcpy(&target_bss, tmp_bss, sizeof(wifi_bss_info_t));
                break;
            }
            tmp_bss++;
        }

        if (found_sta_ssid == true) {
            wifi_util_dbg_print(WIFI_CTRL, "[%s]:%d found sta_ssid\n",__FUNCTION__,__LINE__);
            wifi_hal_connect(vap_index, &target_bss);
            ctrl->scan_result_for_connect_pending = false;
        } else if (band == WIFI_FREQUENCY_2_4_BAND) {
            // start a scan procedure for 5 Ghz radio
            if (wifi_hal_startScan(1, WIFI_RADIO_SCAN_MODE_ONCHAN, 0, 0, NULL) == RETURN_OK) {
                ctrl->scan_result_for_connect_pending = true;
            }
	}
    }
}

void process_mgmt_ctrl_frame_event(frame_data_t *msg, uint32_t msg_length)
{
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->ap_index, msg->len, msg->type, msg->dir);
}

void start_scan_for_both_radio(void)
{
    wifi_ctrl_t *ctrl;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    ctrl = &mgr->ctrl;

    if (ctrl->sta_conn_retry == 0) {
        // start a scan procedure for 2.4 Ghz radio
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi scan start for 2.4 Ghz radio\r\n", __func__, __LINE__);
        if (wifi_hal_startScan(0, WIFI_RADIO_SCAN_MODE_ONCHAN, 0, 0, NULL) == RETURN_OK) {
            ctrl->scan_result_for_connect_pending = true;
        }
        ctrl->sta_conn_retry++;
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi connection retry completed\r\n", __func__, __LINE__);
    }
}

void process_sta_conn_status_event(wifi_station_stats_t *stats, unsigned int len)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    char name[64];
    unsigned int index, i;
    bool active = false;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_vap_info_map_t *vap_map;
    wifi_ctrl_t *ctrl;

    ctrl = &mgr->ctrl;

    // first update the internal cache
    index = (stats->vap_index == 14) ? 0:1;
    vap_map = &mgr->radio_config[index].vaps.vap_map;

    for (i = 0; i < vap_map->num_vaps; i++) {
        if (vap_map->vap_array[i].vap_index == stats->vap_index) {
            vap_map->vap_array[i].u.sta_info.conn_status = stats->connect_status;
            break;
        }
    }

    if (stats->connect_status == wifi_connection_status_connected) {
        // disable hotspot VAPs
    } else if (stats->connect_status == wifi_connection_status_ap_not_found) {
        start_scan_for_both_radio();
    } else {
        // enable hot spot VAPs if they were enabled before
    }

    // then publish the connection status

    sprintf(name, "Device.WiFi.STA.%d.Connection.Status", index);

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus name:%s:connection status:%d\r\n", __func__, __LINE__, name,stats->connect_status);
    active = (stats->connect_status == wifi_connection_status_connected) ? true:false;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, name, value);
    rbusValue_SetBoolean(value, active);
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

void process_sta_connect_command(bool connect)
{
    unsigned int i, j, sta_vap_index;
    wifi_channel_t channel;
    ssid_t sta_ssid;
    wifi_bss_info_t *bss_array, *tmp_bss, target_bss;
    unsigned int num_bss;
    bool found_sta_ssid = false;
    rdk_wifi_radio_t *radio;
    wifi_ctrl_t *ctrl;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    uint8_t num_of_radios = getNumberRadios();
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    ctrl = &mgr->ctrl;

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: sta connect command:%d\n", __func__, __LINE__, connect);
    if (connect == false) {
        // disconnect from STA and return
        for (i = 0; i < num_of_radios; i++) {
            vap_map = &mgr->radio_config[i].vaps.vap_map;
            j = convert_vap_name_to_array_index("mesh_sta");
            vap = &vap_map->vap_array[j];
            if ((vap->vap_mode == wifi_vap_mode_sta) &&
                    (vap->u.sta_info.conn_status == wifi_connection_status_connected)) {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: wifi disconnect :%d\n", __func__, __LINE__, vap->vap_index);
                wifi_hal_disconnect(vap->vap_index);
            }
        }
        return;
    }

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
        sta_vap_index = get_sta_vap_index_for_radio(i);
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
        ctrl->scan_result_for_connect_pending = false;
        ctrl->sta_conn_retry = 0;
    } else {
	// start a scan procedure for 2.4 Ghz Radio
        if (wifi_hal_startScan(0, WIFI_RADIO_SCAN_MODE_ONCHAN, 0, 0, NULL) == RETURN_OK) {
            ctrl->scan_result_for_connect_pending = true;
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
            do {
                assoc_dev_data = (assoc_dev_data_t *)queue_pop(rdk_vap_info->associated_devices_queue);
                free(assoc_dev_data);
            } while (assoc_dev_data != NULL);
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
            assoc_dev_data = (assoc_dev_data_t*)queue_remove(rdk_vap_info->associated_devices_queue, i);
            if (assoc_dev_data != NULL) {
                free(assoc_dev_data);
            }
            break;
        }
    }
}

void process_assoc_device_event(void *data)
{
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    assoc_dev_data_t* assoc_data_to_queue = NULL;

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
        queue_push(rdk_vap_info->associated_devices_queue, assoc_data_to_queue);
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL assoc_device_queue\n", __func__,__LINE__);
        free(assoc_data_to_queue);
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
    start_wifi_radio_vap();
    wifi_util_dbg_print(WIFI_DB,"WIFI Factory reset started wifidb monitor %d\n",__LINE__);
    start_wifidb_monitor();
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
        case ctrl_event_type_command_kickmac:
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

        case ctrl_event_scan_results:
            process_scan_results_event(data, len);
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
            webconfig_decode(config, &data, raw);
            break;

        case ctrl_event_webconfig_get_data:
            // copy the global config
            memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&mgr->global_config, sizeof(wifi_global_config_t));

            // copy the radios and vaps data
            memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
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
