#include <stdio.h>
#include <stdbool.h>
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
#include "wifi_hal_rdk_framework.h"
#ifdef CMWIFI_RDKB
#define FILE_SYSTEM_UPTIME         "/var/systemUptime.txt"
#else
#define FILE_SYSTEM_UPTIME         "/tmp/systemUptime.txt"
#endif
unsigned int get_Uptime(void);
unsigned int startTime[MAX_NUM_RADIOS];
#define BUF_SIZE              256
extern webconfig_error_t webconfig_ctrl_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data);

void deinit_wifi_ctrl(wifi_ctrl_t *ctrl)
{
    if(ctrl->queue != NULL) {
        queue_destroy(ctrl->queue);
    }

    /*Deinitialize the scheduler*/
    if (ctrl->sched != NULL) {
        scheduler_deinit(&ctrl->sched);
    }

    pthread_mutex_destroy(&ctrl->lock);
    pthread_cond_destroy(&ctrl->cond);
}

int push_data_to_ctrl_queue(const void *msg, unsigned int len, ctrl_event_type_t type, ctrl_event_subtype_t sub_type)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    ctrl_event_t *data;

    data = (ctrl_event_t *)malloc(sizeof(ctrl_event_t));
    if(data == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_WARN, WIFI %s: data malloc null\n",__FUNCTION__);
        return RETURN_ERR;
    }

    memset(data, 0, sizeof(ctrl_event_t));
    data->event_type = type;
    data->sub_type = sub_type;
    
    if (msg != NULL) {
        data->msg = malloc(len + 1);
        if(data->msg == NULL) {
            wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_WARN,,,WIFI %s: data message malloc null\n",__FUNCTION__);
            return RETURN_ERR;
        }
        /* copy msg to data */
        memcpy(data->msg, msg, len);
        data->len = len;
    } else {
        data->msg = NULL;
        data->len = 0;
    }

    pthread_mutex_lock(&ctrl->lock);
    queue_push(ctrl->queue, data);
    pthread_cond_signal(&ctrl->cond);
    pthread_mutex_unlock(&ctrl->lock);

    return RETURN_OK;
}

void ctrl_queue_loop(wifi_ctrl_t *ctrl)
{
    struct timespec time_to_wait;
    struct timeval tv_now;
    time_t  time_diff;
    int rc;
    int greylist_event = 0;
    bool greylist_flag = false;
    ctrl_event_t *queue_data = NULL;
    static uint8_t conn_retry = 0;

    while (ctrl->exit_ctrl == false) {
        gettimeofday(&tv_now, NULL);
        time_to_wait.tv_nsec = 0;
        time_to_wait.tv_sec = tv_now.tv_sec + ctrl->poll_period;

        if (ctrl->last_signalled_time.tv_sec > ctrl->last_polled_time.tv_sec) {
            time_diff = ctrl->last_signalled_time.tv_sec - ctrl->last_polled_time.tv_sec;
            if ((UINT)time_diff < ctrl->poll_period) {
                time_to_wait.tv_sec = tv_now.tv_sec + (ctrl->poll_period - time_diff);
            }
        }

        pthread_mutex_lock(&ctrl->lock);
        rc = pthread_cond_timedwait(&ctrl->cond, &ctrl->lock, &time_to_wait);

        if (rc == 0) {
            while (queue_count(ctrl->queue)) {
                queue_data = queue_pop(ctrl->queue);
                if (queue_data == NULL) {
                    pthread_mutex_unlock(&ctrl->lock);
                    continue;
                }
                switch (queue_data->event_type) {
                    case ctrl_event_type_webconfig:
                        handle_webconfig_event(ctrl, queue_data->msg, queue_data->len, queue_data->sub_type);
                        break;

                    case ctrl_event_type_hal_ind:
                        handle_hal_indication(queue_data->msg, queue_data->len, queue_data->sub_type);
                        break;

                    case ctrl_event_type_command:
                        handle_command_event(queue_data->msg, queue_data->len, queue_data->sub_type);
                        break;

                    case ctrl_event_type_wifiapi:
                        handle_wifiapi_event(queue_data->msg, queue_data->len, queue_data->sub_type);
                        break;

                    default:
                        wifi_util_dbg_print(WIFI_CTRL,"[%s]:WIFI ctrl thread not supported this event %d\r\n",__FUNCTION__, queue_data->event_type);
                        break;
                }

                if(queue_data->msg) {
                    free(queue_data->msg);
                }

                free(queue_data);
                gettimeofday(&ctrl->last_signalled_time, NULL);
            }
        } else if (rc == ETIMEDOUT) {
            gettimeofday(&ctrl->last_polled_time, NULL);

            /*
             * Using the below api, New timer tasks can be added to the scheduler
             *
             * int scheduler_add_timer_task(struct scheduler *sched, bool high_prio, int *id,
             *                                 int (*cb)(void *arg), void *arg, unsigned int interval_ms, unsigned int repetitions);
             *
             * Refer to source/utils/scheduler.h for more description regarding the scheduler api's.
             */

            /*Run the scheduler*/
            scheduler_execute(ctrl->sched, ctrl->last_polled_time, (ctrl->poll_period*1000));

            if ((ctrl->rbus_events_subscribed == false) || (ctrl->tunnel_events_subscribed == false) ||
                (ctrl->device_mode_subscribed == false) ||
                (ctrl->device_tunnel_status_subscribed == false) || (ctrl->device_wps_test_subscribed == false) ||
                (ctrl->test_device_mode_subscribed == false)) {
                rbus_subscribe_events(ctrl);
            }

            webconfig_analyze_pending_states(ctrl);

	    if (conn_retry > STA_CONN_RETRY) {
                if (ctrl->network_mode == rdk_dev_mode_type_ext) {
                    sta_pending_connection_retry(ctrl);
                } else if (ctrl->conn_state == connection_state_connected) {
                    wifi_util_dbg_print(WIFI_CTRL,"%s:%d gateway mode, disconnect sta on vap:%d\n",__FUNCTION__, __LINE__, ctrl->connected_vap_index);
                    wifi_hal_disconnect(ctrl->connected_vap_index);
                }
                conn_retry = 0;
            } else {
                conn_retry++;
            }

            if (greylist_event >= GREYLIST_CHECK_IN_SECONDS) {
                greylist_event = 0;
                greylist_flag = check_for_greylisted_mac_filter();
                if (greylist_flag) {
                    wifi_util_dbg_print(WIFI_CTRL,"greylist_mac present\n");
                    remove_greylist_acl_entries(false);
                }
            }
            greylist_event++;

        } else {
            pthread_mutex_unlock(&ctrl->lock);
            wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_WARN, WIFI %s: Invalid Return Status %d\n",__FUNCTION__,rc);
            continue;
        }
        pthread_mutex_unlock(&ctrl->lock);
    }

    return;
}

int init_wifi_global_config(void)
{
    if (RETURN_OK != WiFi_InitGasConfig()) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_WARN, RDKB_SYSTEM_BOOT_UP_LOG : CosaWifiInitialize - WiFi failed to Initialize GAS Configuration.\n");
        return RETURN_ERR;
    }
    if (RETURN_OK != init_wifi_data_plane()) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_WARN, RDKB_SYSTEM_BOOT_UP_LOG : CosaWifiInitialize - WiFi failed to Initialize Wifi Data/Mgmt Handler.\n");
        return RETURN_ERR;
    }
    return RETURN_OK;
}

unsigned int get_Uptime(void)
{
    char cmd[BUF_SIZE] = {0};
    FILE *fp = NULL;
    unsigned int upSecs = 0;
    snprintf(cmd, sizeof(cmd), "/bin/cat /proc/uptime > %s", FILE_SYSTEM_UPTIME);
    system(cmd);
    fp = fopen(FILE_SYSTEM_UPTIME, "r");
    if (fp != NULL) {
        fscanf(fp, "%u", &upSecs);
        wifi_util_dbg_print(WIFI_CTRL,"%s : upSecs=%u ......\n", __FUNCTION__, upSecs);
        fclose(fp);
    }
    return upSecs;
}

int start_radios(void)
{
    wifi_radio_operationParam_t *wifi_radio_oper_param = NULL;
    int ret = RETURN_OK;
    uint8_t index = 0;
    uint8_t num_of_radios = getNumberRadios();

    wifi_util_dbg_print(WIFI_CTRL,"FactoryReset in stat_wifi_radio_vapi fac\n");
    //Check for the number of radios
    if (num_of_radios > MAX_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_CTRL,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        return RETURN_ERR;
    }

    for (index = 0; index < num_of_radios; index++) {
        wifi_radio_oper_param = (wifi_radio_operationParam_t *)get_wifidb_radio_map(index);
        if (wifi_radio_oper_param == NULL) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:wrong index for radio map: %d\n",__FUNCTION__, index);
            return RETURN_ERR;
        }

        wifi_util_dbg_print(WIFI_CTRL,"%s:index: %d num_of_radios:%d\n",__FUNCTION__, index, num_of_radios);

        ret = wifi_hal_setRadioOperatingParameters(index, wifi_radio_oper_param);
        if (ret != RETURN_OK) {
            wifi_util_dbg_print(WIFI_CTRL,"%s: wifi radio parameter set failure: radio_index:%d\n",__FUNCTION__, index);
            return ret;
        } else {
            wifi_util_dbg_print(WIFI_CTRL,"%s: wifi radio parameter set success: radio_index:%d\n",__FUNCTION__, index);
        }

        startTime[index] = get_Uptime();
    }

    return RETURN_OK;
}

bool check_sta_ext_connection_status(void)
{
    unsigned int num_of_radios = getNumberRadios();
    unsigned int i = 0, j = 0;
    wifi_vap_info_map_t *vap_map = NULL;

    for (i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        if (vap_map == NULL) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__, i);
            return -1;
        }

        for (j = 0; j < vap_map->num_vaps; j++) {
            if (isVapSTAMesh(vap_map->vap_array[j].vap_index)) {
                if (vap_map->vap_array[j].u.sta_info.conn_status == wifi_connection_status_connected) {
                    return true;
                }
            }
        }
    }

    return false;
}
wifi_platform_property_t *get_wifi_hal_cap_prop(void)
{
    wifi_mgr_t *wifi_mgr_obj = get_wifimgr_obj();
    return &wifi_mgr_obj->hal_cap.wifi_prop;
}

void sta_pending_connection_retry(wifi_ctrl_t *ctrl)
{
    unsigned int *channel_list = NULL;
    unsigned char num_of_channels;
    unsigned int i;
    unsigned int vap_index = 0, band = 0;
    int radio_index = 0;
    mac_addr_str_t bssid_str;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    if(ctrl->conn_state == connection_state_disconnected || ctrl->conn_state == connection_state_in_progress) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d retry timeout, conn_state:%d scan_count:%d\n",__func__, __LINE__, ctrl->conn_state, ctrl->scan_count);
        if(ctrl->scan_list != NULL) {
            scan_list_t *scan_list;
            scan_list = ctrl->scan_list;

            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: scan_count:%d conn_state:%d\n", __func__, __LINE__, ctrl->scan_count, ctrl->conn_state);

            for(i = 0; i < ctrl->scan_count; i++) {
                if(scan_list->conn_attempt == connection_attempt_wait) {
                    scan_list->conn_attempt = connection_attempt_in_progress;
                    ctrl->conn_state = connection_state_in_progress;
                    if (scan_list->external_ap.freq >= 2412 && scan_list->external_ap.freq <= 2484) {
                        band = WIFI_FREQUENCY_2_4_BAND;
                    } else if (scan_list->external_ap.freq >= 5180 && scan_list->external_ap.freq <= 5980) {
                        band = WIFI_FREQUENCY_5_BAND;
                    }
                    convert_freq_band_to_radio_index(band, &radio_index);
                    vap_index = get_sta_vap_index_for_radio(&mgr->hal_cap.wifi_prop, radio_index);

                    wifi_util_dbg_print(WIFI_CTRL,"%s:%d connecting to ssid:%s bssid:%s rssi:%d frequency:%d on vap:%d radio:%d\n",
                                            __FUNCTION__, __LINE__, scan_list->external_ap.ssid, to_mac_str(scan_list->external_ap.bssid, bssid_str),
                                            scan_list->external_ap.rssi, scan_list->external_ap.freq, vap_index, radio_index);
                    wifi_hal_connect(vap_index, &scan_list->external_ap);
                    break;
                }
                scan_list++;
            }
        }
        if(!ctrl->scan_count) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d no scan results, start scan on 2.4GHz and 5GHz radios\n",__FUNCTION__, __LINE__);
            /* start scan on 2.4Ghz */
            get_default_supported_scan_channel_list(WIFI_FREQUENCY_2_4_BAND, &channel_list, &num_of_channels);
            wifi_hal_startScan(0, WIFI_RADIO_SCAN_MODE_OFFCHAN, 0, num_of_channels, channel_list);

            /* start scan on 5Ghz */
            get_default_supported_scan_channel_list(WIFI_FREQUENCY_5_BAND, &channel_list, &num_of_channels);
            wifi_hal_startScan(1, WIFI_RADIO_SCAN_MODE_OFFCHAN, 0, num_of_channels, channel_list);
        }
    }
}

bool check_for_greylisted_mac_filter(void)
{
    acl_entry_t *acl_entry = NULL;
    rdk_wifi_vap_info_t *l_rdk_vap_array = NULL;
    unsigned int itr, itrj;
    bool greylist_rfc = false;
    int vap_index = 0;
    wifi_vap_info_map_t *wifi_vap_map = NULL;

    wifi_rfc_dml_parameters_t *rfc_info = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
    if (rfc_info) {
        greylist_rfc = rfc_info->radiusgreylist_rfc;
        if (greylist_rfc) {
            for (itr = 0; itr < getNumberRadios(); itr++) {
                wifi_vap_map = get_wifidb_vap_map(itr);
                for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
                    vap_index = wifi_vap_map->vap_array[itrj].vap_index;
                    l_rdk_vap_array = get_wifidb_rdk_vap_info(vap_index);

                    if (l_rdk_vap_array->acl_map != NULL) {
                        acl_entry = hash_map_get_first(l_rdk_vap_array->acl_map);
                        while(acl_entry != NULL) {
                            if (acl_entry->mac != NULL && (acl_entry->reason == WLAN_RADIUS_GREYLIST_REJECT)) {
                                return true;
                            }
                            acl_entry = hash_map_get_next(l_rdk_vap_array->acl_map, acl_entry);
                        }
                    }
                }
            }
        }
    }
    return false;
}
void rbus_get_vap_init_parameter(const char *name, unsigned int *ret_val)
{
    rbusValue_t value;
    int rc = RBUS_ERROR_SUCCESS;
    unsigned int total_slept = 0;
    //rdk_dev_mode_type_t mode;
    wifi_global_param_t global_param = { 0 };
    wifi_ctrl_t *ctrl;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    get_wifi_global_param(&global_param);
    // set all default return values first
    if (strcmp(name, WIFI_DEVICE_MODE) == 0) {
        *ret_val = (unsigned int)global_param.device_network_mode;
	ctrl->network_mode = (unsigned int)*ret_val;
    } else if (strcmp(name, WIFI_DEVICE_TUNNEL_STATUS) == 0) {
        *ret_val = DEVICE_TUNNEL_DOWN; // tunnel down
    }

    while ((rc = rbus_get(ctrl->rbus_handle, name, &value)) != RBUS_ERROR_SUCCESS) {
        sleep(1);
        total_slept++;
        if (total_slept >= 5) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d Giving up on rbus_get for %s\n",__func__, __LINE__, name);
            return;
        }
    }

    if (strcmp(name, WIFI_DEVICE_MODE) == 0) {
        *ret_val = rbusValue_GetUInt32(value);
	ctrl->network_mode = (unsigned int)*ret_val;
        if (global_param.device_network_mode != (int)*ret_val) {
            global_param.device_network_mode = (int)*ret_val;
            update_wifi_global_config(&global_param);
        }
    } else if (strcmp(name, WIFI_DEVICE_TUNNEL_STATUS) == 0) {
        *ret_val = rbusValue_GetBoolean(value);
    }
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d rbus_get for %s: value:%d\n",__func__, __LINE__, name, *ret_val);

}

void start_gateway_vaps()
{
    vap_svc_t *priv_svc, *pub_svc, *mesh_gw_svc;
    unsigned int value;
    wifi_ctrl_t *ctrl;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    priv_svc = get_svc_by_type(ctrl, vap_svc_type_private);
    pub_svc = get_svc_by_type(ctrl, vap_svc_type_public);
    mesh_gw_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_gw);

    // start private
    priv_svc->start_fn(priv_svc, WIFI_ALL_RADIO_INDICES, NULL);

    // start mesh gateway if mesh is enabled
    value = get_wifi_mesh_vap_enable_status();
    if (value == true) {
        mesh_gw_svc->start_fn(mesh_gw_svc, WIFI_ALL_RADIO_INDICES, NULL);
    }

    // start public if tunnel is up
    rbus_get_vap_init_parameter(WIFI_DEVICE_TUNNEL_STATUS, &value);
    if (value == true) {
        set_wifi_public_vap_enable_status();
        pub_svc->start_fn(pub_svc, WIFI_ALL_RADIO_INDICES, NULL);
    }
}

void stop_gateway_vaps()
{
    vap_svc_t *priv_svc, *pub_svc, *mesh_gw_svc;
    wifi_ctrl_t *ctrl;
    
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    
    priv_svc = get_svc_by_type(ctrl, vap_svc_type_private);
    pub_svc = get_svc_by_type(ctrl, vap_svc_type_public);
    mesh_gw_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_gw);

    priv_svc->stop_fn(priv_svc, WIFI_ALL_RADIO_INDICES, NULL);
    pub_svc->stop_fn(pub_svc, WIFI_ALL_RADIO_INDICES, NULL);
    mesh_gw_svc->stop_fn(mesh_gw_svc, WIFI_ALL_RADIO_INDICES, NULL);	
}

void stop_extender_vaps(void)
{
    wifi_ctrl_t *ctrl;
    vap_svc_t *ext_svc;	

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    ext_svc->stop_fn(ext_svc, WIFI_ALL_RADIO_INDICES, NULL);
}

void start_extender_vaps(void)
{
    wifi_ctrl_t *ctrl;
    vap_svc_t *ext_svc;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    ext_svc->start_fn(ext_svc, WIFI_ALL_RADIO_INDICES, NULL);
}

int start_wifi_services(void)
{
    unsigned int value;

    start_radios();

    rbus_get_vap_init_parameter(WIFI_DEVICE_MODE, &value);
    if (value == rdk_dev_mode_type_gw) {
        start_gateway_vaps();
        captive_portal_check();
    } else if (value == rdk_dev_mode_type_ext) {
        start_extender_vaps();
    }

    return RETURN_OK;
}

void factory_reset_wifi(void)
{
    //bool_reset_flag =  false;
    wifi_util_dbg_print(WIFI_CTRL,"FactoryReset before factory_reset\n");
    wifi_mgr_t *p_wifi_data = get_wifimgr_obj();

    wifi_dml_parameters_t *p_dml_param = &p_wifi_data->dml_parameters;
    wifi_util_dbg_print(WIFI_CTRL,"%s: Factory_Reset_wifi start:%d\n",__FUNCTION__, p_dml_param->WifiFactoryReset);

    if (p_dml_param->WifiFactoryReset) {
    }
}
int captive_portal_check(void)
{

    uint8_t num_of_radios = getNumberRadios();
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    bool factory_reset = g_wifi_mgr->ctrl.factory_reset;
    UINT radio_index =0;
    wifi_vap_info_map_t *wifi_vap_map = NULL;
    UINT i =0;
    int rc = 0;
    UINT reset_count = 0;
    rbusValue_t value;
    char path[128] = "";
    char default_ssid[32] = {0};
    char default_password[32] = {0};
    get_ssid_from_device_mac(default_ssid);
    get_default_wifi_password(default_password);

    wifi_util_dbg_print(WIFI_CTRL,"captive_portal check factory_rest is %d def ssid is %s and def pwd is %s\n",factory_reset,default_ssid,default_password);
    for (radio_index = 0; radio_index < num_of_radios; radio_index++) {
        wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(radio_index);
        wifi_util_dbg_print(WIFI_CTRL,"FactoryReset radio_index is %d: num_vaps %d \n",radio_index,wifi_vap_map->num_vaps);
        for ( i = 0; i < wifi_vap_map->num_vaps; i++) {
            wifi_util_dbg_print(WIFI_CTRL,"FactoryReset vap_index is %d: \n",i);
            if (strncmp(wifi_vap_map->vap_array[i].vap_name,"private_ssid",strlen("private_ssid"))== 0) {
                sprintf(path,DEVICE_WIFI_SSID,radio_index+1);
                wifi_util_dbg_print(WIFI_CTRL,"FactoryReset  private ssid is %s and vap_name is %s path is %s\n", wifi_vap_map->vap_array[i].u.bss_info.ssid,wifi_vap_map->vap_array[i].vap_name,path);
                //rbus_setStr(g_wifi_mgr->ctrl.rbus_handle,path,wifi_vap_map->vap_array[i].u.bss_info.ssid);
                wifi_util_dbg_print(WIFI_CTRL,"rbus_set SSID is done\n");
                sprintf(path,DEVICE_WIFI_KEYPASSPHRASE,radio_index+1);
                wifi_util_dbg_print(WIFI_CTRL,"FactoryReset password is %s path is %s\n", wifi_vap_map->vap_array[i].u.bss_info.security.u.key.key,path);
                //rbus_setStr(g_wifi_mgr->ctrl.rbus_handle,path,wifi_vap_map->vap_array[i].u.bss_info.security.u.key.key);
                wifi_util_dbg_print(WIFI_CTRL,"rbus_set SSID is done\n");
                if( strcmp(wifi_vap_map->vap_array[i].u.bss_info.ssid,default_ssid) && strcmp(wifi_vap_map->vap_array[i].u.bss_info.security.u.key.key,default_password)) {
                    reset_count++;
                }
            }
        }
    }
    wifi_util_dbg_print(WIFI_CTRL,"resetcount %d\n",reset_count);
    if (g_wifi_mgr->ctrl.factory_reset) {
        g_wifi_mgr->ctrl.factory_reset = false;
        wifi_util_dbg_print(WIFI_CTRL," FactoryReset  was true NotifyWifiChanges\n");
    }
    wifi_util_dbg_print(WIFI_CTRL," FactoryReset  before NotifyWifiChanges\n");
    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, g_wifi_mgr->ctrl.factory_reset);
    //rbus_set(g_wifi_mgr->ctrl.rbus_handle,FACTORY_RESET_NOTIFICATION,value,NULL);
    rbusValue_Release(value);
    rbusValue_Init(&value);
    if (reset_count == num_of_radios) {
        rbusValue_SetBoolean(value, false);
    }
    else {
        rbusValue_SetBoolean(value, true);
    }
    wifi_util_dbg_print(WIFI_CTRL,"Before setting rbus_set of Device.DeviceInfo.X_RDKCENTRAL-COM_ConfigureWiFi\n");
    rc = rbus_set(g_wifi_mgr->ctrl.rbus_handle,CONFIG_WIFI,value,NULL);
    if(rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_CTRL,"Rbus error Device.DeviceInfo.X_RDKCENTRAL-COM_ConfigureWiFi\n");
    }
    wifi_util_dbg_print(WIFI_CTRL," Captive_portal Ends after NotifyWifiChanges\n");

    return RETURN_OK;
}

int start_wifi_health_monitor_thread(void)
{
    static BOOL monitor_running = false;

    if (monitor_running == true) {
        wifi_util_dbg_print(WIFI_CTRL, "-- %s %d start_wifi_health_monitor_thread already running\n", __func__, __LINE__);
        return RETURN_OK;
    }

    if ((init_wifi_monitor() < RETURN_OK)) {
        wifi_util_dbg_print(WIFI_CTRL, "-- %s %d start_wifi_health_monitor_thread fail\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    monitor_running = true;

    return RETURN_OK;
}

int scan_results_callback(int radio_index, wifi_bss_info_t **bss, unsigned int *num)
{
    push_data_to_ctrl_queue(*bss, (*num)*sizeof(wifi_bss_info_t), ctrl_event_type_hal_ind, ctrl_event_scan_results);
    free(*bss);

    return 0;
}

int sta_connection_status(int apIndex, wifi_bss_info_t *bss_dev, wifi_station_stats_t *sta)
{
    rdk_sta_data_t        sta_data;
    wifi_interface_name_t *interface_name;
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();

    memcpy((unsigned char *)&sta_data.stats, (unsigned char *)sta, sizeof(wifi_station_stats_t));
    memcpy((unsigned char *)&sta_data.bss_info, (unsigned char *)bss_dev, sizeof(wifi_bss_info_t));
    if ((interface_name = get_interface_name_for_vap_index(apIndex, &g_wifi_mgr->hal_cap.wifi_prop)) != NULL) {
        memcpy(&sta_data.interface_name, interface_name, sizeof(wifi_interface_name_t));
    }

    push_data_to_ctrl_queue((rdk_sta_data_t *)&sta_data, sizeof(rdk_sta_data_t), ctrl_event_type_hal_ind, ctrl_event_hal_sta_conn_status);

    return RETURN_OK;
}

int mgmt_wifi_frame_recv(int ap_index, mac_address_t sta_mac, uint8_t *frame, uint32_t len, wifi_mgmtFrameType_t type, wifi_direction_t dir)
{
    frame_data_t wifi_mgmt_frame;

    memset(&wifi_mgmt_frame, 0, sizeof(wifi_mgmt_frame));
    if (len) {
        wifi_mgmt_frame.frame = malloc(len);
        if (wifi_mgmt_frame.frame == NULL) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d Failed to allocate memory in wifi mgmt frame Object\n", __FUNCTION__, __LINE__);
            return RETURN_ERR;
        }
        memset(wifi_mgmt_frame.frame, 0, len);
        memcpy(wifi_mgmt_frame.frame, frame, len);
    }

    wifi_mgmt_frame.ap_index = ap_index;
    memcpy(wifi_mgmt_frame.sta_mac, sta_mac, sizeof(mac_address_t));
    wifi_mgmt_frame.len = len;
    wifi_mgmt_frame.type = type;
    wifi_mgmt_frame.dir = dir;

    //In side this API we have allocate memory and send it to control queue
    push_data_to_ctrl_queue((frame_data_t *)&wifi_mgmt_frame, (sizeof(wifi_mgmt_frame) + len), ctrl_event_type_hal_ind, ctrl_event_hal_mgmt_farmes);

    if (wifi_mgmt_frame.frame != NULL) {
        free(wifi_mgmt_frame.frame);
        wifi_mgmt_frame.frame = NULL;
    }
    return RETURN_OK;
}

void channel_change_callback(wifi_channel_change_event_t radio_channel_param)
{
    wifi_channel_change_event_t channel_change;
    memset(&channel_change, 0, sizeof(channel_change));

    memcpy(&channel_change, &radio_channel_param, sizeof(wifi_channel_change_event_t));

    push_data_to_ctrl_queue((wifi_channel_change_event_t *)&channel_change, sizeof(wifi_channel_change_event_t), ctrl_event_type_hal_ind, ctrl_event_hal_channel_change);
    return;
}

int init_wifi_ctrl(wifi_ctrl_t *ctrl)
{
    unsigned int i;

    //Initialize Webconfig Framework
    ctrl->webconfig.initializer = webconfig_initializer_onewifi;
    ctrl->webconfig.apply_data = (webconfig_apply_data_t) webconfig_ctrl_apply;

    if (webconfig_init(&ctrl->webconfig) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_MGR, "[%s]:%d Init WiFi Web Config  fail\n",__FUNCTION__,__LINE__);
        // unregister and deinit everything
        return RETURN_ERR;
    }
    

    gettimeofday(&ctrl->last_signalled_time, NULL);
    gettimeofday(&ctrl->last_polled_time, NULL);
    pthread_cond_init(&ctrl->cond, NULL);
    pthread_mutex_init(&ctrl->lock, NULL);
    ctrl->poll_period = QUEUE_WIFI_CTRL_TASK_TIMEOUT;

    /*Intialize the scheduler*/
    ctrl->sched = scheduler_init();
    if (ctrl->sched == NULL) {
        deinit_wifi_ctrl(ctrl);
        wifi_util_dbg_print(WIFI_CTRL, "RDK_LOG_WARN, WIFI %s: control monitor scheduler init failed\n", __FUNCTION__);
        return RETURN_ERR;
    }

    ctrl->queue = queue_create();
    if (ctrl->queue == NULL) {
        deinit_wifi_ctrl(ctrl);
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_WARN, WIFI %s: control monitor queue create failed\n",__FUNCTION__);
        return RETURN_ERR;
    }

    // initialize the vap service objects
    for (i = 0; i < vap_svc_type_max; i++) {
        svc_init(&ctrl->ctrl_svc[i], (vap_svc_type_t)i);
    }

    //Register to RBUS for webconfig interactions
    rbus_register_handlers(ctrl);

    // subscribe for RBUS events
    rbus_subscribe_events(ctrl);

    //Register wifi hal sta connect/disconnect callback
    wifi_hal_staConnectionStatus_callback_register(sta_connection_status);

    //Register wifi hal scan results callback
    wifi_hal_scanResults_callback_register(scan_results_callback);

    //Register wifi hal frame recv callback
    wifi_hal_mgmt_frame_callbacks_register(mgmt_wifi_frame_recv);

    /* Register wifi hal channel change events callback */
    wifi_chan_event_register(channel_change_callback);

    ctrl->rbus_events_subscribed = false;
    ctrl->tunnel_events_subscribed = false;
    ctrl->scan_list = NULL;

    register_with_webconfig_framework();

    return RETURN_OK;
}

int wifi_hal_platform_post_init()
{
    int ret = RETURN_OK;

    wifi_util_dbg_print(WIFI_CTRL,"%s: start wifi apps\n",__FUNCTION__);

    ret = wifi_hal_post_init();
    if (ret != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL,"%s start wifi apps failed, ret:%d\n",__FUNCTION__, ret);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int start_wifi_ctrl(wifi_ctrl_t *ctrl)
{

    ctrl->webconfig_state = ctrl_webconfig_state_none;

    start_wifi_services();

    /* start wifi apps */
    wifi_hal_platform_post_init();

    ctrl->exit_ctrl = false;
    ctrl_queue_loop(ctrl);

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Exited queue_wifi_ctrl_task.\n",__FUNCTION__,__LINE__);
    return RETURN_OK;
}

wifi_radio_index_t get_wifidb_radio_index(uint8_t radio_index)
{
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    if ((radio_index < getNumberRadios())) {
        return g_wifi_mgr->radio_config[radio_index].vaps.radio_index;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
        return RETURN_ERR;
    }
}

rdk_wifi_vap_info_t* get_wifidb_rdk_vap_info(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index);
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    if ((radio_index < getNumberRadios()) && (vap_index < getMaxNumberVAPsPerRadio(radio_index))) {
        return &g_wifi_mgr->radio_config[radio_index].vaps.rdk_vap_array[vap_index];
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio or vap index %d\n", __FUNCTION__, radio_index);
        return NULL;
    }
}

wifi_vap_info_map_t* get_wifidb_vap_map(uint8_t radio_index)
{
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    if (radio_index < getNumberRadios()) {
        return &g_wifi_mgr->radio_config[radio_index].vaps.vap_map;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
        return NULL;
    }
}

wifi_radio_operationParam_t* get_wifidb_radio_map(uint8_t radio_index)
{
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    if (radio_index < getNumberRadios()) {
        return &g_wifi_mgr->radio_config[radio_index].oper;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
        return NULL;
    }
}

wifi_GASConfiguration_t* get_wifidb_gas_config(void)
{
     wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
     return &g_wifi_mgr->global_config.gas_config;
}

wifi_global_param_t* get_wifidb_wifi_global_param(void)
{
     wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
     return &g_wifi_mgr->global_config.global_parameters;
}

wifi_global_config_t* get_wifidb_wifi_global_config(void)
{
     wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
     return &g_wifi_mgr->global_config;
}

wifi_vap_info_map_t * Get_wifi_object(uint8_t radio_index)
{
    return get_wifidb_vap_map(radio_index);
}

wifi_GASConfiguration_t * Get_wifi_gas_conf_object(void)
{
    return get_wifidb_gas_config();
}

wifi_interworking_t * Get_wifi_object_interworking_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index);
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= getMaxNumberVAPsPerRadio(radio_index)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.bss_info.interworking;
}

wifi_vap_security_t * Get_wifi_object_bss_security_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index);
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= getMaxNumberVAPsPerRadio(radio_index)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.bss_info.security;
}

wifi_vap_security_t * Get_wifi_object_sta_security_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index);
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= MAX_NUM_VAP_PER_RADIO) {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.sta_info.security;
}

wifi_front_haul_bss_t * Get_wifi_object_bss_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index);
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if(l_vap_maps == NULL || vap_index >= getMaxNumberVAPsPerRadio(radio_index)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.bss_info;
}

wifi_back_haul_sta_t * get_wifi_object_sta_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index);
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if(l_vap_maps == NULL || vap_index >= getMaxNumberVAPsPerRadio(radio_index)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.sta_info;
}

wifi_vap_info_t* get_wifidb_vap_parameters(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index);
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= getMaxNumberVAPsPerRadio(radio_index)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index];
}

int get_wifi_vap_network_status(uint8_t vapIndex, bool *status)
{
    wifi_front_haul_bss_t *bss_param = Get_wifi_object_bss_parameter(vapIndex);
    if(bss_param != NULL) {
        *status = bss_param->enabled;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d bss_param null for vapIndex:%d \n", __func__, __LINE__, vapIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int get_wifi_mesh_sta_network_status(uint8_t vapIndex, bool *status)
{
    wifi_back_haul_sta_t *sta_param = get_wifi_object_sta_parameter(vapIndex);
    if(sta_param != NULL) {
        *status = sta_param->enabled;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d sta_param null for vapIndex:%d \n", __func__, __LINE__, vapIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

bool get_wifi_mesh_vap_enable_status(void)
{
    bool status = false;
    unsigned int num_of_radios = getNumberRadios();
    unsigned int i = 0, j = 0;
    wifi_vap_info_map_t *vap_map = NULL;

    for (i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        if (vap_map == NULL) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__, i);
            return -1;
        }

        for (j = 0; j < vap_map->num_vaps; j++) {
            if (isVapMeshBackhaul(vap_map->vap_array[j].vap_index)) {
                get_wifi_vap_network_status(vap_map->vap_array[j].vap_index, &status);
                if (status == true) {
                    return true;
                }
            }
        }
    }

    return false;
}
bool get_wifi_public_vap_enable_status(void)
{
    bool status = false;
    unsigned int num_of_radios = getNumberRadios();
    unsigned int i = 0, j = 0;
    wifi_vap_info_map_t *vap_map = NULL;
    mac_address_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    for (i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        if (vap_map == NULL) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__, i);
            return -1;
        }

        for (j = 0; j < vap_map->num_vaps; j++) {
            if ((isVapHotspotOpen(vap_map->vap_array[j].vap_index) == TRUE)
                || (isVapHotspotSecure(vap_map->vap_array[j].vap_index) == TRUE)) {

                get_wifi_vap_network_status(vap_map->vap_array[j].vap_index, &status);

                if (status == true &&  (memcmp(vap_map->vap_array[j].u.bss_info.bssid, zero_mac, sizeof(mac_address_t)) != 0)) {
                    wifi_util_dbg_print(WIFI_CTRL,"Public xfinity vap is enabled\n");
                    return true;
                }
            }
        }
    }

    wifi_util_dbg_print(WIFI_CTRL,"Public xfinity vap is disabled\n");
    return false;
}

int set_wifi_vap_network_status(uint8_t vapIndex, bool status)
{
    wifi_front_haul_bss_t *bss_param = Get_wifi_object_bss_parameter(vapIndex);
    if(bss_param != NULL) {
        bss_param->enabled = status;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d bss_param null for vapIndex:%d \n", __func__, __LINE__, vapIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int set_wifi_sta_network_status(uint8_t vapIndex, bool status)
{
    wifi_back_haul_sta_t *sta_param = get_wifi_object_sta_parameter(vapIndex);
    if(sta_param != NULL) {
        sta_param->enabled = status;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d sta_param null for vapIndex:%d \n", __func__, __LINE__, vapIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int set_wifi_public_vap_enable_status(void)
{
    unsigned int num_of_radios = getNumberRadios();
    unsigned int i = 0, j = 0;
    wifi_vap_info_map_t *vap_map = NULL;

    for (i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        if (vap_map == NULL) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__, i);
            return RETURN_ERR;
        }

        for (j = 0; j < vap_map->num_vaps; j++) {
            if ((isVapHotspotOpen(vap_map->vap_array[j].vap_index) == TRUE)
                || (isVapHotspotSecure(vap_map->vap_array[j].vap_index) == TRUE)) {
                set_wifi_vap_network_status(vap_map->vap_array[j].vap_index, true);
            }
        }
    }

    return RETURN_OK;
}

wifi_dml_parameters_t* get_wifi_dml_parameters(void)
{
    wifi_mgr_t *p_wifi_db_data = get_wifimgr_obj();
    return &p_wifi_db_data->dml_parameters;
}

wifi_rfc_dml_parameters_t* get_wifi_db_rfc_parameters(void)
{
    wifi_mgr_t *p_wifi_db_data = get_wifimgr_obj();
    return &p_wifi_db_data->rfc_dml_parameters;
}

wifi_rfc_dml_parameters_t* get_ctrl_rfc_parameters(void)
{
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    g_wifi_mgr->ctrl.rfc_params.wifipasspoint_rfc = g_wifi_mgr->rfc_dml_parameters.wifipasspoint_rfc;
    g_wifi_mgr->ctrl.rfc_params.wifiinterworking_rfc= g_wifi_mgr->rfc_dml_parameters.wifiinterworking_rfc;
    g_wifi_mgr->ctrl.rfc_params.radiusgreylist_rfc = g_wifi_mgr->rfc_dml_parameters.radiusgreylist_rfc;
    g_wifi_mgr->ctrl.rfc_params.dfsatbootup_rfc  = g_wifi_mgr->rfc_dml_parameters.dfsatbootup_rfc ;
    g_wifi_mgr->ctrl.rfc_params.dfs_rfc = g_wifi_mgr->rfc_dml_parameters.dfs_rfc;
    g_wifi_mgr->ctrl.rfc_params.wpa3_rfc = g_wifi_mgr->rfc_dml_parameters.wpa3_rfc;
    strcpy(g_wifi_mgr->ctrl.rfc_params.rfc_id,g_wifi_mgr->rfc_dml_parameters.rfc_id);
    return &g_wifi_mgr->ctrl.rfc_params;
}

int get_wifi_rfc_parameters(char *str, void *value)
{
    int ret = RETURN_OK;
    wifi_mgr_t *l_wifi_mgr = get_wifimgr_obj();
    wifi_util_dbg_print(WIFI_CTRL, "%s get wifi rfc parameter %s\n", __FUNCTION__, str);
    if ((strcmp(str, RFC_WIFI_PASSPOINT) == 0)) {
        *(bool*)value = l_wifi_mgr->rfc_dml_parameters.wifipasspoint_rfc;
    } else if ((strcmp(str, RFC_WIFI_INTERWORKING) == 0)) {
        *(bool*)value = l_wifi_mgr->rfc_dml_parameters.wifiinterworking_rfc;
    } else if ((strcmp(str, RFC_WIFI_RADIUS_GREYLIST) == 0)) {
        *(bool*)value = l_wifi_mgr->rfc_dml_parameters.radiusgreylist_rfc;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s get wifi rfc parameter not found %s\n", __FUNCTION__, str);
        ret = RETURN_ERR;
    }
    return ret;
}

int get_multi_radio_dml_parameters(uint8_t radio_index, char *str, void *value)
{
    int ret = RETURN_OK;
    wifi_mgr_t *l_wifi_mgr = get_wifimgr_obj();
    wifi_util_dbg_print(WIFI_CTRL, "%s get multi radio dml data %s: radio_index:%d \n", __FUNCTION__, str, radio_index);
    if ((strcmp(str, FACTORY_RESET_SSID) == 0)) {
        *(int*)value = l_wifi_mgr->dml_parameters.RadioFactoryResetSSID[radio_index];
    } else {
        ret = RETURN_ERR;
        wifi_util_dbg_print(WIFI_CTRL, "%s get multi radio dml data not match %s: ap_index:%d \n", __FUNCTION__, str, radio_index);
    }
    return ret;
}

int set_multi_radio_dml_parameters(uint8_t radio_index, char *str, void *value)
{
    int ret = RETURN_OK;
    wifi_mgr_t *l_wifi_mgr = get_wifimgr_obj();
    wifi_util_dbg_print(WIFI_CTRL, "%s set multi radio dml data %s: radio_index:%d \n", __FUNCTION__, str, radio_index);
    if ((strcmp(str, FACTORY_RESET_SSID) == 0)) {
        l_wifi_mgr->dml_parameters.RadioFactoryResetSSID[radio_index] = *(int*)value;
    } else {
        ret = RETURN_ERR;
        wifi_util_dbg_print(WIFI_CTRL, "%s set multi radio dml data not match %s: radio_index:%d \n", __FUNCTION__, str, radio_index);
    }
    return ret;
}

int get_multi_vap_dml_parameters(uint8_t ap_index, char *str, void *value)
{
    int ret = RETURN_OK;
    wifi_mgr_t *l_wifi_mgr = get_wifimgr_obj();
    wifi_util_dbg_print(WIFI_CTRL, "%s get multi vap structure data %s: ap_index:%d \n", __FUNCTION__, str, ap_index);
    if ((strcmp(str, RECONNECT_COUNT_STATUS) == 0)) {
        *(bool*)value = l_wifi_mgr->dml_parameters.ReconnectCountEnable[ap_index];
    } else {
        ret = RETURN_ERR;
        wifi_util_dbg_print(WIFI_CTRL, "%s get multi vap structure data not match %s: ap_index:%d \n", __FUNCTION__, str, ap_index);
    }
    return ret;
}

int set_multi_vap_dml_parameters(uint8_t ap_index, char *str, void *value)
{
    int ret = RETURN_OK;
    wifi_mgr_t *l_wifi_mgr = get_wifimgr_obj();
    wifi_util_dbg_print(WIFI_CTRL, "%s set multi vap structure data %s: ap_index:%d \n", __FUNCTION__, str, ap_index);
    if ((strcmp(str, RECONNECT_COUNT_STATUS) == 0)) {
        l_wifi_mgr->dml_parameters.ReconnectCountEnable[ap_index] = *(bool*)value;
    } else {
        ret = RETURN_ERR;
        wifi_util_dbg_print(WIFI_CTRL, "%s set multi vap structure data not match %s: ap_index:%d \n", __FUNCTION__, str, ap_index);
    }
    return ret;
}

int get_vap_dml_parameters(char *str, void *value)
{
    int ret = RETURN_OK;
    wifi_mgr_t *l_wifi_mgr = get_wifimgr_obj();
    wifi_util_dbg_print(WIFI_CTRL, "%s get vap structure data %s\n", __FUNCTION__, str);
    if ((strcmp(str, RSSI_THRESHOLD) == 0)) {
        *(int*)value = l_wifi_mgr->dml_parameters.rssi_threshold;
    } else if ((strcmp(str, MFP_FEATURE_STATUS) == 0)) {
        *(bool*)value = l_wifi_mgr->dml_parameters.FeatureMFPConfig;
    } else if ((strcmp(str, CH_UTILITY_LOG_INTERVAL) == 0)) {
        *(int*)value = l_wifi_mgr->dml_parameters.ChUtilityLogInterval;
    } else if ((strcmp(str, DEVICE_LOG_INTERVAL) == 0)) {
        *(int*)value = l_wifi_mgr->dml_parameters.DeviceLogInterval;
    } else if ((strcmp(str, WIFI_FACTORY_RESET) == 0)) {
        *(bool*)value = l_wifi_mgr->dml_parameters.WifiFactoryReset;
    } else if ((strcmp(str, VALIDATE_SSID_NAME) == 0)) {
        *(bool*)value = l_wifi_mgr->dml_parameters.ValidateSSIDName;
    } else if ((strcmp(str, FIXED_WMM_PARAMS) == 0)) {
        *(int*)value = l_wifi_mgr->dml_parameters.FixedWmmParams;
    } else if((strcmp(str, ASSOC_COUNT_THRESHOLD) == 0)) {
        *(int*)value = l_wifi_mgr->dml_parameters.AssocCountThreshold;
    } else if ((strcmp(str, ASSOC_MONITOR_DURATION) == 0)) {
        *(int*)value = l_wifi_mgr->dml_parameters.AssocMonitorDuration;
    } else if ((strcmp(str, ASSOC_GATE_TIME) == 0)) {
        *(int*)value = l_wifi_mgr->dml_parameters.AssocGateTime;
    } else if ((strcmp(str, WIFI_TX_OVERFLOW_SELF_HEAL) == 0)) {
        *(bool*)value = l_wifi_mgr->dml_parameters.WiFiTxOverflowSelfheal;
    } else if ((strcmp(str, WIFI_FORCE_DISABLE_RADIO) == 0)) {
        *(bool*)value = l_wifi_mgr->dml_parameters.WiFiForceDisableWiFiRadio;
    } else if ((strcmp(str, WIFI_FORCE_DISABLE_RADIO_STATUS) == 0)) {
        *(int*)value = l_wifi_mgr->dml_parameters.WiFiForceDisableRadioStatus;
    } else {
        ret = RETURN_ERR;
        wifi_util_dbg_print(WIFI_CTRL, "%s get vap structure data not match %s:\n", __FUNCTION__, str);
    }
    return ret;
}

int set_vap_dml_parameters(char *str, void *value)
{
    if(!str || !value) {
        return RETURN_ERR;
    }

    int ret = RETURN_OK;
    wifi_mgr_t *l_wifi_mgr = get_wifimgr_obj();
    wifi_util_dbg_print(WIFI_CTRL, "%s set vap structure %s\n", __FUNCTION__, str);
    if ((strcmp(str, RSSI_THRESHOLD) == 0)) {
        l_wifi_mgr->dml_parameters.rssi_threshold = *(int*)value;
    } else if ((strcmp(str, MFP_FEATURE_STATUS) == 0)) {
        l_wifi_mgr->dml_parameters.FeatureMFPConfig = *(bool*)value;
    } else if ((strcmp(str, CH_UTILITY_LOG_INTERVAL) == 0)) {
        l_wifi_mgr->dml_parameters.ChUtilityLogInterval = *(int*)value;
    } else if ((strcmp(str, DEVICE_LOG_INTERVAL) == 0)) {
        l_wifi_mgr->dml_parameters.DeviceLogInterval = *(int*)value;
    } else if ((strcmp(str, WIFI_FACTORY_RESET) == 0)) {
        l_wifi_mgr->dml_parameters.WifiFactoryReset = *(bool*)value;
    } else if ((strcmp(str, VALIDATE_SSID_NAME) == 0)) {
        l_wifi_mgr->dml_parameters.ValidateSSIDName = *(bool*)value;
    } else if ((strcmp(str, FIXED_WMM_PARAMS) == 0)) {
        l_wifi_mgr->dml_parameters.FixedWmmParams = *(int*)value;
    } else if ((strcmp(str, ASSOC_COUNT_THRESHOLD) == 0)) {
        l_wifi_mgr->dml_parameters.AssocCountThreshold = *(int*)value;
    } else if ((strcmp(str, ASSOC_MONITOR_DURATION) == 0)) {
        l_wifi_mgr->dml_parameters.AssocMonitorDuration = *(int*)value;
    } else if ((strcmp(str, ASSOC_GATE_TIME) == 0)) {
        l_wifi_mgr->dml_parameters.AssocGateTime = *(int*)value;
    } else if ((strcmp(str, WIFI_TX_OVERFLOW_SELF_HEAL) == 0)) {
        l_wifi_mgr->dml_parameters.WiFiTxOverflowSelfheal = *(bool*)value;
    } else if ((strcmp(str, WIFI_FORCE_DISABLE_RADIO) == 0)) {
        l_wifi_mgr->dml_parameters.WiFiForceDisableWiFiRadio = *(bool*)value;
    } else if ((strcmp(str, WIFI_FORCE_DISABLE_RADIO_STATUS) == 0)) {
        l_wifi_mgr->dml_parameters.WiFiForceDisableRadioStatus = *(int*)value;
    } else {
        ret = RETURN_ERR;
        wifi_util_dbg_print(WIFI_CTRL, "%s set vap structure data not match %s:\n", __FUNCTION__, str);
    }
    return ret;
}

int set_dml_init_status(bool status)
{
    int ret = RETURN_OK;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_util_dbg_print(WIFI_MGR, "%s Marking DML Init Complete. Start Wifi Ctrl\n", __FUNCTION__);
    pthread_cond_signal(&wifi_mgr->dml_init_status);
    return ret;
}

rdk_wifi_radio_t* find_radio_config_by_index(uint8_t index)
{
    unsigned int i;
    bool found = false;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    uint8_t num_of_radios = getNumberRadios();
    for (i = 0; i < num_of_radios; i++) {
        if (index == wifi_mgr->radio_config[i].vaps.radio_index) {
            found = true;
            break;
        }
    }
    return (found == false)?NULL:&(wifi_mgr->radio_config[i]);
}

int get_sta_ssid_from_radio_config_by_radio_index(unsigned int radio_index, ssid_t ssid)
{
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *map;
    bool found = false;
    unsigned int index, i;

    index = get_sta_vap_index_for_radio(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, radio_index);

    radio = find_radio_config_by_index(radio_index);
    if (radio == NULL) {
        return -1;
    }

    map = &radio->vaps.vap_map;
    for (i = 0; i < map->num_vaps; i++) {
        if (map->vap_array[i].vap_index == index) {
            found = true;
            strcpy(ssid, map->vap_array[i].u.sta_info.ssid);
            break;
        }
    }

    return (found == false) ? -1:0;
}

wifi_hal_capability_t* rdk_wifi_get_hal_capability_map(void)
{
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    return &wifi_mgr->hal_cap;
}

UINT getNumberofVAPsPerRadio(UINT radioIndex)
{
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    return (wifi_mgr->radio_config[radioIndex].vaps.vap_map.num_vaps);
}

rdk_wifi_vap_map_t *getRdkWifiVap(UINT radioIndex)
{
    if (radioIndex >= getNumberRadios()) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input radioIndex = %d not found, out of range\n", __FUNCTION__, radioIndex);
        return NULL;
    }
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    return &wifi_mgr->radio_config[radioIndex].vaps;
}

//Returns the wifi_vap_info_t, here apIndex starts with 0 i.e., (dmlInstanceNumber-1)
wifi_vap_info_t *getVapInfo(UINT apIndex)
{
    UINT radioIndex = 0;
    UINT vapArrayIndex = 0;

    if (apIndex >= getTotalNumberVAPs()) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input apIndex = %d not found, Out of range\n", __FUNCTION__, apIndex);
        return NULL;
    }
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    for (radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        for (vapArrayIndex = 0; vapArrayIndex < getNumberofVAPsPerRadio(radioIndex); vapArrayIndex++) {
            if (apIndex == wifi_mgr->radio_config[radioIndex].vaps.vap_map.vap_array[vapArrayIndex].vap_index) {
                //wifi_util_dbg_print(WIFI_CTRL, "%s Input apIndex = %d  found at radioIndex = %d vapArrayIndex = %d\n ", __FUNCTION__, apIndex, radioIndex, vapArrayIndex);
                return &wifi_mgr->radio_config[radioIndex].vaps.vap_map.vap_array[vapArrayIndex];
            } else {
                continue;
            }
        }
    }

    wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input apIndex = %d not found \n", __FUNCTION__, apIndex);
    return NULL;
}


//Returns the rdk_wifi_vap_info_t, here apIndex starts with 0 i.e., (dmlInstanceNumber-1)
rdk_wifi_vap_info_t *getRdkVapInfo(UINT apIndex)
{
    UINT radioIndex = 0;
    UINT vapArrayIndex = 0;

    if (apIndex >= getTotalNumberVAPs()) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input apIndex = %d not found, Out of range\n", __FUNCTION__, apIndex);
        return NULL;
    }
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    for (radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        for (vapArrayIndex = 0; vapArrayIndex < getNumberofVAPsPerRadio(radioIndex); vapArrayIndex++) {
            if (apIndex == wifi_mgr->radio_config[radioIndex].vaps.rdk_vap_array[vapArrayIndex].vap_index) {
                wifi_util_dbg_print(WIFI_CTRL, "%s Input apIndex = %d  found at radioIndex = %d vapArrayIndex = %d\n ", __FUNCTION__, apIndex, radioIndex, vapArrayIndex);
                return &wifi_mgr->radio_config[radioIndex].vaps.rdk_vap_array[vapArrayIndex];
            } else {
                continue;
            }
        }
    }

    wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input apIndex = %d not found \n", __FUNCTION__, apIndex);
    return NULL;
}

//Returns the wifi_radio_capabilities_t, here radioIndex starts with 0 i.e., (dmlInstanceNumber-1)
wifi_radio_capabilities_t *getRadioCapability(UINT radioIndex)
{
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();
    if (radioIndex >= getNumberRadios()) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input radioIndex = %d not found, out of range\n", __FUNCTION__, radioIndex);
        return NULL;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s Input radioIndex = %d\n", __FUNCTION__, radioIndex);

    return &wifi_hal_cap_obj->wifi_prop.radiocap[radioIndex];
}

//Returns the wifi_radio_operationParam_t, here radioIndex starts with 0 i.e., (dmlInstanceNumber-1)
wifi_radio_operationParam_t *getRadioOperationParam(UINT radioIndex)
{
    if (radioIndex >= getNumberRadios()) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input radioIndex = %d not found, out of range\n", __FUNCTION__, radioIndex);
        return NULL;
    }
    wifi_util_dbg_print(WIFI_CTRL, "%s Input radioIndex = %d\n", __FUNCTION__, radioIndex);

    return get_wifidb_radio_map(radioIndex);
}

//Get the wlanIndex from the Interface name
int rdkGetIndexFromName(char *pIfaceName, UINT *pWlanIndex)
{
    UINT radioIndex = 0;
    UINT vapArrayIndex = 0;

    if (!pIfaceName || !pWlanIndex) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_ERROR,WIFI %s : pIfaceName (or) pWlanIndex is NULL \n",__FUNCTION__);
        return RETURN_ERR;
    }
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    for (radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        for (vapArrayIndex = 0; vapArrayIndex < getNumberofVAPsPerRadio(radioIndex); vapArrayIndex++) {
            if (strncmp(pIfaceName, wifi_mgr->radio_config[radioIndex].vaps.vap_map.vap_array[vapArrayIndex].vap_name, strlen(pIfaceName)) == 0) {
                *pWlanIndex = wifi_mgr->radio_config[radioIndex].vaps.vap_map.vap_array[vapArrayIndex].vap_index;
                wifi_util_dbg_print(WIFI_CTRL, "%s pIfaceName : %s wlanIndex : %d\n", __FUNCTION__, pIfaceName, *pWlanIndex);
                return RETURN_OK;
            } else {
                continue;
            }
        }
    }

    wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_ERROR,WIFI %s : pIfaceName : %s is not found\n",__FUNCTION__, pIfaceName);
    return RETURN_ERR;
}

UINT getRadioIndexFromAp(UINT apIndex)
{
    wifi_vap_info_t * vapInfo = getVapInfo(apIndex);
    if (vapInfo != NULL) {
        return vapInfo->radio_index;
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"getRadioIndexFromAp not recognised!!!\n"); //should never happen
        return 0;
    }
}

UINT getPrivateApFromRadioIndex(UINT radioIndex)
{
    for (UINT apIndex = 0; apIndex < getTotalNumberVAPs(); apIndex++) {
        if((strncmp((CHAR *)getVAPName(apIndex), "private_ssid", strlen("private_ssid")) == 0) &&
               getRadioIndexFromAp(apIndex) == radioIndex ) {
            return apIndex;
        }
    }
    wifi_util_dbg_print(WIFI_CTRL,"getPrivateApFromRadioIndex not recognised for radioIndex %u!!!\n", radioIndex);
    return 0;
}

BOOL isVapPrivate(UINT apIndex)
{
    return is_vap_private(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapXhs(UINT apIndex)
{
    return is_vap_xhs(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapHotspot(UINT apIndex)
{
    return is_vap_hotspot(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapLnf(UINT apIndex)
{
    return is_vap_lnf(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapLnfPsk(UINT apIndex)
{
    return is_vap_lnf_psk(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapMesh(UINT apIndex)
{
    return is_vap_mesh(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapHotspotSecure(UINT apIndex)
{
    return is_vap_hotspot_secure(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapHotspotOpen(UINT apIndex)
{
    return is_vap_hotspot_open(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}


BOOL isVapLnfSecure(UINT apIndex)
{
    return is_vap_lnf_radius(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapSTAMesh(UINT apIndex)
{
    return is_vap_mesh_sta(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapMeshBackhaul(UINT apIndex)
{
    if (strncmp((CHAR *)getVAPName(apIndex), "mesh_backhaul", strlen("mesh_backhaul")) == 0) {
        return TRUE;
    }
    return FALSE;
}

UINT getNumberRadios()
{
    return get_number_of_radios(&(get_wifimgr_obj())->hal_cap.wifi_prop);
}

UINT getMaxNumberVAPsPerRadio(UINT radioIndex)
{
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();
    return wifi_hal_cap_obj->wifi_prop.radiocap[radioIndex].maxNumberVAPs;
}

//Returns total number of Configured vaps for all radios
UINT getTotalNumberVAPs()
{
    UINT numRadios = getNumberRadios();
    static UINT numVAPs = 0;
    UINT radioCount = 0;
    if (numVAPs == 0) {
        for (radioCount = 0; radioCount < numRadios; radioCount++)
            numVAPs += getMaxNumberVAPsPerRadio(radioCount);
    }

    return numVAPs;
}

CHAR* getVAPName(UINT apIndex)
{
    UINT radioIndex = 0;
    UINT vapArrayIndex = 0;
    char *unused = "unused";
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    for (radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        for (vapArrayIndex = 0; vapArrayIndex < getNumberofVAPsPerRadio(radioIndex); vapArrayIndex++) {
            if (apIndex == wifi_mgr->radio_config[radioIndex].vaps.vap_map.vap_array[vapArrayIndex].vap_index) {
                //wifi_util_dbg_print(WIFI_CTRL, "%s Input apIndex = %d  found at radioIndex = %d vapArrayIndex = %d\n ", __FUNCTION__, apIndex, radioIndex, vapArrayIndex);
                if((wifi_mgr->radio_config[radioIndex].vaps.rdk_vap_array[vapArrayIndex].vap_name != NULL) && (strlen((CHAR *)wifi_mgr->radio_config[radioIndex].vaps.rdk_vap_array[vapArrayIndex].vap_name) != 0)) {
                    return (CHAR *)wifi_mgr->radio_config[radioIndex].vaps.rdk_vap_array[vapArrayIndex].vap_name;
                } else {
                    return unused;
                }
            } else {
                continue;
            }
        }
    }
    return unused;
}

int getVAPIndexFromName(CHAR *vapName, UINT *apIndex)
{
    if (vapName == NULL || apIndex == NULL) {
        return RETURN_ERR;
    }
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    for (UINT radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        for (UINT vapArrayIndex = 0; vapArrayIndex < getNumberofVAPsPerRadio(radioIndex); vapArrayIndex++) {
            if (!strncmp (vapName, (CHAR *)wifi_mgr->radio_config[radioIndex].vaps.rdk_vap_array[vapArrayIndex].vap_name, \
                    strlen((CHAR *)wifi_mgr->radio_config[radioIndex].vaps.rdk_vap_array[vapArrayIndex].vap_name) + 1)) {
                *apIndex = wifi_mgr->radio_config[radioIndex].vaps.vap_map.vap_array[vapArrayIndex].vap_index;
                return RETURN_OK;
            }
        }
    }
    return RETURN_ERR;
}

UINT convert_radio_index_to_frequencyNum(UINT radioIndex)
{
    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radioIndex);
    if (radioOperation == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s : failed to getRadioOperationParam with radio index \n", __FUNCTION__);
        return 0;
    }
    switch (radioOperation->band) {
        case WIFI_FREQUENCY_2_4_BAND:
            return NAME_FREQUENCY_2_4;
        case WIFI_FREQUENCY_5_BAND:
            return NAME_FREQUENCY_5;
        case WIFI_FREQUENCY_6_BAND:
            return NAME_FREQUENCY_6;
        default:
            break;
    }
    return 0;
}

int get_vap_interface_bridge_name(unsigned int vap_index, char *bridge_name)
{
    unsigned char i = 0;
    unsigned char total_num_of_vaps = getTotalNumberVAPs();
    char *l_bridge_name = NULL;
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();

    if ((vap_index >= total_num_of_vaps) || (bridge_name == NULL)) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Wrong vap_index:%d \n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    for (i = 0; i < total_num_of_vaps; i++) {
        if (wifi_hal_cap_obj->wifi_prop.interface_map[i].index == vap_index) {
            l_bridge_name = wifi_hal_cap_obj->wifi_prop.interface_map[i].bridge_name;
            break;
        }
    }

    if(l_bridge_name != NULL) {
        strncpy(bridge_name, l_bridge_name, (strlen(l_bridge_name) + 1));
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Bridge name not found:%d \n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

void Hotspot_APIsolation_Set(int apIns)
{
    wifi_front_haul_bss_t *pcfg = Get_wifi_object_bss_parameter(apIns);
    BOOL enabled = FALSE;

    wifi_getApEnable(apIns-1, &enabled);

    if (enabled == FALSE) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_INFO,%s: wifi_getApEnable %d, %d \n", __FUNCTION__, apIns, enabled);
        return;
    }

    if (pcfg != NULL) {
        wifi_setApIsolationEnable(apIns-1,pcfg->isolation);
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_INFO,%s: wifi_setApIsolationEnable %d, %d \n", __FUNCTION__, apIns-1, pcfg->isolation);
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"Wrong vap_index:%s:%d\r\n",__FUNCTION__, apIns);
    }
}

void Load_Hotspot_APIsolation_Settings(void)
{
    for (UINT apIndex = 0; apIndex < getTotalNumberVAPs(); ++apIndex) {
        if (isVapHotspot(apIndex)) {
            Hotspot_APIsolation_Set(apIndex + 1);
        }
    }
}
