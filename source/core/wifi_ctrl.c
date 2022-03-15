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

    data->event_type = type;
    data->sub_type = sub_type;

    data->msg = malloc(len + 1);
    if(data->msg == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_WARN,,,WIFI %s: data message malloc null\n",__FUNCTION__);
        return RETURN_ERR;
    }
    /* copy msg to data */
    memcpy(data->msg, msg, len);
    data->len = len;

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
    ctrl_event_t *queue_data = NULL;

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

            if (ctrl->rbus_events_subscribed == false) {
                rbus_subscribe_events(ctrl);
            }
            webconfig_analyze_pending_states(ctrl);
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

static char *to_mac_str    (mac_address_t mac, mac_addr_str_t key) {
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

int start_wifi_radio_vap(void)
{
    wifi_vap_info_map_t *wifi_vap_map = NULL;
    wifi_radio_operationParam_t *wifi_radio_oper_param = NULL;
    int ret = RETURN_OK;
    uint8_t index = 0;
    uint8_t num_of_radios = getNumberRadios();
    UINT num_vaps, vap_index;
    rdk_wifi_vap_info_t *rdk_vap_info;
    mac_addr_str_t mac_str;
    mac_address_t acl_device_mac;
    acl_entry_t *acl_entry;

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
        wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(index);
        if (wifi_vap_map == NULL) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:index: %d\n",__FUNCTION__, index);
            return RETURN_ERR;
        }
        wifi_util_dbg_print(WIFI_CTRL,"%s:index: %d number of vaps :%d num_of_radios:%d\n",__FUNCTION__, index, wifi_vap_map->num_vaps,num_of_radios);

        ret = wifi_hal_setRadioOperatingParameters(index, wifi_radio_oper_param);
        wifi_util_dbg_print(WIFI_CTRL,"%s: wifi radio parameter set\n",__FUNCTION__);

        ret = wifi_hal_createVAP(index, wifi_vap_map);
        if (ret != RETURN_OK) {
            wifi_util_dbg_print(WIFI_CTRL,"%s: wifi vap create failure: radio_index:%d\n",__FUNCTION__, index);
            return ret;
        } else {
            wifi_util_dbg_print(WIFI_CTRL,"%s: wifi vap create success: radio_index:%d\n",__FUNCTION__, index);
        }
    }

    num_vaps = getTotalNumberVAPs();
    for (vap_index = 0; vap_index < num_vaps; vap_index++) {
        //clean any HAL configuration
        wifi_delApAclDevices(vap_index);

        rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
        if (rdk_vap_info != NULL && rdk_vap_info->acl_map != NULL) {
            acl_entry = hash_map_get_first(rdk_vap_info->acl_map);
            while(acl_entry != NULL) {
                if (acl_entry->mac != NULL) {
                    memcpy(&acl_device_mac,&acl_entry->mac,sizeof(mac_address_t));
                    to_mac_str(acl_device_mac, mac_str);
                    ret = wifi_addApAclDevice(vap_index, (CHAR *) mac_str);
                    if (ret != RETURN_OK) {
                        wifi_util_dbg_print(WIFI_CTRL,"%s: wifi_addApAclDevice failed. vap_index:%d MAC:'%s'\n",__FUNCTION__, vap_index, mac_str);
                        return ret;
                    }
                }
                acl_entry = hash_map_get_next(rdk_vap_info->acl_map,acl_entry);
            }
        }
    }

    wifi_util_dbg_print(WIFI_CTRL,"Before calling captive_portal\n");
    captive_portal_check();
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
        wifi_util_dbg_print(WIFI_CTRL,"FactoryReset radio_index is %d: num_vaps %d \n",radio_index,wifi_vap_map[radio_index].num_vaps);
        for ( i = 0; i < wifi_vap_map[radio_index].num_vaps; i++) {
            wifi_util_dbg_print(WIFI_CTRL,"FactoryReset vap_index is %d: \n",i);
            if (strncmp(wifi_vap_map->vap_array[i].vap_name,"private_ssid",strlen("private_ssid"))== 0) {
                sprintf(path,DEVICE_WIFI_SSID,radio_index+1);
                wifi_util_dbg_print(WIFI_CTRL,"FactoryReset  private ssid is %s and vap_name is %s path is %s\n", wifi_vap_map->vap_array[i].u.bss_info.ssid,wifi_vap_map->vap_array[i].vap_name,path);
                rbus_setStr(g_wifi_mgr->ctrl.rbus_handle,path,wifi_vap_map->vap_array[i].u.bss_info.ssid);
                wifi_util_dbg_print(WIFI_CTRL,"rbus_set SSID is done\n");
                sprintf(path,DEVICE_WIFI_KEYPASSPHRASE,radio_index+1);
                wifi_util_dbg_print(WIFI_CTRL,"FactoryReset password is %s path is %s\n", wifi_vap_map->vap_array[i].u.bss_info.security.u.key.key,path);
                rbus_setStr(g_wifi_mgr->ctrl.rbus_handle,path,wifi_vap_map->vap_array[i].u.bss_info.security.u.key.key);
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
    rbus_set(g_wifi_mgr->ctrl.rbus_handle,FACTORY_RESET_NOTIFICATION,value,NULL);
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
    push_data_to_ctrl_queue((wifi_station_stats_t *)sta, sizeof(wifi_station_stats_t), ctrl_event_type_hal_ind, ctrl_event_hal_sta_conn_status);

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

int init_wifi_ctrl(wifi_ctrl_t *ctrl)
{
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

    ctrl->rbus_events_subscribed = false;

    return RETURN_OK;
}

int start_wifi_ctrl(wifi_ctrl_t *ctrl)
{

#ifdef WEBCONFIG_TESTS_OVER_QUEUE
    webconfig_consumer_set_test_data();
#endif
    ctrl->webconfig_state = ctrl_webconfig_state_none;

    //Set Radio and VAP parameters to HAL
    start_wifi_radio_vap();

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
    get_vap_and_radio_index_from_vap_instance(vapIndex, &radio_index, &vap_index);
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

void get_vap_and_radio_index_from_vap_instance(uint8_t vap_instance, uint8_t *radio_index, uint8_t *vap_index)
{
    if ((vap_instance % 2) == 0) {
        *radio_index = 0;
    } else {
        *radio_index = 1;
    }
    *vap_index = vap_instance / 2;
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
    get_vap_and_radio_index_from_vap_instance(vapIndex, &radio_index, &vap_index);
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
    get_vap_and_radio_index_from_vap_instance(vapIndex, &radio_index, &vap_index);
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
    get_vap_and_radio_index_from_vap_instance(vapIndex, &radio_index, &vap_index);
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
    get_vap_and_radio_index_from_vap_instance(vapIndex, &radio_index, &vap_index);
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
    get_vap_and_radio_index_from_vap_instance(vapIndex, &radio_index, &vap_index);
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
    get_vap_and_radio_index_from_vap_instance(vapIndex, &radio_index, &vap_index);
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= getMaxNumberVAPsPerRadio(radio_index)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index];
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

int get_wifi_rfc_parameters(char *str, void *value)
{
    int ret = RETURN_OK;
    wifi_mgr_t *l_wifi_mgr = get_wifimgr_obj();
    wifi_util_dbg_print(WIFI_CTRL, "%s get wifi rfc parameter %s\n", __FUNCTION__, str);
    if ((strcmp(str, RFC_WIFI_PASSPOINT_STATUS) == 0)) {
        *(UINT*)value = l_wifi_mgr->rfc_dml_parameters.wifi_passpoint_status;
    } else if ((strcmp(str, RFC_WIFI_INTERWORKING_STATUS) == 0)) {
        *(UINT*)value = l_wifi_mgr->rfc_dml_parameters.wifi_interworking_status;
    } else if ((strcmp(str, RFC_WIFI_RADIUS_GREYLIST_STATUS) == 0)) {
        *(bool*)value = l_wifi_mgr->rfc_dml_parameters.RadiusGreyList_status;
    } else if ((strcmp(str, RFC_WIFI_DISABLE_NATIVE_HOSTAPD) == 0)) {
        *(bool*)value = l_wifi_mgr->rfc_dml_parameters.HostapdAuthenticator_status;
    } else if ((strcmp(str, RFC_WIFI_EASY_CONNECT) == 0)) {
        *(bool*)value = l_wifi_mgr->rfc_dml_parameters.wifi_EasyConnect_status;
    } else if ((strcmp(str, RFC_WIFI_CLIENT_ACTIVE_MEASUREMENTS) == 0)) {
        *(bool*)value = l_wifi_mgr->rfc_dml_parameters.wifi_ActiveMeasurements_status;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s get wifi rfc parameter not found %s\n", __FUNCTION__, str);
        ret = RETURN_ERR;
    }
    return ret;
}

int set_wifi_rfc_parameters(char *str, void *value)
{
    int ret = RETURN_OK;
    wifi_mgr_t *l_wifi_mgr = get_wifimgr_obj();
    wifi_util_dbg_print(WIFI_CTRL, "%s set wifi rfc parameter %s\n", __FUNCTION__, str);
    if ((strcmp(str, RFC_WIFI_PASSPOINT_STATUS) == 0)) {
        l_wifi_mgr->rfc_dml_parameters.wifi_passpoint_status = *(UINT*)value;
    } else if ((strcmp(str, RFC_WIFI_INTERWORKING_STATUS) == 0)) {
        l_wifi_mgr->rfc_dml_parameters.wifi_interworking_status = *(UINT*)value;
    } else if ((strcmp(str, RFC_WIFI_RADIUS_GREYLIST_STATUS) == 0)) {
        l_wifi_mgr->rfc_dml_parameters.RadiusGreyList_status = *(bool*)value;
    } else if ((strcmp(str, RFC_WIFI_DISABLE_NATIVE_HOSTAPD) == 0)) {
        l_wifi_mgr->rfc_dml_parameters.HostapdAuthenticator_status = *(bool*)value;
    } else if ((strcmp(str, RFC_WIFI_EASY_CONNECT) == 0)) {
        l_wifi_mgr->rfc_dml_parameters.wifi_EasyConnect_status = *(bool*)value;
    } else if ((strcmp(str, RFC_WIFI_CLIENT_ACTIVE_MEASUREMENTS) == 0)) {
        l_wifi_mgr->rfc_dml_parameters.wifi_ActiveMeasurements_status = *(bool*)value;
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s set wifi rfc parameter not found %s\n", __FUNCTION__, str);
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

    index = get_sta_vap_index_for_radio(radio_index);

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
                wifi_util_dbg_print(WIFI_CTRL, "%s Input apIndex = %d  found at radioIndex = %d vapArrayIndex = %d\n ", __FUNCTION__, apIndex, radioIndex, vapArrayIndex);
                return get_wifidb_vap_parameters(apIndex);
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
    if (strncmp((CHAR *)getVAPName(apIndex), "private_ssid", strlen("private_ssid")) == 0) {
        return TRUE;
    }
    return FALSE;
}

BOOL isVapXhs(UINT apIndex)
{
    if (strncmp((CHAR *)getVAPName(apIndex), "iot_ssid", strlen("iot_ssid")) == 0) {
        return TRUE;
    }
    return FALSE;
}

BOOL isVapHotspot(UINT apIndex)
{
    if (strncmp((CHAR *)getVAPName(apIndex), "hotspot", strlen("hotspot")) == 0) {
        return TRUE;
    }
    return FALSE;
}

BOOL isVapLnf(UINT apIndex)
{
    if (strncmp((CHAR *)getVAPName(apIndex), "lnf", strlen("lnf")) == 0) {
        return TRUE;
    }
    return FALSE;
}

BOOL isVapLnfPsk(UINT apIndex)
{
    if (strncmp((CHAR *)getVAPName(apIndex), "lnf_psk", strlen("lnf_psk")) == 0) {
        return TRUE;
    }
    return FALSE;
}

BOOL isVapMesh(UINT apIndex)
{
    if (strncmp((CHAR *)getVAPName(apIndex), "mesh", strlen("mesh")) == 0) {
        return TRUE;
    }
    return FALSE;
}

BOOL isVapHotspotSecure(UINT apIndex)
{
    if (strncmp((CHAR *)getVAPName(apIndex), "hotspot_secure", strlen("hotspot_secure")) == 0) {

        return TRUE;
    }
    return FALSE;
}

BOOL isVapHotspotOpen(UINT apIndex)
{
    if (strncmp((CHAR *)getVAPName(apIndex), "hotspot_open", strlen("hotspot_open")) == 0) {
        return TRUE;
    }
    return FALSE;
}


BOOL isVapLnfSecure(UINT apIndex)
{
    if (strncmp((CHAR *)getVAPName(apIndex), "lnf_radius", strlen("lnf_radius")) == 0) {
        return TRUE;
    }
    return FALSE;
}

BOOL isVapSTAMesh(UINT apIndex)
{
    if (strncmp((CHAR *)getVAPName(apIndex), "mesh_sta", strlen("mesh_sta")) == 0) {
        return TRUE;
    }
    return FALSE;
}

UINT getNumberRadios()
{
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();
    return wifi_hal_cap_obj->wifi_prop.numRadios;
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
                wifi_util_dbg_print(WIFI_CTRL, "%s Input apIndex = %d  found at radioIndex = %d vapArrayIndex = %d\n ", __FUNCTION__, apIndex, radioIndex, vapArrayIndex);
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
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();

    if ((vap_index >= MAX_VAP) || (bridge_name == NULL)) {
        wifi_util_dbg_print(WIFI_DB,"%s:%d: Wrong vap_index:%d \n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    char *l_bridge_name = wifi_hal_cap_obj->wifi_prop.interface_map[vap_index].bridge_name;

    strncpy(bridge_name, l_bridge_name, (strlen(l_bridge_name) + 1));
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
