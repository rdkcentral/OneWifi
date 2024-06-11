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
#if DML_SUPPORT
#include "ansc_platform.h"
#else
#include <sys/types.h>
#endif // DML_SUPPORT
#include "wifi_stubs.h"
#include "wifi_hal.h"
#include "wifi_hal_rdk_framework.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "scheduler.h"
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <rbus.h>
#include "ieee80211.h"
#ifdef CMWIFI_RDKB
#define FILE_SYSTEM_UPTIME         "/var/systemUptime.txt"
#else
#define FILE_SYSTEM_UPTIME         "/tmp/systemUptime.txt"
#endif
#define ONEWIFI_FR_FLAG  "/nvram/wifi/onewifi_factory_reset_flag"

unsigned int get_Uptime(void);
unsigned int startTime[MAX_NUM_RADIOS];
#define BUF_SIZE              256
extern webconfig_error_t webconfig_ctrl_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data);
void get_action_frame_evt_params(uint8_t *frame, uint32_t len, frame_data_t *mgmt_frame, wifi_event_subtype_t *evt_subtype);

static void ctrl_queue_timeout_scheduler_tasks(wifi_ctrl_t *ctrl);
static int pending_states_webconfig_analyzer(void *arg);
#if DML_SUPPORT
static int rbus_check_and_subscribe_events(void* arg);
static int sta_connectivity_selfheal(void* arg);
static int run_greylist_event(void *arg);
static int run_analytics_event(void* arg);
#endif //DML_SUPPORT

static int switch_dfs_channel(void *arg);
int dfs_channel;

void deinit_wifi_ctrl(wifi_ctrl_t *ctrl)
{
    if(ctrl->vif_apply_pending_queue != NULL) {
        queue_destroy(ctrl->vif_apply_pending_queue);
    }

    if(ctrl->queue != NULL) {
        queue_destroy(ctrl->queue);
    }

    if(ctrl->events_rbus_data.events_rbus_queue != NULL) {
        queue_destroy(ctrl->events_rbus_data.events_rbus_queue);
    }

    /*Deinitialize the scheduler*/
    if (ctrl->sched != NULL) {
        scheduler_deinit(&ctrl->sched);
    }

    pthread_mutexattr_destroy(&ctrl->attr);
    pthread_mutex_destroy(&ctrl->lock);
    pthread_cond_destroy(&ctrl->cond);
    pthread_mutex_destroy(&ctrl->events_rbus_data.events_rbus_lock);
}

static int wifi_radio_set_enable(bool status)
{
    wifi_radio_operationParam_t *wifi_radio_oper_param = NULL;
    int ret = RETURN_OK;
    uint8_t index = 0;
    uint8_t num_of_radios = getNumberRadios();
    wifi_radio_operationParam_t temp_wifi_radio_oper_param;

    memset(&temp_wifi_radio_oper_param, 0, sizeof(temp_wifi_radio_oper_param));

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d num_of_radios:%d\n", __func__, __LINE__, num_of_radios);
    for (index = 0; index < num_of_radios; index++) {
        wifi_radio_oper_param = (wifi_radio_operationParam_t *)get_wifidb_radio_map(index);
        if (wifi_radio_oper_param == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d wrong index for radio map: %d\n", __func__, __LINE__, index);
            return RETURN_ERR;
        }

        if (wifi_radio_oper_param->enable == false) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d index: %d skip, wifi radio already disable:%d\n",
                            __func__, __LINE__, index, wifi_radio_oper_param->enable);
            continue;
        }

        memcpy(&temp_wifi_radio_oper_param, wifi_radio_oper_param, sizeof(wifi_radio_operationParam_t));
        temp_wifi_radio_oper_param.enable = status;
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d index: %d radio enable status:%d\n", __func__, __LINE__, index, status);
        ret = wifi_hal_setRadioOperatingParameters(index, &temp_wifi_radio_oper_param);
        if (ret != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d wifi radio parameter set failure: radio_index:%d\n", __func__, __LINE__, index);
        } else {
            wifi_util_info_print(WIFI_CTRL,"%s:%d wifi radio parameter set success: radio_index:%d\n", __func__, __LINE__, index);
        }

    }

    return ret;
}

int get_ap_index_from_clientmac(mac_address_t mac_addr)
{
    unsigned int r_itr = 0, v_itr = 0, vap_index = 0;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    assoc_dev_data_t *assoc_dev_data = NULL;
    wifi_vap_info_map_t *wifi_vap_map = NULL;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    mac_addr_str_t mac_str;

    if ((mgr == NULL) || (ctrl == NULL)) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
        return -1;
    }

    to_mac_str((unsigned char *)mac_addr, mac_str);
    for (r_itr = 0; r_itr < getNumberRadios(); r_itr++) {
        wifi_vap_map = get_wifidb_vap_map(r_itr);
        if (wifi_vap_map == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
            return -1;
        }
        for (v_itr = 0; v_itr < getMaxNumberVAPsPerRadio(r_itr); v_itr++) {
            vap_index = wifi_vap_map->vap_array[v_itr].vap_index;
            rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
            if (rdk_vap_info == NULL) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
                return -1;
            }
            if (rdk_vap_info->associated_devices_map) {
                assoc_dev_data = hash_map_get(rdk_vap_info->associated_devices_map, mac_str);
                if (assoc_dev_data != NULL) {
                    return vap_index;
                }
            }
        }
    }
    return -1;
}

void reset_wifi_radios(void)
{
    wifi_radio_set_enable(false);
    wifi_radio_set_enable(true);
}

unsigned int selfheal_event_publish_time(void)
{
     FILE *fp;
     char buff[64];
     char *ptr;

     if ((fp = fopen("/nvram/selfheal_event_publish_time", "r")) == NULL) {
         return 10; /* default is 10 minutes */
     }

     fgets(buff, 64, fp);
     if ((ptr = strchr(buff, '\n')) != NULL) {
         *ptr = 0;
     }
     fclose(fp);

     return atoi(buff) ? atoi(buff) : 1;
}

int reboot_device(wifi_ctrl_t *ctrl)
{
    int rc = 0;

    rc = rbus_setStr(ctrl->rbus_handle, "Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason", "ECO Mode Reboot");
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusWrite Failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    }

    rc = rbus_setStr(ctrl->rbus_handle, "Device.X_CISCO_COM_DeviceControl.RebootDevice", "Device");
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusWrite Failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

void selfheal_event_publish(wifi_ctrl_t *ctrl)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    vap_svc_t *ext_svc;
    int rc;
    
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return;
    }

    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    if (ext_svc != NULL) {
        rbusValue_Init(&value);
        rbusObject_Init(&rdata, NULL);
        ext_svc->u.ext.selfheal_status = true;

        rbusObject_SetValue(rdata, WIFI_STA_SELFHEAL_CONNECTION_TIMEOUT, value);
        rbusValue_SetBoolean(value, ext_svc->u.ext.selfheal_status);


        event.name = WIFI_STA_SELFHEAL_CONNECTION_TIMEOUT;
        event.data = rdata;
        event.type = RBUS_EVENT_GENERAL;
        
        rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
        if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)){
            wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed\n", __func__, __LINE__);
            ext_svc->u.ext.selfheal_status = false;
            rbusValue_Release(value);
            rbusObject_Release(rdata);
            return;
        }

        rbusValue_Release(value);
        rbusObject_Release(rdata);
    }
    return;
}

void sta_selfheal_handing(wifi_ctrl_t *ctrl, vap_svc_t *l_svc)
{
    static bool radio_reset_triggered      = false;
    static unsigned int disconnected_time  = 0;
    static unsigned int connection_timeout = 0;
    vap_svc_ext_t   *ext;
    ext = &l_svc->u.ext;

    /* Reboot device is STA connection is unsuccessful */
    if ((ext != NULL) && (ext->conn_state != connection_state_connected)) {
        disconnected_time++;
        connection_timeout++;
        wifi_util_info_print(WIFI_CTRL,"%s:%d selfheal STA Connection Timeout  event publish time is set to %d minutes, disconnected_time:%d\n",
                        __func__, __LINE__, selfheal_event_publish_time(), disconnected_time);
        if ((disconnected_time * STA_CONN_RETRY_TIMEOUT) > (selfheal_event_publish_time() * 60)) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d selfheal: STA connection failed for %d minutes, publish selfheal connection timeout\n",
                            __func__, __LINE__, selfheal_event_publish_time());
            /* publish selfheal STA Connection Timeout  device */
            selfheal_event_publish(ctrl);
            disconnected_time = 0;
            connection_timeout = 0;
        } else if (((disconnected_time * STA_CONN_RETRY_TIMEOUT) >= ((selfheal_event_publish_time() * 60) / 2)) && (radio_reset_triggered == false)) {
            reset_wifi_radios();
            radio_reset_triggered = true;
        } else if ((connection_timeout * STA_CONN_RETRY_TIMEOUT) >= MAX_CONNECTION_ALGO_TIMEOUT) {
            l_svc->event_fn(l_svc, wifi_event_type_exec, wifi_event_exec_timeout, vap_svc_event_none, NULL);
            connection_timeout = 0;
        }
    } else {
        radio_reset_triggered = false;
        disconnected_time = 0;
        connection_timeout = 0;
    }
}

bool is_sta_enabled(void)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    //wifi_util_dbg_print(WIFI_CTRL,"[%s:%d] device mode:%d active_gw_check:%d\r\n",
    //    __func__, __LINE__, ctrl->network_mode, ctrl->active_gw_check);
    return ((ctrl->network_mode == rdk_dev_mode_type_ext || ctrl->active_gw_check == true) &&
        ctrl->eth_bh_status == false);
}

void ctrl_queue_loop(wifi_ctrl_t *ctrl)
{
    struct timespec time_to_wait;
    struct timespec tv_now;
    time_t  time_diff;
    int rc = 0;
    wifi_event_t *event = NULL;

    pthread_mutex_lock(&ctrl->lock);
    while (ctrl->exit_ctrl == false) {

        clock_gettime(CLOCK_MONOTONIC, &tv_now);
        time_to_wait.tv_nsec = 0;
        time_to_wait.tv_sec = tv_now.tv_sec + ctrl->poll_period;

        if (ctrl->last_signalled_time.tv_sec > ctrl->last_polled_time.tv_sec) {
            time_diff = ctrl->last_signalled_time.tv_sec - ctrl->last_polled_time.tv_sec;
            if ((UINT)time_diff < ctrl->poll_period) {
                time_to_wait.tv_sec = tv_now.tv_sec + (ctrl->poll_period - time_diff);
            }
        }

        rc = pthread_cond_timedwait(&ctrl->cond, &ctrl->lock, &time_to_wait);

        if ((rc == 0) || (queue_count(ctrl->queue) != 0)) {
            while (queue_count(ctrl->queue)) {
                event = queue_pop(ctrl->queue);
                if (event == NULL) {
                    continue;
                }
                pthread_mutex_unlock(&ctrl->lock);
                switch (event->event_type) {
                    case wifi_event_type_webconfig:
                        handle_webconfig_event(ctrl, event->u.core_data.msg, event->u.core_data.len, event->sub_type);
                        break;

                    case wifi_event_type_hal_ind:
                        handle_hal_indication(ctrl, event->u.core_data.msg, event->u.core_data.len, event->sub_type);
                        break;

                    case wifi_event_type_command:
                        handle_command_event(ctrl, event->u.core_data.msg, event->u.core_data.len, event->sub_type);
                        break;

                    case wifi_event_type_wifiapi:
                        handle_wifiapi_event(event->u.core_data.msg, event->u.core_data.len, event->sub_type);
                        break;

                    case wifi_event_type_monitor:
                        // TODO: event 4 flood
                        // wifi_util_dbg_print(WIFI_CTRL,"[%s]: Received monitor Event %d\r\n",__FUNCTION__, event->event_type);
                        break;

                    default:
                        wifi_util_dbg_print(WIFI_CTRL,"[%s]:WIFI ctrl thread not supported this event %d\r\n",__FUNCTION__, event->event_type);
                        break;
                }

                if (event->event_type != wifi_event_type_webconfig) {
                    // now forward the event to apps manager
                    apps_mgr_event(&ctrl->apps_mgr, event);
                }

                destroy_wifi_event(event);

                clock_gettime(CLOCK_MONOTONIC, &ctrl->last_signalled_time);
                pthread_mutex_lock(&ctrl->lock);
            }
        } else if (rc == ETIMEDOUT) {
            clock_gettime(CLOCK_MONOTONIC, &ctrl->last_polled_time);

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
        } else {
            wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_WARN, WIFI %s: Invalid Return Status %d\n",__FUNCTION__,rc);
            continue;
        }
    }
    pthread_mutex_unlock(&ctrl->lock);

    return;
}

int init_wifi_global_config(void)
{
    static bool wifi_global_param_init = false;
    if (wifi_global_param_init == true) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d wifi global params already initialized\r\n",__func__, __LINE__);
        return RETURN_OK;
    }

    if (RETURN_OK != WiFi_InitGasConfig()) {
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_WARN, RDKB_SYSTEM_BOOT_UP_LOG : CosaWifiInitialize - WiFi failed to Initialize GAS Configuration.\n");
        return RETURN_ERR;
    }

    wifi_global_param_init = true;
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

int start_radios(rdk_dev_mode_type_t mode)
{
    wifi_radio_operationParam_t *wifi_radio_oper_param = NULL;
    int ret = RETURN_OK;
    uint8_t index = 0;
    uint8_t num_of_radios = getNumberRadios();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_CTRL,"%s(): Start radios\n", __FUNCTION__);
    //Check for the number of radios
    if (num_of_radios > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_CTRL,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        return RETURN_ERR;
    }

    for (index = 0; index < num_of_radios; index++) {
        wifi_radio_oper_param = (wifi_radio_operationParam_t *)get_wifidb_radio_map(index);
        if (wifi_radio_oper_param == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:wrong index for radio map: %d\n",__FUNCTION__, index);
            return RETURN_ERR;
        }

        wifi_util_dbg_print(WIFI_CTRL,"%s:index: %d num_of_radios:%d\n",__FUNCTION__, index, num_of_radios);

        if((mode == rdk_dev_mode_type_ext) && (wifi_radio_oper_param->band == WIFI_FREQUENCY_2_4_BAND) && (wifi_radio_oper_param->channel != 1)) {
            wifi_radio_oper_param->channel = 1;
            wifi_util_dbg_print(WIFI_CTRL,"%s: initializing radio_index:%d with channel 1\n",__FUNCTION__, index);
        }

        ctrl->acs_pending[index] = false;
        if (wifi_radio_oper_param->autoChannelEnabled == true) {
            ctrl->acs_pending[index] = true;
        }

        //In case of reboot/FR, Non DFS channel will be selected and radio will switch to DFS Channel after 1 min.
        if( ((wifi_radio_oper_param->band == WIFI_FREQUENCY_5_BAND ) || ( wifi_radio_oper_param->band == WIFI_FREQUENCY_5L_BAND ) || ( wifi_radio_oper_param->band == WIFI_FREQUENCY_5H_BAND)) &&
            (wifi_radio_oper_param->channel >= 52 && wifi_radio_oper_param->channel <= 144)) {
                if( mode == rdk_dev_mode_type_gw ) {
                    dfs_channel = wifi_radio_oper_param->channel;
                    wifi_radio_oper_param->channel = 44;
                    wifi_radio_oper_param->op_class = 1;
                    wifi_util_info_print(WIFI_CTRL,"%s:%d Calling switch_dfs_channel for dfs_chan:%d \n",__func__, __LINE__, dfs_channel);
                    scheduler_add_timer_task(ctrl->sched, TRUE, NULL, switch_dfs_channel, &dfs_channel, (60 * 1000), 1, FALSE);
                } else {
                    wifi_radio_oper_param->channel = 36;
                    wifi_radio_oper_param->op_class = 1;
                }
        }

        wifi_platform_property_t *wifi_prop =  (wifi_platform_property_t *) get_wifi_hal_cap_prop();
        if ((wifi_radio_oper_param->EcoPowerDown == false) && (wifi_prop->radio_presence[index] == false)) {
            wifi_util_error_print(WIFI_CTRL,"%s: !!!!-ALERT-!!!-Radio not present-!!!-Kernel driver interface down-!!!.Index %d\n",__FUNCTION__, index);
        }
        ret = wifi_hal_setRadioOperatingParameters(index, wifi_radio_oper_param);
        if (ret != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s: wifi radio parameter set failure: radio_index:%d\n",__FUNCTION__, index);
            return ret;
        } else {
            wifi_util_info_print(WIFI_CTRL,"%s: wifi radio parameter set success: radio_index:%d\n",__FUNCTION__, index);
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
            wifi_util_error_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__, i);
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

bool is_acs_channel_updated(unsigned int num_radios)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    for (unsigned int i = 0; i < num_radios; i++) {
        if (ctrl->acs_pending[i] == true) {
            return false;
        }
    }
    return true;
}

#if CCSP_COMMON
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
#endif // CCSP_COMMON

void rbus_get_vap_init_parameter(const char *name, unsigned int *ret_val)
{
    rbusValue_t value;
    int len = 0;
    int rc = RBUS_ERROR_SUCCESS;
    unsigned int total_slept = 0;
    //rdk_dev_mode_type_t mode;
    wifi_global_param_t global_param = { 0 };
    wifi_ctrl_t *ctrl;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    get_wifi_global_param(&global_param);
    // set all default return values first
    if (strcmp(name, WIFI_DEVICE_MODE) == 0) {
#ifdef ONEWIFI_DEFAULT_NETWORKING_MODE
        *ret_val = ONEWIFI_DEFAULT_NETWORKING_MODE;
#else 
        *ret_val = (unsigned int)global_param.device_network_mode;
#endif
        ctrl->network_mode = (unsigned int)*ret_val;

#ifdef ONEWIFI_DEFAULT_DEVICE_TYPE
        ctrl->dev_type = ONEWIFI_DEFAULT_DEVICE_TYPE;
#else
        ctrl->dev_type = dev_subtype_rdk;
#endif

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
        const char * pTmp = rbusValue_GetString(value, &len);
        if(pTmp == NULL) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Unable to get  value in event:%s\n", __func__, __LINE__);
            return;
        }
        if(strcmp(pTmp,"Up") == 0) {
            *ret_val = 1;
        }
        else {
            *ret_val = 0;
        }
    }
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d rbus_get for %s: value:%d\n",__func__, __LINE__, name, *ret_val);
}

int rbus_get_active_gw_parameter(const char *name, unsigned int *ret_val)
{
    rbusValue_t value;
    int rc = RBUS_ERROR_SUCCESS;
    wifi_ctrl_t *ctrl;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    rc = rbus_get(ctrl->rbus_handle, name, &value);

    if(rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d rbus_get failed for [%s] with error [%d]\n",__func__, __LINE__, name, rc);
        return RETURN_ERR;
    }

    *ret_val = rbusValue_GetBoolean(value);

    wifi_util_info_print(WIFI_CTRL,"%s:%d rbus_get for %s: value:%d\n",__func__, __LINE__, name, *ret_val);
    return RETURN_OK;
}

void start_extender_vaps(void)
{
    wifi_ctrl_t *ctrl;
    vap_svc_t *ext_svc;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    ext_svc->start_fn(ext_svc, WIFI_ALL_RADIO_INDICES, NULL);
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

    value = false;
    // start public if tunnel is up
    rbus_get_vap_init_parameter(WIFI_DEVICE_TUNNEL_STATUS, &value);
    if (value == true) {
        set_wifi_public_vap_enable_status();
        pub_svc->start_fn(pub_svc, WIFI_ALL_RADIO_INDICES, NULL);
    }

    value = false;
    if (rbus_get_active_gw_parameter(WIFI_ACTIVE_GATEWAY_CHECK, &value) == RETURN_OK) {
        ctrl->active_gw_check = value;
        if (is_sta_enabled() == true) {
            wifi_util_info_print(WIFI_CTRL, "%s:%d start mesh sta\n",__func__, __LINE__);
            start_extender_vaps();
        }
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

int start_wifi_services(void)
{
    wifi_ctrl_t *ctrl = NULL;
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();


    if (ctrl->network_mode == rdk_dev_mode_type_gw) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d start gw vaps\n",__func__, __LINE__);
        start_radios(rdk_dev_mode_type_gw);
        start_gateway_vaps();
        captive_portal_check();
#if !defined(NEWPLATFORM_PORT) && !defined(_SR213_PRODUCT_REQ_)
        /* Function to check for default SSID and Passphrase for Private VAPS
        if they are default and last-reboot reason is SW get the previous config from Webconfig */
        validate_and_sync_private_vap_credentials();
#endif
    } else if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        start_radios(rdk_dev_mode_type_ext);
        if (is_sta_enabled()) {
            wifi_util_info_print(WIFI_CTRL, "%s:%d start mesh sta\n",__func__, __LINE__);
            start_extender_vaps();
        } else {
            wifi_util_info_print(WIFI_CTRL, "%s:%d mesh sta disabled\n",__func__, __LINE__);
        }
    }

    return RETURN_OK;
}

#if DML_SUPPORT
bool get_notify_wifi_from_psm(char *PsmParamName)
{
    int rc = 0;
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    bool psm_notify_flag = false;
    char psm_notify_get[32] = "";
    rbusValue_t value = NULL;
    rbusProperty_t prop = NULL;
    rbusObject_t inParams = NULL,outParams = NULL;

    wifi_util_dbg_print(WIFI_CTRL,"%s PSMParam %s \n",__func__,PsmParamName);

    rbusObject_Init(&inParams, NULL);
    rbusValue_Init(&value);
    // Get PSM value of eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges
    rbusProperty_Init(&prop, PsmParamName, value);
    rbusObject_SetProperty(inParams,prop);
    rbusProperty_Release(prop);

    rc = rbusMethod_Invoke(g_wifi_mgr->ctrl.rbus_handle,"GetPSMRecordValue()" , inParams, &outParams);
    if(inParams) {
        rbusObject_Release(inParams);
    }
    if (RBUS_ERROR_SUCCESS == rc) {
        prop = rbusObject_GetProperties(outParams);
        value = rbusProperty_GetValue(prop);
        strcpy(psm_notify_get,rbusValue_ToString(value,NULL,0));
        wifi_util_dbg_print(WIFI_CTRL," PSMDB value=%s\n",psm_notify_get);
        if (strcmp(psm_notify_get,"true") == 0)
            psm_notify_flag = true;
        else
            psm_notify_flag = false;
    }
    rbusValue_Release(value);
    wifi_util_dbg_print(WIFI_CTRL,"get_notify_wifi_from_psm ends\n");
    return psm_notify_flag;
}

void set_notify_wifi_to_psm(char *PsmParamName,char *pInValue)
{
    rbusProperty_t prop = NULL;
    rbusValue_t value = NULL;
    rbusObject_t inParams = NULL,outParams = NULL;
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    rbusValue_Init(&value);
    rbusObject_Init(&inParams, NULL);
    int rc = 0;
    wifi_util_dbg_print(WIFI_CTRL,"Notify flag and values are different PSMParam %s pInValue %s\n",PsmParamName,pInValue);

    if (false == rbusValue_SetFromString(value, RBUS_STRING, pInValue)) {
        wifi_util_dbg_print(WIFI_CTRL,"%s: Invalid value '%s' for the parameter %s\n\r", __FUNCTION__, pInValue, PsmParamName);
    }
    rbusProperty_Init(&prop, PsmParamName, value);
    rbusObject_SetProperty(inParams,prop);
    rbusValue_Release(value);
    rbusProperty_Release(prop);

    rc = rbusMethod_Invoke(g_wifi_mgr->ctrl.rbus_handle,"SetPSMRecordValue()" , inParams, &outParams);
    if(inParams) {
        rbusObject_Release(inParams);
    }
    if (RBUS_ERROR_SUCCESS != rc) {

        wifi_util_error_print(WIFI_CTRL," %s failed for  with err: '%s'\n\r",__FUNCTION__,rbusError_ToString(rc));
    }
    wifi_util_dbg_print(WIFI_CTRL,"set_notify_wifi_to_psm ends\n");
}

#endif // DML_SUPPORT

int captive_portal_check(void)
{
#ifdef WIFI_CAPTIVE_PORTAL
    uint8_t num_of_radios = getNumberRadios();
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    UINT radio_index =0;
    wifi_vap_info_map_t *wifi_vap_map = NULL;
    UINT i =0;
    int rc = 0;
    bool default_private_credentials = false,get_config_wifi = false;
    char default_ssid[128] = {0}, default_password[128] = {0};
    rbusValue_t value = NULL, config_wifi_value = NULL;

#if DML_SUPPORT
    bool psm_notify_flag=false;
    char pInValue[32] = "";
    char *PsmParamName = "eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges";
#endif //// DML_SUPPORT

    rbusValue_Init(&value);
    rbusValue_Init(&config_wifi_value);

    //Get CONFIG_WIFI
    rc = rbus_get(g_wifi_mgr->ctrl.rbus_handle, CONFIG_WIFI, &value);

    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d rbus_get failed for [] with error [%d]\n",__func__, __LINE__, rc);
        if (value != NULL) {
            rbusValue_Release(value);
        }
        return RETURN_ERR;
    }

    get_config_wifi = rbusValue_GetBoolean(value);

    wifi_util_info_print(WIFI_CTRL,"CONFIG_WIFI=%d is_factory_reset_done=%d fun %s \n",get_config_wifi,access(ONEWIFI_FR_FLAG,F_OK),__func__);

    //From previous release and captive portal is already customized then need not customize here
    if ((access(ONEWIFI_FR_FLAG,F_OK) != 0) && get_config_wifi == false) {
        wifi_util_info_print(WIFI_CTRL,"FactoryReset is not done and captive portal customization already done fun %s return\n",__func__);
        rbusValue_Release(value);
        return RETURN_OK;
    }
    get_ssid_from_device_mac(default_ssid);

    for (radio_index = 0; radio_index < num_of_radios && !default_private_credentials; radio_index++) {

        wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(radio_index);
        for ( i = 0; i < wifi_vap_map->num_vaps; i++) {

            if (strncmp(wifi_vap_map->vap_array[i].vap_name,"private_ssid",strlen("private_ssid"))== 0) {

                wifi_hal_get_default_keypassphrase(default_password, wifi_vap_map->vap_array[i].vap_index);

                if ((strcmp(wifi_vap_map->vap_array[i].u.bss_info.ssid,default_ssid) == 0) || \
                      ((strcmp(wifi_vap_map->vap_array[i].u.bss_info.security.u.key.key,default_password) == 0))) {

                    wifi_util_dbg_print(WIFI_CTRL,"private vaps have default credentials\n");
                    default_private_credentials = true;
                    break;
                }
            }
        }
    }
    wifi_util_dbg_print(WIFI_CTRL,"Private vaps credentials= %d\n",default_private_credentials);
 
#if DML_SUPPORT
    // Get PSM value of eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges
    psm_notify_flag = get_notify_wifi_from_psm(PsmParamName);

    if (default_private_credentials != psm_notify_flag) {
        wifi_util_dbg_print(WIFI_CTRL,"PSM Notify flag and wifi values are different\n");
        if (default_private_credentials) {
            strcpy(pInValue,"true");
        }
        else {
            strcpy(pInValue,"false");
        }
        // set PSM value of eRT.com.cisco.spvtg.ccsp.Device.WiFi.NotifyWiFiChanges
        set_notify_wifi_to_psm(PsmParamName,pInValue);
    }
#endif // DML_SUPPORT

    wifi_util_dbg_print(WIFI_CTRL,"CONFIG_WIFI= %d fun %s  and wifi_value %d \n",get_config_wifi,__func__,default_private_credentials);

    if (default_private_credentials != get_config_wifi) {
        wifi_util_dbg_print(WIFI_CTRL,"set CONFIG_WIFI value to %d\n",default_private_credentials);
        if (default_private_credentials) {
            rbusValue_SetBoolean(config_wifi_value, true);
        }
        else {
            rbusValue_SetBoolean(config_wifi_value, false);
        }
 
        rc = rbus_set(g_wifi_mgr->ctrl.rbus_handle,CONFIG_WIFI,config_wifi_value,NULL);

        if (rc != RBUS_ERROR_SUCCESS) {
            wifi_util_error_print(WIFI_CTRL,"Rbus error Device.DeviceInfo.X_RDKCENTRAL-COM_ConfigureWiFi\n");
        }

    }
    rbusValue_Release(value);
    rbusValue_Release(config_wifi_value);
    wifi_util_info_print(WIFI_CTRL," Captive_portal Ends after NotifyWifiChanges\n");
#else //WIFI_CAPTIVE_PORTAL
    // Some devices use captive portal only for SelfHelp, and the UI need not be redirected to captive portal.
    int rc =0;
    rbusValue_t config_wifi_value = NULL;

    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();

    rbusValue_Init(&config_wifi_value);
    rbusValue_SetBoolean(config_wifi_value, false);

    rc = rbus_set(g_wifi_mgr->ctrl.rbus_handle,CONFIG_WIFI,config_wifi_value,NULL);

    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL,"Rbus error Device.DeviceInfo.X_RDKCENTRAL-COM_ConfigureWiFi\n");
    }

#endif //WIFI_CAPTIVE_PORTAL
    return RETURN_OK;

}

int start_wifi_health_monitor_thread(void)
{
    static BOOL monitor_running = false;

    if (monitor_running == true) {
        wifi_util_error_print(WIFI_CTRL, "-- %s %d start_wifi_health_monitor_thread already running\n", __func__, __LINE__);
        return RETURN_OK;
    }

    if ((start_wifi_monitor() < RETURN_OK)) {
        wifi_util_error_print(WIFI_CTRL, "-- %s %d start_wifi_health_monitor_thread fail\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    monitor_running = true;

    return RETURN_OK;
}

int scan_results_callback(int radio_index, wifi_bss_info_t **bss, unsigned int *num)
{
    scan_results_t  res;
    memset(&res, 0, sizeof(scan_results_t));

    res.radio_index = radio_index;

    if (*num) {
        // if number of scanned AP's is more than size of res.bss array - truncate
        if (*num > MAX_SCANNED_VAPS){
            *num = MAX_SCANNED_VAPS;
        }
        res.num = *num;
        memcpy((unsigned char *)res.bss, (unsigned char *)(*bss), (*num)*sizeof(wifi_bss_info_t));
    }

    push_event_to_ctrl_queue(&res, sizeof(scan_results_t), wifi_event_type_hal_ind, wifi_event_scan_results, NULL);
    free(*bss);

    return 0;
}

void sta_connection_handler(const char *vif_name, wifi_bss_info_t *bss_info, wifi_station_stats_t *sta)
{
    rdk_sta_data_t sta_data = {0};
    if (!vif_name) {
        wifi_util_dbg_print(WIFI_CTRL,"%s: vif_name is Invalid\n",__FUNCTION__);
        return;
    }

    memcpy(&sta_data.stats, sta, sizeof(wifi_station_stats_t));
    memcpy(&sta_data.bss_info, bss_info, sizeof(wifi_bss_info_t));
    strncpy(sta_data.interface_name, vif_name, sizeof(wifi_interface_name_t));

    push_event_to_ctrl_queue((rdk_sta_data_t *)&sta_data, sizeof(rdk_sta_data_t), wifi_event_type_hal_ind, wifi_event_hal_sta_conn_status, NULL);
    wifi_util_dbg_print(WIFI_CTRL,"%s: STA data is pushed to the ctrl queue: sta_data.interface_name=%s\n",__FUNCTION__, sta_data.interface_name);
}

int sta_connection_status(int apIndex, wifi_bss_info_t *bss_dev, wifi_station_stats_t *sta)
{
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    wifi_interface_name_t *vif_name = get_interface_name_for_vap_index(apIndex, &g_wifi_mgr->hal_cap.wifi_prop);

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d: backhaul connection status changed\n", __func__, __LINE__);
    sta_connection_handler((char *)vif_name, bss_dev, sta);
    return RETURN_OK;
}

#ifdef WIFI_HAL_VERSION_3_PHASE2
int mgmt_wifi_frame_recv(int ap_index, wifi_frame_t *frame)
{
    frame_data_t wifi_mgmt_frame;

    memset(&wifi_mgmt_frame, 0, sizeof(wifi_mgmt_frame));

    memcpy(wifi_mgmt_frame.data, frame->data, frame->len);
    memcpy(&mgmt_frame.frame, frame, sizeof(wifi_frame_t));

    //In side this API we have allocate memory and send it to control queue
    push_event_to_ctrl_queue((frame_data_t *)&wifi_mgmt_frame, (sizeof(wifi_mgmt_frame) + len), wifi_event_type_hal_ind, wifi_event_hal_mgmt_frames, NULL);

    return RETURN_OK;
}
#else
#if defined (_XB7_PRODUCT_REQ_) || defined (_CBR_PRODUCT_REQ_)
int mgmt_wifi_frame_recv(int ap_index, mac_address_t sta_mac, uint8_t *frame, uint32_t len, wifi_mgmtFrameType_t type, wifi_direction_t dir, int sig_dbm , int phy_rate)
#else
int mgmt_wifi_frame_recv(int ap_index, mac_address_t sta_mac, uint8_t *frame, uint32_t len, wifi_mgmtFrameType_t type, wifi_direction_t dir)
#endif
{
    wifi_actionFrameHdr_t *paction = NULL;
    frame_data_t mgmt_frame;
    wifi_event_subtype_t evt_subtype = wifi_event_hal_unknown_frame;

    if (len == 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d Recived zero length frame\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (len > MAX_FRAME_SZ) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d Recived frame len: %d, more than allowed allocation\n", __func__, __LINE__, len);
        return RETURN_ERR;
    }

    memset(&mgmt_frame, 0, sizeof(mgmt_frame));
    mgmt_frame.frame.ap_index = ap_index;
    memcpy(mgmt_frame.frame.sta_mac, sta_mac, sizeof(mac_address_t));
    mgmt_frame.frame.type = type;
    mgmt_frame.frame.dir = dir;
#if defined (_XB7_PRODUCT_REQ_) || defined (_CBR_PRODUCT_REQ_)
    mgmt_frame.frame.sig_dbm = sig_dbm;
    mgmt_frame.frame.phy_rate = phy_rate;
#endif

    if (type == WIFI_MGMT_FRAME_TYPE_PROBE_REQ) {
        memcpy(mgmt_frame.data, frame, len);
        mgmt_frame.frame.len = len;
        evt_subtype = wifi_event_hal_probe_req_frame;
    } else if (type == WIFI_MGMT_FRAME_TYPE_AUTH) {
        memcpy(mgmt_frame.data, frame, len);
        mgmt_frame.frame.len = len;
        evt_subtype = wifi_event_hal_auth_frame;
    } else if (type == WIFI_MGMT_FRAME_TYPE_ASSOC_REQ) {
        memcpy(mgmt_frame.data, frame, len);
        mgmt_frame.frame.len = len;
        evt_subtype = wifi_event_hal_assoc_req_frame;
    } else if (type == WIFI_MGMT_FRAME_TYPE_ASSOC_RSP) {
        memcpy(mgmt_frame.data, frame, len);
        mgmt_frame.frame.len = len;
        evt_subtype = wifi_event_hal_assoc_rsp_frame;
    } else if (type == WIFI_MGMT_FRAME_TYPE_REASSOC_REQ) {
        memcpy(mgmt_frame.data, frame, len);
        mgmt_frame.frame.len = len;
        evt_subtype = wifi_event_hal_reassoc_req_frame;
    } else if (type == WIFI_MGMT_FRAME_TYPE_REASSOC_RSP) {
        memcpy(mgmt_frame.data, frame, len);
        mgmt_frame.frame.len = len;
        evt_subtype = wifi_event_hal_reassoc_rsp_frame;
    } else if (type == WIFI_MGMT_FRAME_TYPE_ACTION) {
        paction = (wifi_actionFrameHdr_t *)(frame + sizeof(struct ieee80211_frame));
        switch (paction->cat) {
            case wifi_action_frame_type_public:
                get_action_frame_evt_params(frame, len, &mgmt_frame, &evt_subtype);
                break;
            default:
                break;
        }
    }

    push_event_to_ctrl_queue((frame_data_t *)&mgmt_frame, sizeof(mgmt_frame), wifi_event_type_hal_ind, evt_subtype, NULL);
    return RETURN_OK;
}
#endif


void get_gas_init_frame_evt_params(uint8_t *frame, uint32_t len, frame_data_t *mgmt_frame, wifi_event_subtype_t *evt_subtype)
{
    unsigned short query_len, *pquery_len;
    unsigned char *query_req;
    wifi_advertisementProtoElement_t *adv_proto_elem;
    wifi_advertisementProtoTuple_t *adv_tuple;
    const char dpp_oui[3] = {0x50, 0x6f, 0x9a};
    wifi_gasInitialRequestFrame_t *pgas_req = (wifi_gasInitialRequestFrame_t *)frame;

    adv_proto_elem = &pgas_req->proto_elem;
    adv_tuple = &adv_proto_elem->proto_tuple;

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d: advertisement proto element id:%d length:%d\n", __func__, __LINE__, adv_proto_elem->id, adv_proto_elem->len);

    pquery_len = (unsigned short*)((unsigned char *)&adv_proto_elem->proto_tuple + adv_proto_elem->len);
    query_len = *pquery_len;
    query_req = (unsigned char *)((unsigned char *)pquery_len + sizeof(unsigned short));

    switch (adv_tuple->adv_proto_id) {

        case wifi_adv_proto_id_vendor_specific:
            if ((adv_tuple->len == sizeof(dpp_oui) + 2) && (memcmp(adv_tuple->oui, dpp_oui, sizeof(dpp_oui)) == 0) &&
                    (*(adv_tuple->oui + sizeof(dpp_oui)) == DPP_OUI_TYPE) && (*(adv_tuple->oui + sizeof(dpp_oui) + 1) == DPP_CONFPROTO)) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d dpp gas initial req frame received callback, length:%d\n", __func__, __LINE__, query_len);
                *evt_subtype = wifi_event_hal_dpp_config_req_frame;
                memcpy(mgmt_frame->data, query_req, query_len);
                mgmt_frame->frame.len = query_len;
                mgmt_frame->frame.token = pgas_req->token;

            }
            break;

        case wifi_adv_proto_id_anqp:
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d anqp gas initial req frame received call back, length:%d\n", __func__, __LINE__, query_len);
            *evt_subtype = wifi_event_hal_anqp_gas_init_frame;
            memcpy(mgmt_frame->data, query_req, query_len);
            mgmt_frame->frame.len = query_len;
            mgmt_frame->frame.token = pgas_req->token;
            break;

        default:
            break;
    }
}

void get_action_frame_evt_params(uint8_t *frame, uint32_t len, frame_data_t *mgmt_frame, wifi_event_subtype_t *evt_subtype)
{
    unsigned char *public_action_data;
    wifi_publicActionFrameHdr_t *ppublic_hdr = (wifi_publicActionFrameHdr_t *)(frame + sizeof(struct ieee80211_frame)); // frame_control + duration + da + sa + bssid + seq

    len -= sizeof(struct ieee80211_frame);

    public_action_data = (unsigned char *)ppublic_hdr + sizeof(wifi_publicActionFrameHdr_t);
    len -= sizeof(wifi_publicActionFrameHdr_t);

    switch (ppublic_hdr->action) {

        case wifi_public_action_type_vendor:
            break;

        case wifi_public_action_type_gas_init_req:
            get_gas_init_frame_evt_params(public_action_data, len, mgmt_frame, evt_subtype);
            break;

        case wifi_public_action_type_gas_comeback_req:
            break;

        default:
            break;
    }

}

void channel_change_callback(wifi_channel_change_event_t radio_channel_param)
{
    wifi_channel_change_event_t channel_change;
    memset(&channel_change, 0, sizeof(channel_change));

    memcpy(&channel_change, &radio_channel_param, sizeof(wifi_channel_change_event_t));

    push_event_to_ctrl_queue((wifi_channel_change_event_t *)&channel_change, sizeof(wifi_channel_change_event_t), wifi_event_type_hal_ind, wifi_event_hal_channel_change, NULL);
    return;
}

int init_wifi_ctrl(wifi_ctrl_t *ctrl)
{
    unsigned int i;
    pthread_condattr_t cond_attr;

    ctrl->db_consolidated = (0 == access("/tmp/db_consolidated", F_OK));

    //Initialize Webconfig Framework
    ctrl->webconfig.initializer = webconfig_initializer_onewifi;
    ctrl->webconfig.apply_data = (webconfig_apply_data_t) webconfig_ctrl_apply;

    if (webconfig_init(&ctrl->webconfig) != webconfig_error_none) {
        wifi_util_error_print(WIFI_MGR, "[%s]:%d Init WiFi Web Config  fail\n",__FUNCTION__,__LINE__);
        // unregister and deinit everything
        return RETURN_ERR;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &ctrl->last_signalled_time);
    clock_gettime(CLOCK_MONOTONIC, &ctrl->last_polled_time);
    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&ctrl->cond, &cond_attr);
    pthread_condattr_destroy(&cond_attr);
    pthread_mutexattr_init(&ctrl->attr);
    pthread_mutexattr_settype(&ctrl->attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&ctrl->lock, &ctrl->attr);
    pthread_mutex_init(&ctrl->events_rbus_data.events_rbus_lock, NULL);

    ctrl->poll_period = QUEUE_WIFI_CTRL_TASK_TIMEOUT;

    /*Intialize the scheduler*/
    ctrl->sched = scheduler_init();
    if (ctrl->sched == NULL) {
        deinit_wifi_ctrl(ctrl);
        wifi_util_error_print(WIFI_CTRL, "RDK_LOG_WARN, WIFI %s: control monitor scheduler init failed\n", __FUNCTION__);
        return RETURN_ERR;
    }

    ctrl->queue = queue_create();
    if (ctrl->queue == NULL) {
        deinit_wifi_ctrl(ctrl);
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_WARN, WIFI %s: control monitor queue create failed\n",__FUNCTION__);
        return RETURN_ERR;
    }

    ctrl->vif_apply_pending_queue = queue_create();
    if (ctrl->vif_apply_pending_queue == NULL) {
        deinit_wifi_ctrl(ctrl);
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_WARN, WIFI %s: vif apply pending queue create failed\n",__FUNCTION__);
        return RETURN_ERR;
    }

    ctrl->events_rbus_data.events_rbus_queue = queue_create();
    if (ctrl->events_rbus_data.events_rbus_queue == NULL) {
        deinit_wifi_ctrl(ctrl);
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_WARN, WIFI %s: rbus data events queue create failed\n",__FUNCTION__);
        return RETURN_ERR;
    }

    // initialize the vap service objects
    for (i = 0; i < vap_svc_type_max; i++) {
        svc_init(&ctrl->ctrl_svc[i], (vap_svc_type_t)i);
    }

    //Register to RBUS for webconfig interactions
    rbus_register_handlers(ctrl);

#if DML_SUPPORT
    // subscribe for RBUS events
    rbus_subscribe_events(ctrl);
#endif

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

    register_with_webconfig_framework();

    return RETURN_OK;
}

#if HAL_IPC
int onewifi_get_ap_assoc_dev_diag_res3(int ap_index, 
                                       wifi_associated_dev3_t *assoc_dev_array, 
						               unsigned int *output_array_size)
{
    return get_sta_stats_for_vap(ap_index, assoc_dev_array, output_array_size);
}

int onewifi_get_neighbor_ap2(int radio_index, 
                             wifi_neighbor_ap2_t *neighbor_results,
                             unsigned int *output_array_size)
{
    get_neighbor_scan_cfg(radio_index, neighbor_results, output_array_size);

    return 0;
}

int onewifi_get_radio_channel_stats(int radio_index, 
                                    wifi_channelStats_t *channel_stats_array, 
                                    int *array_size)
{
    return get_radio_channel_stats(radio_index, channel_stats_array, array_size);
}

int onewifi_get_radio_traffic_stats(int radio_index, 
                                    wifi_radioTrafficStats2_t *radio_traffic_stats)
{
    get_radio_data(radio_index, radio_traffic_stats);

    return 0;
}

typedef int (* app_get_ap_assoc_dev_diag_res3_t)(int ap_index, 
                                                 wifi_associated_dev3_t *assoc_dev_array, 
                                                 unsigned int *output_array_size);

typedef int (* app_get_neighbor_ap2_t) (int radio_index, 
                                        wifi_neighbor_ap2_t *neighbor_results,
                                        unsigned int *output_array_size);

typedef int (* app_get_radio_channel_stats_t) (int radio_index, 
                                               wifi_channelStats_t *channel_stats_array, 
                                               int *array_size);

typedef int (* app_get_radio_traffic_stats_t) (int radio_index, 
                                               wifi_radioTrafficStats2_t *radio_traffic_stats);

typedef struct {
    unsigned int version;
    app_get_ap_assoc_dev_diag_res3_t app_get_ap_assoc_dev_diag_res3_fn;		
    app_get_neighbor_ap2_t           app_get_neighbor_ap2_fn;
    app_get_radio_channel_stats_t    app_get_radio_channel_stats_fn;
    app_get_radio_traffic_stats_t    app_get_radio_traffic_stats_fn;
} wifi_app_info_t;

typedef struct{
    wifi_vap_info_map_t *vap_map;
    wifi_app_info_t *app_info;
} wifi_hal_post_init_t;

int wifi_hal_platform_post_init()
{
    int ret = RETURN_OK;
    unsigned int num_of_radios = getNumberRadios();
    unsigned int index = 0;
    wifi_vap_info_map_t vap_map[MAX_NUM_RADIOS];
    wifi_vap_info_map_t *p_vap_map = NULL;
    wifi_hal_post_init_t post_init_struct;

    memset(vap_map, 0, sizeof(vap_map));

    for (index = 0; index < num_of_radios; index++) {
        p_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(index);
        if (p_vap_map != NULL) {
            memcpy(&vap_map[index], p_vap_map, sizeof(wifi_vap_info_map_t));
        } else {
            wifi_util_error_print(WIFI_CTRL,"%s:%d vap_map NULL for radio_index:%d\r\n",__func__, __LINE__, index);
        }
    }

    wifi_util_info_print(WIFI_CTRL,"%s: start wifi apps\n",__FUNCTION__);

    post_init_struct.vap_map = vap_map;
    post_init_struct.app_info = (wifi_app_info_t*) malloc(sizeof(wifi_app_info_t));

    if (!post_init_struct.app_info){
        wifi_util_error_print(WIFI_CTRL,"%s failed to allocate memory for wifi_app_info_t\n",__FUNCTION__);
    }
    post_init_struct.app_info->app_get_ap_assoc_dev_diag_res3_fn = onewifi_get_ap_assoc_dev_diag_res3;
    post_init_struct.app_info->app_get_neighbor_ap2_fn = onewifi_get_neighbor_ap2;
    post_init_struct.app_info->app_get_radio_channel_stats_fn = onewifi_get_radio_channel_stats;
    post_init_struct.app_info->app_get_radio_traffic_stats_fn = onewifi_get_radio_traffic_stats;

    ret = wifi_hal_post_init(&post_init_struct);
  
    free(post_init_struct.app_info);
    
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL,"%s start wifi apps failed, ret:%d\n",__FUNCTION__, ret);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
#else
int wifi_hal_platform_post_init()
{
    int ret = RETURN_OK;
    unsigned int num_of_radios = getNumberRadios();
    unsigned int index = 0;
    wifi_vap_info_map_t vap_map[MAX_NUM_RADIOS];
    wifi_vap_info_map_t *p_vap_map = NULL;

    memset(vap_map, 0, sizeof(vap_map));

    for (index = 0; index < num_of_radios; index++) {
        p_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(index);
        if (p_vap_map != NULL) {
            memcpy(&vap_map[index], p_vap_map, sizeof(wifi_vap_info_map_t));
        } else {
            wifi_util_error_print(WIFI_CTRL,"%s:%d vap_map NULL for radio_index:%d\r\n",__func__, __LINE__, index);
        }
    }

    wifi_util_info_print(WIFI_CTRL,"%s: start wifi apps\n",__FUNCTION__);

    ret = wifi_hal_post_init(vap_map);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL,"%s start wifi apps failed, ret:%d\n",__FUNCTION__, ret);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
#endif // HAL_IPC

void telemetry_bootup_time_wifibroadcast()
{
    wifi_vap_info_t *vapInfo = NULL;
    BOOL advertise_enabled = FALSE;
    UINT apIndex = 0;
    int num_radios = getNumberRadios();
    for (int i = 0; i < num_radios; i++) {
        apIndex = getPrivateApFromRadioIndex(i);
        wifi_util_dbg_print(WIFI_CTRL, "bootup_time_wifibroadcast - apIndex %d\n",apIndex);
        vapInfo =  get_wifidb_vap_parameters(apIndex);
        if(vapInfo != NULL) {
            if ( vapInfo->u.bss_info.showSsid == TRUE) {
                advertise_enabled = TRUE;
            }
        }
        if(advertise_enabled) {
            advertise_enabled = FALSE;
            unsigned int uptime;
            uptime = get_Uptime();
            wifi_util_info_print(WIFI_CTRL, "Wifi_Broadcast_complete:%d\n",uptime);
            get_stubs_descriptor()->t2_event_d_fn("bootuptime_WifiBroadcasted_split", uptime);
            wifi_util_info_print(WIFI_CTRL,"Wifi_Name_Broadcasted:%s\n",vapInfo->u.bss_info.ssid);
        }
    }
}

void check_log_upload_cron_job()
{
    if (access("/nvram/wifi_log_upload",F_OK) == 0) {
        wifi_util_dbg_print(WIFI_CTRL,"Device.WiFi.Log_Uploadd cronjob was added\n");
        get_stubs_descriptor()->v_secure_system_fn("/usr/ccsp/wifi/wifi_logupload.sh start");
    }
}

int init_wireless_interface_mac()
{
    unsigned int itr=0;
    unsigned int j = 0;
    unsigned int k = 0;
    int ret = RETURN_OK;
    wifi_vap_info_map_t  hal_vap_info_map;
    wifi_vap_info_t *wifi_vap_info = NULL;
    wifi_vap_info_map_t *mgr_vap_info_map = NULL;

    for (itr=0; itr < getNumberRadios(); itr++) {
        memset(&hal_vap_info_map, 0, sizeof(hal_vap_info_map));

        //wifi_hal_getRadioVapInfoMap is used  to get the macaddress of wireless interfaces
        ret = wifi_hal_getRadioVapInfoMap(itr, &hal_vap_info_map);
        if (ret != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"RDK_LOG_ERROR, %s wifi_hal_getRadioVapInfoMap returned with error %d for radio : %d\n",
                    __FUNCTION__, ret, itr);
            return RETURN_ERR;
        }

        //get the mgr map_info_map
        mgr_vap_info_map = get_wifidb_vap_map(itr);
        if (mgr_vap_info_map == NULL) {
            wifi_util_error_print(WIFI_CTRL,"RDK_LOG_ERROR, %s get_wifidb_vap_map returned with error %d for radio : %d\n",
                    __FUNCTION__, ret, itr);
            return RETURN_ERR;
        }

        for (j = 0; j < hal_vap_info_map.num_vaps; j++) {
            for (k = 0; k < mgr_vap_info_map->num_vaps; k++) {

                //compare the vap_names from hal_vap_info_map and mgr_vap_info_map to get the wifi_vap_info structure
                if (strncmp(hal_vap_info_map.vap_array[j].vap_name, mgr_vap_info_map->vap_array[k].vap_name, strlen(hal_vap_info_map.vap_array[j].vap_name)) == 0) {
                    wifi_vap_info = &mgr_vap_info_map->vap_array[k];
                    break;
                }
            }

            //For backhaul interfaces, update the sta_info.mac
            if (strncmp((char *)hal_vap_info_map.vap_array[j].vap_name, "mesh_sta", strlen("mesh_sta")) == 0) {
                memcpy(wifi_vap_info->u.sta_info.mac, hal_vap_info_map.vap_array[j].u.sta_info.mac, sizeof(wifi_vap_info->u.sta_info.mac));
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d: vapindex %d vap_name : %s Mac address : %02X:%02X:%02X:%02X:%02X:%02X\n",__func__, __LINE__,
                        wifi_vap_info->vap_index,
                        wifi_vap_info->vap_name,
                        wifi_vap_info->u.sta_info.mac[0],
                        wifi_vap_info->u.sta_info.mac[1],
                        wifi_vap_info->u.sta_info.mac[2],
                        wifi_vap_info->u.sta_info.mac[3],
                        wifi_vap_info->u.sta_info.mac[4],
                        wifi_vap_info->u.sta_info.mac[5]
                        );
            } else {
                //For fronthaul interfaces, update the bss_info.bssid
                memcpy(wifi_vap_info->u.bss_info.bssid, hal_vap_info_map.vap_array[j].u.bss_info.bssid, sizeof(wifi_vap_info->u.bss_info.bssid));
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d: vapindex %d vap_name : %s Mac address : %02X:%02X:%02X:%02X:%02X:%02X\n",__func__, __LINE__,
                        wifi_vap_info->vap_index,
                        wifi_vap_info->vap_name,
                        wifi_vap_info->u.bss_info.bssid[0],
                        wifi_vap_info->u.bss_info.bssid[1],
                        wifi_vap_info->u.bss_info.bssid[2],
                        wifi_vap_info->u.bss_info.bssid[3],
                        wifi_vap_info->u.bss_info.bssid[4],
                        wifi_vap_info->u.bss_info.bssid[5]
                        );
            }
        }
    }
    return RETURN_OK;
}
int validate_and_sync_private_vap_credentials()
{
    char last_reboot_reason[32];
    uint8_t num_of_radios = getNumberRadios();
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    UINT radio_index =0;
    wifi_vap_info_map_t *wifi_vap_map = NULL;
    UINT i =0;
    int rc = 0, len =0;
    const char * pTmp = NULL;
    bool default_private_credentials = false;
    char default_ssid[128] = {0}, default_password[128] = {0};
    rbusValue_t value;

    memset(last_reboot_reason, 0, sizeof(last_reboot_reason));

    rbusValue_Init(&value);
    rc = rbus_get(g_wifi_mgr->ctrl.rbus_handle, LAST_REBOOT_REASON_NAMESPACE, &value);

    if(rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_MGR,"[%s:%d] Rbus error param: %s\r\n", __func__, __LINE__, LAST_REBOOT_REASON_NAMESPACE);
        rbusValue_Release(value);
        return RETURN_ERR;
    }

    pTmp = rbusValue_GetString(value, &len);
    wifi_util_info_print(WIFI_CTRL,"Last reboot reason is %s\n",pTmp);
    if (strcmp(pTmp,"factory-reset") && strcmp(pTmp,"WPS-Factory-Reset")) {

        get_ssid_from_device_mac(default_ssid);

        for (radio_index = 0; radio_index < num_of_radios && !default_private_credentials; radio_index++) {

            wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(radio_index);
            for ( i = 0; i < wifi_vap_map->num_vaps; i++) {

                if (strncmp(wifi_vap_map->vap_array[i].vap_name,"private_ssid",strlen("private_ssid"))== 0) {

                    wifi_hal_get_default_keypassphrase(default_password, wifi_vap_map->vap_array[i].vap_index);

                    if ((strcmp(wifi_vap_map->vap_array[i].u.bss_info.ssid,default_ssid) == 0) || \
                        ((strcmp(wifi_vap_map->vap_array[i].u.bss_info.security.u.key.key,default_password) == 0))) {

                       wifi_util_error_print(WIFI_CTRL,"private vaps have default credentials\n");
                       default_private_credentials = true;
                       break;
                    }
                }
            }
        }
        wifi_util_info_print(WIFI_CTRL,"Private vaps credentials= %d and reboot reason =%s\n",default_private_credentials,pTmp);
        if (default_private_credentials) {
            rc = rbus_setStr(g_wifi_mgr->ctrl.rbus_handle,SUBDOC_FORCE_RESET,PRIVATE_SUB_DOC);
            if(rc != RBUS_ERROR_SUCCESS) {
                wifi_util_error_print(WIFI_MGR,"[%s:%d] Rbus error in setting: %s\n", __func__, __LINE__, SUBDOC_FORCE_RESET);
                get_stubs_descriptor()->v_secure_system_fn("touch /tmp/sw_upgrade_private_defaults");
                rbusValue_Release(value);
                return RETURN_ERR;
            }
            wifi_util_info_print(WIFI_CTRL,"Force Reset called on %s because privatevap vap credentials are default \n",PRIVATE_SUB_DOC);

        }

    }
    rbusValue_Release(value);
    return RETURN_OK;
}

int start_wifi_ctrl(wifi_ctrl_t *ctrl)
{
    int monitor_ret = 0;

    monitor_ret = init_wifi_monitor();

    start_wifi_services();

    init_wireless_interface_mac();


#if CCSP_COMMON
    ctrl->webconfig_state = ctrl_webconfig_state_vap_all_cfg_rsp_pending;
    telemetry_bootup_time_wifibroadcast(); //Telemetry Marker for btime_wifibcast_split

    /* Check for whether Log_Upload was enabled or not
       If Enabled add cron job to do log upload */
    check_log_upload_cron_job();

    /* start wifi apps */
    wifi_hal_platform_post_init();
#else
  ctrl->webconfig_state = ctrl_webconfig_state_none;
#endif

    if (monitor_ret == 0) {
        //Start Wifi Monitor Thread
        start_wifi_health_monitor_thread();
    } else {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Failed to start Wifi Monitor\n", __func__, __LINE__);
    }

    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_start, NULL);
 
#ifdef ONEWIFI_CAC_APP_SUPPORT
    apps_mgr_cac_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_start, NULL, 0);
#endif

    ctrl_queue_timeout_scheduler_tasks(ctrl);

    ctrl->exit_ctrl = false;
    ctrl->ctrl_initialized = true;
    ctrl_queue_loop(ctrl);

#if CCSP_COMMON
    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_stop, NULL);
#ifdef ONEWIFI_CAC_APP_SUPPORT
    apps_mgr_cac_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_stop, NULL, 0);
#endif
#endif // CCSP_COMMON
    wifi_util_info_print(WIFI_CTRL,"%s:%d Exited queue_wifi_ctrl_task.\n",__FUNCTION__,__LINE__);
    return RETURN_OK;
}

bool check_wifi_csa_sched_timeout_active_status(wifi_ctrl_t *l_ctrl)
{
    unsigned int index = 0;
    wifi_scheduler_id_t  *sched_id = &l_ctrl->wifi_sched_id;

    for (index = 0; index < getNumberRadios(); index++) {
        if (sched_id->wifi_csa_sched_handler_id[index] != 0) {
            return true;
        }
    }

    return false;
}

bool check_wifi_radio_sched_timeout_active_status(wifi_ctrl_t *l_ctrl)
{
    unsigned int index = 0;
    wifi_scheduler_id_t  *sched_id = &l_ctrl->wifi_sched_id;

    for (index = 0; index < getNumberRadios(); index++) {
        if (sched_id->wifi_radio_sched_handler_id[index] != 0) {
            return true;
        }
    }

    return false;
}

bool check_wifi_vap_sched_timeout_active_status(wifi_ctrl_t *l_ctrl, BOOL (*cb)(UINT apIndex))
{
    unsigned int index = 0;
    wifi_scheduler_id_t  *sched_id = &l_ctrl->wifi_sched_id;

    for (index = 0; index < getTotalNumberVAPs(); index++) {
        if (cb(index) != FALSE && sched_id->wifi_vap_sched_handler_id[index] != 0) {
            return true;
        }
    }

    return false;
}

void resched_data_to_ctrl_queue()
{
    wifi_ctrl_t *l_ctrl;
    l_ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    webconfig_subdoc_data_t *queue_data;
    char *str;

    if((l_ctrl->vif_apply_pending_queue != NULL) && (queue_count(l_ctrl->vif_apply_pending_queue) != 0)) {
        // dequeue data
        while (queue_count(l_ctrl->vif_apply_pending_queue)) {
            queue_data = queue_pop(l_ctrl->vif_apply_pending_queue);
            if (queue_data == NULL) {
                continue;
            }
            str = queue_data->u.encoded.raw;
#if CCSP_COMMON
            apps_mgr_analytics_event(&l_ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_data_resched_to_ctrl_queue, queue_data);
#endif
            push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_data_resched_to_ctrl_queue, NULL);

            //Free the allocated memory
            webconfig_data_free(queue_data);
            if (queue_data) {
                free(queue_data);
            }
        }
    }
}

int wifi_sched_timeout(void *arg)
{
    int *handler_id;
    wifi_ctrl_t *l_ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_scheduler_id_t  *sched_id = &l_ctrl->wifi_sched_id;
    wifi_scheduler_id_arg_t *args = (wifi_scheduler_id_arg_t *)arg;

    if (args == NULL) {
        return TIMER_TASK_ERROR;
    }

    switch(args->type) {
        case wifi_csa_sched:
            handler_id = sched_id->wifi_csa_sched_handler_id;
            break;
        case wifi_radio_sched:
            handler_id = sched_id->wifi_radio_sched_handler_id;
            break;
        case wifi_vap_sched:
            handler_id = sched_id->wifi_vap_sched_handler_id;
            break;
        default:
            free(args);
            wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi index:%d invalid type:%d\n", __func__, __LINE__, args->index, args->type);
            return TIMER_TASK_ERROR;
    }

    wifi_util_info_print(WIFI_CTRL,"%s:%d - wifi index:%d type:%d scheduler timeout\r\n",
                                    __func__, __LINE__, args->index, args->type);
    handler_id[args->index] = 0;

    if (args->type == wifi_csa_sched) {
        resched_data_to_ctrl_queue();
    }

    free(args);

    return TIMER_TASK_COMPLETE;
}

void start_wifi_sched_timer(unsigned int index, wifi_ctrl_t *l_ctrl, wifi_scheduler_type_t type)
{
    int *handler_id;
    unsigned int handler_index, vap_array_index;
    wifi_scheduler_id_arg_t *args;
    wifi_scheduler_id_t  *sched_id = &l_ctrl->wifi_sched_id;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    switch(type) {
        case wifi_csa_sched:
            handler_id = sched_id->wifi_csa_sched_handler_id;
            handler_index = index;
            break;
        case wifi_radio_sched:
            handler_id = sched_id->wifi_radio_sched_handler_id;
            handler_index = index;
            break;
        case wifi_vap_sched:
            handler_id = sched_id->wifi_vap_sched_handler_id;
            VAP_ARRAY_INDEX(vap_array_index, mgr->hal_cap, index);
            handler_index = vap_array_index;
            break;
        default:
            wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi index:%d invalid type:%d\n", __func__, __LINE__, index, type);
            return;
    }

    if (handler_id[handler_index] == 0) {
        wifi_util_info_print(WIFI_CTRL,"%s:%d - start wifi index:%d type:%d scheduler timer\r\n",
            __func__, __LINE__, handler_index, type);

        if ((args = calloc(1, sizeof(wifi_scheduler_id_arg_t))) == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d: Unable to allocate memory!\n", __func__, __LINE__);
            return;
        }

        args->type = type;
        args->index = handler_index;

        scheduler_add_timer_task(l_ctrl->sched, FALSE, &handler_id[handler_index],
            wifi_sched_timeout, args, MAX_WIFI_SCHED_TIMEOUT, 1, FALSE);
    } else {
        wifi_util_info_print(WIFI_CTRL,"%s:%d - Already wifi index:%d type:%d scheduler timer started\r\n",
                                __func__, __LINE__, handler_index, type);
    }
}

void stop_wifi_sched_timer(unsigned int index, wifi_ctrl_t *l_ctrl, wifi_scheduler_type_t type)
{
    int *handler_id;
    unsigned int handler_index, vap_array_index;
    wifi_scheduler_id_t  *sched_id = &l_ctrl->wifi_sched_id;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    switch(type) {
        case wifi_csa_sched:
            handler_id = sched_id->wifi_csa_sched_handler_id;
            handler_index = index;
            break;
        case wifi_radio_sched:
            handler_id = sched_id->wifi_radio_sched_handler_id;
            handler_index = index;
            break;
        case wifi_vap_sched:
            handler_id = sched_id->wifi_vap_sched_handler_id;
            VAP_ARRAY_INDEX(vap_array_index, mgr->hal_cap, index);
            handler_index = vap_array_index;
            break;
        default:
            wifi_util_error_print(WIFI_CTRL, "%s:%d: wifi index:%d invalid type:%d\n", __func__, __LINE__, index, type);
            return;
   }

    if (handler_id[handler_index] != 0) {
        wifi_util_info_print(WIFI_CTRL,"%s:%d - stop wifi index:%d type:%d scheduler timer\r\n", __func__, __LINE__, handler_index, type);
        scheduler_free_timer_task_arg(l_ctrl->sched, handler_id[handler_index]);
        scheduler_cancel_timer_task(l_ctrl->sched, handler_id[handler_index]);
        handler_id[handler_index] = 0;

        if (type == wifi_csa_sched) {
            resched_data_to_ctrl_queue();
        }
    }
}

#if defined (FEATURE_SUPPORT_ACL_SELFHEAL)
int sync_wifi_hal_hotspot_vap_mac_entry_with_db(void)
{
    mac_addr_str_t mac_str;
    mac_address_t acl_device_mac;
    acl_entry_t *acl_entry;
    // hotspot open 5g VAP index
    uint8_t vap_index = 5;
    uint32_t acl_hal_count = 0, acl_db_count = 0;
    uint8_t acl_count= 0;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    int ret;

    rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);
    if ((rdk_vap_info == NULL) || (rdk_vap_info->acl_map == NULL)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: idk vap_info get failure for Vap:%d\n", __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    acl_db_count  = hash_map_count(rdk_vap_info->acl_map);
#ifdef NL80211_ACL
    ret = wifi_hal_getApAclDeviceNum(vap_index, &acl_hal_count);
#else
    ret = wifi_getApAclDeviceNum(vap_index, &acl_hal_count);
#endif

    if (ret != RETURN_OK) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: wifi get ap acl device count failure:%d hal acl count:%d\r\n", __func__, __LINE__, ret, acl_hal_count);
    }

    if ((acl_db_count == 0) || (acl_db_count == acl_hal_count)) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: acl_db_count = %d acl_hal_count = %d\r\n", __func__, __LINE__, acl_db_count, acl_hal_count);
        return RETURN_OK;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d: mismatch in mac filter entries, hal_count:%d db_count:%d\r\n", __func__, __LINE__, acl_hal_count, acl_db_count);

    acl_entry = hash_map_get_first(rdk_vap_info->acl_map);
    while(acl_entry != NULL && acl_count < MAX_ACL_COUNT ) {
        memcpy(&acl_device_mac,&acl_entry->mac,sizeof(mac_address_t));
        to_mac_str(acl_device_mac, mac_str);
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: calling wifi_addApAclDevice for mac %s vap_index %d\n", __func__, __LINE__, mac_str, vap_index);
#ifdef NL80211_ACL
        if (wifi_hal_addApAclDevice(vap_index, (CHAR *) mac_str) != RETURN_OK) {
#else
        if (wifi_addApAclDevice(vap_index, (CHAR *) mac_str) != RETURN_OK) {
#endif
            wifi_util_error_print(WIFI_CTRL,"%s:%d wifi_addApAclDevice failed. vap_index:%d MAC:'%s'\n", __func__, __LINE__, vap_index, mac_str);
        }
        acl_entry = hash_map_get_next(rdk_vap_info->acl_map,acl_entry);
        acl_count++;
    }

    return RETURN_OK;
}

static int sync_wifi_hal_hotspot_vap_mac_entry(void *arg)
{
    sync_wifi_hal_hotspot_vap_mac_entry_with_db();
    return TIMER_TASK_COMPLETE;
}
#endif

#if CCSP_COMMON
static int rbus_check_and_subscribe_events(void* arg)
{
    wifi_ctrl_t *ctrl = NULL;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if ((ctrl->rbus_events_subscribed == false) || (ctrl->tunnel_events_subscribed == false) ||
        (ctrl->device_mode_subscribed == false) || (ctrl->active_gateway_check_subscribed == false) ||
        (ctrl->device_tunnel_status_subscribed == false) || (ctrl->device_wps_test_subscribed == false) ||
        (ctrl->test_device_mode_subscribed == false) || (ctrl->mesh_status_subscribed == false) ||
        (ctrl->marker_list_config_subscribed == false)
#if defined (RDKB_EXTENDER_ENABLED)
        || (ctrl->eth_bh_status_subscribed == false)
#endif
        ) {
        rbus_subscribe_events(ctrl);
    }
    return TIMER_TASK_COMPLETE;
}

static int sta_connectivity_selfheal(void* arg)
{
    wifi_ctrl_t *ctrl = NULL;
    vap_svc_t *ext_svc;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    
    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    if (is_sta_enabled()) {
        // check sta connectivity selfheal
        sta_selfheal_handing(ctrl, ext_svc);
    }
    return TIMER_TASK_COMPLETE;
}

static int run_greylist_event(void *arg)
{
    bool greylist_flag = false;

    greylist_flag = check_for_greylisted_mac_filter();
    if (greylist_flag) {
        wifi_util_dbg_print(WIFI_CTRL,"greylist_mac present\n");
        remove_xfinity_acl_entries(false,false);
    }
    return TIMER_TASK_COMPLETE;
}

static int run_analytics_event(void* arg)
{
    wifi_ctrl_t *ctrl = NULL;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_timeout, NULL);

    return TIMER_TASK_COMPLETE;
}

#ifdef ONEWIFI_CAC_APP_SUPPORT
static int run_cac_event(void* arg)
{
    wifi_ctrl_t *ctrl = NULL;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    apps_mgr_cac_event(&ctrl->apps_mgr, wifi_event_type_exec, wifi_event_exec_timeout, NULL, 0);

    return TIMER_TASK_COMPLETE;
}
#endif
#endif //CCSP_COMMON

static int pending_states_webconfig_analyzer(void *arg)
{
    wifi_ctrl_t *ctrl = NULL;

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    webconfig_analyze_pending_states(ctrl);
    return TIMER_TASK_COMPLETE;
}

static void ctrl_queue_timeout_scheduler_tasks(wifi_ctrl_t *ctrl)
{
#if CCSP_COMMON
    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, run_analytics_event, NULL, (ANAYLYTICS_PERIOD * 1000), 0, FALSE);

#ifdef ONEWIFI_CAC_APP_SUPPORT
    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, run_cac_event, NULL, (CAC_PERIOD * 1000), 0, FALSE);
#endif

    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, run_greylist_event, NULL, (GREYLIST_CHECK_IN_SECONDS * 1000), 0, FALSE);

    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, sta_connectivity_selfheal, NULL, (STA_CONN_RETRY_TIMEOUT * 1000), 0, FALSE);

    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, rbus_check_and_subscribe_events, NULL, (ctrl->poll_period * 1000), 0, FALSE);
#endif //CCSP_COMMON
    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, pending_states_webconfig_analyzer, NULL, (ctrl->poll_period * 1000), 0, FALSE);

#if defined (FEATURE_SUPPORT_ACL_SELFHEAL)
    scheduler_add_timer_task(ctrl->sched, FALSE, NULL, sync_wifi_hal_hotspot_vap_mac_entry, NULL, (HOTSPOT_VAP_MAC_FILTER_ENTRY_SYNC * 1000), 0, FALSE);
#endif
    wifi_util_dbg_print(WIFI_CTRL, "%s():%d Ctrl queue timeout tasks scheduled\n", __FUNCTION__, __LINE__);
}

wifi_radio_index_t get_wifidb_radio_index(uint8_t radio_index)
{
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    if ((radio_index < getNumberRadios())) {
        return g_wifi_mgr->radio_config[radio_index].vaps.radio_index;
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
        return RETURN_ERR;
    }
}

rdk_wifi_vap_info_t* get_wifidb_rdk_vap_info(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    if (get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index) == -1) {
        wifi_util_dbg_print(WIFI_CTRL, "%s: Invalid VAP index %u\n", __func__, vapIndex);
        return NULL;
    }
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    if ((radio_index < getNumberRadios()) && (vap_index < getNumberVAPsPerRadio(radio_index))) {
        return &g_wifi_mgr->radio_config[radio_index].vaps.rdk_vap_array[vap_index];
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio or vap index %d\n", __FUNCTION__, radio_index);
        return NULL;
    }
}

rdk_wifi_vap_info_t* get_wifidb_rdk_vaps(uint8_t radio_index)
{
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();

    if (radio_index < getNumberRadios()) {
        return g_wifi_mgr->radio_config[radio_index].vaps.rdk_vap_array;
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
        return NULL;
    }
}

wifi_vap_info_map_t* get_wifidb_vap_map(uint8_t radio_index)
{
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    if (radio_index < getNumberRadios()) {
        return &g_wifi_mgr->radio_config[radio_index].vaps.vap_map;
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
        return NULL;
    }
}

wifi_radio_operationParam_t* get_wifidb_radio_map(uint8_t radio_index)
{
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    if (radio_index < getNumberRadios()) {
        return &g_wifi_mgr->radio_config[radio_index].oper;
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
        return NULL;
    }
}

wifi_radio_feature_param_t* get_wifidb_radio_feat_map(uint8_t radio_index)
{
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    if (radio_index < getNumberRadios()) {
        return &g_wifi_mgr->radio_config[radio_index].feature;
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
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
    if (get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index)) {
        wifi_util_error_print(WIFI_CTRL, "%s: Invalid VAP index %u\n", __func__, vapIndex);
        return NULL;
    }

    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= getNumberVAPsPerRadio(radio_index)) {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.bss_info.interworking;
}

wifi_preassoc_control_t * Get_wifi_object_preassoc_ctrl_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    if (get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index)) {
        wifi_util_error_print(WIFI_CTRL, "%s: Invalid VAP index %u\n", __func__, vapIndex);
        return NULL;
    }

    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= getNumberVAPsPerRadio(radio_index)) {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.bss_info.preassoc;
}

wifi_postassoc_control_t * Get_wifi_object_postassoc_ctrl_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    if (get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index)) {
        wifi_util_error_print(WIFI_CTRL, "%s: Invalid VAP index %u\n", __func__, vapIndex);
        return NULL;
    }

    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= getNumberVAPsPerRadio(radio_index)) {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.bss_info.postassoc;
}

wifi_vap_security_t * Get_wifi_object_bss_security_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    if (get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index) == -1) {
        wifi_util_error_print(WIFI_CTRL, "%s: Invalid VAP index %u\n", __func__, vapIndex);
        return NULL;
    }

    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= getNumberVAPsPerRadio(radio_index)) {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.bss_info.security;
}

wifi_vap_security_t * Get_wifi_object_sta_security_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    if (get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index) == -1) {
        wifi_util_error_print(WIFI_CTRL, "%s: Invalid VAP index %u\n", __func__, vapIndex);
        return NULL;
    }
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= MAX_NUM_VAP_PER_RADIO) {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.sta_info.security;
}

wifi_front_haul_bss_t * Get_wifi_object_bss_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    if (get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index) == -1) {
        wifi_util_error_print(WIFI_CTRL, "%s: Invalid VAP index %u\n", __func__, vapIndex);
        return NULL;
    }
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if(l_vap_maps == NULL || vap_index >= getNumberVAPsPerRadio(radio_index)) {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.bss_info;
}

wifi_back_haul_sta_t * get_wifi_object_sta_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    if (get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index) == -1) {
        wifi_util_error_print(WIFI_CTRL, "%s: Invalid VAP index %u\n", __func__, vapIndex);
        return NULL;
    }
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if(l_vap_maps == NULL || vap_index >= getMaxNumberVAPsPerRadio(radio_index)) {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index].u.sta_info;
}

wifi_vap_info_t* get_wifidb_vap_parameters(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    if (get_vap_and_radio_index_from_vap_instance(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index) == -1) {
        wifi_util_error_print(WIFI_CTRL, "%s: Invalid VAP index %u\n", __func__, vapIndex);
        return NULL;
    }
    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_index >= getMaxNumberVAPsPerRadio(radio_index)) {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &l_vap_maps->vap_array[vap_index];
}

int get_wifi_vap_network_status(uint8_t vapIndex, bool *status)
{
    int ret;
    wifi_vap_info_t vap_cfg;
    rdk_wifi_vap_info_t rdk_vap_cfg;
    char vap_name[32];
    memset(vap_name, 0, sizeof(vap_name));
    memset(&vap_cfg, 0, sizeof(vap_cfg));

    ret = convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vapIndex, vap_name);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d failure convert vap-index to name vapIndex:%d \n", __func__, __LINE__, vapIndex);
        return RETURN_ERR;
    }
    ret = wifidb_get_wifi_vap_info(vap_name, &vap_cfg, &rdk_vap_cfg);
    if (ret != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d wifiDb get vapInfo failure :vap_name:%s \n", __func__, __LINE__, vap_name);
        wifi_front_haul_bss_t *bss_param = Get_wifi_object_bss_parameter(vapIndex);
        if(bss_param != NULL) {
            *status = bss_param->enabled;
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s:%d bss_param null for vapIndex:%d \n", __func__, __LINE__, vapIndex);
            return RETURN_ERR;
        }
        return RETURN_OK;
    }
    *status = vap_cfg.u.bss_info.enabled;
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d vap_info: vap_name:%s vap_index:%d, bss_status:%d\n", __func__, __LINE__, vap_name, vapIndex, *status);

    return RETURN_OK;
}

int get_wifi_mesh_sta_network_status(uint8_t vapIndex, bool *status)
{
    wifi_back_haul_sta_t *sta_param = get_wifi_object_sta_parameter(vapIndex);
    if(sta_param != NULL) {
        *status = sta_param->enabled;
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s:%d sta_param null for vapIndex:%d \n", __func__, __LINE__, vapIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

bool get_wifi_mesh_vap_enable_status(void)
{
    bool status = false;
    int count;
    int vap_index;
    wifi_vap_name_t backhauls[MAX_NUM_RADIOS];

    /* get a list of mesh backhaul names of all radios */
    count = get_list_of_mesh_backhaul(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, sizeof(backhauls)/sizeof(wifi_vap_name_t), backhauls);
    for (int i = 0; i < count; i++) {
        vap_index = convert_vap_name_to_index(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, &backhauls[i][0]);
        get_wifi_vap_network_status(vap_index, &status);
        if (status == true) {
            return true;
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
            wifi_util_error_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__, i);
            return -1;
        }

        for (j = 0; j < vap_map->num_vaps; j++) {
            if ((isVapHotspotOpen(vap_map->vap_array[j].vap_index) == TRUE)
                || (isVapHotspotSecure(vap_map->vap_array[j].vap_index) == TRUE)) {

                get_wifi_vap_network_status(vap_map->vap_array[j].vap_index, &status);

                if (status == true &&  (memcmp(vap_map->vap_array[j].u.bss_info.bssid, zero_mac, sizeof(mac_address_t)) != 0)) {
                    wifi_util_info_print(WIFI_CTRL,"Public xfinity vap is enabled\n");
                    return true;
                }
            }
        }
    }

    wifi_util_info_print(WIFI_CTRL,"Public xfinity vap is disabled\n");
    return false;
}

int set_wifi_vap_network_status(uint8_t vapIndex, bool status)
{
    wifi_front_haul_bss_t *bss_param = Get_wifi_object_bss_parameter(vapIndex);
    if(bss_param != NULL) {
        bss_param->enabled = status;
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s:%d bss_param null for vapIndex:%d \n", __func__, __LINE__, vapIndex);
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
        wifi_util_error_print(WIFI_CTRL, "%s:%d sta_param null for vapIndex:%d \n", __func__, __LINE__, vapIndex);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

void set_wifi_public_vap_enable_status(void)
{
    UINT vap_index;
    int count;
    wifi_vap_name_t hotspots[MAX_NUM_RADIOS];

    count = get_list_of_vap_names(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, hotspots, \
                                  sizeof(hotspots)/sizeof(wifi_vap_name_t), 1, VAP_PREFIX_HOTSPOT);
    for (int i = 0; i < count; i++) {
        vap_index = convert_vap_name_to_index(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, &hotspots[i][0]);
        set_wifi_vap_network_status(vap_index, true);
    }
}

int  get_wifi_rfc_parameters(char *str, void *value)
{
    int ret = RETURN_OK;

    if (!value) {
        return RETURN_ERR;
    }

#if DML_SUPPORT
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
#else
    if (strncmp(str, RFC_WIFI_PASSPOINT, strlen(RFC_WIFI_PASSPOINT)) == 0) {
        *(bool*)value = false;
    } else if (strncmp(str, RFC_WIFI_INTERWORKING, strlen(RFC_WIFI_INTERWORKING)) == 0) {
        *(bool*)value = false;
    } else {
        ret = RETURN_ERR;
    }
#endif // CCSP_COMMON

    return ret;
}

#if DML_SUPPORT
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
    g_wifi_mgr->ctrl.rfc_params.levl_enabled_rfc = g_wifi_mgr->rfc_dml_parameters.levl_enabled_rfc;
    g_wifi_mgr->ctrl.rfc_params.twoG80211axEnable_rfc = g_wifi_mgr->rfc_dml_parameters.twoG80211axEnable_rfc;
    g_wifi_mgr->ctrl.rfc_params.hotspot_open_2g_last_enabled = g_wifi_mgr->rfc_dml_parameters.hotspot_open_2g_last_enabled;
    g_wifi_mgr->ctrl.rfc_params.hotspot_open_5g_last_enabled = g_wifi_mgr->rfc_dml_parameters.hotspot_open_5g_last_enabled;
    g_wifi_mgr->ctrl.rfc_params.hotspot_open_6g_last_enabled = g_wifi_mgr->rfc_dml_parameters.hotspot_open_6g_last_enabled;
    g_wifi_mgr->ctrl.rfc_params.hotspot_secure_2g_last_enabled = g_wifi_mgr->rfc_dml_parameters.hotspot_secure_2g_last_enabled;
    g_wifi_mgr->ctrl.rfc_params.hotspot_secure_5g_last_enabled = g_wifi_mgr->rfc_dml_parameters.hotspot_secure_5g_last_enabled;
    g_wifi_mgr->ctrl.rfc_params.hotspot_secure_6g_last_enabled = g_wifi_mgr->rfc_dml_parameters.hotspot_secure_6g_last_enabled;
    g_wifi_mgr->ctrl.rfc_params.wifioffchannelscan_rfc = g_wifi_mgr->rfc_dml_parameters.wifioffchannelscan_rfc;
    strcpy(g_wifi_mgr->ctrl.rfc_params.rfc_id,g_wifi_mgr->rfc_dml_parameters.rfc_id);
    return &g_wifi_mgr->ctrl.rfc_params;
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

int get_device_config_list(char *d_list, int size, char *str)
{
    int ret = RETURN_OK;

    if (d_list == NULL) {
        return RETURN_ERR;
    }

    memset(d_list, '\0', size);
    wifi_mgr_t *g_wifidb = get_wifimgr_obj();
    wifi_global_param_t *global_param = &g_wifidb->global_config.global_parameters;

    pthread_mutex_lock(&g_wifidb->data_cache_lock);
    if ((strcmp(str, WIFI_NORMALIZED_RSSI_LIST) == 0)) {
        strncpy(d_list, global_param->normalized_rssi_list, size-1);
    } else if ((strcmp(str, WIFI_SNR_LIST) == 0)) {
        strncpy(d_list, global_param->snr_list, size-1);
    } else if ((strcmp(str, WIFI_CLI_STAT_LIST) == 0)) {
        strncpy(d_list, global_param->cli_stat_list, size-1);
    } else if ((strcmp(str, WIFI_TxRx_RATE_LIST) == 0)) {
        strncpy(d_list, global_param->txrx_rate_list, size-1);
    } else {
        pthread_mutex_unlock(&g_wifidb->data_cache_lock);
        wifi_util_dbg_print(WIFI_CTRL, "%s get %s device list structure data not match:\n", __FUNCTION__, str);
        return RETURN_ERR;
    }
    pthread_mutex_unlock(&g_wifidb->data_cache_lock);

    // NULL check for copied config list
    if (d_list == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Failed to get config for %s \n",__func__, __LINE__, str);
        return RETURN_ERR;
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
    wifi_util_info_print(WIFI_MGR, "%s Marking DML Init Complete. Start Wifi Ctrl\n", __FUNCTION__);
    pthread_mutex_lock(&wifi_mgr->lock);
    wifi_mgr->dml_init_status.condition = true;
    pthread_cond_signal(&wifi_mgr->dml_init_status.cv);
    pthread_mutex_unlock(&wifi_mgr->lock);
    return ret;
}
#endif // DML_SUPPORT

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

rdk_wifi_vap_map_t *getRdkWifiVap(UINT radioIndex)
{
    if (radioIndex >= getNumberRadios()) {
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input radioIndex = %d not found, out of range\n", __FUNCTION__, radioIndex);
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
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    if (apIndex >= wifi_mgr->hal_cap.wifi_prop.numRadios * MAX_NUM_VAP_PER_RADIO) {
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input apIndex = %d not found, Out of range\n", __FUNCTION__, apIndex);
        return NULL;
    }

    for (radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        for (vapArrayIndex = 0; vapArrayIndex < getNumberVAPsPerRadio(radioIndex); vapArrayIndex++) {
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
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    if (apIndex >= wifi_mgr->hal_cap.wifi_prop.numRadios * MAX_NUM_VAP_PER_RADIO) {
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input apIndex = %d not found, Out of range\n", __FUNCTION__, apIndex);
        return NULL;
    }

    for (radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        for (vapArrayIndex = 0; vapArrayIndex < getNumberVAPsPerRadio(radioIndex); vapArrayIndex++) {
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
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input radioIndex = %d not found, out of range\n", __FUNCTION__, radioIndex);
        return NULL;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s Input radioIndex = %d\n", __FUNCTION__, radioIndex);

    return &wifi_hal_cap_obj->wifi_prop.radiocap[radioIndex];
}

//Returns the wifi_radio_operationParam_t, here radioIndex starts with 0 i.e., (dmlInstanceNumber-1)
wifi_radio_operationParam_t *getRadioOperationParam(UINT radioIndex)
{
    if (radioIndex >= getNumberRadios()) {
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_ERROR, %s Input radioIndex = %d not found, out of range\n", __FUNCTION__, radioIndex);
        return NULL;
    }
    //TODO: dbg log flood
    //wifi_util_dbg_print(WIFI_CTRL, "%s Input radioIndex = %d\n", __FUNCTION__, radioIndex);

    return get_wifidb_radio_map(radioIndex);
}

//Get the wlanIndex from the Interface name
int rdkGetIndexFromName(char *pIfaceName, UINT *pWlanIndex)
{
    UINT radioIndex = 0;
    UINT vapArrayIndex = 0;

    if (!pIfaceName || !pWlanIndex) {
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_ERROR,WIFI %s : pIfaceName (or) pWlanIndex is NULL \n",__FUNCTION__);
        return RETURN_ERR;
    }
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    for (radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        for (vapArrayIndex = 0; vapArrayIndex < getNumberVAPsPerRadio(radioIndex); vapArrayIndex++) {
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
        wifi_util_error_print(WIFI_CTRL,"getRadioIndexFromAp not recognised!!!\n"); //should never happen
        return 0;
    }
}

UINT getPrivateApFromRadioIndex(UINT radioIndex)
{
    UINT apIndex;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (UINT index = 0; index < getTotalNumberVAPs(); index++) {
        apIndex = VAP_INDEX(mgr->hal_cap, index);
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

BOOL isVapHotspotSecure5g(UINT apIndex)
{
    return is_vap_hotspot_secure_5g(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapHotspotSecure6g(UINT apIndex)
{
    return is_vap_hotspot_secure_6g(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapHotspotOpen5g(UINT apIndex)
{
    return is_vap_hotspot_open_5g(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
}

BOOL isVapHotspotOpen6g(UINT apIndex)
{
    return is_vap_hotspot_open_6g(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex);
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

UINT getNumberVAPsPerRadio(UINT radioIndex)
{
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    return wifi_mgr->radio_config[radioIndex].vaps.num_vaps;
}


void get_subdoc_name_from_vap_index(uint8_t vap_index, int* subdoc)
{
    if (isVapPrivate(vap_index)) {
        *subdoc = PRIVATE;
        return;
    } else if (isVapHotspot(vap_index) || isVapHotspotSecure(vap_index)) {
        *subdoc = HOTSPOT;
        return;
    } else if (isVapXhs(vap_index)) {
        *subdoc = HOME;
        return;
    } else if (isVapSTAMesh(vap_index)) {
        *subdoc = MESH_STA;
        return;
    } else if (isVapMeshBackhaul(vap_index)) {
        *subdoc = MESH_BACKHAUL;
        return;
    } else if (isVapMesh(vap_index)) {
        *subdoc = MESH;
        return;
    } else if (isVapLnf(vap_index)) {
        *subdoc = LNF;
        return;
    } else {
        *subdoc = MESH_STA;
        return;
    }
}

//Returns total number of Configured vaps for all radios
UINT getTotalNumberVAPs()
{
    UINT numRadios = getNumberRadios();
    static UINT numVAPs = 0;
    UINT radioCount = 0;
    if (numVAPs == 0) {
        for (radioCount = 0; radioCount < numRadios; radioCount++)
            numVAPs += getNumberVAPsPerRadio(radioCount);
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
        for (vapArrayIndex = 0; vapArrayIndex < getNumberVAPsPerRadio(radioIndex); vapArrayIndex++) {
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
        for (UINT vapArrayIndex = 0; vapArrayIndex < getNumberVAPsPerRadio(radioIndex); vapArrayIndex++) {
            if (!strncmp (vapName, (CHAR *)wifi_mgr->radio_config[radioIndex].vaps.rdk_vap_array[vapArrayIndex].vap_name, \
                    strlen((CHAR *)wifi_mgr->radio_config[radioIndex].vaps.rdk_vap_array[vapArrayIndex].vap_name) + 1)) {
                *apIndex = wifi_mgr->radio_config[radioIndex].vaps.vap_map.vap_array[vapArrayIndex].vap_index;
                return RETURN_OK;
            }
        }
    }
    return RETURN_ERR;
}

int getVAPArrayIndexFromVAPIndex(unsigned int apIndex, unsigned int *vap_array_index)
{
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    VAP_ARRAY_INDEX(*vap_array_index, wifi_mgr->hal_cap, apIndex);
    return RETURN_OK;
}

char* convert_radio_index_to_band_str_g(UINT radioIndex)
{
    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radioIndex);
    if (radioOperation == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s : failed to getRadioOperationParam with radio index \n", __FUNCTION__);
        return NULL;
    }
    switch (radioOperation->band) {
        case WIFI_FREQUENCY_2_4_BAND:
            return NAME_FREQUENCY_2_4_G;
        case WIFI_FREQUENCY_5_BAND:
            return NAME_FREQUENCY_5_G;
        case WIFI_FREQUENCY_5L_BAND:
            return NAME_FREQUENCY_5L_G;
        case WIFI_FREQUENCY_5H_BAND:
            return NAME_FREQUENCY_5H_G;
        case WIFI_FREQUENCY_6_BAND:
            return NAME_FREQUENCY_6_G;
        default:
            break;
    }
    return NULL;
}

char *convert_radio_index_to_band_str(UINT radioIndex)
{
    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radioIndex);
    if (radioOperation == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s : failed to getRadioOperationParam with radio index \n", __FUNCTION__);
        return NULL;
    }

    switch (radioOperation->band) {
        case WIFI_FREQUENCY_2_4_BAND:
            return NAME_FREQUENCY_2_4;
        case WIFI_FREQUENCY_5_BAND:
            return NAME_FREQUENCY_5;
        case WIFI_FREQUENCY_5L_BAND:
            return NAME_FREQUENCY_5L;
        case WIFI_FREQUENCY_5H_BAND:
            return NAME_FREQUENCY_5H;
        case WIFI_FREQUENCY_6_BAND:
            return NAME_FREQUENCY_6;
        default:
            break;
    }

    return NULL;
}

int get_vap_interface_bridge_name(unsigned int vap_index, char *bridge_name)
{
    unsigned char i = 0;
    unsigned char total_num_of_vaps = getTotalNumberVAPs();
    char *l_bridge_name = NULL;
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();

    if ((vap_index >= wifi_hal_cap_obj->wifi_prop.numRadios*MAX_NUM_VAP_PER_RADIO) || (bridge_name == NULL)) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d: Wrong vap_index:%d \n",__func__, __LINE__, vap_index);
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
        wifi_util_error_print(WIFI_CTRL,"%s:%d: Bridge name not found:%d \n",__func__, __LINE__, vap_index);
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
    int count;
    int vap_index;
    wifi_vap_name_t hotspots[MAX_NUM_RADIOS*2];

    count = get_list_of_vap_names(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, hotspots, \
                                  sizeof(hotspots)/sizeof(wifi_vap_name_t), 1, VAP_PREFIX_HOTSPOT);
    for (int i = 0; i < count; i++) {
        vap_index = convert_vap_name_to_index(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, &hotspots[i][0]);
        Hotspot_APIsolation_Set(vap_index + 1);
    }
}

int get_rbus_param(rbusHandle_t rbus_handle, rbus_data_type_t data_type, const char *paramNames, void *data_value)
{
    rbusValue_t value;
    int rc = RETURN_ERR;

    rc = rbus_get(rbus_handle, paramNames, &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_MGR,"[%s:%d] rbus_get failed for [%s] with error [%d]\n", __func__, __LINE__, paramNames, rc);
        return RETURN_ERR;
    }

    if (data_type == rbus_string_data) {
        strcpy((char *)data_value, rbusValue_GetString(value, NULL));
        wifi_util_dbg_print(WIFI_MGR,":%s:%d rbus get[%s] data value = [%s]\n", __func__, __LINE__, paramNames, (char *)data_value);
    } else if (data_type == rbus_bool_data) {
        *(bool *)data_value = rbusValue_GetBoolean(value);
        wifi_util_dbg_print(WIFI_MGR,":%s:%d rbus get[%s] data value = [%d]\n", __func__, __LINE__, paramNames, *(bool *)data_value);
    } else if (data_type == rbus_uint_data) {
        *(unsigned int *)data_value = rbusValue_GetUInt32(value);
        wifi_util_dbg_print(WIFI_MGR,":%s:%d rbus get[%s] data value = [%d]\n", __func__, __LINE__, paramNames, *(unsigned int *)data_value);
    }

    return RETURN_OK;
}

int set_rbus_bool_param(rbusHandle_t rbus_handle, const char *paramNames, bool data_value)
{
    rbusValue_t value;
    int rc = RETURN_ERR;

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, data_value);

    rc = rbus_set(rbus_handle, paramNames, value, NULL);
    if(rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_MGR,"[%s:%d] Rbus error param: %s\r\n", __func__, __LINE__, paramNames);
        return RETURN_ERR;
    }
    wifi_util_dbg_print(WIFI_MGR,"[%s:%d] wifi rbus set[%s]:value:%d\r\n", __func__, __LINE__, paramNames, data_value);

    return RETURN_OK;
}

static int switch_dfs_channel(void *arg)
{
    int *dfs_chan = (int *)arg;
    wifi_radio_operationParam_t *wifi_radio_oper_param = NULL;
    uint8_t index = 0;
    uint8_t num_of_radios = getNumberRadios();

    for (index = 0; index < num_of_radios; index++) {
        wifi_radio_oper_param = (wifi_radio_operationParam_t *)get_wifidb_radio_map(index);
        if (wifi_radio_oper_param == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:wrong index for radio map: %d\n",__FUNCTION__, index);
            return TIMER_TASK_ERROR;
        }

        if( ((wifi_radio_oper_param->band == WIFI_FREQUENCY_5_BAND ) || ( wifi_radio_oper_param->band == WIFI_FREQUENCY_5L_BAND ) || ( wifi_radio_oper_param->band == WIFI_FREQUENCY_5H_BAND)) &&
            (wifi_radio_oper_param->channel >= 52 && wifi_radio_oper_param->channel <= 144)) {
                wifi_radio_oper_param->channel = *dfs_chan;
                wifi_util_info_print(WIFI_CTRL,"%s:%d Switching to dfs_chan:%d \n", __func__, __LINE__, *dfs_chan);

                if(wifi_hal_setRadioOperatingParameters(index, wifi_radio_oper_param)) {
                    wifi_util_error_print(WIFI_CTRL, "%s:%d: setRadioOperating Parameters failed \n", __func__, __LINE__);
                    return TIMER_TASK_ERROR;
                }
        }
    }

    return TIMER_TASK_COMPLETE;
}
