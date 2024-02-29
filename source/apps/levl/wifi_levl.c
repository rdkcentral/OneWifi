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
#include "wifi_util.h"
#include "wifi_levl.h"
#if DML_SUPPORT
#include "wifi_analytics.h"
#endif
#include <rbus.h>
//#include <ieee80211.h>
#include "common/ieee802_11_defs.h"
#include <fcntl.h>
#include <errno.h>

#define WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE   "Device.WiFi.Events.VAP.%d.Frames.Mgmt"
#define CSI_LEVL_PIPE                           "/tmp/csi_levl_pipe"

#define MAX_EVENT_NAME_SIZE     200
#define MIN_TEMPERATURE_INTERVAL_MS 5000
#define MIN_LEVL_PUBLISH_INTERVAL_MS 100
#define MIN_LEVL_SOUNDING_DURATION_MS 1000
#define UNREFERENCED_PARAMETER(_p_)         (void)(_p_)
static int schedule_mac_for_sounding(int ap_index, mac_address_t mac_address, int duration, int interval);
static int process_levl_sounding_timeout(timeout_data_t *t_data);
static int process_levl_postpone_sounding(wifi_app_t *app);

static int levl_csi_status_publish(rbusHandle_t rbus_handle, mac_addr_t mac_addr, unsigned int status)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    char eventName[MAX_EVENT_NAME_SIZE];
    char eventValue[50];
    mac_addr_str_t mac_str = { 0 };
    int rc;

    snprintf(eventName, MAX_EVENT_NAME_SIZE, "%s", WIFI_LEVL_CSI_STATUS);
    snprintf(eventValue, sizeof(eventValue), "%s;%d", to_mac_str(mac_addr, mac_str), status);

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, eventName, value);
    rbusValue_SetString(value, eventValue);
    event.name = eventName;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    } else {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: rbusEvent_Publish Event for %s %s\n", __func__, __LINE__, eventName, eventValue);
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return RETURN_OK;
}


static int schedule_from_pending_map(wifi_app_t *wifi_app)
{
    int p_map_count = 0, ap_index = 0;
    hash_map_t *p_map = NULL;
    mac_addr_str_t mac_str = { 0 };
    mac_addr_t mac_addr;

    levl_sched_data_t *levl_sc_data = NULL, *tmp_data = NULL;

    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s %d: NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    p_map = wifi_app->data.u.levl.pending_mac_map;
    if (p_map == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pending map\n", __func__, __LINE__);
        return -1;
    }

    p_map_count = hash_map_count(p_map);
    if ((p_map_count > 0) && (wifi_app->data.u.levl.num_current_sounding < wifi_app->data.u.levl.max_num_csi_clients)) {
        levl_sc_data = (levl_sched_data_t *)hash_map_get_first(p_map);
        while(levl_sc_data != NULL)
        {
            ap_index = get_ap_index_from_clientmac(levl_sc_data->mac_addr);
            memset(mac_str, 0, sizeof(mac_addr_str_t));
            to_mac_str((unsigned char *)levl_sc_data->mac_addr, mac_str);
            if (ap_index < 0) {
                wifi_util_error_print(WIFI_APPS,"%s:%d MAC not connected not sounding \n", __func__, __LINE__);
                levl_sc_data = hash_map_get_next(p_map, levl_sc_data);
                tmp_data = hash_map_remove(p_map, mac_str);
                if (tmp_data != NULL) {
                    free(tmp_data);
                }
                continue;
            }

            memset(mac_addr, 0, sizeof(mac_address_t));
            memcpy(mac_addr, levl_sc_data->mac_addr, sizeof(mac_address_t));
            levl_sc_data = hash_map_remove(p_map, mac_str);
            if (levl_sc_data != NULL) {
                free(levl_sc_data);
            }

            //schedule for sounding
            schedule_mac_for_sounding(ap_index, mac_addr, levl_sc_data->duration, levl_sc_data->interval);
            break;
        }
    }
    return 0;
}

static int push_levl_data_dml_to_ctrl_queue(levl_config_t **levl)
{
    webconfig_subdoc_data_t *data;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    char *str = NULL;

    if (*levl == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: NULL Pointer\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    data = (webconfig_subdoc_data_t *) malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", \
                __func__, sizeof(webconfig_subdoc_data_t));
        return RBUS_ERROR_BUS_ERROR;
    }

    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy(&(data->u.decoded.levl), *levl, sizeof(levl_config_t));

    if (webconfig_encode(&ctrl->webconfig, data, webconfig_subdoc_type_levl) == webconfig_error_none) {
        str = data->u.encoded.raw;
        wifi_util_info_print(WIFI_CTRL, "%s: Levl encoded successfully  \n", __FUNCTION__);
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data_dml, NULL);
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
        if (data != NULL) {
            free(data);
        }
        return RBUS_ERROR_BUS_ERROR;
    }

    wifi_util_info_print(WIFI_CTRL, "%s: Levl pushed to queue encoded data is %s\n", __FUNCTION__, str);
    webconfig_data_free(data);
    if (data != NULL) {
        free(data);
    }
    return RBUS_ERROR_SUCCESS;
}

unsigned int get_max_probe_ttl_cnt(void)
{
    FILE *fp;
    char buff[64];
    char *ptr;
    memset(buff, 0, sizeof(buff));

    if ((fp = fopen("/nvram/max_probe_ttl_cnt", "r")) == NULL) {
        return MAX_PROBE_MAP_TTL; /* default is 64 count */
    }

    fgets(buff, 64, fp);
    if ((ptr = strchr(buff, '\n')) != NULL) {
        *ptr = 0;
    }
    fclose(fp);

    return (atoi(buff) ? atoi(buff) : MAX_PROBE_MAP_TTL);
}

void update_probe_map(wifi_app_t *apps, char *mac_key)
{
    probe_req_elem_t *elem;
    hash_map_t *probe_map = apps->data.u.levl.probe_req_map;
    unsigned int max_probe_map_ttl_cnt = get_max_probe_ttl_cnt();
#if DML_SUPPORT
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    probe_ttl_data_t ttl_data;

    memset(&ttl_data, 0, sizeof(ttl_data));
#endif

    if ((mac_key == NULL) || (probe_map == NULL)) {
        wifi_util_error_print(WIFI_APPS,"%s:%d mac str key or probe hash map is null\r\n", __func__, __LINE__);
        return;
    }

    elem = (probe_req_elem_t *)hash_map_get(probe_map, mac_key);
    if (elem != NULL) {
        elem->curr_time_alive++;

        if (elem->curr_time_alive > max_probe_map_ttl_cnt) {
#if DML_SUPPORT
            ttl_data.max_probe_ttl_cnt = elem->curr_time_alive;
            strcpy(ttl_data.mac_str, mac_key);
            apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_hal_ind, wifi_event_hal_potential_misconfiguration, &ttl_data);
#endif

            if (mac_key != NULL) {
                elem = hash_map_remove(probe_map, mac_key);
                if (elem != NULL) {
                    free(elem);
                }
            }
        }
    }
}

void apps_unknown_frame_event(wifi_app_t *app, frame_data_t *msg)
{
    //wifi_util_dbg_print(WIFI_APPS,"%s:%d unknown wifi mgmt frame message\r\n", __FUNCTION__, __LINE__);
}

void apps_probe_req_frame_event(wifi_app_t *app, frame_data_t *msg)
{
    struct ieee80211_mgmt *frame;
    mac_addr_str_t mac_str = { 0 };
    char *str;
    probe_req_elem_t *elem;

    frame = (struct ieee80211_mgmt *)msg->data;
    str = to_mac_str((unsigned char *)frame->sa, mac_str);
    if (str == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d mac str convert failure\r\n", __func__, __LINE__);
        return;
    }

    if (app->data.u.levl.probe_req_map == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d probe hash map is null\r\n", __func__, __LINE__);
        return;
    }
    if (hash_map_count(app->data.u.levl.probe_req_map) > MAX_PROBE_ENTRIES) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d [SKIP] wifi mgmt frame message: ap_index:%d length:%d src mac:%s rssi:%d\r\n", __func__,
                            __LINE__, msg->frame.ap_index, msg->frame.len, str, msg->frame.sig_dbm);
        return;
    }

    update_probe_map(app, str);

    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d src mac:%s rssi:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, str, msg->frame.sig_dbm);

    str_tolower(mac_str);
    if ((elem = (probe_req_elem_t *)hash_map_get(app->data.u.levl.probe_req_map, mac_str)) == NULL) {
        elem = (probe_req_elem_t *)malloc(sizeof(probe_req_elem_t));
        memset(elem, 0, sizeof(probe_req_elem_t));
        memcpy(&elem->msg_data, msg, sizeof(frame_data_t));
        memcpy(elem->mac_str, mac_str, sizeof(mac_addr_str_t));
        hash_map_put(app->data.u.levl.probe_req_map, strdup(mac_str), elem);
        elem->curr_alive_time_sec = get_current_time_in_sec();
        wifi_util_info_print(WIFI_APPS,"%s:%d wifi mgmt probe frame message for %s time:%ld\r\n", __func__, __LINE__, mac_str, elem->curr_alive_time_sec);
    } else {
        memset(&elem->msg_data, 0, sizeof(elem->msg_data));
        memcpy(&elem->msg_data, msg, sizeof(frame_data_t));
    }
}

void apps_probe_rsp_frame_event(wifi_app_t *app, frame_data_t *msg)
{
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi probe rsp mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __func__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}

void apps_auth_frame_event(wifi_app_t *app, frame_data_t *msg)
{
    char namespace[50];
    //wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n",__FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
    snprintf(namespace, sizeof(namespace), WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE, msg->frame.ap_index+1);
    mgmt_frame_rbus_send(app->rbus_handle, namespace, msg);
}


void apps_assoc_req_frame_event(wifi_app_t *app, frame_data_t *msg)
{
    struct ieee80211_mgmt *frame;
    mac_addr_str_t mac_str = { 0 };
    char *str;
    probe_req_elem_t *elem, *tmp;
    char namespace[50];

    frame = (struct ieee80211_mgmt *)msg->data;
    str = to_mac_str(frame->sa, mac_str);
    if (str == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d mac str convert failure\r\n", __func__, __LINE__);
        return;
    }

    str_tolower(mac_str);

    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d src mac:%s rssi:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, str, msg->frame.sig_dbm);


    if ((elem = (probe_req_elem_t *)hash_map_get(app->data.u.levl.probe_req_map, mac_str)) == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d:probe not found for mac address:%s\n", __func__, __LINE__, str);
        //assert(1);
        // assoc request rbus send
        snprintf(namespace, sizeof(namespace), WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE, msg->frame.ap_index+1);
        mgmt_frame_rbus_send(app->rbus_handle, namespace, msg);
    } else {
        // prob request rbus send
        snprintf(namespace, sizeof(namespace), WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE, elem->msg_data.frame.ap_index+1);
        mgmt_frame_rbus_send(app->rbus_handle, namespace, &elem->msg_data);

        // assoc request rbus send
        snprintf(namespace, sizeof(namespace), WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE, msg->frame.ap_index+1);
        mgmt_frame_rbus_send(app->rbus_handle, namespace, msg);

        // remove prob request
        tmp = elem;
        frame = (struct ieee80211_mgmt *)tmp->msg_data.data;
        str = to_mac_str((unsigned char *)frame->sa, mac_str);
        if (str != NULL) {
            tmp = hash_map_remove(app->data.u.levl.probe_req_map, str);
            if (tmp != NULL) {
                free(tmp);
            }
        }

        wifi_util_dbg_print(WIFI_APPS,"%s:%d Send probe and assoc ap_index:%d length:%d type:%d dir:%d rssi:%d\r\n",
                __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, msg->frame.sig_dbm);

    }
}

void apps_assoc_rsp_frame_event(wifi_app_t *apps, frame_data_t *msg)
{
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi assoc rsp mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}

void apps_reassoc_req_frame_event(wifi_app_t *apps, frame_data_t *msg)
{
    char namespace[50];
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi reassoc req mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
    snprintf(namespace, sizeof(namespace), WIFI_ANALYTICS_FRAME_EVENTS_NAMESPACE, msg->frame.ap_index+1);
    mgmt_frame_rbus_send(apps->rbus_handle, namespace, msg);
}

void apps_reassoc_rsp_frame_event(wifi_app_t *apps, frame_data_t *msg)
{
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi reassoc rsp mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}

static int process_levl_postpone_sounding(wifi_app_t *app)
{
    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    app->data.u.levl.postpone_sched_handler_id = 0;
    //schedule from pending list
    schedule_from_pending_map(app);
    return 0;
}


static int process_levl_sounding_timeout(timeout_data_t *t_data)
{
    hash_map_t  *curr_map = NULL;
    mac_addr_str_t mac_str = { 0 };
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr;
    levl_sched_data_t *levl_sc_data = NULL;
    wifi_app_t *wifi_app =  NULL;

    if (t_data == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        free(t_data);
        return -1;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        free(t_data);
        return -1;
    }

    wifi_app_t *csi_app = wifi_app->data.u.levl.csi_app;
    if (csi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        free(t_data);
        return -1;
    }
    to_mac_str((unsigned char *)(t_data->mac_addr), mac_str);
    curr_map = wifi_app->data.u.levl.curr_sounding_mac_map;
    if (curr_map == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL hash map\n", __func__, __LINE__);
        free(t_data);
        return -1;
    }

    levl_sc_data = (levl_sched_data_t *)hash_map_get(curr_map, mac_str);
    if (levl_sc_data != NULL) {
        //Disable CSI Sounding.
        //No current sounding for this MAC
        wifi_util_error_print(WIFI_APPS,"%s:%d Disable CSI Sounding for %02x:...%02x\n", __func__, __LINE__, t_data->mac_addr[0], t_data->mac_addr[5]);
        csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, t_data->ap_index, t_data->mac_addr, wifi_app_inst_levl);
        levl_csi_status_publish(wifi_app->rbus_handle, t_data->mac_addr, 0);
        levl_sc_data = hash_map_remove(curr_map, mac_str);
        if (levl_sc_data != NULL) {
            free(levl_sc_data);
        }
    }

    schedule_from_pending_map(wifi_app);
    free(t_data);
    return 0;
}

static int schedule_mac_for_sounding(int ap_index, mac_address_t mac_address, int duration, int interval)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    hash_map_t *curr_map = NULL, *p_map = NULL;

    wifi_apps_mgr_t *apps_mgr;
    mac_addr_str_t mac_str;
    timeout_data_t *t_data = NULL;
    struct timeval t_now = {0};
    apps_mgr = &ctrl->apps_mgr;
    levl_sched_data_t *levl_sc_data = NULL;
    wifi_app_t *wifi_app = NULL;
    int curr_map_count = 0;

    to_mac_str((unsigned char *)mac_address, mac_str);
    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL wifi_app pointer\n", __func__, __LINE__);
        return -1;
    }
    if (!wifi_app->data.u.levl.csi_event_subscribed) {
        wifi_util_info_print(WIFI_APPS,"%s:%d No SUBSCRIBERS not processing MAC for Sounding \n", __func__, __LINE__);
        return 0;
    }

    wifi_app_t *csi_app = wifi_app->data.u.levl.csi_app;
    if (csi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL csi_app pointer\n", __func__, __LINE__);
        return -1;
    }

    p_map = wifi_app->data.u.levl.pending_mac_map;
    curr_map = wifi_app->data.u.levl.curr_sounding_mac_map;
    if ((curr_map == NULL) || (p_map == NULL)) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL hash map\n", __func__, __LINE__);
        return -1;
    }

    levl_sc_data = (levl_sched_data_t *)hash_map_get(curr_map, mac_str);
    if (levl_sc_data != NULL) {
        wifi_util_info_print(WIFI_APPS,"%s:%d Multiple request for same MAC %02x...%02x\n", __func__, __LINE__, mac_address[0], mac_address[5]);
        return -1;
    }

    levl_sc_data = (levl_sched_data_t *)malloc(sizeof(levl_sched_data_t));
    if (levl_sc_data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL  Pointer\n", __func__, __LINE__);
        return -1;
    }
    memcpy(levl_sc_data->mac_addr, mac_address, sizeof(mac_address_t));
    levl_sc_data->ap_index = ap_index;
    levl_sc_data->duration = duration;
    levl_sc_data->interval = interval;
    levl_sc_data->last_time_publish = t_now;

    if (wifi_app->data.u.levl.paused) {
        wifi_util_info_print(WIFI_APPS,"%s:%d Speed test in progress, pushing to control map\n", __func__, __LINE__);
        hash_map_put(p_map, strdup(mac_str), levl_sc_data);
        return 0;
    }

    curr_map_count = hash_map_count(curr_map);
    if ((curr_map_count < wifi_app->data.u.levl.max_num_csi_clients)) {
        t_data = (timeout_data_t *)malloc(sizeof(timeout_data_t));
        if (t_data == NULL) {
            free(levl_sc_data);
            wifi_util_error_print(WIFI_APPS,"%s:%d NULL wifi_app pointer\n", __func__, __LINE__);
            return -1;
        }
        memset(t_data, 0, sizeof(timeout_data_t));
        memcpy(t_data->mac_addr, mac_address, sizeof(mac_address_t));
        t_data->ap_index = ap_index;
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Enabling CSI for MAC %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, __LINE__,
                           mac_address[0],mac_address[1],mac_address[2],mac_address[3],mac_address[4],mac_address[5]);
        levl_sc_data->ap_index = ap_index;
        if (csi_app->data.u.csi.csi_fns.csi_start_fn(csi_app, ap_index, mac_address, wifi_app_inst_levl) < 0) {
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Unable to schedule sounding for the client, pushing to pending list.\n", __func__, __LINE__);
            hash_map_put(p_map, strdup(mac_str), levl_sc_data);
            if ((hash_map_count(curr_map) == 0) && (wifi_app->data.u.levl.postpone_sched_handler_id == 0)) {
                scheduler_add_timer_task(ctrl->sched, FALSE, &(wifi_app->data.u.levl.postpone_sched_handler_id),
                   process_levl_postpone_sounding, wifi_app, 2000, 1, FALSE);
            }
            free(t_data);
            return RETURN_OK;
        }
        levl_csi_status_publish(wifi_app->rbus_handle, mac_address, 1);

        scheduler_add_timer_task(ctrl->sched, FALSE, &(levl_sc_data->sched_handler_id),
                process_levl_sounding_timeout, t_data, levl_sc_data->duration, 1, FALSE);
        hash_map_put(curr_map, strdup(mac_str), levl_sc_data);
    } else {
        //Push MAC to pending queue
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Pushing to Pending list MAC %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, __LINE__,
                           mac_address[0],mac_address[1],mac_address[2],mac_address[3],mac_address[4],mac_address[5]);
        hash_map_put(p_map, strdup(mac_str), levl_sc_data);
    }
    return RETURN_OK;
}

void levl_csi_publish(mac_address_t mac_address, wifi_csi_dev_t *csi_dev_data)
{
    char eventName[MAX_EVENT_NAME_SIZE];
    wifi_app_t *wifi_app = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr;
    apps_mgr = &ctrl->apps_mgr;
    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL wifi_app pointer\n", __func__, __LINE__);
        return;
    }
    // Construct Header.
    unsigned int total_length, num_csi_clients, csi_data_length, curr_length = 0;
    time_t datetime;
    char *header = csi_dev_data->header;
    memcpy(header, "CSI", (strlen("CSI") + 1));
    curr_length = curr_length + strlen("CSI") + 1;
    total_length = sizeof(time_t) + (sizeof(unsigned int)) +
        (1 * (sizeof(mac_addr_t) + sizeof(unsigned int) + sizeof(wifi_csi_data_t)));
    memcpy((header + curr_length), &total_length, sizeof(unsigned int));
    curr_length = curr_length + sizeof(unsigned int);
    datetime = time(NULL);
    memcpy((header + curr_length), &datetime, sizeof(time_t));
    curr_length = curr_length + sizeof(time_t);
    num_csi_clients = 1;
    memcpy((header + curr_length), &num_csi_clients, sizeof(unsigned int));
    curr_length = curr_length + sizeof(unsigned int);
    memcpy((header + curr_length), csi_dev_data->sta_mac, sizeof(mac_addr_t));
    curr_length = curr_length + sizeof(mac_addr_t);
    csi_data_length = sizeof(wifi_csi_data_t);
    memcpy((header + curr_length), &csi_data_length, sizeof(unsigned int));
    int buffer_size = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t);
    if (wifi_app->data.u.levl.csi_over_fifo == false) {
        strncpy(eventName, "Device.WiFi.X_RDK_CSI_LEVL.data", sizeof(eventName) - 1);
        // Publish using new API
        rbusEventRawData_t event_data;
        event_data.name = eventName;
        event_data.rawData = csi_dev_data->header;
        event_data.rawDataLen = buffer_size;
        rbusEvent_PublishRawData(wifi_app->rbus_handle, &event_data);
    } else {
        if (wifi_app->data.u.levl.csi_fd < 0) {
            wifi_app->data.u.levl.csi_fd = open(CSI_LEVL_PIPE, O_WRONLY);
            if (wifi_app->data.u.levl.csi_fd < 0) {
                wifi_util_error_print(WIFI_APPS, "%s(): Failed to open pipe reason %s\n", __func__,
                    strerror(errno));
                return;
            }
        }
        if ((write(wifi_app->data.u.levl.csi_fd, header, buffer_size) < 0)) {
            wifi_util_error_print(WIFI_APPS, "%s:%d Messed up write error is %s\n", __func__,
                __LINE__, strerror(errno));
            return;
        }
    }

    return;
}

static bool levl_check_timeout(levl_sched_data_t *sched_data, struct timeval *t_now)
{
    struct timeval interval;
    int  interval_ms_margin;
    struct timeval timeout;

    if (sched_data == NULL || t_now == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s: Invalid arguments. sched_data %p and t_now %p\n", __func__, sched_data, t_now);
        return FALSE;
    }

    interval_ms_margin = sched_data->interval - (MIN_CSI_INTERVAL/2);

    interval.tv_sec = (interval_ms_margin / 1000);
    interval.tv_usec = (interval_ms_margin % 1000) * 1000;

    timeradd(&sched_data->last_time_publish, &interval, &timeout);

    if (timercmp(t_now, &timeout, >)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

int process_levl_csi(wifi_app_t *app, wifi_csi_dev_t *csi_data)
{
    mac_address_t mac_addr;
    mac_addr_str_t mac_str = { 0 };
    struct timeval t_now = {0};
    memset(mac_addr, 0, sizeof(mac_address_t));
    memcpy(mac_addr, csi_data->sta_mac, sizeof(mac_address_t));

    to_mac_str((unsigned char *)mac_addr, mac_str);
    if (app->data.u.levl.curr_sounding_mac_map != NULL) {
        if (hash_map_get(app->data.u.levl.curr_sounding_mac_map, mac_str) == NULL) {
            //Not subscribed by Levl app
            return RETURN_OK;
        }
    }
    wifi_util_dbg_print(WIFI_APPS, "%s: Levl CSI data received - MAC  %02x:%02x:%02x:%02x:%02x:%02x\n",__func__, mac_addr[0], mac_addr[1],
                                                        mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    //publish only when interval reaches apps->data.u.levl.publish_interval
    levl_sched_data_t *levl_sc_data = NULL;
    to_mac_str(mac_addr, mac_str);
    levl_sc_data = (levl_sched_data_t *)hash_map_get(app->data.u.levl.curr_sounding_mac_map, mac_str);

    if (levl_sc_data == NULL) {
        return RETURN_ERR;
    }
    //calculate timeout with current time and last time publish
    gettimeofday(&t_now, NULL);

    if ((levl_sc_data->interval == 0) || levl_check_timeout(levl_sc_data, &t_now)) {
        levl_csi_publish(mac_addr, csi_data);
        levl_sc_data->last_time_publish = t_now;
    }

    return RETURN_OK;
}

void levl_disassoc_device_event(wifi_app_t *apps, void *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;
    levl_sched_data_t *levl_sc_data = NULL;
    hash_map_t *p_map = NULL, *curr_map = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr = NULL;
    mac_addr_str_t mac_str;
    wifi_app_t *wifi_app =  NULL;
    apps_mgr = &ctrl->apps_mgr;

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    wifi_app_t *csi_app = wifi_app->data.u.levl.csi_app;
    if (csi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    p_map = wifi_app->data.u.levl.pending_mac_map;
    curr_map = wifi_app->data.u.levl.curr_sounding_mac_map;
    if ((curr_map == NULL) || (p_map == NULL)) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL hash map Unable to handle disassoc\n", __func__, __LINE__);
        return;
    }

    to_mac_str((unsigned char *)assoc_data->dev_stats.cli_MACAddress, mac_str);

    if (wifi_app->data.u.levl.num_current_sounding > 0) {
        --(wifi_app->data.u.levl.num_current_sounding);
    } else {
        wifi_app->data.u.levl.num_current_sounding = 0;
    }

    levl_sc_data = (levl_sched_data_t *)hash_map_get(curr_map, mac_str);
    if (levl_sc_data != NULL) {
        //Cancel scheduler Task
        if (levl_sc_data->sched_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, levl_sc_data->sched_handler_id);
            levl_sc_data->sched_handler_id = 0;
        }
        //Disable CSI Sounding
        pthread_mutex_unlock(&apps->data.u.levl.lock);
        wifi_util_error_print(WIFI_APPS,"%s:%d Disabling Sounding for MAC %02x:...:%02x\n", __func__, __LINE__,
                assoc_data->dev_stats.cli_MACAddress[0],assoc_data->dev_stats.cli_MACAddress[5]);
        csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, assoc_data->ap_index, assoc_data->dev_stats.cli_MACAddress, wifi_app_inst_levl);
        levl_csi_status_publish(wifi_app->rbus_handle, assoc_data->dev_stats.cli_MACAddress, 0);
        pthread_mutex_lock(&apps->data.u.levl.lock);
    }

    levl_sc_data = (levl_sched_data_t *)hash_map_remove(curr_map, mac_str);
    if (levl_sc_data != NULL) {
        free(levl_sc_data);
    }

    levl_sc_data = (levl_sched_data_t *)hash_map_get(p_map, mac_str);
    if (levl_sc_data  != NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Removing from Pending List\n", __func__, __LINE__);
        levl_sc_data = (levl_sched_data_t *)hash_map_remove(p_map, mac_str);
        if (levl_sc_data != NULL) {
            free(levl_sc_data);
        }
    }

    return;
}

int levl_event_webconfig_set_data(wifi_app_t *apps, void *arg, wifi_event_subtype_t sub_type)
{
    int ap_index = 0;
    int max_value = 0;
    levl_config_t *levl_config = NULL;
    mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    webconfig_subdoc_data_t *doc = (webconfig_subdoc_data_t *)arg;
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;

    decoded_params = &doc->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Decoded data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    switch(doc->type) {
        case webconfig_subdoc_type_levl:
            levl_config = &decoded_params->levl;
            if (levl_config == NULL) {
                wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL pointer \n", __func__, __LINE__);
                return RETURN_ERR;
            }
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Received config Client num %d, Client MAC %02x:... %02x publish interval %d sounding duration %d\n", __func__, __LINE__,
                    levl_config->max_num_csi_clients, levl_config->clientMac[0], levl_config->clientMac[5], levl_config->levl_publish_interval, levl_config->levl_sounding_duration);
            if (levl_config->max_num_csi_clients == 0) {
                max_value = MAX_LEVL_CSI_CLIENTS;
            } else {
                max_value = levl_config->max_num_csi_clients;
            }
            apps->data.u.levl.max_num_csi_clients = max_value;
            if (levl_config->levl_sounding_duration != apps->data.u.levl.sounding_duration) {
                apps->data.u.levl.sounding_duration = levl_config->levl_sounding_duration;
            }

            if (levl_config->levl_publish_interval != apps->data.u.levl.publish_interval) {
                apps->data.u.levl.publish_interval = levl_config->levl_publish_interval;
            }
            if (memcmp(null_mac, levl_config->clientMac, sizeof(mac_address_t)) != 0) {
                ap_index = get_ap_index_from_clientmac(levl_config->clientMac);
                if (ap_index < 0) {
                    wifi_util_dbg_print(WIFI_APPS,"%s:%d Client is not connected not pushing to queue\n", __func__, __LINE__);
                } else {
                    schedule_mac_for_sounding(ap_index, levl_config->clientMac, levl_config->levl_sounding_duration, levl_config->levl_publish_interval);
                }
            }
            break;
        default:
            break;
    }

    return RETURN_OK;
}

void push_radio_temperature_request_to_monitor_queue(wifi_mon_stats_request_state_t state, int32_t interval, unsigned int radio_index)
{
    wifi_monitor_data_t *data;
    data = (wifi_monitor_data_t *)malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        return;
    }

    memset(data, 0, sizeof(wifi_monitor_data_t));
    data->u.mon_stats_config.req_state = state;

    wifi_event_route_t route;
    memset(&route, 0, sizeof(wifi_event_route_t));
    route.dst = wifi_sub_component_mon;
    route.u.inst_bit_map = wifi_app_inst_levl;
    
    wifi_util_dbg_print(WIFI_APPS, "%s:%d Interval is %d\n", __func__, __LINE__, interval);
    data->u.mon_stats_config.interval_ms = interval;
    data->u.mon_stats_config.start_immediately = TRUE;

    data->u.mon_stats_config.data_type = mon_stats_type_radio_temperature;
    data->u.mon_stats_config.args.radio_index = radio_index;
    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
}

int webconfig_event_levl(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *data)
{
    switch(sub_type) {
        case wifi_event_webconfig_set_data:
        case wifi_event_webconfig_set_data_dml:
            levl_event_webconfig_set_data(apps, data, sub_type);
            break;
        default:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Not Processing\n", __func__, __LINE__);
            break;
    }
    return RETURN_OK;
}

int hal_event_levl(wifi_app_t *app, wifi_event_subtype_t sub_type, void *data)
{
    switch(sub_type) {
        case wifi_event_hal_probe_req_frame:
            apps_probe_req_frame_event(app, data);
            break;
        case wifi_event_hal_probe_rsp_frame:
            apps_probe_rsp_frame_event(app, data);
            break;
        case wifi_event_hal_auth_frame:
            apps_auth_frame_event(app, data);
            break;
        case wifi_event_hal_assoc_req_frame:
            apps_assoc_req_frame_event(app, data);
            break;
        case wifi_event_hal_assoc_rsp_frame:
            apps_assoc_rsp_frame_event(app, data);
            break;
        case wifi_event_hal_reassoc_req_frame:
            apps_reassoc_req_frame_event(app, data);
            break;
        case wifi_event_hal_reassoc_rsp_frame:
            apps_reassoc_rsp_frame_event(app, data);
            break;
        case wifi_event_hal_disassoc_device:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Got DisAssoc device for Levl\n", __func__, __LINE__);
            levl_disassoc_device_event(app, data);
            break;
        default:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d app sub_event:%d not handle\r\n", __func__, __LINE__, sub_type);
            break;
    }
    return RETURN_OK;
}

int levl_event_csi(wifi_app_t *app, wifi_event_subtype_t sub_type, wifi_csi_dev_t *csi)
{
    switch(sub_type) {
        case wifi_event_type_csi_data:
            process_levl_csi(app, csi);
            break;
        default:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d wrong apps event:%d\n", __func__, __LINE__, sub_type);
            break;
    }

    return RETURN_OK;
}

int process_csi_stop_levl(wifi_app_t *app)
{
    mac_addr_str_t mac_str = { 0 };
    levl_sched_data_t *tmp_data = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    levl_sched_data_t *levl_sched_data = NULL;
    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    wifi_app_t *csi_app = app->data.u.levl.csi_app;

    if (app->data.u.levl.curr_sounding_mac_map == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    levl_sched_data = (levl_sched_data_t *)hash_map_get_first(app->data.u.levl.curr_sounding_mac_map);
    while(levl_sched_data != NULL) {
        memset(mac_str, 0, sizeof(mac_addr_str_t));
        to_mac_str((unsigned char *)levl_sched_data->mac_addr, mac_str);
        if (levl_sched_data->sched_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, levl_sched_data->sched_handler_id);
            levl_sched_data->sched_handler_id = 0;
        }
        csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, levl_sched_data->ap_index, levl_sched_data->mac_addr, wifi_app_inst_levl);
        levl_csi_status_publish(app->rbus_handle, levl_sched_data->mac_addr, 0);
        levl_sched_data = hash_map_get_next(app->data.u.levl.curr_sounding_mac_map, levl_sched_data);
        tmp_data = (levl_sched_data_t *)hash_map_remove(app->data.u.levl.curr_sounding_mac_map, mac_str);
        hash_map_put(app->data.u.levl.pending_mac_map, strdup(mac_str), tmp_data);
    }
    return 0;
}

int process_csi_start_levl(wifi_app_t *app) 
{
    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    wifi_util_dbg_print(WIFI_APPS, "Calling %s\n", __func__);
    app->data.u.levl.paused = false;
    schedule_from_pending_map(app);
    return 0;
}

int process_speed_test_timeout_levl()
{
    wifi_app_t *app =  NULL;
    wifi_apps_mgr_t *apps_mgr;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    if (app->data.u.levl.paused) {
        process_csi_start_levl(app);
    }
    return 0;
}

int levl_event_speed_test(wifi_app_t *app, wifi_event_subtype_t sub_type, void *data)
{
    speed_test_data_t *speed_test_data = (speed_test_data_t *)data;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    if (speed_test_data->speed_test_running == 1) {
        app->data.u.levl.paused = true;
        process_csi_stop_levl(app);

        if (app->data.u.levl.sched_handler_id == 0) {
            app->data.u.levl.speed_test_timeout  = speed_test_data->speed_test_timeout;
            scheduler_add_timer_task(ctrl->sched, FALSE, &(app->data.u.levl.sched_handler_id),
                    process_speed_test_timeout_levl, NULL, (app->data.u.levl.speed_test_timeout)*1000, 1, FALSE);
        } else if ((app->data.u.levl.speed_test_timeout != speed_test_data->speed_test_timeout) && (app->data.u.levl.sched_handler_id > 0)) {
            app->data.u.levl.speed_test_timeout = speed_test_data->speed_test_timeout;
            scheduler_update_timer_task_interval(ctrl->sched, app->data.u.levl.sched_handler_id, (app->data.u.levl.speed_test_timeout)*1000);
        }
    } else if (speed_test_data->speed_test_running == 5) {
        if (app->data.u.levl.paused == true) {
            process_csi_start_levl(app);
        }
    }
    return 0;
}

int apps_frame_event_exec_timeout(wifi_app_t *apps)
{
    time_t l_curr_alive_time_sec, delta_time_sec;
    hash_map_t *probe_map = apps->data.u.levl.probe_req_map;
    probe_req_elem_t *l_elem = NULL, *l_temp_elem = NULL;

    if (probe_map == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d probe map is NULL\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    l_curr_alive_time_sec = get_current_time_in_sec();
    wifi_util_info_print(WIFI_APPS,"%s:%d current time in sec:%ld total probe entry:%d\r\n", __func__, __LINE__,
                                    l_curr_alive_time_sec, hash_map_count(probe_map));

    l_elem = hash_map_get_first(probe_map);
    while (l_elem != NULL) {
        delta_time_sec = l_curr_alive_time_sec - l_elem->curr_alive_time_sec;
        l_temp_elem = l_elem;
        l_elem = hash_map_get_next(probe_map, l_elem);
        if (delta_time_sec >= MAX_PROBE_TTL_TIME) {
            l_temp_elem = hash_map_remove(probe_map, l_temp_elem->mac_str);
            if (l_temp_elem != NULL) {
                wifi_util_info_print(WIFI_APPS,"%s:%d probe map entry removed for mac_str:%s\r\n", __func__, __LINE__, l_temp_elem->mac_str);
                free(l_temp_elem);
            }
        }
    }

    wifi_util_info_print(WIFI_APPS,"%s:%d total probe entry:%d\r\n", __func__, __LINE__, hash_map_count(probe_map));
    return 0;
}

int radio_temperature_response(wifi_provider_response_t *provider_response)
{
    wifi_app_t *wifi_app =  NULL;
    wifi_apps_mgr_t *apps_mgr = NULL;
    rbusObject_t inParams;
    rbusValue_t value;
    rbusEvent_t event;
    char eventName[64] = {0};
    unsigned int radio_index = provider_response->args.radio_index;
    int rc = RBUS_ERROR_SUCCESS;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio_data_t *temperature_stats = (radio_data_t*) provider_response->stat_pointer;
    for(unsigned int count = 0; count < provider_response->stat_array_size; count++) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Radio temperature for radio%d is %u\n", __func__, __LINE__, radio_index, temperature_stats->radio_Temperature);
        rbusObject_Init(&inParams, NULL);
        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, temperature_stats->radio_Temperature);
        snprintf(eventName, sizeof(eventName), "Device.WiFi.Events.Radio.%u.Temperature", radio_index+1);
        rbusObject_SetValue(inParams, eventName, value);

        event.name = eventName;
        event.data = inParams;
        event.type = RBUS_EVENT_GENERAL;

        rc = rbusEvent_Publish(wifi_app->rbus_handle, &event);
        if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
            wifi_util_error_print(WIFI_APPS, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);
            return RETURN_ERR;
        } else {
            wifi_util_dbg_print(WIFI_APPS, "%s:%d: rbusEvent_Publish Event for %s %s\n", __func__, __LINE__, eventName, value);
        }
        rbusValue_Release(value);
        rbusObject_Release(inParams);
    }
    return RETURN_OK;
}

int set_radio_temperature_rbus(wifi_app_t *app, wifi_event_t *event)
{
    wifi_provider_response_t    *provider_response;
    provider_response = (wifi_provider_response_t *)event->u.provider_response;
    int ret = RETURN_ERR;
    if (provider_response == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d input event is NULL\r\n", __func__, __LINE__);
        return ret;
    }


    switch(provider_response->data_type) {
        case mon_stats_type_radio_temperature:
            ret = radio_temperature_response(provider_response);
        break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d Invalid data type %d\r\n", __func__, __LINE__, provider_response->data_type);
    }
    return ret;
}

void monitor_radio_temperature(wifi_app_t *app, wifi_event_t *event)
{
    switch(event->sub_type) {
        case wifi_event_monitor_provider_response:
            set_radio_temperature_rbus(app, event);
        break;
        default:
        break;
    }
}

#ifdef ONEWIFI_LEVL_APP_SUPPORT
int levl_event(wifi_app_t *app, wifi_event_t *event)
{

    pthread_mutex_lock(&app->data.u.levl.lock);
    switch (event->event_type) {
        case wifi_event_type_hal_ind:
            hal_event_levl(app, event->sub_type, event->u.core_data.msg);
            break;
        case wifi_event_type_webconfig:
            webconfig_event_levl(app, event->sub_type, event->u.webconfig_data);
            break;
        case wifi_event_type_monitor:
            monitor_radio_temperature(app, event);
            break;
        case wifi_event_type_csi:
            levl_event_csi(app, event->sub_type, event->u.csi);
            break;
        case wifi_event_type_speed_test:
            levl_event_speed_test(app, event->sub_type, event->u.core_data.msg);
            break;
        default:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d wrong apps event:%d\n", __func__, __LINE__, event->event_type);
        break;
    }
    pthread_mutex_unlock(&app->data.u.levl.lock);

    return RETURN_OK;
}
#endif

int mgmt_frame_rbus_apply(rbusHandle_t rbus_handle, char *rbus_namespace, frame_data_t *l_data)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    int rc;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, rbus_namespace, value);
    rbusValue_SetBytes(value, (uint8_t *)l_data, (sizeof(l_data->frame) + l_data->frame.len));
    event.name = rbus_namespace;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    } else {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: rbusEvent_Publish Event for %s: len:%d\n", __func__, __LINE__, rbus_namespace, (sizeof(l_data->frame) + l_data->frame.len));
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return RETURN_OK;
}

int mgmt_frame_rbus_send(rbusHandle_t rbus_handle, char *rbus_namespace, frame_data_t *data)
{
    return (mgmt_frame_rbus_apply(rbus_handle, rbus_namespace, data));
}

#ifdef ONEWIFI_LEVL_APP_SUPPORT
int levl_update(wifi_app_t *app)
{
    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    //Only handling RFC as of NOW
    if (app->desc.inst != wifi_app_inst_levl) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: Unknown app instance\n", __func__, __LINE__);
        return -1;
    }
    if (app->desc.enable != app->desc.rfc) {
        app->desc.enable = app->desc.rfc;
        if (app->desc.enable) {
            levl_init(app, app->desc.create_flag);
        } else {
            levl_deinit(app);
        }
    }
    return 0;
}

int levl_deinit(wifi_app_t *app)
{
    //Going for a TearDown.
    int rc = RBUS_ERROR_SUCCESS;
    mac_addr_str_t mac_str;
    levl_sched_data_t *levl_sched_data = NULL;
    probe_req_elem_t *probe_data = NULL;
    void *tmp_data = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_util_info_print(WIFI_APPS, "%s:%d: Deinit Levl\n", __func__, __LINE__);

    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    app_deinit(app, app->desc.create_flag);
    pthread_mutex_lock(&app->data.u.levl.lock);

    //Cancel scheduler Task
    if (app->data.u.levl.probe_collector_sched_handler_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, app->data.u.levl.probe_collector_sched_handler_id);
        app->data.u.levl.probe_collector_sched_handler_id = 0;
    }

    for (unsigned int radio_idx = 0; radio_idx < MAX_NUM_RADIOS; radio_idx++) {
        if (app->data.u.levl.temperature_event_subscribed[radio_idx] == TRUE) {
            app->data.u.levl.temperature_event_subscribed[radio_idx] = FALSE;
            push_radio_temperature_request_to_monitor_queue(mon_stats_request_state_stop, MIN_TEMPERATURE_INTERVAL_MS, radio_idx);
        }
    }

    //Cancel all Sounding.
    app->data.u.levl.csi_event_subscribed = FALSE;
    wifi_app_t *csi_app = app->data.u.levl.csi_app;
    if (csi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&app->data.u.levl.lock);
        return -1;
    }

    wifi_util_dbg_print(WIFI_APPS, "%s:%d: Cancelling all Levl Sounding\n", __func__, __LINE__);
    levl_sched_data = (levl_sched_data_t *)hash_map_get_first(app->data.u.levl.curr_sounding_mac_map);
    while(levl_sched_data != NULL) {
        memset(mac_str, 0, sizeof(mac_addr_str_t));
        to_mac_str((unsigned char *)levl_sched_data->mac_addr, mac_str);
        if (levl_sched_data->sched_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, levl_sched_data->sched_handler_id);
        }
        csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, levl_sched_data->ap_index, levl_sched_data->mac_addr, wifi_app_inst_levl);
        levl_csi_status_publish(app->rbus_handle, levl_sched_data->mac_addr, 0);
        levl_sched_data = hash_map_get_next(app->data.u.levl.curr_sounding_mac_map, levl_sched_data);
        tmp_data = (levl_sched_data_t *)hash_map_remove(app->data.u.levl.curr_sounding_mac_map, mac_str);
        if (tmp_data != NULL) {
            free(tmp_data);
        }
    }
    hash_map_destroy(app->data.u.levl.curr_sounding_mac_map);

    levl_sched_data = (levl_sched_data_t *)hash_map_get_first(app->data.u.levl.pending_mac_map);
    while(levl_sched_data != NULL) {
        memset(mac_str, 0, sizeof(mac_addr_str_t));
        to_mac_str((unsigned char *)levl_sched_data->mac_addr, mac_str);
        levl_sched_data = hash_map_get_next(app->data.u.levl.pending_mac_map, levl_sched_data);
        tmp_data = (levl_sched_data_t *)hash_map_remove(app->data.u.levl.pending_mac_map, mac_str);
        if (tmp_data !=  NULL) {
            free(tmp_data);
        }
    }
    hash_map_destroy(app->data.u.levl.pending_mac_map);

    probe_data = (probe_req_elem_t *)hash_map_get_first(app->data.u.levl.probe_req_map);
    while(probe_data != NULL) {
        memset(mac_str, 0, sizeof(mac_addr_str_t));
        memcpy(mac_str, probe_data->mac_str, sizeof(mac_addr_str_t));
        probe_data = hash_map_get_next(app->data.u.levl.probe_req_map, probe_data);
        tmp_data = hash_map_remove(app->data.u.levl.probe_req_map, mac_str);
        if (tmp_data != NULL) {
            free(tmp_data);
        }
    }
    hash_map_destroy(app->data.u.levl.probe_req_map);

    rc = rbus_close(app->rbus_handle);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: Unable to close Levl rbus handle\n", __func__, __LINE__);
    }
    
    unlink(CSI_LEVL_PIPE);
    if (app->data.u.levl.csi_fd >=0 ) {
        close(app->data.u.levl.csi_fd);
        app->data.u.levl.csi_fd = -1;
    }

    pthread_mutex_unlock(&app->data.u.levl.lock);
    pthread_mutex_destroy(&app->data.u.levl.lock);
    if (app->queue != NULL) {
        queue_destroy(app->queue);
    }

    return RETURN_OK;
}
#endif

rbusError_t levl_get_handler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(opts);
    char const* name;
    rbusValue_t value;
    int max_value = 0, duration = 0;
    char parameter[MAX_EVENT_NAME_SIZE];
    wifi_app_t *wifi_app =  NULL;
    wifi_apps_mgr_t *apps_mgr = NULL;
    mac_address_t null_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    name = rbusProperty_GetName(property);
    if (!name) {
        wifi_util_dbg_print(WIFI_CTRL, "%s(): invalid property name : %s \n", __FUNCTION__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, name);
    sscanf(name, "Device.WiFi.X_RDK_CSI_LEVL.%200s", parameter);
    rbusValue_Init(&value);

    if (strcmp(parameter, "clientMac") == 0) {
        char mac_string[18];
        memset(mac_string, 0, 18);
        to_mac_str(null_mac, mac_string);
        rbusValue_SetString(value, mac_string);
    } else if(strcmp(parameter, "maxNumberCSIClients") == 0) {
        if (wifi_app->data.u.levl.max_num_csi_clients == 0) {
            max_value = MAX_LEVL_CSI_CLIENTS;
        } else {
            max_value = wifi_app->data.u.levl.max_num_csi_clients;
        }

        rbusValue_SetUInt32(value, max_value);
    } else if(strcmp(parameter, "Duration") == 0) {
        if (wifi_app->data.u.levl.sounding_duration == 0) {
            duration = DEFAULT_SOUNDING_DURATION_MS;
        } else {
            duration = wifi_app->data.u.levl.sounding_duration;
        }
        rbusValue_SetUInt32(value, duration);
    } else if (strcmp(parameter, "clientMacData") == 0) {
        char buff[32] = {0};
        snprintf(buff, sizeof(buff), " ");
        rbusValue_SetString(value, buff);
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return RBUS_ERROR_SUCCESS;
}

void update_levl_config_from_levl_config(levl_config_t *levl) 
{
    wifi_app_t *wifi_app =  NULL;
    wifi_apps_mgr_t *apps_mgr = NULL;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }


    levl->max_num_csi_clients = wifi_app->data.u.levl.max_num_csi_clients;
    levl->levl_sounding_duration = wifi_app->data.u.levl.sounding_duration;

    return;
}

rbusError_t levl_set_handler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)opts;
    char const* name;
    rbusValue_t value;
    rbusValueType_t type;
    int len = 0, levl_sounding_duration = 0;
    char const* pTmp = NULL;
    char parameter[MAX_EVENT_NAME_SIZE];
    unsigned int csinum = 0;
    levl_config_t *levl = NULL;

    name = rbusProperty_GetName(property);
    value = rbusProperty_GetValue(property);
    type = rbusValue_GetType(value);

    if (!name) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: invalid rbus property name %s\n", __FUNCTION__, __LINE__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }
    levl = (levl_config_t *)malloc(sizeof(levl_config_t));
    if (levl == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: NULL Pointer\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }
    memset(levl, 0, sizeof(levl_config_t));
    update_levl_config_from_levl_config(levl);

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, name);

    sscanf(name, "Device.WiFi.X_RDK_CSI_LEVL.%200s", parameter);
    if (strcmp(parameter, "clientMac") == 0) {
        if (type != RBUS_STRING) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
            if (levl != NULL) {
                free(levl);
            }
            return RBUS_ERROR_INVALID_INPUT;
        }

        pTmp = rbusValue_GetString(value, &len);
        str_to_mac_bytes((char *)pTmp, levl->clientMac);
    } else if(strcmp(parameter, "maxNumberCSIClients") == 0) {
        if (type != RBUS_UINT32) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
            if (levl != NULL) {
                free(levl);
            }
            return RBUS_ERROR_INVALID_INPUT;
        }

        csinum = rbusValue_GetUInt32(value);
        if (csinum > MAX_LEVL_CSI_CLIENTS) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d Exceeds MAX_LEVL_CSI_CLIENTS\n", __func__, __LINE__);
            if (levl != NULL) {
                free(levl);
            }
            return RBUS_ERROR_INVALID_INPUT;
        }
        levl->max_num_csi_clients = csinum;
    } else if (strcmp(parameter, "Duration") == 0) {
        if (type != RBUS_UINT32) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
            if (levl != NULL) {
                free(levl);
            }
            return RBUS_ERROR_INVALID_INPUT;
        }
        levl_sounding_duration = rbusValue_GetUInt32(value);
        if (levl_sounding_duration == 0) {
            levl->levl_sounding_duration = DEFAULT_SOUNDING_DURATION_MS;
        } else {
            levl->levl_sounding_duration = levl_sounding_duration;
        }
    } else if (strcmp(parameter, "clientMacData") == 0) {
        if (type != RBUS_STRING) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
            if (levl != NULL) {
                free(levl);
            }
            return RBUS_ERROR_INVALID_INPUT;
        }
        char *mac_data = NULL, *saveptr = NULL, *ptr = NULL;
        int interval = 0, duration = 0;
        pTmp = rbusValue_GetString(value, &len);

        ptr = strdup(pTmp);
        mac_data = strtok_r(ptr, ";", &saveptr);
        if (mac_data != NULL)
            string_mac_to_uint8_mac(levl->clientMac, mac_data);

        mac_data = strtok_r(NULL, ";", &saveptr);
        if (mac_data != NULL) {
            interval = atoi(mac_data);
            if (interval < MIN_LEVL_PUBLISH_INTERVAL_MS) {
                wifi_util_error_print(WIFI_APPS, "%s:%d The publish interval should be at least %dms\n", __func__, __LINE__, MIN_LEVL_PUBLISH_INTERVAL_MS);
                free(levl);
                free(ptr);
                return RBUS_ERROR_INVALID_INPUT;
            }
            levl->levl_publish_interval = interval;
       }

        mac_data = strtok_r(NULL, ";", &saveptr);
        if (mac_data != NULL) {
            duration = atoi(mac_data);
            if (duration < MIN_LEVL_SOUNDING_DURATION_MS) {
                wifi_util_error_print(WIFI_APPS, "%s:%d The sounding duration should be at least %dms\n", __func__, __LINE__, MIN_LEVL_SOUNDING_DURATION_MS);
                free(levl);
                free(ptr);
                return RBUS_ERROR_INVALID_INPUT;
            }
            levl->levl_sounding_duration = duration;
        }

        free(ptr);
    }

    push_levl_data_dml_to_ctrl_queue(&levl);
    if (levl != NULL) {
        free(levl);
    }
    return RBUS_ERROR_SUCCESS;
}

rbusError_t levl_event_handler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    unsigned int radio = 0;
    (void)handle;
    (void)filter;
    wifi_app_t *wifi_app = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    wifi_apps_mgr_t *apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_levl);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    *autoPublish = false;
    wifi_util_dbg_print(WIFI_APPS,"%s:%d eventSubHandler called: action=%s\n eventName=%s autoPublish:%d\n",
            __func__, __LINE__, action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe",
            eventName, *autoPublish);
    pthread_mutex_lock(&wifi_app->data.u.levl.lock);
    if(action == RBUS_EVENT_ACTION_SUBSCRIBE)
    {
        /* If radio temperature event, then start the request to collect data */
        if (strstr(eventName, "Temperature")) {
            if (interval < MIN_TEMPERATURE_INTERVAL_MS) {
                 wifi_util_info_print(WIFI_APPS,"%s:%d Subscribed interval is not valid(%d)\n", __func__, __LINE__, interval);
                pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
                return RBUS_ERROR_BUS_ERROR;
            }

            if (sscanf(eventName, "Device.WiFi.Events.Radio.%u.Temperature", &radio) != 1) {
                wifi_util_info_print(WIFI_APPS,"%s:%d Sscanf failed\n", __func__, __LINE__);
                pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
                return RBUS_ERROR_BUS_ERROR;
            }

            if ((radio < 0) || (radio > MAX_NUM_RADIOS)) {
                wifi_util_dbg_print(WIFI_APPS, "%s:%d Invalid Radio: %u\n", __func__, __LINE__, radio-1);
                pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
                return RBUS_ERROR_BUS_ERROR;
            }

            if (wifi_app->data.u.levl.temperature_event_subscribed[radio-1] == TRUE) {
                wifi_util_info_print(WIFI_APPS,"%s:%d Temperature event already subscribed for radio %u\n", __func__, __LINE__, radio-1);
                pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
                return RBUS_ERROR_BUS_ERROR;
            } else {
                wifi_app->data.u.levl.temperature_event_subscribed[radio-1] = TRUE;
                wifi_util_info_print(WIFI_APPS,"%s:%d Adding Subscription for radio %u with interval %d\n", __func__, __LINE__, radio-1, interval);
                wifi_app->data.u.levl.radio_temperature_interval[radio-1] = interval;
                push_radio_temperature_request_to_monitor_queue(mon_stats_request_state_start, interval, radio-1);
                pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
                return RBUS_ERROR_SUCCESS;
            }
        }
        if (strstr(eventName, "X_RDK_CSI_LEVL")) {
            if (wifi_app->data.u.levl.csi_event_subscribed == true){
                wifi_util_info_print(WIFI_APPS,"%s:%d Already Subscribed\n", __func__, __LINE__);
                pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
                return RBUS_ERROR_BUS_ERROR;
            }
            if (strstr(eventName, WIFI_LEVL_CSI_DATAFIFO)) {
                wifi_app->data.u.levl.csi_over_fifo = true;
                wifi_util_info_print(WIFI_APPS,"%s:%d Adding CSI Subscription over fifo\n", __func__, __LINE__);
            } else {
                wifi_app->data.u.levl.csi_over_fifo = false;
                wifi_util_info_print(WIFI_APPS,"%s:%d Adding CSI Subscription over rbus\n", __func__, __LINE__);
            }
            wifi_app->data.u.levl.csi_event_subscribed = true;
            pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
            return RBUS_ERROR_SUCCESS;
        }
    } else {
        if (strstr(eventName, "Temperature")) {
            if (sscanf(eventName, "Device.WiFi.Events.Radio.%u.Temperature", &radio) != 1) {
                wifi_util_error_print(WIFI_APPS, "%s:%d Sscanf failed\n", __func__, __LINE__);
                pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
                return RBUS_ERROR_BUS_ERROR;
            }
            wifi_util_info_print(WIFI_APPS,"%s:%d Removing subscription for radio %u\n", __func__, __LINE__, radio-1);
            if (wifi_app->data.u.levl.temperature_event_subscribed[radio-1] == TRUE) {
                wifi_app->data.u.levl.temperature_event_subscribed[radio-1] = FALSE;
                /* If radio temperature event, then stop the request to collect data */
                push_radio_temperature_request_to_monitor_queue(mon_stats_request_state_stop, wifi_app->data.u.levl.radio_temperature_interval[radio-1], radio-1);
            }
        }
        if (strstr(eventName, "X_RDK_CSI_LEVL")) {
            wifi_app->data.u.levl.csi_event_subscribed = FALSE;
            wifi_util_info_print(WIFI_APPS,"%s:%d Removing Subscription\n", __func__, __LINE__);
        }
    }
    pthread_mutex_unlock(&wifi_app->data.u.levl.lock);
    return RBUS_ERROR_SUCCESS;
}

rbusError_t levl_vap_addrowhandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum)
{
    static unsigned int instanceCounter = 1;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    unsigned int vap_index;

    if (instanceCounter > getTotalNumberVAPs(NULL)) {
        instanceCounter = 1;
    }
    vap_index  = VAP_INDEX(mgr->hal_cap, (instanceCounter-1)) + 1;
    *instNum = vap_index;
    instanceCounter++;

    wifi_util_dbg_print(WIFI_APPS, "%s(): %s %d\n", __FUNCTION__, tableName, *instNum);

    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(aliasName);
    return RBUS_ERROR_SUCCESS;
}


rbusError_t levl_vap_removerowhandler(rbusHandle_t handle, char const* rowName)
{
    wifi_util_dbg_print(WIFI_APPS, "%s(): %s\n", __FUNCTION__, rowName);

    UNREFERENCED_PARAMETER(handle);

    return RBUS_ERROR_SUCCESS;
}

int levl_start_fn(void* csi_app, unsigned int ap_index, mac_addr_t mac_addr, int sounding_app)
{
    return 0;
}

int levl_stop_fn(void* csi_app, unsigned int ap_index, mac_addr_t mac_addr, int sounding_app)
{
    return 0;
}

#ifdef ONEWIFI_LEVL_APP_SUPPORT
static int levl_event_exec_timeout(void* arg)
{
    if (arg == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d wifi_apps object is NULL\n", __func__, __LINE__);
        return RETURN_OK;
    }
    wifi_app_t *app = (wifi_app_t *)arg;

    apps_frame_event_exec_timeout(app);
    return RETURN_OK;
}
#endif

rbusError_t levl_radio_addrowhandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum)
{
    static int unsigned instanceCounter = 1;

    if (instanceCounter > getNumberRadios(NULL)) {
        instanceCounter = 1;
    }

    *instNum = instanceCounter;
    instanceCounter++;

    wifi_util_dbg_print(WIFI_APPS, "%s(): %s %u\n", __FUNCTION__, tableName, *instNum);

    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(aliasName);
    return RBUS_ERROR_SUCCESS;
}


rbusError_t levl_radio_removerowhandler(rbusHandle_t handle, char const* rowName)
{
    wifi_util_dbg_print(WIFI_APPS, "%s(): %s\n", __FUNCTION__, rowName);

    UNREFERENCED_PARAMETER(handle);

    return RBUS_ERROR_SUCCESS;
}

#ifdef ONEWIFI_LEVL_APP_SUPPORT
int levl_init(wifi_app_t *app, unsigned int create_flag)
{
    int rc = RBUS_ERROR_SUCCESS;
    unsigned int index = 0;
    char *component_name = "WifiAppsLevl";

    rbusDataElement_t dataElements[] = {
        { WIFI_EVENTS_VAP_TABLE, RBUS_ELEMENT_TYPE_TABLE,
            { NULL, NULL, levl_vap_addrowhandler, levl_vap_removerowhandler, NULL, NULL }},
        { WIFI_ANALYTICS_DATA_EVENTS, RBUS_ELEMENT_TYPE_METHOD,
            { NULL, NULL, NULL, NULL, NULL, NULL }},
        { WIFI_ANALYTICS_FRAME_EVENTS, RBUS_ELEMENT_TYPE_METHOD,
            { NULL, NULL, NULL, NULL, NULL, NULL }},
        { WIFI_LEVL_CSI_DATA, RBUS_ELEMENT_TYPE_EVENT,
            { NULL, NULL, NULL, NULL, levl_event_handler, NULL }},
        { WIFI_LEVL_CSI_DATAFIFO, RBUS_ELEMENT_TYPE_EVENT,
            { NULL, NULL, NULL, NULL, levl_event_handler, NULL }},
        { WIFI_LEVL_CLIENTMAC, RBUS_ELEMENT_TYPE_PROPERTY,
            { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}},
        { WIFI_LEVL_NUMBEROFENTRIES, RBUS_ELEMENT_TYPE_PROPERTY,
            { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}},
        { WIFI_LEVL_SOUNDING_DURATION, RBUS_ELEMENT_TYPE_PROPERTY,
            { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}},
        { WIFI_LEVL_CSI_MAC_DATA, RBUS_ELEMENT_TYPE_PROPERTY,
            { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}},
        { WIFI_LEVL_CSI_STATUS, RBUS_ELEMENT_TYPE_EVENT,
            { NULL, NULL, NULL, NULL, NULL, NULL }},
        { RADIO_LEVL_TEMPERATURE_TABLE, RBUS_ELEMENT_TYPE_TABLE,
            { NULL, NULL, levl_radio_addrowhandler, levl_radio_removerowhandler, NULL, NULL}},
        { RADIO_LEVL_TEMPERATURE_EVENT, RBUS_ELEMENT_TYPE_EVENT,
            { NULL, NULL, NULL, NULL, levl_event_handler, NULL }}
    };

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: Init Levl\n", __func__, __LINE__);

    wifi_app_t *csi_app = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_apps_mgr_t *apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    csi_app = get_app_by_inst(apps_mgr, wifi_app_inst_csi);
    if (csi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL CSI app instance\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    app->data.u.levl.csi_app = csi_app;
    app->data.u.levl.csi_fns.csi_start_fn = levl_start_fn;
    app->data.u.levl.csi_fns.csi_stop_fn = levl_stop_fn;
    app->data.u.levl.probe_req_map = hash_map_create();
    app->data.u.levl.curr_sounding_mac_map = hash_map_create();
    app->data.u.levl.pending_mac_map = hash_map_create();
    app->data.u.levl.postpone_sched_handler_id = 0;
    if ((app->data.u.levl.curr_sounding_mac_map == NULL) || (app->data.u.levl.pending_mac_map == NULL)) {
        wifi_util_error_print(WIFI_APPS,"%s:%d Unable to create hash map\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    app->data.u.levl.max_num_csi_clients = MAX_LEVL_CSI_CLIENTS;
    app->data.u.levl.sounding_duration = DEFAULT_SOUNDING_DURATION_MS;
    app->data.u.levl.num_current_sounding = 0;
    app->data.u.levl.csi_event_subscribed = FALSE;
    for (unsigned int radio = 0; radio < MAX_NUM_RADIOS; radio++) {
        app->data.u.levl.temperature_event_subscribed[radio] = FALSE;
    }
    pthread_mutex_init(&app->data.u.levl.lock, NULL);

    scheduler_add_timer_task(ctrl->sched, FALSE, &(app->data.u.levl.probe_collector_sched_handler_id),
                               levl_event_exec_timeout, app, (APPS_FRAME_EXEC_TIMEOUT_PERIOD * 1000), 0, FALSE);

    //Create FIFO for the csi.
    mkfifo(CSI_LEVL_PIPE, 0777);
    app->data.u.levl.csi_fd = -1;
 
    rc = rbus_open(&app->rbus_handle, component_name);
    if (rc != RBUS_ERROR_SUCCESS) {
        return RETURN_ERR;
    }

    rc = rbus_regDataElements(app->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d rbus_regDataElements failed\n", __func__, __LINE__);
        rbus_unregDataElements(app->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
        rbus_close(app->rbus_handle);
        return RETURN_ERR;
    } else {
        wifi_util_info_print(WIFI_APPS,"%s:%d Apps rbus_regDataElement success\n", __func__, __LINE__);
    }

    for (unsigned int radio_index = 1; radio_index <= getNumberRadios(NULL); radio_index++) {
        rc = rbusTable_addRow(app->rbus_handle, "Device.WiFi.Events.Radio.", NULL, NULL);
        if(rc != RBUS_ERROR_SUCCESS) {
            wifi_util_info_print(WIFI_APPS, "%s() rbusTable_addRow failed %d\n", __FUNCTION__, rc);
        }
    }

    for (index = 1; index <= getTotalNumberVAPs(NULL); index++) {
        rc = rbusTable_addRow(app->rbus_handle, "Device.WiFi.Events.VAP.", NULL, NULL);
        if(rc != RBUS_ERROR_SUCCESS) {
            wifi_util_error_print(WIFI_APPS, "%s() rbusTable_addRow failed %d!\n", __FUNCTION__, rc);
            rbus_unregDataElements(app->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
            rbus_close(app->rbus_handle);
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
}
#endif

