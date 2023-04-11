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

void update_probe_map(wifi_app_t *app)
{
    probe_req_elem_t *elem, *tmp;
    struct ieee80211_mgmt *frame;
    mac_addr_str_t mac_str;
    char *str;
    hash_map_t *probe_map = app->data.u.probe_req_map;
    unsigned int max_probe_map_ttl_cnt = get_max_probe_ttl_cnt();
#if DML_SUPPORT
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    probe_ttl_data_t ttl_data;

    memset(&ttl_data, 0, sizeof(ttl_data));
#endif

    elem = (probe_req_elem_t *)hash_map_get_first(probe_map);
    while (elem != NULL) {
        tmp = elem;
        elem->curr_time_alive++;
        //wifi_util_dbg_print(WIFI_APPS,"%s:%d max probe ttl cnt:%d current probe ttl count:%d\r\n", __func__, __LINE__, max_probe_map_ttl_cnt, elem->curr_time_alive);

        if (tmp->curr_time_alive > max_probe_map_ttl_cnt) {
            frame = (struct ieee80211_mgmt *)tmp->msg_data.data;
            str = to_mac_str((unsigned char *)frame->sa, mac_str);

#if DML_SUPPORT
            ttl_data.max_probe_ttl_cnt = tmp->curr_time_alive;
            strcpy(ttl_data.mac_str, str);
            apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_hal_ind, wifi_event_hal_potential_misconfiguration, &ttl_data);
#endif

            if (str != NULL) {
                tmp = hash_map_remove(probe_map, str);
                if (tmp != NULL) {
                    free(tmp);
                }
            }
        }
        elem = (probe_req_elem_t *)hash_map_get_next(probe_map, elem);
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

    update_probe_map(app);

    frame = (struct ieee80211_mgmt *)msg->data;
    str = to_mac_str((unsigned char *)frame->sa, mac_str);
    if (str == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d mac str convert failure\r\n", __func__, __LINE__);
        return;
    }

    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d src mac:%s\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, str);

    if ((elem = (probe_req_elem_t *)hash_map_get(app->data.u.probe_req_map, mac_str)) == NULL) {
        elem = (probe_req_elem_t *)malloc(sizeof(probe_req_elem_t));
        memset(elem, 0, sizeof(probe_req_elem_t));
        memcpy(&elem->msg_data, msg, sizeof(frame_data_t));
        hash_map_put(app->data.u.probe_req_map, strdup(mac_str), elem);
    } else {
        memcpy(&elem->msg_data, msg, sizeof(frame_data_t));
    }
}

void apps_probe_rsp_frame_event(wifi_app_t *app, frame_data_t *msg)
{
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi probe rsp mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __func__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}

void apps_auth_frame_event(wifi_app_t *app, frame_data_t *msg)
{
    //wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n",__FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
    mgmt_frame_rbus_send(app->rbus_handle, WIFI_ANALYTICS_FRAME_EVENTS, msg);
}


void apps_assoc_req_frame_event(wifi_app_t *app, frame_data_t *msg)
{
    struct ieee80211_mgmt *frame;
    mac_addr_str_t mac_str = { 0 };
    char *str;
    probe_req_elem_t *elem, *tmp;

    frame = (struct ieee80211_mgmt *)msg->data;
    str = to_mac_str(frame->sa, mac_str);
    if (str == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d mac str convert failure\r\n", __func__, __LINE__);
        return;
    }

    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d src mac:%s rssi:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, str, msg->frame.sig_dbm);


    if ((elem = (probe_req_elem_t *)hash_map_get(app->data.u.probe_req_map, mac_str)) == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d:probe not found for mac address:%s\n", __func__, __LINE__, str);
        //assert(1);
        // assoc request rbus send
        mgmt_frame_rbus_send(app->rbus_handle, WIFI_ANALYTICS_FRAME_EVENTS, msg);
    } else {
        // prob request rbus send
        mgmt_frame_rbus_send(app->rbus_handle, WIFI_ANALYTICS_FRAME_EVENTS, &elem->msg_data);

        // assoc request rbus send
        mgmt_frame_rbus_send(app->rbus_handle, WIFI_ANALYTICS_FRAME_EVENTS, msg);

        // remove prob request
        tmp = elem;
        frame = (struct ieee80211_mgmt *)tmp->msg_data.data;
        str = to_mac_str((unsigned char *)frame->sa, mac_str);
        if (str != NULL) {
            tmp = hash_map_remove(app->data.u.probe_req_map, str);
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
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi reassoc req mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
    mgmt_frame_rbus_send(apps->rbus_handle, WIFI_ANALYTICS_FRAME_EVENTS, msg);
}

void apps_reassoc_rsp_frame_event(wifi_app_t *apps, frame_data_t *msg)
{
    wifi_util_dbg_print(WIFI_APPS,"%s:%d wifi reassoc rsp mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n",
            __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}


int levl_event(wifi_app_t *app, wifi_event_t *event)
{

    frame_data_t *mgmt_data = (frame_data_t *)event->u.core_data.msg;

    wifi_util_dbg_print(WIFI_APPS,"%s:%d recv frame type:%d sub_type:%d\r\n", __func__, __LINE__, 
            event->event_type, event->sub_type);


    switch (event->event_type) {
        case wifi_event_type_hal_ind:
            switch (event->sub_type) {
                case wifi_event_hal_probe_req_frame:
                    apps_probe_req_frame_event(app, mgmt_data);
                break;
                case wifi_event_hal_probe_rsp_frame:
                    apps_probe_rsp_frame_event(app, mgmt_data);
                break;
                case wifi_event_hal_auth_frame:
                    apps_auth_frame_event(app, mgmt_data);
                break;
                case wifi_event_hal_assoc_req_frame:
                    apps_assoc_req_frame_event(app, mgmt_data);
                break;
                case wifi_event_hal_assoc_rsp_frame:
                    apps_assoc_rsp_frame_event(app, mgmt_data);
                break;
                case wifi_event_hal_reassoc_req_frame:
                    apps_reassoc_req_frame_event(app, mgmt_data);
                break;
                case wifi_event_hal_reassoc_rsp_frame:
                    apps_reassoc_rsp_frame_event(app, mgmt_data);
                break;
                default:
                    wifi_util_dbg_print(WIFI_APPS,"%s:%d app sub_event:%d not handle\r\n", __func__, __LINE__, event->sub_type);
                break;
            }
        break;
        default:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d wrong apps event:%d\n", __func__, __LINE__, event->event_type);
        break;
    }

    return RETURN_OK;
}

bool is_mgmt_frame_app_rbus_enabled(void)
{
    bool status;
    get_wifi_rfc_parameters(RFC_WIFI_MGMT_FRAME_RBUS, &status);

    return status;
}

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
    if (is_mgmt_frame_app_rbus_enabled()) {
        return (mgmt_frame_rbus_apply(rbus_handle, rbus_namespace, data));
    }

    return RETURN_OK;
}


int levl_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}

int levl_init(wifi_app_t *app, unsigned int create_flag)
{
    int rc = RBUS_ERROR_SUCCESS;
    char *component_name = "WifiApps";
    rbusDataElement_t dataElements[] = {
        { WIFI_ANALYTICS_FRAME_EVENTS, RBUS_ELEMENT_TYPE_METHOD,
            { NULL, NULL, NULL, NULL, NULL, NULL }},
        { WIFI_ANALYTICS_DATA_EVENTS, RBUS_ELEMENT_TYPE_METHOD,
            { NULL, NULL, NULL, NULL, NULL, NULL }},
    };

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    app->data.u.probe_req_map = hash_map_create();
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

    return ((rc == RBUS_ERROR_SUCCESS) ? RETURN_OK : RETURN_ERR);
}
