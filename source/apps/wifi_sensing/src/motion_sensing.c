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
#include "wifi_util.h"
#include "wifi_events.h"
#include "wifi_apps_mgr.h"
#include "wifi_ctrl.h"
#include "motion_sensing.h"

sensing_app_obj_t *get_sensing_app_obj(void)
{
    wifi_app_t *app =  NULL;
    wifi_apps_mgr_t *apps_mgr;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_SENSING, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }

    apps_mgr = &ctrl->apps_mgr;
    app = get_app_by_inst(apps_mgr, wifi_app_inst_wifi_sensing);
    if (app == NULL) {
        wifi_util_error_print(WIFI_SENSING,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }

    return &app->data.u.sensing_obj;
}

void sensing_app_assoc_device_event(wifi_app_t *apps, void *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_SENSING,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;

    if (isVapPrivate(assoc_data->ap_index)) {
        mac_addr_str_t str_sta_mac = { 0 };

        to_mac_str(assoc_data->dev_stats.cli_MACAddress, str_sta_mac);
        wifi_util_info_print(WIFI_SENSING,"%s:%d sta info:%s\n", __func__, __LINE__, str_sta_mac);
    }
}

void sensing_app_disassoc_device_event(wifi_app_t *apps, void *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_SENSING,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;

    if (isVapPrivate(assoc_data->ap_index)) {
        mac_addr_str_t str_sta_mac = { 0 };

        to_mac_str(assoc_data->dev_stats.cli_MACAddress, str_sta_mac);
        wifi_util_info_print(WIFI_SENSING,"%s:%d sta info:%s\n", __func__, __LINE__, str_sta_mac);
    }
}

int hal_event_for_sensing_app(wifi_app_t *app, wifi_event_subtype_t sub_type, void *data)
{
    switch (sub_type) {
    case wifi_event_hal_assoc_device:
        sensing_app_assoc_device_event(app, data);
        break;
    case wifi_event_hal_disassoc_device:
        sensing_app_disassoc_device_event(app, data);
        break;
    default:
        break;
    }
    return RETURN_OK;
}

int sensing_app_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
        case wifi_event_type_hal_ind:
            hal_event_for_sensing_app(app, event->sub_type, event->u.core_data.msg);
            break;

        default:
            break;
    }

    return RETURN_OK;
}

int sensing_app_init(wifi_app_t *app, unsigned int create_flag)
{
    wifi_util_info_print(WIFI_SENSING,"%s:%d wifi sensing app started...\n", __func__, __LINE__);
    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    return 0;
}

int sensing_app_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}
