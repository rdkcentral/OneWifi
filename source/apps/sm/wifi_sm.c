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

#include <stdbool.h>
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_sm.h"

int monitor_event_sm(wifi_app_t *apps, wifi_event_t *event)
{
    wifi_util_dbg_print(WIFI_APPS,"%s:%d: event handled[%d]\r\n",__func__, __LINE__, event->sub_type);

    /*TODO: to be implemented*/
    switch (event->sub_type) {
        case wifi_event_monitor_data_collection_response:
        break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, event->sub_type);
        break;
    }

    return RETURN_OK;
}

int webconfig_event_sm(wifi_app_t *apps, wifi_event_t *event)
{
    stats_config_t *stat_config_entry;
    hash_map_t *stats_config_map = event->u.webconfig_data->u.decoded.stats_config_map;

    wifi_util_dbg_print(WIFI_APPS,"%s:%d: event handled[%d]\r\n",__func__, __LINE__, event->event_type);

    if (stats_config_map != NULL) {
        stat_config_entry = hash_map_get_first(stats_config_map);
        while (stat_config_entry != NULL) {
            switch (stat_config_entry->stats_type) {
                case stats_type_neighbor:
                case stats_type_survey:
                case stats_type_client:
                case stats_type_capacity:
                case stats_type_radio:
                case stats_type_essid:
                case stats_type_quality:
                case stats_type_device:
                case stats_type_rssi:
                case stats_type_steering:
                case stats_type_client_auth_fails:
                    push_event_to_monitor_queue(&event->u.mon_data, wifi_event_monitor_data_collection_config, NULL);
                break;
                default:
                    wifi_util_error_print(WIFI_APPS,"%s:%d app sub_event:%d not handle\r\n", __func__, __LINE__, event->sub_type);
                break;
            }
            stat_config_entry = hash_map_get_next(stats_config_map, stat_config_entry);
        }
    }

    return RETURN_OK;
}

int sm_init(wifi_app_t *app, unsigned int create_flag)
{
    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int sm_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}

int sm_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
        case wifi_event_type_webconfig:
            //webconfig_event_sm(app, event);
        break;
        case wifi_event_type_monitor:
            // monitor_event_sm(app, event);
        break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, event->sub_type);
        break;
    }

    return RETURN_OK;
}
