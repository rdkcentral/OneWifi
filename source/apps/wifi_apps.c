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
#include "wifi_apps.h"
#include <rbus.h>

int wifi_apps_init(wifi_apps_t *apps, wifi_apps_type_t type)
{
    int ret = RETURN_ERR;
    wifi_mgr_t *wifi_mgr_obj = get_wifimgr_obj();

    memset(apps, 0, sizeof(wifi_apps_t));

    apps->type = type;
    apps->ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    apps->prop = &wifi_mgr_obj->hal_cap.wifi_prop;

    switch (type) {
        case wifi_apps_type_frame_dist:
            ret = wifi_apps_frame_dist_init(apps);
            break;
        case wifi_apps_type_analytics:
            ret = wifi_apps_analytics_init(apps);
            break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, type);
            break;
    }

    return ret;
}

wifi_apps_t *get_app_by_type(wifi_ctrl_t *ct, wifi_apps_type_t type)
{
    unsigned int i;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)ct;

    for (i = 0; i < wifi_apps_type_max; i++) {
        if (ctrl->fi_apps[i].type == type) {
            return &ctrl->fi_apps[i];
        }
    }

    return NULL;
}
