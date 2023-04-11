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
#include "wifi_apps_mgr.h"
#include "wifi_cac.h"
#include "wifi_hal_rdk_framework.h"
#include "wifi_monitor.h"
#include <rbus.h>

int cac_event(wifi_app_t *app, wifi_event_t *event)
{
    return RETURN_OK;
}

int cac_init(wifi_app_t *app, unsigned int create_flag)
{
    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    return 0;
}

int cac_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}
