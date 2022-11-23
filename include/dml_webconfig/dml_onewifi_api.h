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

#ifndef WIFI_WEBCONFIG_DML_H
#define WIFI_WEBCONFIG_DML_H

#include "rbus.h"
#include "wifi_webconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    webconfig_t		webconfig;
    wifi_global_config_t    config;
    wifi_hal_capability_t   hal_cap;
    rdk_wifi_radio_t    radios[MAX_NUM_RADIOS];
    rbusHandle_t	rbus_handle;	
} webconfig_dml_t;

#ifdef __cplusplus
}
#endif

#endif // WIFI_WEBCONFIG__DML_H
