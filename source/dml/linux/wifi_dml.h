/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

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

#ifndef _WIFI_DML_H_
#define _WIFI_DML_H_

#include <stdint.h>
#include "stdbool.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" 
{
#endif

#define WIFI_PSM_DB_NAMESPACE         "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WiFi-PSM-DB.Enable"
#define LAST_REBOOT_REASON_NAMESPACE  "Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason"
#define INACTIVE_FIRMWARE_NAMESPACE   "Device.DeviceInfo.X_RDKCENTRAL-COM_InActiveFirmware"

typedef void (* wifi_start_dml_t)();
typedef void (* wifi_set_dml_init_status_t)(bool status);
typedef void (* wifi_ssp_init_t)();
typedef int (* push_data_to_ssp_queue_t)(const void *msg, unsigned int len, uint32_t type, uint32_t sub_type);

typedef struct {
    wifi_start_dml_t                 start_dml_fn;
    wifi_set_dml_init_status_t       set_dml_init_status_fn;
    wifi_ssp_init_t                  ssp_init_fn;
    push_data_to_ssp_queue_t         push_data_to_ssp_queue_fn;
} wifidml_desc_t;

typedef struct {
    wifidml_desc_t                  desc;
    struct {
        pthread_cond_t cv;
        bool condition;
    } dml_init_status;
} wifi_dml_t;

#ifdef __cplusplus
}
#endif

#endif //_WIFI_DML_H_
