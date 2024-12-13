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
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" 
{
#endif

#define WIFI_PSM_DB_NAMESPACE         "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WiFi-PSM-DB.Enable"
#define LAST_REBOOT_REASON_NAMESPACE  "Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason"
#define INACTIVE_FIRMWARE_NAMESPACE   "Device.DeviceInfo.X_RDKCENTRAL-COM_InActiveFirmware"

//extern char* Get_PSM_Record_Status(char *recName, char *strValue);
//extern int get_wifi_last_reboot_reason_psm_value(char *last_reboot_reason);

typedef enum {
    ssp_event_type_psm_read,
    ssp_event_type_psm_write,
    ssp_event_type_max
} ssp_event_type_t;

typedef enum {
    radio_config,
    radio_feature_config,
    vap_config,
    global_config,
    security_config,
    mac_config_add,
    mac_config_delete
} ssp_event_subtype_t;

typedef void (* wifi_start_dml_t)();
typedef void (* wifi_set_dml_init_status_t)(bool status);
typedef void (* wifi_ssp_init_t)();
typedef int (* push_data_to_ssp_queue_t)(const void *msg, unsigned int len, ssp_event_type_t type, ssp_event_subtype_t sub_type);

typedef struct {
    wifi_start_dml_t                 start_dml_fn;
    wifi_set_dml_init_status_t       set_dml_init_status_fn;
    wifi_ssp_init_t                  ssp_init_fn;
    push_data_to_ssp_queue_t         push_data_to_ssp_queue_fn;
} wifidml_desc_t;

typedef struct {
    pthread_t   tid;
    int         argc;
    char        **argv;
} wifi_ssp_t;

typedef struct {
    wifidml_desc_t                  desc;
    wifi_ssp_t                      ssp;
    struct {
        pthread_cond_t cv;
        bool condition;
    } dml_init_status;
} wifi_dml_t;

int push_data_to_ssp_queue(const void *msg, unsigned int len, uint32_t type, uint32_t sub_type);

#ifdef __cplusplus
}
#endif

#endif //_WIFI_DML_H_
