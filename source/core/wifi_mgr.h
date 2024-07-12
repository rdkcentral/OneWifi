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

#ifndef WIFI_MGR_H
#define WIFI_MGR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#if DML_SUPPORT
#include "ssp_main.h"
#endif // DML_SUPPORT
#include "wifi_base.h"
#include "wifi_db.h"
#if DML_SUPPORT
#endif // DML_SUPPORT
#include "wifi_ctrl.h"

#define WIFI_PSM_DB_NAMESPACE         "Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Feature.WiFi-PSM-DB.Enable"
#define LAST_REBOOT_REASON_NAMESPACE  "Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason"
#define INACTIVE_FIRMWARE_NAMESPACE   "Device.DeviceInfo.X_RDKCENTRAL-COM_InActiveFirmware"

typedef struct {
    wifi_db_t                       wifidb;
    pthread_mutex_t                 data_cache_lock;
    pthread_mutex_t                 lock;
    wifi_ctrl_t                     ctrl;
    wifi_global_config_t            global_config;
    wifi_hal_capability_t           hal_cap;
    queue_t                         *csi_data_queue;
    active_msmt_t                   blaster_config_global;
    rdk_wifi_radio_t                radio_config[MAX_NUM_RADIOS];
    bool                            is_db_update_required;
    hash_map_t                      *stats_config_map;
    hash_map_t                      *steering_config_map;
    hash_map_t                      *steering_client_map;
    hash_map_t                      *vif_neighbors_map;
#if DML_SUPPORT
    wifi_ssp_t                      ssp;
    wifi_dml_parameters_t           dml_parameters;
    wifi_rfc_dml_parameters_t       rfc_dml_parameters;
    struct {
        pthread_cond_t cv;
        bool condition;
    }                               dml_init_status;
#endif // DML_SUPPORT
    int                             db_version;
} wifi_mgr_t;

wifi_mgr_t *get_wifimgr_obj();
#if DML_SUPPORT
char* Get_PSM_Record_Status(char *recName, char *strValue);
#endif // DML_SUPPORT
#ifdef __cplusplus
}
#endif

#endif //WIFI_MGR_H
