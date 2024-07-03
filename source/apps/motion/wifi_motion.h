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

#ifndef WIFI_MOTION_H
#define WIFI_MOTION_H

#include "wifi_csi.h"
#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_CSI_TABLE                      "Device.WiFi.X_RDK_CSI.{i}."
#define WIFI_CSI_DATA                       "Device.WiFi.X_RDK_CSI.{i}.data"
#define WIFI_CSI_CLIENTMACLIST              "Device.WiFi.X_RDK_CSI.{i}.ClientMaclist"
#define WIFI_CSI_ENABLE                     "Device.WiFi.X_RDK_CSI.{i}.Enable"
#define WIFI_CSI_NUMBEROFENTRIES            "Device.WiFi.X_RDK_CSINumberOfEntries"

typedef struct {
    csi_base_app_t       csi_fns;
    pthread_mutex_t      lock;
    rbusHandle_t         rbus_handle;
    int                  paused;
    int                  sched_handler_id;
    int                  speed_test_timeout;
    queue_t              *csi_session_queue;
    queue_t              *csi_data_queue;
    wifi_app_t           *csi_app;
} motion_data_t;

typedef struct {
    bool enable;
    bool subscribed;
    bool mac_is_connected[MAX_CSI_CLIENTS_PER_SESSION];
    int  csi_time_interval;
    int  no_of_mac;
    int  csi_sess_number;
    int  csi_fd;
    int  ap_index[MAX_CSI_CLIENTS_PER_SESSION];
    mac_address_t mac_list[MAX_CSI_CLIENTS_PER_SESSION];
    struct timeval last_publish_time[MAX_CSI_CLIENTS_PER_SESSION];
} __attribute__((__packed__)) csi_session_t;

#ifdef __cplusplus
}
#endif

#endif // WIFI_MOTION_H
