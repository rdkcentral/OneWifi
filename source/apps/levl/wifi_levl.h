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

#ifndef WIFI_LEVL_H
#define WIFI_LEVL_H

#include "wifi_csi.h"
#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PROBE_MAP_TTL    500
#define WIFI_LEVL_CLIENTMAC                 "Device.WiFi.X_RDK_CSI_LEVL.clientMac"
#define WIFI_LEVL_NUMBEROFENTRIES           "Device.WiFi.X_RDK_CSI_LEVL.maxNumberCSIClients"
#define WIFI_LEVL_CSI_DATA                  "Device.WiFi.X_RDK_CSI_LEVL.data"
#define WIFI_LEVL_SOUNDING_DURATION         "Device.WiFi.X_RDK_CSI_LEVL.Duration"

typedef struct {
    unsigned int    max_probe_ttl_cnt;
    mac_addr_str_t  mac_str;
} __attribute__((__packed__)) probe_ttl_data_t;

typedef struct {
    unsigned int       curr_time_alive;
    frame_data_t       msg_data;
    mac_addr_str_t     mac_str;
} __attribute__((__packed__)) probe_req_elem_t;

typedef struct {
    int           sched_handler_id;
    mac_address_t mac_addr;
    unsigned int  ap_index;
    int           request_count;
}levl_sched_data_t;

typedef struct {
    mac_address_t mac_addr;
    int ap_index;
}timeout_data_t;

typedef struct {
    int                  max_num_csi_clients;
    int                  num_current_sounding;
    int                  sounding_duration;
    bool                 event_subscribed;
    pthread_mutex_t      lock;
    hash_map_t           *probe_req_map;
    hash_map_t           *curr_sounding_mac_map;
    hash_map_t           *pending_mac_map;
    int                  sched_handler_id;
    int                  postpone_sched_handler_id;
    int                  paused;
    int                  speed_test_timeout;
    levl_config_t        levl;
    wifi_app_t           *csi_app;
    csi_base_app_t       csi_fns;
} levl_data_t;

typedef struct wifi_app wifi_app_t;

int levl_init(wifi_app_t *app, unsigned int create_flag);
int levl_deinit(wifi_app_t *app);
int levl_event(wifi_app_t *app, wifi_event_t *event);
int levl_update(wifi_app_t *app);

#ifdef __cplusplus
}
#endif

#endif // WIFI_LEVL_H
