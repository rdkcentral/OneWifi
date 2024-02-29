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

//Apps frame execution timeout period is 30 minutes
#define APPS_FRAME_EXEC_TIMEOUT_PERIOD    (30 * 60)
//Max probe ttl time is 5 minutes
#define MAX_PROBE_TTL_TIME   (5 * 60)
//Max probe entries
#define MAX_PROBE_ENTRIES    2000

#define MAX_PROBE_MAP_TTL    500
#define WIFI_EVENTS_VAP_TABLE               "Device.WiFi.Events.VAP.{i}."
#define WIFI_ANALYTICS_FRAME_EVENTS         "Device.WiFi.Events.VAP.{i}.Frames.Mgmt"
#define WIFI_ANALYTICS_DATA_EVENTS          "Device.WiFi.Events.VAP.{i}.Frames.Data"
#define WIFI_LEVL_CLIENTMAC                 "Device.WiFi.X_RDK_CSI_LEVL.clientMac"
#define WIFI_LEVL_NUMBEROFENTRIES           "Device.WiFi.X_RDK_CSI_LEVL.maxNumberCSIClients"
#define WIFI_LEVL_CSI_DATA                  "Device.WiFi.X_RDK_CSI_LEVL.data"
#define WIFI_LEVL_CSI_DATAFIFO              "Device.WiFi.X_RDK_CSI_LEVL.datafifo"
#define WIFI_LEVL_SOUNDING_DURATION         "Device.WiFi.X_RDK_CSI_LEVL.Duration"
#define WIFI_LEVL_CSI_STATUS                "Device.WiFi.X_RDK_CSI_LEVL.soundingStatus"
#define WIFI_LEVL_CSI_MAC_DATA              "Device.WiFi.X_RDK_CSI_LEVL.clientMacData"
#define RADIO_LEVL_TEMPERATURE_TABLE        "Device.WiFi.Events.Radio.{i}."
#define RADIO_LEVL_TEMPERATURE_EVENT        "Device.WiFi.Events.Radio.{i}.Temperature"

typedef struct {
    unsigned int    max_probe_ttl_cnt;
    mac_addr_str_t  mac_str;
} __attribute__((__packed__)) probe_ttl_data_t;

typedef struct {
    unsigned int       curr_time_alive;
    time_t             curr_alive_time_sec;
    frame_data_t       msg_data;
    mac_addr_str_t     mac_str;
} __attribute__((__packed__)) probe_req_elem_t;

typedef struct {
    int           sched_handler_id;
    mac_address_t mac_addr;
    unsigned int  ap_index;
    int           request_count;
    int duration;
    int interval;
    struct timeval last_time_publish;
}levl_sched_data_t;

typedef struct {
    mac_address_t mac_addr;
    int ap_index;
}timeout_data_t;

typedef struct {
    int                  max_num_csi_clients;
    int                  num_current_sounding;
    int                  sounding_duration;
    int                  publish_interval;
    bool                 csi_event_subscribed;
    bool                 csi_over_fifo;
    bool                 temperature_event_subscribed[MAX_NUM_RADIOS];
    int                  radio_temperature_interval[MAX_NUM_RADIOS];
    pthread_mutex_t      lock;
    hash_map_t           *probe_req_map;
    hash_map_t           *curr_sounding_mac_map;
    hash_map_t           *pending_mac_map;
    int                  sched_handler_id;
    int                  postpone_sched_handler_id;
    int                  paused;
    int                  speed_test_timeout;
    int                  probe_collector_sched_handler_id;
    levl_config_t        levl;
    wifi_app_t           *csi_app;
    csi_base_app_t       csi_fns;
    int                  csi_fd;
} levl_data_t;

typedef struct wifi_app wifi_app_t;

#ifdef __cplusplus
}
#endif

#endif // WIFI_LEVL_H
