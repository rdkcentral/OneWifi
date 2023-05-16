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

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PROBE_MAP_TTL    500
#define LEVL_SOUNDING_TIMEOUT_MS 2000

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
    bool          sounding_complete;
    bool          enforced_sounding;
}levl_sched_data_t;

typedef struct {
    mac_address_t mac_addr;
    int ap_index;
}timeout_data_t;

typedef struct {
    int                  max_num_csi_clients;
    int                  num_current_sounding;
    bool                 event_subscribed;
    pthread_mutex_t      lock;
    hash_map_t           *probe_req_map;
    hash_map_t           *radomized_client_map;
    hash_map_t           *pending_mac_map;
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
