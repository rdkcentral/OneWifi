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

typedef struct {
    unsigned int    max_probe_ttl_cnt;
    mac_addr_str_t  mac_str;
} __attribute__((__packed__)) probe_ttl_data_t;

typedef struct {
    unsigned int       curr_time_alive;
    frame_data_t       msg_data;
} __attribute__((__packed__)) probe_req_elem_t;

typedef struct wifi_app wifi_app_t;

int levl_init(wifi_app_t *app, unsigned int create_flag);
int levl_deinit(wifi_app_t *app);
int levl_event(wifi_app_t *app, wifi_event_t *event);

#ifdef __cplusplus
}
#endif

#endif // WIFI_LEVL_H
