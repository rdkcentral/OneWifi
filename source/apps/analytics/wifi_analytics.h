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

#ifndef WIFI_ANALYTICS_H
#define WIFI_ANALYTICS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/resource.h>

#define analytics_format_mgr_core    "MGR -> CORE : %s : %s\r\n"
#define analytics_format_ovsm_core   "OVSM -> CORE : %s : %s\r\n"
#define analytics_format_core_ovsm   "CORE -> OVSM : %s : %s\r\n"
#define analytics_format_generic     "%s -> %s : %s : %s\r\n"
#define analytics_format_hal_core    "HAL -> CORE : %s : %s\r\n"
#define analytics_format_other_core  "OMGR -> CORE : %s : %s\r\n"
#define analytics_format_dml_core    "DML -> CORE : %s : %s\r\n"
#define analytics_format_core_core   "CORE -> CORE : %s : %s\r\n"
#define analytics_format_webconfig_core   "WEBCONFIG -> CORE : %s : %s\r\n"
#define analytics_format_note_over_core "note over CORE : %s\r\n"
#define analytics_format_core_hal    "CORE -> HAL : %s : %s\r\n"
#define analytics_format_core_core_reverse   "CORE <- CORE : %s : %s\r\n"

typedef struct wifi_app wifi_app_t;

typedef struct {
    unsigned int    ap_index;
    mac_address_t   sta_mac;
} analytics_sta_info_t;

typedef struct {
    unsigned int    minutes_alive;
    unsigned int    tick_demultiplexer;
    hash_map_t      *sta_map;
    struct rusage   last_usage;
} analytics_data_t;

int analytics_init(wifi_app_t *app, unsigned int create_flag);
int analytics_deinit(wifi_app_t *app);
int analytics_event(wifi_app_t *app, wifi_event_t *event);

#ifdef __cplusplus
}
#endif

#endif // WIFI_ANALYTICS_H
