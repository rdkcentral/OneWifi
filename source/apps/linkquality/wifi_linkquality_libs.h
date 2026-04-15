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

#ifndef WIFI_LINKQUALITY_LIBS_H
#define WIFI_LINKQUALITY_LIBS_H
#include "run_qmgr.h"
#define ETH_P_1905 0x893a
#ifdef __cplusplus
  extern "C" {
 #endif
 
 typedef struct {
    int len;
    ext_qualitymgr_type_t ext_event_type;
    stats_arg_t stats[];
} qmgr_packet_t;

typedef int (* periodic_caffinity_stats_update_t)(stats_arg_t *stats,int len);
typedef void (* register_station_mac_t)(const char *str);
typedef void (* unregister_station_mac_t)(const char *str);
typedef int (* start_link_metrics_t)();
typedef int (* stop_link_metrics_t)();
typedef int (* disconnect_link_stats_t)(stats_arg_t *stats);
typedef int (* reinit_link_metrics_t)(server_arg_t *arg);
typedef int (* remove_link_stats_t) (stats_arg_t *stats);
typedef char* (* get_link_metrics_t) ();
typedef int (* set_quality_flags_t) (quality_flags_t *flag);
typedef int (* get_quality_flags_t) (quality_flags_t *flag);
typedef int (* process_lq_stats_t)(stats_arg_t *stats, int len);


typedef struct {
    periodic_caffinity_stats_update_t periodic_caffinity_stats_update_fn;
    register_station_mac_t register_station_mac_fn;
    unregister_station_mac_t unregister_station_mac_fn;
    start_link_metrics_t start_link_metrics_fn;
    stop_link_metrics_t stop_link_metrics_fn;
    disconnect_link_stats_t disconnect_link_stats_fn;
    reinit_link_metrics_t reinit_link_metrics_fn;
    remove_link_stats_t remove_link_stats_fn;
    get_link_metrics_t get_link_metrics_fn;
    set_quality_flags_t set_quality_flags_fn;
    get_quality_flags_t get_quality_flags_fn;
    process_lq_stats_t process_lq_stats_fn;

} wifi_lq_descriptor_t;

wifi_lq_descriptor_t *get_lq_descriptor();

void* run_extender_1905_thread(void *arg);
int lq_send_autoconf_search(const char *ifname);
void lq_handle_1905_frame(const uint8_t *buf, ssize_t len);

#ifdef __cplusplus
 }
 #endif

#endif // WIFI_LINKQUALITY_LIBS_H
