/************************************************************************************ If not stated otherwise in this file or this component's LICENSE file the  
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

#ifndef WIFI_SERVICE_MESH_H
#define WIFI_SERVICE_MESH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi_events.h"
#include "wifi_services_mgr.h"
#include "wifi_service_node.h"

typedef struct service  service_t;
typedef struct wifi_service wifi_service_t;
typedef struct wifi_service_node wifi_service_node_t;

//sta connection 10 seconds retry
#define STA_CONN_RETRY_TIMEOUT                 9
#define STA_MAX_CONNECT_ATTEMPT                2
#define STA_MAX_DISCONNECT_ATTEMPT             2
#define MAX_SCAN_RESULT_WAIT                   2
// max connection algoritham timeout 4 minutes
#define MAX_CONNECTION_ALGO_TIMEOUT            4 * 60
#define EXT_CONNECT_ALGO_PROCESSOR_INTERVAL    1000

#define EXT_SCAN_RESULT_TIMEOUT                4000
#define EXT_SCAN_RESULT_WAIT_TIMEOUT           4000
#define EXT_CONN_STATUS_IND_TIMEOUT            5000
#define EXT_CSA_WAIT_TIMEOUT                   3000
#define EXT_DISCONNECTION_IND_TIMEOUT          5000
#define EXT_UDHCP_IP_CHECK_INTERVAL            60000

typedef enum {
    connection_attempt_wait,
    //connection_attempt_in_progress,
    connection_attempt_failed
} connection_attempt_t;

typedef enum {
    connection_state_disconnected_scan_list_none,
    connection_state_disconnected_scan_list_in_progress,
    connection_state_disconnected_scan_list_all,
    connection_state_connection_in_progress,
    connection_state_connection_to_lcb_in_progress,
    connection_state_connection_to_nb_in_progress,
    connection_state_connected,
    connection_state_connected_wait_for_csa,
    connection_state_connected_scan_list,
    connection_state_disconnection_in_progress,
} connection_state_t;

typedef struct scan_result {
    wifi_bss_info_t      external_ap;
    wifi_freq_bands_t    radio_freq_band;
    connection_attempt_t conn_attempt;
    unsigned int         conn_retry_attempt;
    wifi_vap_index_t     vap_index;
}__attribute__((packed)) bss_candidate_t;

typedef struct {
    bss_candidate_t    *scan_list;
    unsigned int        scan_count;
}__attribute__((packed)) bss_candidate_list_t;

typedef struct {
    bss_candidate_list_t   candidates_list;
    bss_candidate_t        last_connected_bss;
    bss_candidate_t        new_bss;
    connection_state_t     conn_state;
    unsigned int           selfheal_status;
    unsigned int           connected_vap_index;
    unsigned long long int last_connected_time;
    unsigned char          conn_retry;
    unsigned char          disconn_retry;
    unsigned char          wait_scan_result;
    unsigned char          scanned_radios;
    unsigned int           go_to_channel;
    unsigned int           go_to_channel_width;
    unsigned int           channel_change_pending_map;
    int                    ext_connect_algo_processor_id;
    int                    ext_scan_result_timeout_handler_id;
    int                    ext_scan_result_wait_timeout_handler_id;
    int                    ext_conn_status_ind_timeout_handler_id;
    int                    ext_csa_wait_timeout_handler_id;
    int                    ext_connected_scan_result_timeout_handler_id;
    int                    ext_disconnection_event_timeout_handler_id;
    int                    ext_udhcp_ip_check_id;
    int                    ext_udhcp_disconnect_event_timeout_handler_id;
    int                    ext_trigger_disconnection_timeout_handler_id;
}__attribute__((packed)) mesh_sta_node_data_t;

int process_scan_result_timeout(wifi_service_node_t *node);
int process_ext_connect_algorithm(wifi_service_node_t *node);
int process_disconnection_event_timeout(wifi_service_node_t *node);
int process_trigger_disconnection_event_timeout(wifi_service_node_t *node);
int process_ext_webconfig_set_data_sta_bssid(wifi_service_node_t *node, wifi_core_data_t *data);
void cancel_scan_result_timer(wifi_service_node_t *node);
int get_dwell_time();

int mesh_service_init(wifi_service_t *svc);
int mesh_service_create_nodes(wifi_service_t *svc, rdk_wifi_radio_t *radio_config, wifi_hal_capability_t *hal_cap, const service_t *service);
void mesh_service_delete_nodes(wifi_service_t *svc);
int mesh_service_start(wifi_service_t *svc);
int mesh_service_stop(wifi_service_t *svc);
int mesh_service_update(wifi_service_t *svc);
int mesh_service_event(wifi_service_t *svc, wifi_event_t *event);

int mesh_backhaul_node_start(wifi_service_node_t *node);
int mesh_backhaul_node_stop(wifi_service_node_t *node);
int mesh_backhaul_node_update(wifi_service_node_t *node);
int mesh_backhaul_node_event(wifi_service_node_t *node, wifi_event_t *event);

int mesh_sta_node_start(wifi_service_node_t *node);
int mesh_sta_node_stop(wifi_service_node_t *node);
int mesh_sta_node_update(wifi_service_node_t *node);
int mesh_sta_node_event(wifi_service_node_t *node, wifi_event_t *event);

#ifdef __cplusplus
}
#endif

#endif // WIFI_SERVICE_MESH_H

