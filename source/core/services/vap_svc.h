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

#ifndef VAP_SVC_H
#define VAP_SVC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <math.h>
#include "wifi_hal.h"
#include "wifi_base.h"
#include "wifi_events.h"

typedef struct wifi_ctrl wifi_ctrl_t;

typedef enum {
    vap_svc_type_private,
    vap_svc_type_public,
    vap_svc_type_mesh_gw,
    vap_svc_type_mesh_ext,
    vap_svc_type_max
} vap_svc_type_t;

typedef enum {
    vap_svc_event_none,
    add_prefer_private_acl_to_public,
    add_macmode_to_public
} vap_svc_event_t;

typedef struct vap_svc vap_svc_t;

typedef int (* vap_svc_start_fn_t)(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
typedef int (* vap_svc_stop_fn_t)(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
typedef int (* vap_svc_update_fn_t)(vap_svc_t *svc, unsigned int radio_index,
    wifi_vap_info_map_t *map, rdk_wifi_vap_info_t *rdk_vap_info);
typedef int (* vap_svc_event_fn_t)(vap_svc_t *svc, wifi_event_type_t type, wifi_event_subtype_t sub_type, vap_svc_event_t event, void *arg);
typedef bool (* vap_svc_is_my_fn_t)(unsigned int vap_index);

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
#define EXT_UDHCP_IP_CHECK_NUM                 3

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
    bool                   is_radio_ignored;
    wifi_radio_index_t     ignored_radio_index;
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
    bool                   is_started;
}__attribute__((packed)) vap_svc_ext_t;

typedef struct vap_svc {
    bool                     created;
    vap_svc_type_t           type;
    wifi_ctrl_t              *ctrl;
    wifi_platform_property_t *prop;
    union {
              vap_svc_ext_t   ext;
          } u;
    vap_svc_start_fn_t       start_fn;
    vap_svc_stop_fn_t        stop_fn;
    vap_svc_update_fn_t      update_fn;
    vap_svc_event_fn_t       event_fn;
    vap_svc_is_my_fn_t       is_my_fn;
} __attribute__((packed)) vap_svc_t;

int svc_init(vap_svc_t *svc, vap_svc_type_t type);

// private
extern int vap_svc_private_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_private_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_private_update(vap_svc_t *svc, unsigned int radio_index,
    wifi_vap_info_map_t *map, rdk_wifi_vap_info_t *rdk_vap_info);
extern int vap_svc_private_event(vap_svc_t *svc, wifi_event_type_t type, wifi_event_subtype_t sub_type, vap_svc_event_t event, void *arg);
extern bool vap_svc_is_private(unsigned int vap_index);

// public
extern int vap_svc_public_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_public_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_public_update(vap_svc_t *svc, unsigned int radio_index,
    wifi_vap_info_map_t *map, rdk_wifi_vap_info_t *rdk_vap_info);
extern int vap_svc_public_event(vap_svc_t *svc, wifi_event_type_t type, wifi_event_subtype_t sub_type, vap_svc_event_t event, void *arg);
extern bool vap_svc_is_public(unsigned int vap_index);

// mesh_gateway
extern int vap_svc_mesh_gw_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_mesh_gw_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_mesh_gw_update(vap_svc_t *svc, unsigned int radio_index,
    wifi_vap_info_map_t *map, rdk_wifi_vap_info_t *rdk_vap_info);
extern int vap_svc_mesh_gw_event(vap_svc_t *svc, wifi_event_type_t type, wifi_event_subtype_t sub_type, vap_svc_event_t event, void *arg);
extern bool vap_svc_is_mesh_gw(unsigned int vap_index);

// mesh_extender
extern int vap_svc_mesh_ext_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_mesh_ext_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_mesh_ext_update(vap_svc_t *svc, unsigned int radio_index,
    wifi_vap_info_map_t *map, rdk_wifi_vap_info_t *rdk_vap_info);
extern int vap_svc_mesh_ext_event(vap_svc_t *svc, wifi_event_type_t type, wifi_event_subtype_t sub_type, vap_svc_event_t event, void *arg);
extern bool vap_svc_is_mesh_ext(unsigned int vap_index);

vap_svc_t *get_svc_by_type(wifi_ctrl_t *ctrl, vap_svc_type_t type);
vap_svc_t *get_svc_by_vap_index(wifi_ctrl_t *ctrl, unsigned int vap_index);
vap_svc_t *get_svc_by_name(wifi_ctrl_t *ct, char *vap_name);

int process_ext_connect_algorithm(vap_svc_t *svc);

#ifdef __cplusplus
}
#endif

#endif // VAP_SVC_H
