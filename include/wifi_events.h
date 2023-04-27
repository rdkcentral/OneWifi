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

#ifndef _WIFI_EVENTS_H_
#define _WIFI_EVENTS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi_hal.h"
#include "collection.h"
#include "wifi_monitor.h"
#include "wifi_base.h"

#define wifi_event_type_base    0x1
#define CLIENTDIAG_JSON_BUFFER_SIZE 665

typedef enum {
    wifi_sub_component_core = wifi_sub_component_base << 2,
    wifi_sub_component_mon = wifi_sub_component_base << 3,
    wifi_sub_component_apps = wifi_sub_component_base << 4,
    wifi_sub_component_hal = wifi_sub_component_base << 5,
    wifi_sub_component_dml = wifi_sub_component_base << 6
} wifi_sub_component_t;

typedef enum {
    wifi_app_inst_blaster = wifi_app_inst_base,
    wifi_app_inst_harvester = wifi_app_inst_base << 1,
    wifi_app_inst_single_msmt = wifi_app_inst_base << 2,
    wifi_app_inst_analytics = wifi_app_inst_base << 3,
    wifi_app_inst_cognitive = wifi_app_inst_base << 4,
    wifi_app_inst_levl = wifi_app_inst_base << 5,
    wifi_app_inst_opensync = wifi_app_inst_base << 6,
    wifi_app_inst_easymesh = wifi_app_inst_base << 7,
    wifi_app_inst_matter = wifi_app_inst_base << 8,
    wifi_app_inst_cac = wifi_app_inst_base << 9,
    wifi_app_inst_max = wifi_app_inst_base << 10
} wifi_app_inst_t;

typedef enum {
    wifi_event_type_exec,
    wifi_event_type_webconfig,
    wifi_event_type_hal_ind,
    wifi_event_type_command,
    wifi_event_type_monitor,
    wifi_event_type_net,
    wifi_event_type_wifiapi,
    wifi_event_type_max
} wifi_event_type_t;

typedef enum {
    // Controller loop execution
    wifi_event_exec_start = wifi_event_type_base << wifi_event_type_exec,       // wifi_event_type_base << 0
    wifi_event_exec_stop,
    wifi_event_exec_timeout,
    wifi_event_exec_max,

    // WebConfig event sub types
    wifi_event_webconfig_set_data = wifi_event_type_base << (wifi_event_type_webconfig + 2),    // wifi_event_type_base << 3
    wifi_event_webconfig_set_status,
    wifi_event_webconfig_hal_result,
    wifi_event_webconfig_get_data,
    wifi_event_webconfig_set_data_tunnel,
    wifi_event_webconfig_set_data_dml,
    wifi_event_webconfig_set_data_webconfig,
    wifi_event_webconfig_set_data_ovsm,
    wifi_event_webconfig_data_resched_to_ctrl_queue,
    wifi_event_webconfig_data_to_apply_pending_queue,
    wifi_event_webconfig_data_to_hal_apply,
    wifi_event_webconfig_set_data_sta_bssid,
    wifi_event_webconfig_data_req_from_dml,
    wifi_event_webconfig_max,


    // HAL events
    wifi_event_hal_unknown_frame = wifi_event_type_base << (wifi_event_type_hal_ind + 6), // wifi_event_type_base << 8
    wifi_event_hal_mgmt_farmes,
    wifi_event_hal_probe_req_frame,
    wifi_event_hal_probe_rsp_frame,
    wifi_event_hal_auth_frame,
    wifi_event_hal_deauth_frame,
    wifi_event_hal_assoc_req_frame,
    wifi_event_hal_assoc_rsp_frame,
    wifi_event_hal_reassoc_req_frame,
    wifi_event_hal_reassoc_rsp_frame,
    wifi_event_hal_dpp_public_action_frame,
    wifi_event_hal_dpp_config_req_frame,
    wifi_event_hal_anqp_gas_init_frame,
    wifi_event_hal_sta_conn_status,
    wifi_event_hal_assoc_device,
    wifi_event_hal_disassoc_device,
    wifi_event_scan_results,
    wifi_event_hal_channel_change,
    wifi_event_radius_greylist,
    wifi_event_hal_potential_misconfiguration,
    wifi_event_hal_analytics,
    wifi_event_hal_max,

    // Commands
    wifi_event_type_command_sta_connect = wifi_event_type_base << (wifi_event_type_command + 10), // wifi_event_type_base << 13
    wifi_event_type_command_factory_reset,
    wifi_event_type_radius_grey_list_rfc,
    wifi_event_type_wifi_passpoint_rfc,
    wifi_event_type_wifi_interworking_rfc,
    wifi_event_type_wpa3_rfc,
    wifi_event_type_ow_core_thread_rfc,
    wifi_event_type_dfs_rfc,
    wifi_event_type_dfs_atbootup_rfc,
    wifi_event_type_command_kickmac,
    wifi_event_type_command_kick_assoc_devices,
    wifi_event_type_command_wps,
    wifi_event_type_command_wps_pin,
    wifi_event_type_command_wifi_host_sync,
    wifi_event_type_device_network_mode,
    wifi_event_type_twoG80211axEnable_rfc,
    wifi_event_type_command_wifi_neighborscan,
    wifi_event_type_command_mesh_status,
    wifi_event_type_normalized_rssi,
    wifi_event_type_snr,
    wifi_event_type_cli_stat,
    wifi_event_type_txrx_rate,
    wifi_event_type_prefer_private_rfc,
    wifi_event_type_mgmt_frame_rbus_rfc,
    wifi_event_type_sta_connect_in_progress,
    wifi_event_type_udhcp_ip_fail,
    wifi_event_type_trigger_disconnection,
    wifi_event_type_trigger_disconnection_analytics,
    wifi_event_type_new_bssid,
    wifi_event_type_xfinity_enable,
    wifi_event_type_wifi_offchannelscan_rfc,
    wifi_event_command_max,


    wifi_event_monitor_diagnostics = wifi_event_type_base << (wifi_event_type_monitor + 14), // wifi_event_type_base << 18,
    wifi_event_monitor_connect,
    wifi_event_monitor_disconnect,
    wifi_event_monitor_deauthenticate,
    wifi_event_monitor_start_inst_msmt,
    wifi_event_monitor_stop_inst_msmt,
    wifi_event_monitor_stats_flag_change,
    wifi_event_monitor_radio_stats_flag_change,
    wifi_event_monitor_vap_stats_flag_change,
    wifi_event_monitor_process_active_msmt,
    wifi_event_monitor_csi,
    wifi_event_monitor_csi_update_config,
    wifi_event_monitor_clientdiag_update_config,
    wifi_event_monitor_max,

    // Tunnel
    wifi_event_type_xfinity_tunnel_up = wifi_event_type_base << (wifi_event_type_net + 18), // wifi_event_type_base << 23
    wifi_event_type_xfinity_tunnel_down,
    wifi_event_type_xfinity_tunnel_max,

    // wif_api
    wifi_event_type_wifiapi_execution = wifi_event_type_base << (wifi_event_type_wifiapi + 22), // wifi_event_type_base << 28
    wifi_event_type_wifiapi_max = wifi_event_type_base << 31
} wifi_event_subtype_t;

typedef struct {
    wifi_event_type_t     event_type;
    wifi_event_subtype_t  sub_type;
    union {
        wifi_monitor_data_t mon_data;
        wifi_core_data_t    core_data;
        wifi_analytics_data_t   analytics_data;
    } u;
} __attribute__((__packed__)) wifi_event_t;

// wifi events functions
int push_event_to_ctrl_queue(const void *msg, unsigned int len, wifi_event_type_t type, wifi_event_subtype_t sub_type);
int push_event_to_mon_queue(const void *msg, unsigned int len, wifi_event_type_t type, wifi_event_subtype_t sub_type);

// rbus events functions
int events_rbus_init(void);
int events_rbus_publish(wifi_event_t *event);
int events_rbus_deinit(void);
void events_update_clientdiagdata(unsigned int num_devs, int vap_idx, wifi_associated_dev3_t *dev_array);

#ifdef __cplusplus
}
#endif

#endif