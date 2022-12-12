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

#ifndef WIFI_BASE_H
#define WIFI_BASE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wifi_hal.h>
#include <collection.h>
#include <pthread.h>
#include <sys/time.h>

#define WIFI_STA_2G_VAP_CONNECT_STATUS      "Device.WiFi.STA.1.Connection.Status"
#define WIFI_STA_5G_VAP_CONNECT_STATUS      "Device.WiFi.STA.2.Connection.Status"
#define WIFI_STA_2G_INTERFACE_NAME          "Device.WiFi.STA.1.InterfaceName"
#define WIFI_STA_5G_INTERFACE_NAME          "Device.WiFi.STA.2.InterfaceName"
#define WIFI_STA_NAMESPACE                  "Device.WiFi.STA.{i}."
#define WIFI_STA_CONNECT_STATUS             "Device.WiFi.STA.{i}.Connection.Status"
#define WIFI_STA_INTERFACE_NAME             "Device.WiFi.STA.{i}.InterfaceName"
#define WIFI_STA_CONNECTED_GW_BSSID         "Device.WiFi.STA.{i}.Bssid"
#define WIFI_ACTIVE_GATEWAY_CHECK           "Device.X_RDK_GatewayManagement.ExternalGatewayPresent"
#define WIFI_WAN_FAILOVER_TEST              "Device.WiFi.WanFailoverTest"
#define WIFI_LMLITE_NOTIFY                  "Device.Hosts.X_RDKCENTRAL-COM_LMHost_Sync_From_WiFi"
#define WIFI_HOTSPOT_NOTIFY                 "Device.X_COMCAST-COM_GRE.Hotspot.ClientChange"
#define WIFI_NOTIFY_ASSOCIATED_ENTRIES      "Device.NotifyComponent.SetNotifi_ParamName"
#define MESH_STATUS                         "Device.DeviceInfo.X_RDKCENTRAL-COM_xOpsDeviceMgmt.Mesh.Enable"
#define WIFI_ANALYTICS_FRAME_EVENTS         "Device.WiFi.Events.Frames.Mgmt"
#define WIFI_ANALYTICS_DATA_EVENTS          "Device.WiFi.Events.Frames.Data"
#define WIFI_FRAME_INJECTOR_TO_ONEWIFI      "Device.WiFi.TestFrameInput"

#define PLAN_ID_LENGTH     38
#define MAX_STEP_COUNT  32 /*Active Measurement Step Count */
#define  MAC_ADDRESS_LENGTH  13
#define WIFI_AP_MAX_WPSPIN_LEN  9
#define MAX_BUF_LENGTH 128

#define QUEUE_WIFI_CTRL_TASK_TIMEOUT  1
#define MAX_FRAME_SZ                  2048

typedef enum {
    ctrl_event_type_exec,
    ctrl_event_type_webconfig,
    ctrl_event_type_hal_ind,
    ctrl_event_type_command,
    ctrl_event_type_wifiapi,
    ctrl_event_type_max
} ctrl_event_type_t;

typedef enum {
    // Controller loop execution
    ctrl_event_exec_start = 0x100,
    ctrl_event_exec_stop,
    ctrl_event_exec_timeout,
    ctrl_event_exec_max,

    // WebConfig event sub types
    ctrl_event_webconfig_set_data = 0x200,
    ctrl_event_webconfig_set_status,
    ctrl_event_webconfig_hal_result,
    ctrl_event_webconfig_get_data,
    ctrl_event_webconfig_set_data_tunnel,
    ctrl_event_webconfig_set_data_dml,
    ctrl_event_webconfig_set_data_webconfig,
    ctrl_event_webconfig_set_data_ovsm,
    ctrl_event_webconfig_max,

    // HAL events
    ctrl_event_hal_unknown_frame = 0x300,
    ctrl_event_hal_mgmt_farmes,
    ctrl_event_hal_probe_req_frame,
    ctrl_event_hal_probe_rsp_frame,
    ctrl_event_hal_auth_frame,
    ctrl_event_hal_deauth_frame,
    ctrl_event_hal_assoc_req_frame,
    ctrl_event_hal_assoc_rsp_frame,
    ctrl_event_hal_dpp_public_action_frame,
    ctrl_event_hal_dpp_config_req_frame,
    ctrl_event_hal_anqp_gas_init_frame,
    ctrl_event_hal_sta_conn_status,
    ctrl_event_hal_assoc_device,
    ctrl_event_hal_disassoc_device,
    ctrl_event_scan_results,
    ctrl_event_hal_channel_change,
    ctrl_event_radius_greylist,
    ctrl_event_hal_potential_misconfiguration,
    ctrl_event_hal_analytics,
    ctrl_event_hal_max,

    // Commands
    ctrl_event_type_command_sta_connect = 0x400,
    ctrl_event_type_command_factory_reset,
    ctrl_event_type_radius_grey_list_rfc,
    ctrl_event_type_wifi_passpoint_rfc,
    ctrl_event_type_wifi_interworking_rfc,
    ctrl_event_type_wpa3_rfc,
    ctrl_event_type_ow_core_thread_rfc,
    ctrl_event_type_dfs_rfc,
    ctrl_event_type_dfs_atbootup_rfc,
    ctrl_event_type_command_kickmac,
    ctrl_event_type_command_kick_assoc_devices,
    ctrl_event_type_command_wps,
    ctrl_event_type_command_wifi_host_sync,
    ctrl_event_type_device_network_mode,
    ctrl_event_type_twoG80211axEnable_rfc,
    ctrl_event_type_command_wifi_neighborscan,
    ctrl_event_type_command_mesh_status,
    ctrl_event_type_normalized_rssi,
    ctrl_event_type_snr,
    ctrl_event_type_cli_stat,
    ctrl_event_type_txrx_rate,
    ctrl_event_type_prefer_private_rfc,
    ctrl_event_type_mgmt_frame_rbus_rfc,
    ctrl_event_type_sta_connect_in_progress,
    ctrl_event_type_udhcp_ip_fail,
    ctrl_event_command_max,

    // wif_api
    ctrl_event_type_wifiapi_execution = 0x500,
    ctrl_event_type_wifiapi_max,

    // Tunnel
    ctrl_event_type_xfinity_tunnel_up = 0x600,
    ctrl_event_type_xfinity_tunnel_down,
    ctrl_event_type_xfinity_tunnel_maxi,

} ctrl_event_subtype_t;

typedef struct {
    wifi_frame_t    frame;
    unsigned char data[MAX_FRAME_SZ];
} __attribute__((__packed__)) frame_data_t;

#define MAX_SCANNED_VAPS       32

typedef struct {
    unsigned int radio_index;
    wifi_bss_info_t bss[MAX_SCANNED_VAPS];
    unsigned int num;
} scan_results_t;

typedef enum {
    rdk_dev_mode_type_gw,
    rdk_dev_mode_type_ext
} rdk_dev_mode_type_t;

#define MAX_MQTT_TOPIC_LEN 256
char awlan_mqtt_topic[MAX_MQTT_TOPIC_LEN];

typedef enum {
    blaster_state_new,
    blaster_state_completed
} blaster_state_t;

typedef struct {
    unsigned char SrcMac[MAC_ADDRESS_LENGTH];
    unsigned char DestMac[MAC_ADDRESS_LENGTH];
    unsigned int StepId;
    int ApIndex;
} active_msmt_step_t;

typedef struct {
    bool                ActiveMsmtEnable;
    unsigned int        ActiveMsmtSampleDuration;
    unsigned int        ActiveMsmtPktSize;
    unsigned int        ActiveMsmtNumberOfSamples;
    unsigned char       PlanId[PLAN_ID_LENGTH];
    unsigned char       StepInstance[MAX_STEP_COUNT];
    active_msmt_step_t    Step[MAX_STEP_COUNT];
    blaster_state_t     Status;
    unsigned char       blaster_mqtt_topic[MAX_MQTT_TOPIC_LEN];
} active_msmt_t;

#if DML_SUPPORT
typedef struct {
    int rssi_threshold;
    bool ReconnectCountEnable[MAX_VAP];
    bool FeatureMFPConfig;
    int ChUtilityLogInterval;
    int DeviceLogInterval;

    bool WifiFactoryReset;
    int  RadioFactoryResetSSID[MAX_NUM_RADIOS];
    bool ValidateSSIDName;
    int  FixedWmmParams;
    int  AssocCountThreshold;
    int  AssocMonitorDuration;
    int  AssocGateTime;
    bool WiFiTxOverflowSelfheal;
    bool WiFiForceDisableWiFiRadio;
    int  WiFiForceDisableRadioStatus;
} wifi_dml_parameters_t;

typedef struct {
    bool wifipasspoint_rfc;
    bool wifiinterworking_rfc;
    bool radiusgreylist_rfc;
    bool dfsatbootup_rfc;
    bool dfs_rfc;
    bool wpa3_rfc;
    bool twoG80211axEnable_rfc;
    bool hotspot_open_2g_last_enabled;
    bool hotspot_open_5g_last_enabled;
    bool hotspot_secure_2g_last_enabled;
    bool hotspot_secure_5g_last_enabled;
    bool mgmt_frame_rbus_enabled_rfc;
    char rfc_id[5];
} wifi_rfc_dml_parameters_t;
#endif

typedef struct {
    bool notify_wifi_changes;
    bool prefer_private;
    bool prefer_private_configure;
    bool factory_reset;
    bool tx_overflow_selfheal;
    bool inst_wifi_client_enabled;
    int  inst_wifi_client_reporting_period;
    mac_address_t inst_wifi_client_mac;
    int  inst_wifi_client_def_reporting_period;
    bool wifi_active_msmt_enabled;
    int  wifi_active_msmt_pktsize;
    int  wifi_active_msmt_num_samples;
    int  wifi_active_msmt_sample_duration;
    int  vlan_cfg_version;
    char wps_pin[WIFI_AP_MAX_WPSPIN_LEN];
    bool bandsteering_enable;
    int  good_rssi_threshold;
    int  assoc_count_threshold;
    int  assoc_gate_time;
    int  assoc_monitor_duration;
    bool rapid_reconnect_enable;
    bool vap_stats_feature;
    bool mfp_config_feature;
    bool force_disable_radio_feature;
    bool force_disable_radio_status;
    int  fixed_wmm_params;
    char wifi_region_code[4];
    bool diagnostic_enable;
    bool validate_ssid;
    int device_network_mode;
    char normalized_rssi_list[MAX_BUF_LENGTH];
    char cli_stat_list[MAX_BUF_LENGTH];
    char snr_list[MAX_BUF_LENGTH];
    char txrx_rate_list[MAX_BUF_LENGTH];
} __attribute__((packed)) wifi_global_param_t;

typedef struct {
    int   vap_index;
    char  mfp[MAX_STEP_COUNT];
} __attribute__((packed)) wifi_security_psm_param_t;

typedef struct {
    bool cts_protection;
    UINT beacon_interval;
    UINT dtim_period;
    UINT fragmentation_threshold;
    UINT rts_threshold;
    bool obss_coex;
    bool stbc_enable;
    bool greenfield_enable;
    UINT user_control;
    UINT admin_control;
    wifi_guard_interval_t guard_interval;
    UINT transmit_power;
    UINT radio_stats_measuring_rate;
    UINT radio_stats_measuring_interval;
    UINT chan_util_threshold;
    bool chan_util_selfheal_enable;
} __attribute__((packed)) wifi_radio_psm_param_t;

typedef struct {
    unsigned int data_index;
    CHAR mac[18];
    CHAR device_name[64];
} __attribute__((packed)) wifi_mac_psm_param_t;

typedef struct {
    hash_map_t *mac_entry[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
} __attribute__((packed)) wifi_mac_psm_entry_t;

typedef struct {
    int vlan_cfg_version;
    bool prefer_private;
    bool notify_wifi_changes;
    bool diagnostic_enable;
    int good_rssi_threshold;
    int assoc_count_threshold;
    int assoc_monitor_duration;
    int assoc_gate_time;
    bool mfp_config_feature;
    bool tx_overflow_selfheal;
    bool force_disable_radio_feature;
    bool force_disable_radio_status;
    bool validate_ssid;
    bool rapid_reconnect_enable;
    int fixed_wmm_params;
    bool vap_stats_feature;
    char wifi_region_code[4];
    char wps_pin[WIFI_AP_MAX_WPSPIN_LEN];
} __attribute__((packed)) wifi_global_psm_param_t;

typedef struct {
    bool mac_filter_enable;
    wifi_mac_filter_mode_t mac_filter_mode;
    bool wmm_enabled;
    bool uapsd_enabled;
    UINT  wmm_noack;
    char  mfp[MAX_STEP_COUNT];
    UINT  bss_max_sta;
    bool isolation_enabled;
    bool bss_transition_activated;
    bool bss_hotspot;
    UINT  wps_push_button;
    bool rapid_connect_enable;
    UINT  rapid_connect_threshold;
    bool vap_stats_enable;
    bool nbr_report_activated;
    char beacon_rate_ctl[MAX_STEP_COUNT];
} __attribute__((packed)) wifi_vap_psm_param_t;

typedef struct {
    wifi_radio_psm_param_t  radio_psm_cfg[MAX_NUM_RADIOS];
    wifi_vap_psm_param_t    vap_psm_cfg[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    wifi_mac_psm_entry_t    mac_psm_cfg;
    wifi_global_psm_param_t global_psm_cfg;
} __attribute__((packed)) wifi_psm_param_t;

typedef struct {
    unsigned char vap_index;
    hash_map_t    *acl_map;
    CHAR mac[18];
    CHAR device_name[64];
} __attribute__((packed)) wifi_mac_entry_param_t;

typedef struct {
    wifi_GASConfiguration_t gas_config;
    wifi_global_param_t global_parameters;
} __attribute__((packed)) wifi_global_config_t;

typedef struct {
    wifi_vap_name_t         vap_name;
    UINT                    vap_index;
    hash_map_t              *acl_map;
    hash_map_t              *associated_devices_map;
    int                     kick_device_task_counter;
    bool                    kick_device_config_change;
    bool                    is_mac_filter_initialized;
} rdk_wifi_vap_info_t;

typedef struct {
    char  if_name[128+1];
    char  freq_band[128+1];
    bool  enabled;
    bool  dfs_demo;
    char  hw_type[128+1];
    char  hw_params[65][64];
    char  radar[65][64];
    char  hw_config[65][64];
    char  country[128+1];
    int   channel;
    int   channel_sync;
    char  channel_mode[128+1];
    char  mac[128+1];
    char  hw_mode[128+1];
    char  ht_mode[128+1];
    int   thermal_shutdown;
    int   thermal_downgrade_temp;
    int   thermal_upgrade_temp;
    int   thermal_integration;
    bool  thermal_downgraded;
    char  temperature_control[65][64];
    int   tx_power;
    int   bcn_int;
    int   tx_chainmask;
    int   thermal_tx_chainmask;
    int   allowed_channels[64];
    char  channels[65][64];
    int   fallback_parents[8];
    char  zero_wait_dfs[128+1];
} schema_wifi_radio_state_t;

typedef struct {
    bool  enabled;
    char  if_name[128];
    char  mode[128+1];
    char  state[128+1];
    int   channel;
    char  mac[17+1];
    char  vif_radio_idx;
    bool  wds;
    char  parent[17+1];
    char  ssid[36+1];
    char  ssid_broadcast[128+1];
    char  security[65][64];
    char  bridge[128+1];
    char  mac_list[65][64];
    char  mac_list_type[128+1];
    int   vlan_id;
    char  min_hw_mode[128+1];
    bool  uapsd_enable;
    int   group_rekey;
    bool  ap_bridge;
    int   ft_psk;
    int   ft_mobility_domain;
    int   rrm;
    int   btm;
    bool  dynamic_beacon;
    bool  mcast2ucast;
    char  multi_ap[128+1];
    char  ap_vlan_sta_addr[17+1];
    bool  wps;
    bool  wps_pbc;
    char  wps_pbc_key_id[128+1];
} schema_wifi_vap_state_t;

typedef struct {
    //Hal variables
    wifi_vap_info_map_t          vap_map;
    wifi_radio_index_t           radio_index;
    unsigned int    num_vaps;
    rdk_wifi_vap_info_t          rdk_vap_array[MAX_NUM_VAP_PER_RADIO];
    schema_wifi_vap_state_t      vap_state[MAX_NUM_VAP_PER_RADIO];
} __attribute__((packed)) rdk_wifi_vap_map_t;

typedef struct {
    char    name[16];
    wifi_radio_operationParam_t oper;
    rdk_wifi_vap_map_t          vaps;
    schema_wifi_radio_state_t   radio_state;
}  __attribute__((packed)) rdk_wifi_radio_t;

#define  MAC_ADDRESS_LENGTH  13
typedef struct {
    bool                   b_inst_client_enabled;
    unsigned long          u_inst_client_reporting_period;
    unsigned long          u_inst_client_def_reporting_period;
    unsigned long          u_inst_client_def_override_ttl;
    char                   mac_address[MAC_ADDRESS_LENGTH];
} instant_measurement_config_t;

typedef struct {
    wifi_station_stats_t   stats;
    wifi_interface_name_t  interface_name;
    wifi_bss_info_t        bss_info;
} __attribute__((packed)) rdk_sta_data_t;

typedef struct {
    int ap_index;
    wifi_associated_dev3_t dev_stats;
    int reason;
} __attribute__((__packed__)) assoc_dev_data_t;

struct active_msmt_data;

typedef struct {
    mac_address_t  sta_mac;
    unsigned int    good_rssi_time;
    unsigned int    bad_rssi_time;
    unsigned int    connected_time;
    unsigned int    disconnected_time;
    unsigned int    total_connected_time;
    unsigned int    total_disconnected_time;
    struct timeval  last_connected_time;
    struct timeval  last_disconnected_time;
    unsigned int    rapid_reconnects;
    bool            updated;
    wifi_associated_dev3_t dev_stats;
    wifi_associated_dev3_t dev_stats_last;
    unsigned int    reconnect_count;
    long            assoc_monitor_start_time;
    long            gate_time;
    unsigned int    redeauth_count;
    long            deauth_monitor_start_time;
    long            deauth_gate_time;
    struct active_msmt_data *sta_active_msmt_data;
} __attribute__((__packed__)) sta_data_t;

typedef enum {
    WLAN_RADIUS_GREYLIST_REJECT=100,
    PREFER_PRIVATE_RFC_REJECT=101
} acl_entry_reason_t;

typedef struct {
    mac_address_t mac;
    CHAR device_name[64];
    acl_entry_reason_t  reason;
    int expiry_time;
}__attribute__((__packed__)) acl_entry_t;
#ifdef __cplusplus
}
#endif

#endif // WIFI_BASE_H
