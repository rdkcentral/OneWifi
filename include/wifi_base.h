#ifndef WIFI_BASE_H
#define WIFI_BASE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wifi_hal.h>
#include <collection.h>

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

#define PLAN_ID_LENGTH     16
#define MAX_STEP_COUNT  32 /*Active Measurement Step Count */
#define  MAC_ADDRESS_LENGTH  13
#define WIFI_AP_MAX_WPSPIN_LEN  9
#define MAX_BUF_LENGTH 128

typedef enum {
    rdk_dev_mode_type_gw,
    rdk_dev_mode_type_ext
} rdk_dev_mode_type_t;

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
} active_msmt_t;


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
    char rfc_id[4];
} wifi_rfc_dml_parameters_t;

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
    queue_t                 *associated_devices_queue;
    hash_map_t              *acl_map;
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

#ifdef __cplusplus
}
#endif

#endif // WIFI_BASE_H
