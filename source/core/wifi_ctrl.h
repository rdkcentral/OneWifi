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

#ifndef WIFI_CTRL_H
#define WIFI_CTRL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ev.h>
#include <rbus.h>
#include <pthread.h>
#include "wifi_base.h"
#include "wifi_db.h"
#if DML_SUPPORT
#endif // DML_SUPPORT
#include "vap_svc.h"
#include "cJSON.h"
#include "collection.h"
#include "wifi_util.h"
#include "wifi_webconfig.h"
#include "wifi_apps_mgr.h"


#define WIFI_WEBCONFIG_PRIVATESSID         1
#define WIFI_WEBCONFIG_HOMESSID            2

#define WIFI_FEATURE_ResetSsid             1
#define WIFI_FEATURE_LoadDefaults          0

#define WIFI_MAX_SSID_NAME_LEN             33
#define MAX_FRAME_SZ       2048

#define RFC_WIFI_PASSPOINT          "RfcWifiPasspointEnable"
#define RFC_WIFI_INTERWORKING       "RfcWifiInterworkingEnable"
#define RFC_WIFI_RADIUS_GREYLIST    "RadiusGreyListEnable"
#define RFC_WIFI_DFSatBootup        "Wifi_DFSatBootup"
#define RFC_WIFI_DFS                "Wifi_DFS"
#define RFC_WIFI_WPA3               "Wifi_WPA3"

#define CSI_CLIENT_PER_SESSION      5
#define MAX_NUM_CSI_CLIENTS         5
#define MAX_LEVL_CSI_CLIENTS        5

#define RSSI_THRESHOLD                     "RssiThresholdValue"
#define RECONNECT_COUNT_STATUS             "ReconnectCountStatus"
#define MFP_FEATURE_STATUS                 "MfpFeatureStatus"
#define CH_UTILITY_LOG_INTERVAL            "ChUtilityLogInterval"
#define DEVICE_LOG_INTERVAL                "DeviceLogInterval"
#define WIFI_FACTORY_RESET                 "WifiFactoryReset"
#define FACTORY_RESET_SSID                 "FactoryResetSSID"
#define VALIDATE_SSID_NAME                 "ValidateSSIDName"
#define FIXED_WMM_PARAMS                   "FixedWmmParams"
#define ASSOC_COUNT_THRESHOLD              "AssocCountThreshold"
#define ASSOC_MONITOR_DURATION             "AssocMonitorDuration"
#define ASSOC_GATE_TIME                    "AssocGateTime"
#define WIFI_TX_OVERFLOW_SELF_HEAL         "WiFiTxOverflowSelfheal"
#define WIFI_FORCE_DISABLE_RADIO           "WiFiForceDisableWiFiRadio"
#define WIFI_FORCE_DISABLE_RADIO_STATUS    "WiFiForceDisableRadioStatus"

#define WIFI_RBUS_WIFIAPI_COMMAND          "Device.WiFi.WiFiAPI.command"
#define WIFI_RBUS_WIFIAPI_RESULT           "Device.WiFi.WiFiAPI.result"

#define WIFI_NORMALIZED_RSSI_LIST          "Device.DeviceInfo.X_RDKCENTRAL-COM_WIFI_TELEMETRY.NormalizedRssiList"
#define WIFI_SNR_LIST                      "Device.DeviceInfo.X_RDKCENTRAL-COM_WIFI_TELEMETRY.SNRList"
#define WIFI_CLI_STAT_LIST                 "Device.DeviceInfo.X_RDKCENTRAL-COM_WIFI_TELEMETRY.CliStatList"
#define WIFI_TxRx_RATE_LIST                "Device.DeviceInfo.X_RDKCENTRAL-COM_WIFI_TELEMETRY.TxRxRateList"
#define WIFI_DEVICE_MODE                   "Device.X_RDKCENTRAL-COM_DeviceControl.DeviceNetworkingMode"
#define WIFI_DEVICE_TUNNEL_STATUS          "Device.X_COMCAST-COM_GRE.Tunnel.1.TunnelStatus"
#define SPEEDTEST_STATUS                   "Device.IP.Diagnostics.X_RDKCENTRAL-COM_SpeedTest.Status"
#define SPEEDTEST_SUBSCRIBE                "Device.IP.Diagnostics.X_RDK_SpeedTest.SubscriberUnPauseTimeOut"

#define TEST_WIFI_DEVICE_MODE              "Device.X_RDKCENTRAL-COM_DeviceControl.DeviceNetworkingMode_1"

#define WIFI_RBUS_HOTSPOT_UP               "Device.WiFi.HotspotUp"
#define WIFI_RBUS_HOTSPOT_DOWN             "Device.WiFi.HotspotDown"

#define WIFI_WEBCONFIG_KICK_MAC            "Device.WiFi.KickAssocDevices"
#define RBUS_WIFI_WPS_PIN_START            "Device.WiFi.WPS.Start"

#define ETH_BH_STATUS                      "Device.X_RDK_MeshAgent.EthernetBhaulUplink.Status"

#define WIFI_ALL_RADIO_INDICES             0xffff
#define DEVICE_TUNNEL_UP                   1
#define DEVICE_TUNNEL_DOWN                 0

#define GREYLIST_TIMEOUT_IN_SECONDS        (24 * 60 * 60)
#define GREYLIST_CHECK_IN_SECONDS          (1 * 60 * 60)

// 15 Minutes
#define HOTSPOT_VAP_MAC_FILTER_ENTRY_SYNC  (15 * 60)

#define MAX_WIFI_SCHED_TIMEOUT         (4 * 1000)

//This is a dummy string if the value is not passed.
#define INVALID_KEY                      "12345678"
#define INVALID_IP_STRING                "0.0.0.0"

#define SUBDOC_FORCE_RESET               "Device.X_RDK_WebConfig.webcfgSubdocForceReset"
#define PRIVATE_SUB_DOC                  "privatessid"
// Connected building wifi subdoc and rbus related constants
#define MULTI_COMP_SUPPORTED_SUBDOC_COUNT 2
#define MANAGED_WIFI_BRIDGE "Device.LAN.Bridge.1.Name"
#define MANAGED_WIFI_INTERFACE "Device.LAN.Bridge.1.WiFiInterfaces"

#define PRIVATE 0b0001
#define HOTSPOT 0b0010
#define HOME 0b0100
#define MESH 0b1000
#define MESH_STA 0b10000
#define MESH_BACKHAUL 0b100000
#define LNF 0b1000000

typedef enum {
    rbus_bool_data,
    rbus_int_data,
    rbus_uint_data,
    rbus_string_data
} rbus_data_type_t;

typedef enum {
    ctrl_webconfig_state_none = 0,
    ctrl_webconfig_state_radio_cfg_rsp_pending = 0x0001,
    ctrl_webconfig_state_vap_all_cfg_rsp_pending = 0x0002,
    ctrl_webconfig_state_vap_private_cfg_rsp_pending = 0x0004,
    ctrl_webconfig_state_vap_home_cfg_rsp_pending = 0x0008,
    ctrl_webconfig_state_vap_xfinity_cfg_rsp_pending = 0x0010,
    ctrl_webconfig_state_vap_mesh_cfg_rsp_pending = 0x0020,
    ctrl_webconfig_state_wifi_config_cfg_rsp_pending = 0x0040,
    ctrl_webconfig_state_macfilter_cfg_rsp_pending = 0x0080,
    ctrl_webconfig_state_factoryreset_cfg_rsp_pending = 0x0100,
    ctrl_webconfig_state_associated_clients_cfg_rsp_pending = 0x0200,
    ctrl_webconfig_state_csi_cfg_rsp_pending = 0x0400,
    ctrl_webconfig_state_sta_conn_status_rsp_pending = 0x0800,
    ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending = 0x1000,
    ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending = 0x2000,
    ctrl_webconfig_state_steering_clients_rsp_pending = 0x4000,
    ctrl_webconfig_state_vap_lnf_cfg_rsp_pending = 0x8000,
    ctrl_webconfig_state_blaster_cfg_init_rsp_pending = 0x10000,
    ctrl_webconfig_state_blaster_cfg_complete_rsp_pending = 0x20000,
    ctrl_webconfig_state_vap_mesh_backhaul_sta_cfg_rsp_pending = 0x40000,
    ctrl_webconfig_state_trigger_dml_thread_data_update_pending = 0x80000,
    ctrl_webconfig_state_max = 0x100000
} wifi_ctrl_webconfig_state_t;

#define CTRL_WEBCONFIG_STATE_MASK   0xfffff

typedef struct {
        char mac_addr[MAC_STR_LEN];
        char if_name[8];
} bm_client_assoc_req;

typedef struct {
    wifi_ctrl_webconfig_state_t type;
    wifi_vap_name_t  vap_name;
}__attribute__((packed)) wifi_webconfig_vapname_state_map_t;

typedef struct {
    char *result;
} wifiapi_t;

typedef struct kick_details {
    char *kick_list;
    int vap_index;
}kick_details_t;

typedef struct {
    wifi_connection_status_t    connect_status;
    bssid_t                     bssid;
}__attribute__((packed)) wifi_sta_conn_info_t;

typedef struct {
    int  wifi_csa_sched_handler_id[MAX_NUM_RADIOS];
    int  wifi_radio_sched_handler_id[MAX_NUM_RADIOS];
    int  wifi_vap_sched_handler_id[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
} wifi_scheduler_id_t;

typedef enum {
    wifi_csa_sched,
    wifi_radio_sched,
    wifi_vap_sched,
} wifi_scheduler_type_t;

typedef struct {
    wifi_scheduler_type_t type;
    unsigned int index;
}__attribute__((packed)) wifi_scheduler_id_arg_t;

#define MAX_EVENT_NAME_SIZE     200
typedef struct {
    char name[MAX_EVENT_NAME_SIZE];
    int idx;
    wifi_event_subtype_t type;
    BOOL subscribed;
    unsigned int num_subscribers;
}__attribute__((packed)) event_rbus_element_t;

typedef struct {
    char                 *diag_events_json_buffer[MAX_VAP];
    queue_t              *events_rbus_queue; //event_rbus_element_t
    pthread_mutex_t      events_rbus_lock;
} events_rbus_data_t;

typedef struct wifi_ctrl {
    bool                exit_ctrl;
    queue_t             *queue;
    pthread_mutex_t     lock;
    pthread_cond_t      cond;
    pthread_mutexattr_t attr;
    unsigned int        poll_period;
    struct timespec     last_signalled_time;
    struct timespec     last_polled_time;
    struct scheduler    *sched;
    webconfig_t         webconfig;
    wifi_ctrl_webconfig_state_t webconfig_state;
    rbusHandle_t        rbus_handle;
    bool                rbus_events_subscribed;
    bool                active_gateway_check_subscribed;
    bool                tunnel_events_subscribed;
    bool                mesh_status_subscribed;
    bool                device_mode_subscribed;
    bool                test_device_mode_subscribed;
    bool                device_tunnel_status_subscribed;
    bool                device_wps_test_subscribed;
    bool                frame_802_11_injector_subscribed;
    bool                factory_reset;
    bool                marker_list_config_subscribed;
    bool                eth_bh_status_subscribed;
    wifiapi_t           wifiapi;
#if DML_SUPPORT
    wifi_rfc_dml_parameters_t    rfc_params;
#endif // DML_SUPPORT
    unsigned int        sta_tree_instance_num;
    vap_svc_t           ctrl_svc[vap_svc_type_max];
    wifi_apps_mgr_t      apps_mgr;
    rdk_dev_mode_type_t  network_mode; /* 0 - gateway, 1 - extender */
    dev_subtype_t        dev_type;
    bool                active_gw_check;
    wifi_scheduler_id_t wifi_sched_id;
    queue_t             *vif_apply_pending_queue;
    bool                ctrl_initialized; 
    bool                acs_pending[MAX_NUM_RADIOS];
    int                 reset_params_retry_counter[MAX_NUM_RADIOS];
    bool                eth_bh_status;
    bool                db_consolidated;
    int                 speed_test_timeout;
    int                 speed_test_running;
    events_rbus_data_t  events_rbus_data;
} wifi_ctrl_t;


typedef struct {
    mac_address_t sta_mac;
    int reason;
} greylist_data_t;

typedef struct {
    unsigned int apIndex;
    int failure_reason;
} radius_eap_data_t;

typedef struct {
    unsigned long csi_session_num;
    bool enabled;
    unsigned int csi_client_count;
    mac_address_t csi_client_list[CSI_CLIENT_PER_SESSION];
} csi_data_t;

typedef enum {
    acl_action_add,
    acl_action_del,
    acl_action_none
} acl_action;

typedef enum {
    normalized_rssi_list_type,
    snr_list_type,
    cli_stat_list_type,
    txrx_rate_list_type
} marker_list_t;

typedef struct {
    wifi_vap_name_t  vap_name;;
    bool enabled;
} public_vaps_data_t;

void process_mgmt_ctrl_frame_event(frame_data_t *msg, uint32_t msg_length);
wifi_db_t *get_wifidb_obj();
wifi_ctrl_t *get_wifictrl_obj();
void deinit_ctrl_monitor(wifi_ctrl_t *ctrl);
bool is_db_consolidated();
bool is_db_backup_required();

UINT getRadioIndexFromAp(UINT apIndex);
UINT getPrivateApFromRadioIndex(UINT radioIndex);
CHAR* getVAPName(UINT apIndex);
BOOL isVapPrivate(UINT apIndex);
BOOL isVapXhs(UINT apIndex);
BOOL isVapHotspot(UINT apIndex);
BOOL isVapHotspotOpen(UINT apIndex);
BOOL isVapLnf(UINT apIndex);
BOOL isVapLnfPsk(UINT apIndex);
BOOL isVapMesh(UINT apIndex);
BOOL isVapSTAMesh(UINT apIndex);
BOOL isVapHotspotSecure(UINT apIndex);
BOOL isVapHotspotOpen5g(UINT apIndex);
BOOL isVapHotspotOpen6g(UINT apIndex);
BOOL isVapHotspotSecure5g(UINT apIndex);
BOOL isVapHotspotSecure6g(UINT apIndex);
BOOL isVapMeshBackhaul(UINT apIndex);
int getVAPIndexFromName(CHAR *vapName, UINT *apIndex);
BOOL isVapLnfSecure(UINT apIndex);
wifi_vap_info_t *getVapInfo(UINT apIndex);
wifi_radio_capabilities_t *getRadioCapability(UINT radioIndex);
wifi_radio_operationParam_t *getRadioOperationParam(UINT radioIndex);
rdk_wifi_vap_info_t *getRdkVapInfo(UINT apIndex);
wifi_hal_capability_t* rdk_wifi_get_hal_capability_map(void);
UINT getTotalNumberVAPs();
UINT getNumberRadios();
UINT getMaxNumberVAPsPerRadio(UINT radioIndex);
UINT getNumberVAPsPerRadio(UINT radioIndex);
//getVAPArrayIndexFromVAPIndex() need to be used in case of VAPS considered as single array (from 0 to MAX_VAP)
//In case of to get vap array index per radio, use convert_vap_index_to_vap_array_index()
int getVAPArrayIndexFromVAPIndex(unsigned int apIndex, unsigned int *vap_array_index);
rdk_wifi_vap_map_t *getRdkWifiVap(UINT radioIndex);
char* convert_radio_index_to_band_str_g(UINT radioIndex);
char* convert_radio_index_to_band_str(UINT radioIndex);
wifi_vap_info_map_t * Get_wifi_object(uint8_t radio_index);
wifi_GASConfiguration_t * Get_wifi_gas_conf_object(void);
wifi_interworking_t * Get_wifi_object_interworking_parameter(uint8_t vap_instance_number);
wifi_back_haul_sta_t * get_wifi_object_sta_parameter(uint8_t vapIndex);
rdk_wifi_vap_info_t* get_wifidb_rdk_vap_info(uint8_t vapIndex);
rdk_wifi_vap_info_t* get_wifidb_rdk_vaps(uint8_t radio_index);
int convert_radio_index_to_radio_name(int index,char *name);
wifi_global_param_t* get_wifidb_wifi_global_param(void);
wifi_global_config_t* get_wifidb_wifi_global_config(void);
wifi_radio_operationParam_t* get_wifidb_radio_map(uint8_t radio_index);
wifi_radio_feature_param_t* get_wifidb_radio_feat_map(uint8_t radio_index);
wifi_vap_info_map_t* get_wifidb_vap_map(uint8_t radio_index);
wifi_GASConfiguration_t* get_wifidb_gas_config(void);
wifi_interworking_t * Get_wifi_object_interworking_parameter(uint8_t vapIndex);
wifi_preassoc_control_t * Get_wifi_object_preassoc_ctrl_parameter(uint8_t vapIndex);
wifi_postassoc_control_t * Get_wifi_object_postassoc_ctrl_parameter(uint8_t vapIndex);
wifi_front_haul_bss_t * Get_wifi_object_bss_parameter(uint8_t vapIndex);
wifi_vap_security_t * Get_wifi_object_security_parameter(uint8_t vapIndex);
wifi_vap_info_t* get_wifidb_vap_parameters(uint8_t vapIndex);
#if DML_SUPPORT
wifi_rfc_dml_parameters_t* get_wifi_db_rfc_parameters(void);
wifi_rfc_dml_parameters_t* get_ctrl_rfc_parameters(void);
#endif // DML_SUPPORT
rdk_wifi_radio_t* find_radio_config_by_index(uint8_t r_index);
int get_device_config_list(char *d_list, int size, char *str);
int get_cm_mac_address(char *mac);
int get_vap_interface_bridge_name(unsigned int vap_index, char *bridge_name);
void Load_Hotspot_APIsolation_Settings();
void Hotspot_APIsolation_Set(int apIns);
int set_wifi_vap_network_status(uint8_t vapIndex, bool status);
void set_wifi_public_vap_enable_status(void);
void sta_pending_connection_retry(wifi_ctrl_t *ctrl);
bool get_wifi_mesh_vap_enable_status(void);
int get_wifi_mesh_sta_network_status(uint8_t vapIndex, bool *status);
bool check_for_greylisted_mac_filter(void);
void wait_wifi_scan_result(wifi_ctrl_t *ctrl);
int get_rbus_param(rbusHandle_t rbus_handle, rbus_data_type_t data_type, const char *paramNames, void *data_value);
int set_rbus_bool_param(rbusHandle_t rbus_handle, const char *paramNames, bool data_value);
bool is_sta_enabled(void);
void reset_wifi_radios();
wifi_platform_property_t *get_wifi_hal_cap_prop(void);
wifi_vap_security_t * Get_wifi_object_bss_security_parameter(uint8_t vapIndex);
wifi_vap_security_t * Get_wifi_object_sta_security_parameter(uint8_t vapIndex);
char *get_assoc_devices_blob();
void get_subdoc_name_from_vap_index(uint8_t vap_index, int* subdoc);

#ifdef __cplusplus
}
#endif

#endif //WIFI_CTRL_H
