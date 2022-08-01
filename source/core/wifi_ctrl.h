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
#include "wifi_blaster.h"
#include "vap_svc.h"
#include "cJSON.h"
#include "collection.h"
#include "wifi_util.h"
#include "wifi_webconfig.h"

#define WIFI_WEBCONFIG_PRIVATESSID         1
#define WIFI_WEBCONFIG_HOMESSID            2

#define WIFI_FEATURE_ResetSsid             1
#define WIFI_FEATURE_LoadDefaults          0

#define WIFI_MAX_SSID_NAME_LEN             33
#define QUEUE_WIFI_CTRL_TASK_TIMEOUT       1

#define RFC_WIFI_PASSPOINT          "RfcWifiPasspointEnable"
#define RFC_WIFI_INTERWORKING       "RfcWifiInterworkingEnable"
#define RFC_WIFI_RADIUS_GREYLIST    "RadiusGreyListEnable"
#define RFC_WIFI_DFSatBootup        "Wifi_DFSatBootup"
#define RFC_WIFI_DFS                "Wifi_DFS"
#define RFC_WIFI_WPA3               "Wifi_WPA3"

#define CSI_CLIENT_PER_SESSION 5
#define MAX_NUM_CSI_CLIENTS         3

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

#define WIFI_DEVICE_MODE                   "Device.X_RDKCENTRAL-COM_DeviceControl.DeviceNetworkingMode"
#define WIFI_DEVICE_TUNNEL_STATUS          "Device.TunnelStatus"

#define TEST_WIFI_DEVICE_MODE              "Device.X_RDKCENTRAL-COM_DeviceControl.DeviceNetworkingMode_1"

#define WIFI_RBUS_HOTSPOT_UP               "Device.WiFi.HotspotUp"
#define WIFI_RBUS_HOTSPOT_DOWN             "Device.WiFi.HotspotDown"

#define WIFI_WEBCONFIG_KICK_MAC            "Device.WiFi.KickAssocDevices"
#define RBUS_WIFI_WPS_PIN_START            "Device.WiFi.WPS.Start"

#define NAME_FREQUENCY_2_4                 2
#define NAME_FREQUENCY_5                   5
#define NAME_FREQUENCY_6                   6

#define WIFI_ALL_RADIO_INDICES             0xffff
#define DEVICE_TUNNEL_UP                   1
#define DEVICE_TUNNEL_DOWN                 0
//sta connection 9 seconds retry
#define STA_CONN_RETRY                     5

#define WLAN_RADIUS_GREYLIST_REJECT        100
#define GREYLIST_TIMEOUT_IN_SECONDS        (24 * 60 * 60)
#define GREYLIST_CHECK_IN_SECONDS          (1 * 60 * 60)

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
    ctrl_webconfig_state_max = 0x4000
} wifi_ctrl_webconfig_state_t;

#define CTRL_WEBCONFIG_STATE_MASK   0xffff

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

typedef enum {
    connection_attempt_wait,
    connection_attempt_in_progress,
    connection_attempt_failed
} connection_attempt_t;

typedef enum {
    connection_state_disconnected,
    connection_state_in_progress,
    connection_state_connected
} connection_state_t;

typedef struct scan_result {
    wifi_bss_info_t      external_ap;
    connection_attempt_t conn_attempt;
} scan_list_t;

typedef struct wifi_ctrl {
    bool                exit_ctrl;
    queue_t             *queue;
    pthread_mutex_t     lock;
    pthread_cond_t      cond;
    unsigned int        poll_period;
    struct timeval      last_signalled_time;
    struct timeval      last_polled_time;
    struct scheduler    *sched;
    webconfig_t         webconfig;
    wifi_ctrl_webconfig_state_t webconfig_state;
    rbusHandle_t        rbus_handle;
    bool                rbus_events_subscribed;
    bool                active_gateway_check_subscribed;
    bool                tunnel_events_subscribed;
    bool                device_mode_subscribed;
    bool                test_device_mode_subscribed;
    bool                device_tunnel_status_subscribed;
    bool                device_wps_test_subscribed;
    bool                factory_reset;
    wifiapi_t           wifiapi;
    wifi_rfc_dml_parameters_t    rfc_params;
    unsigned int        sta_tree_instance_num;
    vap_svc_t           ctrl_svc[vap_svc_type_max];
    scan_list_t         *scan_list;
    unsigned int        scan_count;
    connection_state_t  conn_state;
    unsigned int        network_mode; /* 0 - gateway, 1 - extender */
    unsigned int        connected_vap_index;
} wifi_ctrl_t;

typedef enum {
    ctrl_event_type_webconfig,
    ctrl_event_type_hal_ind,
    ctrl_event_type_command,
    ctrl_event_type_wifiapi,
    ctrl_event_type_max
} ctrl_event_type_t;

typedef enum {
    // WebConfig event sub types
    ctrl_event_webconfig_set_data,
    ctrl_event_webconfig_get_data,
    ctrl_event_webconfig_set_data_tunnel,

    // HAL events
    ctrl_event_hal_mgmt_farmes = 0x100,
    ctrl_event_hal_sta_conn_status,
    ctrl_event_hal_assoc_device,
    ctrl_event_hal_disassoc_device,
    ctrl_event_scan_results,
    ctrl_event_hal_channel_change,
    ctrl_event_radius_greylist,
    // Commands
    ctrl_event_type_command_sta_connect = 0x200,
    ctrl_event_type_command_factory_reset,
    ctrl_event_type_radius_grey_list_rfc,
    ctrl_event_type_wifi_passpoint_rfc,
    ctrl_event_type_wifi_interworking_rfc,
    ctrl_event_type_wpa3_rfc,
    ctrl_event_type_dfs_rfc,
    ctrl_event_type_dfs_atbootup_rfc,
    ctrl_event_type_command_kickmac,
    ctrl_event_type_command_kick_assoc_devices,
    ctrl_event_type_command_wps,
    ctrl_event_type_command_wifi_host_sync,
    ctrl_event_type_device_network_mode,
    ctrl_event_type_twoG80211axEnable_rfc,
    ctrl_event_type_command_wifi_neighborscan,

    // wif_api
    ctrl_event_type_wifiapi_execution = 0x300,

    // Tunnel
    ctrl_event_type_xfinity_tunnel_up = 0x400,
    ctrl_event_type_xfinity_tunnel_down,

} ctrl_event_subtype_t;

typedef struct {
    ctrl_event_type_t     event_type;
    ctrl_event_subtype_t  sub_type;
    void *msg;
    unsigned int len;
} __attribute__((__packed__)) ctrl_event_t;

typedef struct {
    int ap_index;
    mac_address_t sta_mac;
    void *frame;
    uint32_t len;
    wifi_mgmtFrameType_t type;
    wifi_direction_t dir;
} frame_data_t;


typedef struct {
    int ap_index;
    wifi_associated_dev3_t dev_stats;
}__attribute__((__packed__)) assoc_dev_data_t;


typedef struct {
    mac_address_t sta_mac;
    int reason;
} greylist_data_t;

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

typedef struct {
    mac_address_t mac;
    CHAR device_name[64];
    int reason;
    int expiry_time;
}__attribute__((__packed__)) acl_entry_t;

void process_mgmt_ctrl_frame_event(frame_data_t *msg, uint32_t msg_length);
wifi_db_t *get_wifidb_obj();
wifi_ctrl_t *get_wifictrl_obj();
void deinit_ctrl_monitor(wifi_ctrl_t *ctrl);

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
UINT getNumberofVAPsPerRadio(UINT radioIndex);
rdk_wifi_vap_map_t *getRdkWifiVap(UINT radioIndex);
UINT convert_radio_index_to_frequencyNum(UINT radioIndex);
wifi_vap_info_map_t * Get_wifi_object(uint8_t radio_index);
wifi_GASConfiguration_t * Get_wifi_gas_conf_object(void);
wifi_interworking_t * Get_wifi_object_interworking_parameter(uint8_t vap_instance_number);
wifi_back_haul_sta_t * get_wifi_object_sta_parameter(uint8_t vapIndex);
rdk_wifi_vap_info_t* get_wifidb_rdk_vap_info(uint8_t vapIndex);
int convert_radio_index_to_radio_name(int index,char *name);
wifi_global_param_t* get_wifidb_wifi_global_param(void);
wifi_global_config_t* get_wifidb_wifi_global_config(void);
wifi_radio_operationParam_t* get_wifidb_radio_map(uint8_t radio_index);
wifi_vap_info_map_t* get_wifidb_vap_map(uint8_t radio_index);
wifi_GASConfiguration_t* get_wifidb_gas_config(void);
wifi_interworking_t * Get_wifi_object_interworking_parameter(uint8_t vapIndex);
wifi_front_haul_bss_t * Get_wifi_object_bss_parameter(uint8_t vapIndex);
wifi_vap_security_t * Get_wifi_object_security_parameter(uint8_t vapIndex);
wifi_vap_info_t* get_wifidb_vap_parameters(uint8_t vapIndex);
wifi_rfc_dml_parameters_t* get_wifi_db_rfc_parameters(void);
rdk_wifi_radio_t* find_radio_config_by_index(uint8_t r_index);
int get_cm_mac_address(char *mac);
int get_vap_interface_bridge_name(unsigned int vap_index, char *bridge_name);
void Load_Hotspot_APIsolation_Settings();
void Hotspot_APIsolation_Set(int apIns);
int set_wifi_vap_network_status(uint8_t vapIndex, bool status);
int set_wifi_public_vap_enable_status(void);
void sta_pending_connection_retry(wifi_ctrl_t *ctrl);
bool get_wifi_mesh_vap_enable_status(void);
int get_wifi_mesh_sta_network_status(uint8_t vapIndex, bool *status);
bool check_for_greylisted_mac_filter(void);
#ifdef __cplusplus
}
#endif

#endif //WIFI_CTRL_H
