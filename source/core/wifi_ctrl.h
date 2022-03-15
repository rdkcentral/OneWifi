#ifndef WIFI_CTRL_H
#define WIFI_CTRL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ev.h>
#include <rbus.h>
#include "wifi_base.h"
#include "wifi_db.h"
#include "wifi_blaster.h"
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

#define RFC_WIFI_PASSPOINT_STATUS          "RfcWifiPasspointEnable"
#define RFC_WIFI_INTERWORKING_STATUS       "RfcWifiInterworkingEnable"
#define RFC_WIFI_RADIUS_GREYLIST_STATUS    "RadiusGreyListStatus"
#define RFC_WIFI_DISABLE_NATIVE_HOSTAPD    "DisableNativeHostapd"
#define RFC_WIFI_EASY_CONNECT              "WifiEasyConnect"
#define RFC_WIFI_CLIENT_ACTIVE_MEASUREMENTS "Wifi_ActiveMeasurements"

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

#define NAME_FREQUENCY_2_4                 2
#define NAME_FREQUENCY_5                   5
#define NAME_FREQUENCY_6                   6

typedef enum {
    ctrl_webconfig_state_none,
    ctrl_webconfig_state_radio_cfg_rsp_pending,
    ctrl_webconfig_state_vap_cfg_rsp_pending,
    ctrl_webconfig_state_wifi_config_cfg_rsp_pending,
    ctrl_webconfig_state_max
} wifi_ctrl_webconfig_state_t;

typedef struct {
    char *result;
} wifiapi_t;

typedef struct {
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
    bool                factory_reset;
    bool                scan_result_for_connect_pending;
    unsigned char       sta_conn_retry;
    wifiapi_t           wifiapi;
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

    // HAL events
    ctrl_event_hal_mgmt_farmes = 0x100,
    ctrl_event_hal_sta_conn_status,
    ctrl_event_hal_assoc_device,
    ctrl_event_hal_disassoc_device,
    ctrl_event_scan_results,

    // Commands
    ctrl_event_type_command_sta_connect = 0x200,
    ctrl_event_type_command_factory_reset,
    ctrl_event_type_command_kickmac,

    // wif_api
    ctrl_event_type_wifiapi_execution = 0x300,

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

typedef enum {
    acl_action_add,
    acl_action_del,
    acl_action_none
} acl_action;

typedef struct {
    mac_address_t mac;
    CHAR device_name[64];
    acl_action acl_action_type;
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
int getVAPIndexFromName(CHAR *vapName, UINT *apIndex);
BOOL isVapLnfSecure(UINT apIndex);
wifi_vap_info_t *getVapInfo(UINT apIndex);
wifi_radio_capabilities_t *getRadioCapability(UINT radioIndex);
wifi_radio_operationParam_t *getRadioOperationParam(UINT radioIndex);
rdk_wifi_vap_info_t *getRdkVapInfo(UINT apIndex);
UINT getTotalNumberVAPs();
UINT getNumberRadios();
UINT getMaxNumberVAPsPerRadio(UINT radioIndex);
UINT getNumberofVAPsPerRadio(UINT radioIndex);
rdk_wifi_vap_map_t *getRdkWifiVap(UINT radioIndex);
UINT convert_radio_index_to_frequencyNum(UINT radioIndex);
wifi_vap_info_map_t * Get_wifi_object(uint8_t radio_index);
wifi_GASConfiguration_t * Get_wifi_gas_conf_object(void);
wifi_interworking_t * Get_wifi_object_interworking_parameter(uint8_t vap_instance_number);
wifi_front_haul_bss_t * Get_wifi_object_bss_parameter(uint8_t vap_instance_number);
wifi_back_haul_sta_t * get_wifi_object_sta_parameter(uint8_t vapIndex);
rdk_wifi_vap_info_t* get_wifidb_rdk_vap_info(uint8_t vapIndex);
void get_vap_and_radio_index_from_vap_instance(uint8_t vap_instance, uint8_t *radio_index, uint8_t *vap_index);
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

#ifdef __cplusplus
}
#endif

#endif //WIFI_CTRL_H
