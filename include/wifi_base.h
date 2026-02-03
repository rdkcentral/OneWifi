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

#include "collection.h"
#include <pthread.h>
#include <sys/time.h>
#include "wifi_hal.h"

#define WIFI_STA_2G_VAP_CONNECT_STATUS      "Device.WiFi.STA.1.Connection.Status"
#define WIFI_STA_5G_VAP_CONNECT_STATUS      "Device.WiFi.STA.2.Connection.Status"
#define WIFI_STA_2G_INTERFACE_NAME          "Device.WiFi.STA.1.InterfaceName"
#define WIFI_STA_5G_INTERFACE_NAME          "Device.WiFi.STA.2.InterfaceName"
#define WIFI_STA_NAMESPACE                  "Device.WiFi.STA.{i}."
#define WIFI_STA_CONNECT_STATUS             "Device.WiFi.STA.{i}.Connection.Status"
#define WIFI_STA_INTERFACE_NAME             "Device.WiFi.STA.{i}.InterfaceName"
#define WIFI_STA_CONNECTED_GW_BSSID         "Device.WiFi.STA.{i}.Bssid"
#define WIFI_STA_SELFHEAL_CONNECTION_TIMEOUT "Device.WiFi.STAConnectionTimeout"
#define WIFI_ENDPOINT_CONNECT_STATUS        "Device.WiFi.EndPoint.1.Status"
#define WIFI_ACTIVE_GATEWAY_CHECK           "Device.X_RDK_GatewayManagement.ExternalGatewayPresent"
#define WIFI_ENDPOINT_ENABLE_CHECK          "Device.WiFi.EndPoint.1.Enable"
#define WIFI_WAN_FAILOVER_TEST              "Device.WiFi.WanFailoverTest"
#define WIFI_LMLITE_NOTIFY                  "Device.Hosts.X_RDKCENTRAL-COM_LMHost_Sync_From_WiFi"
#define WIFI_HOTSPOT_NOTIFY                 "Device.X_COMCAST-COM_GRE.Hotspot.ClientChange"
#define WIFI_NOTIFY_SYNC_COMPONENT          "Device.NotifyComponent.SetNotifi_ParamName"
#define WIFI_NOTIFY_FORCE_DISASSOCIATION    "Device.WiFi.ConnectionControl.ClientForceDisassociation"
#define WIFI_NOTIFY_DENY_ASSOCIATION        "Device.WiFi.ConnectionControl.ClientDenyAssociation"
#define MESH_STATUS                         "Device.DeviceInfo.X_RDKCENTRAL-COM_xOpsDeviceMgmt.Mesh.Enable"
#define WIFI_FRAME_INJECTOR_TO_ONEWIFI      "Device.WiFi.TestFrameInput"
#define WIFI_STA_TRIGGER_DISCONNECTION      "Device.WiFi.X_RDK_STATriggerDisconnection"
#define ACCESSPOINT_ASSOC_REQ_EVENT         "Device.WiFi.AP.STA.AssocRequest"
#define WIFI_CLIENT_GET_ASSOC_REQ           "Device.WiFi.AP.STA.GetAssocRequest"
#define WIFI_ACCESSPOINT_TABLE              "Device.WiFi.AccessPoint.{i}."
#define WIFI_ACCESSPOINT_DEV_CONNECTED      "Device.WiFi.AccessPoint.{i}.X_RDK_deviceConnected"
#define WIFI_ACCESSPOINT_DEV_DISCONNECTED   "Device.WiFi.AccessPoint.{i}.X_RDK_deviceDisconnected"
#define WIFI_ACCESSPOINT_DEV_DEAUTH         "Device.WiFi.AccessPoint.{i}.X_RDK_deviceDeauthenticated"
#define WIFI_ACCESSPOINT_DIAGDATA           "Device.WiFi.AccessPoint.{i}.X_RDK_DiagData"
#define WIFI_ACCESSPOINT_FORCE_APPLY        "Device.WiFi.AccessPoint.{i}.ForceApply"
#define WIFI_ACCESSPOINT_RADIUS_CONNECTED_ENDPOINT   "Device.WiFi.AccessPoint.{i}.Security.ConnectedRadiusEndpoint"
#define WIFI_ACCESSPOINT_RAWFRAME_MGMT_ACTION_TX     "Device.WiFi.AccessPoint.{i}.RawFrame.Mgmt.Action.Tx"
#define WIFI_ACCESSPOINT_RAWFRAME_MGMT_ACTION_RX     "Device.WiFi.AccessPoint.{i}.RawFrame.Mgmt.Action.Rx"
#define WIFI_CSI_TABLE                      "Device.WiFi.X_RDK_CSI.{i}."
#define WIFI_CSI_DATA                       "Device.WiFi.X_RDK_CSI.{i}.data"
#define WIFI_CSI_CLIENTMACLIST              "Device.WiFi.X_RDK_CSI.{i}.ClientMaclist"
#define WIFI_CSI_ENABLE                     "Device.WiFi.X_RDK_CSI.{i}.Enable"
#define WIFI_CSI_NUMBEROFENTRIES            "Device.WiFi.X_RDK_CSINumberOfEntries"
#define WIFI_COLLECT_STATS_TABLE            "Device.WiFi.CollectStats.Radio.{i}."
#define WIFI_COLLECT_STATS_RADIO_ON_CHANNEL_STATS      "Device.WiFi.CollectStats.Radio.{i}.ScanMode.on_channel.ChannelStats"
#define WIFI_COLLECT_STATS_RADIO_OFF_CHANNEL_STATS     "Device.WiFi.CollectStats.Radio.{i}.ScanMode.off_channel.ChannelStats"
#define WIFI_COLLECT_STATS_RADIO_FULL_CHANNEL_STATS    "Device.WiFi.CollectStats.Radio.{i}.ScanMode.full_channel.ChannelStats"
#define WIFI_COLLECT_STATS_NEIGHBOR_ON_CHANNEL_STATS   "Device.WiFi.CollectStats.Radio.{i}.ScanMode.on_channel.NeighborStats"
#define WIFI_COLLECT_STATS_NEIGHBOR_OFF_CHANNEL_STATS  "Device.WiFi.CollectStats.Radio.{i}.ScanMode.off_channel.NeighborStats"
#define WIFI_COLLECT_STATS_NEIGHBOR_FULL_CHANNEL_STATS "Device.WiFi.CollectStats.Radio.{i}.ScanMode.full_channel.NeighborStats"
#define WIFI_COLLECT_STATS_RADIO_DIAGNOSTICS           "Device.WiFi.CollectStats.Radio.{i}.RadioDiagnosticStats"
#define WIFI_COLLECT_STATS_RADIO_TEMPERATURE           "Device.WiFi.CollectStats.Radio.{i}.RadioTemperatureStats"
#define WIFI_COLLECT_STATS_VAP_TABLE                   "Device.WiFi.CollectStats.AccessPoint.{i}."
#define WIFI_COLLECT_STATS_ASSOC_DEVICE_STATS          "Device.WiFi.CollectStats.AccessPoint.{i}.AssociatedDeviceStats"
#define WIFI_NOTIFY_DENY_TCM_ASSOCIATION               "Device.WiFi.ConnectionControl.TcmClientDenyAssociation"
#define WIFI_CSA_BEACON_FRAME_RECEIVED                 "Device.WiFi.CSABeaconFrameRecieved"
#define WIFI_STUCK_DETECT_FILE_NAME         "/nvram/wifi_stuck_detect"

#ifdef CONFIG_IEEE80211BE

#ifndef MAX_NUM_MLD_LINKS
#define MAX_NUM_MLD_LINKS 15
#endif /*MAX_NUM_MLD_LINKS*/

#define UNDEFINED_MLD_ID 255
#define MLD_UNIT_COUNT 8

#endif /* CONFIG_IEEE80211BE */

#define PLAN_ID_LENGTH     38
#define MAX_STEP_COUNT  32 /*Active Measurement Step Count */
#define  MAC_ADDRESS_LENGTH  13
#define WIFI_AP_MAX_WPSPIN_LEN  9
#define MAX_BUF_LENGTH 128

#define ANAYLYTICS_PERIOD             60
#define MAX_ASSOC_FRAME_REFRESH_PERIOD 30

//Broadcom driver max acl count for each vap
#define MAX_ACL_COUNT 20
#define CAC_PERIOD                     1


#define QUEUE_WIFI_CTRL_TASK_TIMEOUT  1
#define MAX_FRAME_SZ                  2048

#define MAX_CSI_INTERVAL    30000
#define MIN_CSI_INTERVAL    100
#define MIN_DIAG_INTERVAL   5000
#define CSI_PING_INTERVAL   100

#define DEFAULT_RSS_CHECK_INTERVAL 5 //minutes
#define DEFAULT_RSS_THRESHOLD 1000 //kbytes
#define DEFAULT_RSS_MAXLIMIT 70000 //kbytes
#define DEFAULT_HEAPWALK_DURATION 60 //minutes
#define DEFAULT_HEAPWALK_INTERVAL 15 //minutes

#define RSS_MEM_THRESHOLD1_DEFAULT 81920 /*Threshold1 is 80MB*/
#define RSS_MEM_THRESHOLD2_DEFAULT 112640 /*Threshold2 is 110MB*/

#define wifi_sub_component_base     0x01
#define wifi_app_inst_base          0x01

#define DEFAULT_SOUNDING_DURATION_MS 2000

#if (defined SIMULATION)
#define NEIGHBORHOOD_SCAN_AVRO_FILENAME         "GatewayAccessPointNeighborScanReport.avsc"
#define INTERFACE_DEVICES_WIFI_AVRO_FILENAME            "InterfaceDevicesWifi.avsc"
#define WIFI_SINGLE_CLIENT_AVRO_FILENAME        "/usr/ccsp/wifi/WifiSingleClient.avsc"
#define RADIO_INTERFACE_STATS_AVRO_FILENAME             "RadioInterfacesStatistics.avsc"
#else
#define NEIGHBORHOOD_SCAN_AVRO_FILENAME         "/usr/ccsp/harvester/GatewayAccessPointNeighborScanReport.avsc"
#define INTERFACE_DEVICES_WIFI_AVRO_FILENAME            "/usr/ccsp/harvester/InterfaceDevicesWifi.avsc"
#define WIFI_SINGLE_CLIENT_AVRO_FILENAME        "/usr/ccsp/wifi/WifiSingleClient.avsc"
#define RADIO_INTERFACE_STATS_AVRO_FILENAME             "/usr/ccsp/harvester/RadioInterfacesStatistics.avsc"
#define WIFI_SINGLE_CLIENT_BLASTER_AVRO_FILENAME        "/usr/ccsp/wifi/WifiSingleClientActiveMeasurement.avsc"
#endif
#define CHK_AVRO_ERR (strlen(avro_strerror()) > 0)

#define CFG_ID_LEN             64
typedef char stats_cfg_id_t[CFG_ID_LEN];

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
    wifi_app_inst_sm = wifi_app_inst_base << 10,
    wifi_app_inst_motion = wifi_app_inst_base << 11,
    wifi_app_inst_csi = wifi_app_inst_base << 12,
    wifi_app_inst_whix = wifi_app_inst_base << 13,
    wifi_app_inst_core = wifi_app_inst_base << 14,
    wifi_app_inst_ocs = wifi_app_inst_base << 15,
    wifi_app_inst_easyconnect = wifi_app_inst_base << 16,
    wifi_app_inst_sta_mgr = wifi_app_inst_base << 17,
    wifi_app_inst_memwraptool = wifi_app_inst_base << 18,
    wifi_app_inst_csi_analytics = wifi_app_inst_base << 19,
    wifi_app_inst_max = wifi_app_inst_base << 20
} wifi_app_inst_t;

typedef struct {
    void *msg;
    unsigned int len;
} wifi_core_data_t;

typedef void *wifi_analytics_data_t;

#define MAC_ADDR_LEN    6
#define STA_KEY_LEN     2*MAC_ADDR_LEN + 6
#define MAX_IPC_DATA_LEN    1024
#define KMSG_WRAPPER_FILE_NAME  "/tmp/goodbad-rssi"

#define CLIENT_STATS_MAX_LEN_BUF    (128)
#define MIN_MAC_ADDR_LEN    2*MAC_ADDR_LEN + 1

#define IP_STR_LEN 64
#define MILLISEC_TO_MICROSEC 1000
#define IPREFRESH_PERIOD_IN_MILLISECONDS 24 * 60 * 60 * 1000
#define MAX_CSI_CLIENTS_PER_SESSION 50

#define MONITOR_RUNNING_INTERVAL_IN_MILLISEC    100

#define MAX_CSI_CLIENTMACLIST_STR  650
#define CSI_HEADER_SIZE (4 + sizeof(unsigned int) + sizeof(time_t) + (sizeof(unsigned int)) + (1 *((sizeof(unsigned char)*6) + sizeof(unsigned int))))


#define MAX_BUF_SIZE 128
#define MON_STATS_KEY_LEN_32     32
#define MON_STATS_KEY_LEN_16     16
#define MON_STATS_KEY_LEN_8       8

/* Number of stations supported defines */
#define BSS_MAX_NUM_STA_COMMON   75      /**< Max supported stations for all common platforms except following defines... */
#define BSS_MAX_NUM_STA_SKY      64      /**< Max supported stations for SKY HUB specific platforms */
#define BSS_MAX_NUM_STA_XB8      100     /**< Max supported stations for TCHX8 specific platform */
#define BSS_MAX_NUM_STATIONS     100     /**< Max supported stations by RDK-B firmware which would varies based on platform */
#define BSS_MAX_NUM_STA_HOTSPOT_CBRV2    15      /**< Max supported stations for hotspot vaps in CBR2 platform */
#define BSS_MAX_NUM_STA_HOTSPOT_XB      5      /**< Max supported stations for hotspot vaps in XB platform */

#define STA_MAX_BSS_ASSOCIATIONS  1

typedef unsigned char   mac_addr_t[MAC_ADDR_LEN];
typedef signed short    rssi_t;
typedef char            sta_key_t[STA_KEY_LEN];
typedef struct {
    unsigned int num;
    wifi_associated_dev3_t  devs[BSS_MAX_NUM_STATIONS];
} associated_devs_t;
typedef struct {
    mac_address_t  sta_mac;
    int        reason;
    wifi_associated_dev3_t dev_stats;
} auth_deauth_dev_t;

#define MAX_MQTT_TOPIC_LEN 256

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

typedef enum {
    ACTIVE_MSMT_STEP_DONE,
    ACTIVE_MSMT_STEP_PENDING,
    ACTIVE_MSMT_STEP_INVALID,
} active_msmt_step_status_t;

typedef struct {
    double cpu_one;
    double cpu_five;
    double cpu_fifteen;
    unsigned int util_cpu;
    unsigned int util_mem;
} active_msmt_resources_t;

typedef struct {
  char traceParent[512];
  char traceState[512];
} trace_headers_t;

typedef struct {
    bool                              ActiveMsmtEnable;
    unsigned int                      ActiveMsmtSampleDuration;
    unsigned int                      ActiveMsmtPktSize;
    unsigned int                      ActiveMsmtNumberOfSamples;
    unsigned char                     PlanId[PLAN_ID_LENGTH];
    active_msmt_step_status_t         StepInstance[MAX_STEP_COUNT];
    active_msmt_step_t                Step[MAX_STEP_COUNT];
    active_msmt_resources_t           ActiveMsmtResources;
    blaster_state_t                   Status;
    trace_headers_t                   t_header;
    unsigned char                     blaster_mqtt_topic[MAX_MQTT_TOPIC_LEN];
} active_msmt_t;

typedef struct {
    int type;  //Device.WiFi.X_RDKCENTRAL-COM_vAPStatsEnable= 0, Device.WiFi.AccessPoint.<vAP>.X_RDKCENTRAL-COM_StatsEnable = 1
    bool enable; // true, false
} client_stats_enable_t;

typedef struct {
    mac_address_t  sta_mac;
    unsigned int   ap_index;
    bool           active;
} instant_msmt_t;

typedef struct {
    mac_address_t   sta_mac;
    char header[CSI_HEADER_SIZE];
    wifi_csi_data_t csi;
} __attribute__((packed)) wifi_csi_dev_t;

#ifdef EM_APP
typedef struct wifi_hal_rrm_request {
    uint8_t dialog_token;
    uint8_t duration;
    bool duration_mandatory;
    uint8_t op_class;
    uint8_t channel;
} wifi_hal_rrm_request_t;

typedef struct {
    mac_address_t sta_mac;
    unsigned int ap_index;
    size_t len;
    wifi_BeaconReport_t *data;
} beacon_repo_data_t;
#endif

// data collection api type
typedef enum {
    mon_stats_type_radio_channel_stats=1,
    mon_stats_type_neighbor_stats,
    mon_stats_type_associated_device_stats,
    mon_stats_type_radio_diagnostic_stats,
    mon_stats_type_radio_temperature,
    mon_stats_type_max
} wifi_mon_stats_type_t;

typedef enum {
    mon_stats_request_state_stop,
    mon_stats_request_state_start
} wifi_mon_stats_request_state_t;

typedef enum {
    whix_app_event_type_chan_stats = 1,
    whix_app_event_type_chan_util,
    whix_app_event_type_assoc_dev_stats,
    whix_app_event_type_assoc_dev_diagnostics,
    whix_app_event_type_radio_diag_stats,
    whix_app_event_type_max
} whix_app_event_type_t;

typedef struct {
    unsigned int ap_index;
    mac_addr_t dest_addr;
    unsigned int frequency;
    unsigned int wait_time_ms;
    unsigned int frame_len;
    uint8_t frame_data[0];
} __attribute__((packed)) action_frame_params_t;

typedef struct {
    unsigned int            radio_index;
    unsigned int            vap_index;
    wifi_channels_list_t    channel_list;
    unsigned char target_mac[MAC_ADDRESS_LENGTH];
    wifi_neighborScanMode_t scan_mode;
    int dwell_time; //survey_interval_ms
    unsigned int app_info; //This is respective specific variable. Can be used by app for internal event identification
} __attribute__((packed)) wifi_mon_stats_args_t;


typedef struct {
    wifi_mon_stats_type_t  data_type;
    wifi_mon_stats_args_t     args;
    void *stat_pointer;
    unsigned int stat_array_size;
    time_t response_time;
} __attribute__((packed)) wifi_provider_response_t;

typedef struct {
    wifi_app_inst_t     inst;
    wifi_mon_stats_type_t  data_type;
    unsigned long       interval_ms;
    bool                task_priority; //if TRUE its high priority
    bool                start_immediately;
    unsigned int        delay_provider_sec;
    wifi_mon_stats_request_state_t    req_state;
    wifi_mon_stats_args_t     args;
} __attribute__((packed)) wifi_mon_stats_config_t;

typedef struct {
    wifi_channelMap_t channel_map[MAX_CHANNELS];
    wifi_radio_index_t radio_index;
} wifi_channel_status_event_t;

typedef struct {
    wifi_frame_t    frame;
    unsigned char data[MAX_FRAME_SZ];
} __attribute__((__packed__)) frame_data_t;

typedef struct {
    queue_t    *csi_queue;
    bool       pause_pinger;
    int        ap_index;
    mac_addr_t mac_addr;
} csi_mon_t;

typedef struct {
    ULONG            TidleSec;
    ULONG            NscanSec;
    unsigned int     radio_index;
} ocs_params_t;

typedef struct {
    bool is_event_subscribed;
    unsigned int radio_index;
    unsigned int vap_index;
    wifi_neighborScanMode_t  scan_mode;
    wifi_mon_stats_type_t stats_type;
    unsigned char target_mac[MAC_ADDRESS_LENGTH];
    unsigned int stats_type_subscribed;//bitmask  for wifi_mon_stats_type_t
} collect_stats_t;

typedef struct {
    unsigned int id;
    int  csi_session;
    unsigned int    ap_index;
    union {
        auth_deauth_dev_t   dev;
        client_stats_enable_t   flag;
        instant_msmt_t      imsmt;
        active_msmt_t       amsmt;
        associated_devs_t   devs;
        csi_mon_t           csi_mon;
        wifi_mon_stats_config_t mon_stats_config;
        frame_data_t msg;
        ocs_params_t        ocs_params;
        collect_stats_t     collect_stats;
        wifi_channel_status_event_t channel_status_map;
    } u;
} wifi_monitor_data_t;

typedef struct {
    unsigned int  vap_index;
    char          wps_pin[10];
} __attribute__((__packed__)) wps_pin_config_t;

#define MAX_SCANNED_VAPS       200

typedef struct {
    unsigned int radio_index;
    wifi_bss_info_t bss[MAX_SCANNED_VAPS];
    unsigned int num;
} scan_results_t;

typedef enum {
    dev_subtype_rdk,
    dev_subtype_pod
} dev_subtype_t;

typedef enum {
    rdk_dev_mode_type_gw,
    rdk_dev_mode_type_ext,
    rdk_dev_mode_type_em_node,
    rdk_dev_mode_type_em_colocated_node
} rdk_dev_mode_type_t;

typedef struct {
    mac_address_t clientMac;
    int max_num_csi_clients;
    int levl_sounding_duration;
    int levl_publish_interval;
}levl_config_t;

typedef struct {
    unsigned int rss_check_interval; //minutes
    unsigned int rss_threshold; //kbytes
    unsigned int rss_maxlimit; //kbytes
    unsigned int heapwalk_duration; //minutes
    unsigned int heapwalk_interval; //minutes
    bool enable;
} __attribute__((packed)) memwraptool_config_t;

typedef struct {
    bool wifi_offchannelscan_app_rfc;
    bool wifi_offchannelscan_sm_rfc;
    bool wifipasspoint_rfc;
    bool wifiinterworking_rfc;
    bool radiusgreylist_rfc;
    bool dfsatbootup_rfc;
    bool dfs_rfc;
    bool wpa3_rfc;
    bool twoG80211axEnable_rfc;
    bool hotspot_open_2g_last_enabled;
    bool hotspot_open_5g_last_enabled;
    bool hotspot_open_6g_last_enabled;
    bool hotspot_secure_2g_last_enabled;
    bool hotspot_secure_5g_last_enabled;
    bool hotspot_secure_6g_last_enabled;
    char rfc_id[5];
    // app specific rfc
    bool levl_enabled_rfc;
    bool multiap_enabled_rfc;
    bool motion_enabled_rfc;
    bool scm_enabled_rfc;
    bool harverster_enabled_rfc;
    bool blaster_enabled_rfc;
    bool greylist_enabled_rfc;
    bool cac_enabled_rfc;
    bool tcm_enabled_rfc;
    bool wpa3_compatibility_enable;
    bool memwraptool_app_rfc;
    bool csi_analytics_enabled_rfc;
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
    int  whix_log_interval; //seconds
    int  whix_chutility_loginterval; //seconds
    ULONG rss_memory_restart_threshold_low;
    ULONG rss_memory_restart_threshold_high;
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
    memwraptool_config_t memwraptool;
    bool mgt_frame_rate_limit_enable;
    int mgt_frame_rate_limit;
    int mgt_frame_rate_limit_window_size;
    int mgt_frame_rate_limit_cooldown_time;
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
    ULONG Tscan;
    ULONG Nscan;
    ULONG Tidle;
} __attribute__((packed)) wifi_radio_feat_psm_param_t;

typedef struct {
//This structure is used for all the feature developments for radio
// offchannel scan params
    ULONG OffChanTscanInMsec; // time that a single channel is scanned (unit: msec)
    ULONG OffChanNscanInSec; // number of scans/channel (stored in sec)
    ULONG OffChanTidleInSec; // time to account for network idleness (sec)
    unsigned int radio_index;
    ULONG Nchannel;
} __attribute__((packed)) wifi_radio_feature_param_t;

typedef struct {
    unsigned int data_index;
    CHAR mac[18];
    CHAR device_name[64];
} __attribute__((packed)) wifi_mac_psm_param_t;

typedef struct {
    hash_map_t *mac_entry[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
} wifi_mac_psm_entry_t;

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
    wifi_radio_feat_psm_param_t radio_feat_psm_cfg[MAX_NUM_RADIOS];
} wifi_psm_param_t;

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
    hash_map_t              *associated_devices_map; //Full
    hash_map_t              *associated_devices_diff_map; //Add,Remove
    pthread_mutex_t         *associated_devices_lock;
    int                     kick_device_task_counter;
    bool                    kick_device_config_change;
    bool                    is_mac_filter_initialized;
    bool                    exists;
    int                     anqp_request_count;
    int                     anqp_response_count;
    bool                    force_apply;
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
    // steering_cfg_id is source VAP name concatenated with "_to_" and concatenated
    // with target VAP name. So id for the configuration of private on 2G to private
    // on 5G will be private_ssid_2g_to_private_ssid_5g
    char    steering_cfg_id[CFG_ID_LEN];
    unsigned int chan_util_avg_count;
    unsigned int chan_util_check_sec;
    unsigned int chan_util_hwm;
    unsigned int chan_util_lwm;
    bool dbg_2g_raw_chan_util;
    bool dbg_2g_raw_rssi;
    bool dbg_5g_raw_chan_util;
    bool dbg_5g_raw_rssi;
    unsigned int    debug_level;
    unsigned int    def_rssi_inact_xing;
    unsigned int    def_rssi_low_xing;
    unsigned int    def_rssi_xing;
    bool    gw_only;
    wifi_vap_name_t   vap_name_list[16];
    int               vap_name_list_len;
    unsigned int    inact_check_sec;
    unsigned int    inact_tmout_sec_normal;
    unsigned int    inact_tmout_sec_overload;
    unsigned int    kick_debounce_period;
    unsigned int    kick_debounce_thresh;
    unsigned int    stats_report_interval;
    unsigned int    success_threshold_secs;
} steering_config_t;

 typedef enum {
     stats_type_neighbor,
     stats_type_survey,
     stats_type_client,
     stats_type_capacity,
     stats_type_radio,
     stats_type_essid,
     stats_type_quality,
     stats_type_device,
     stats_type_rssi,
     stats_type_steering,
     stats_type_client_auth_fails,
     stats_type_max
 } stats_type_t;

 typedef enum {
     report_type_raw,
     report_type_average,
     report_type_histogram,
     report_type_percentile,
     report_type_diff,
     report_type_max
 } reporting_type_t;

typedef enum {
    survey_type_on_channel,
    survey_type_off_channel,
    survey_type_full,
    survey_type_max
} survey_type_t;

typedef struct {
    // stats_cfg_id is generated by doing a sha256 of stats_type
    // reporting_type, radio_type and survey_type and then taking the
    // first 9 bytes of the digest to create the key string
    stats_cfg_id_t  stats_cfg_id;
    stats_type_t    stats_type;
    reporting_type_t  report_type;
    wifi_freq_bands_t radio_type;
    survey_type_t   survey_type;
    unsigned int    reporting_interval;
    unsigned int    reporting_count;
    unsigned int    sampling_interval;
    unsigned int    survey_interval;
    wifi_channels_list_t    channels_list;
    unsigned int    threshold_util;
    unsigned int    threshold_max_delay;
} stats_config_t;

typedef struct {
    stats_cfg_id_t  stats_cfg_id;
    int             task_id;
} stats_report_task_t;

typedef struct {
    //Hal variables
    wifi_vap_info_map_t          vap_map;
    wifi_radio_index_t           radio_index;
    unsigned int    num_vaps;
    rdk_wifi_vap_info_t          rdk_vap_array[MAX_NUM_VAP_PER_RADIO];
//  schema_wifi_vap_state_t      vap_state[MAX_NUM_VAP_PER_RADIO];
} rdk_wifi_vap_map_t;

typedef struct {
    int last_channel;
    int num_detected;
    long long int timestamp;
} __attribute__((packed)) radarInfo_t;

typedef struct {
    mac_address_t sta_mac;
    mac_address_t ap_mac;
    int sta_status_counts[6];
    int sta_reason_counts[9];
    int ap_status_counts[6];
    int ap_reason_counts[9];
} interop_data_t;

typedef struct {
    char    name[16];
    wifi_radio_operationParam_t oper;
    rdk_wifi_vap_map_t          vaps;
    wifi_radio_feature_param_t  feature;
    radarInfo_t                  radarInfo;
//  schema_wifi_radio_state_t   radio_state;
} rdk_wifi_radio_t;

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

typedef enum {
    client_state_connected,
    client_state_disconnected
} client_state_t;

#define WPA_KEY_MGMT_LEN      (128)
#define PAIRWISE_CIPHER_LEN   (128)

typedef struct {
    char wpa_key_mgmt[WPA_KEY_MGMT_LEN];
    char pairwise_cipher[WPA_KEY_MGMT_LEN];
} __attribute__((__packed__)) conn_security_t;

typedef struct {
    time_t frame_timestamp;
    frame_data_t msg_data;
} __attribute__((__packed__)) assoc_req_elem_t;

typedef struct {
    mac_address_t sta_mac;
    int assoc_akm;
    int eapol_akm;
    int akm_24_24_count;
    int akm_8_8_count;
    int akm_2_2_count;
    int akm_24_8_count;
    int akm_24_2_count;
    int akm_8_2_count;
} telemetry_data_t;

typedef struct {
    int ap_index;
    wifi_associated_dev3_t dev_stats;
    int reason;
    client_state_t client_state;
    conn_security_t conn_security;
    assoc_req_elem_t sta_data;
} __attribute__((__packed__)) assoc_dev_data_t;

struct active_msmt_data;

typedef struct {
    mac_address_t  sta_mac; /* this is mld-mac addr for wifi7 clients */
    unsigned int    good_rssi_time;
    unsigned int    bad_rssi_time;
    struct timespec  disconnected_time;
    struct timespec  total_connected_time;
    struct timespec  total_disconnected_time;
    struct timespec  last_connected_time;
    struct timespec  last_disconnected_time;
    unsigned int    rapid_reconnects;
    bool            updated;
    wifi_associated_dev3_t dev_stats;
    unsigned int    reconnect_count;
    long            assoc_monitor_start_time;
    long            gate_time;
    unsigned int    redeauth_count;
    long            deauth_monitor_start_time;
    long            deauth_gate_time;
    struct active_msmt_data *sta_active_msmt_data;
    bool            connection_authorized;
    assoc_req_elem_t assoc_frame_data;

    /* wifi7 client specific data */
    bool            primary_link; /* TRUE for auth/primary link, FALSE for secondary links */
    mac_address_t   link_mac;     /* link mac addr */
} sta_data_t;

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

typedef enum {
    cs_mode_off,
    cs_mode_home,
    cs_mode_away,
    cs_mode_max
} cs_mode_t;

typedef enum {
    cs_state_none,
    cs_state_steering,
    cs_state_expired,
    cs_state_failed,
    cs_state_xing_low,
    cs_state_xing_high,
    cs_state_xing_disabled,
    cs_state_max
} cs_state_t;

typedef enum {
    force_kick_none,
    force_kick_speculative,
    force_kick_directed,
    force_kick_ghost_device,
    force_kick_max
} force_kick_t;

typedef enum {
    kick_type_none,
    kick_type_deauth,
    kick_type_disassoc,
    kick_type_bss_tm_req,
    kick_type_rrm_br_req,
    kick_type_btm_deauth,
    kick_type_btm_disassoc,
    kick_type_max
} kick_type_t;

typedef enum {
    pref_5g_hwm,
    pref_5g_never,
    pref_5g_always,
    pref_5g_nonDFS,
    pref_5g_max
} pref_5g_t;

typedef enum {
    reject_detection_none,
    reject_detection_probe_all,
    reject_detection_probe_null,
    reject_detection_probe_direcet,
    reject_detection_auth_blocked,
    reject_detection_max
} reject_detection_t;

typedef enum {
    sc_kick_type_none,
    sc_kick_type_deauth,
    sc_kick_type_disassoc,
    sc_kick_type_bss_tm_req,
    sc_kick_type_rrm_br_req,
    sc_kick_type_btm_deauth,
    sc_kick_type_btm_disassoc,
    sc_kick_type_rrm_deauth,
    sc_kick_type_rrm_disassoc,
    sc_kick_type_max
} sc_kick_type_t;

typedef enum {
    sticky_kick_type_none,
    sticky_kick_type_deauth,
    sticky_kick_type_disassoc,
    sticky_kick_type_bss_tm_req,
    sticky_kick_type_rrm_br_req,
    sticky_kick_type_btm_deauth,
    sticky_kick_type_btm_disassoc,
    sticky_kick_type_max
} sticky_kick_type_t;

typedef struct {
    char key[32];
    char value[32];
} key_value_map;

typedef struct {
    char    steering_client_id[CFG_ID_LEN];
    int backoff_exp_base;
    int backoff_secs;
    cs_mode_t cs_mode;
    key_value_map cs_params[32];
    int cs_params_len;
    cs_state_t cs_state;
    force_kick_t force_kick;
    int hwm;
    int kick_debounce_period;
    int kick_reason;
    kick_type_t kick_type;
    bool kick_upon_idle;
    int lwm;
    mac_addr_str_t mac;
    int max_rejects;
    bool pre_assoc_auth_block;
    pref_5g_t pref_5g;
    reject_detection_t reject_detection;
    int rejects_tmout_secs;
    key_value_map rrm_bcn_rpt_params[32];
    int rrm_bcn_rpt_params_len;
    int sc_kick_debounce_period;
    int sc_kick_reason;
    sc_kick_type_t sc_kick_type;
    key_value_map sc_btm_params[32];
    int sc_btm_params_len;
    int stats_2g[32];
    int stats_5g[32];
    bool steer_during_backoff;
    key_value_map steering_btm_params[32];
    int steering_btm_params_len;
    int steering_fail_cnt;
    int steering_kick_cnt;
    int steering_success_cnt;
    int sticky_kick_cnt;
    int sticky_kick_debounce_period;
    int sticky_kick_reason;
    sticky_kick_type_t sticky_kick_type;
} band_steering_clients_t;

typedef enum {
    ht_mode_HT20,
    ht_mode_HT2040,
    ht_mode_HT40,
    ht_mode_HT40plus,
    ht_mode_HT20minus,
    ht_mode_HT80,
    ht_mode_HT160,
    ht_mode_HT80plus80,
    ht_mode_max
} ht_mode_t;

typedef struct {
    char    neighbor_id[CFG_ID_LEN];
    mac_addr_str_t bssid;
    char if_name[32] ;
    int channel;
    ht_mode_t ht_mode;
    int priority;
} vif_neighbors_t;

typedef struct {
    int     speed_test_running;
    int     speed_test_timeout;
} speed_test_data_t;

typedef struct {
    bool ch_in_pool;
    bool ch_radar_noise;
    int  ch_number;
    int  ch_noise;
    int  ch_max_80211_rssi;
    int  ch_non_80211_noise;
    int  ch_utilization;
    unsigned long long ch_utilization_busy_tx;
    unsigned long long ch_utilization_busy_self;
    unsigned long long ch_utilization_total;
    unsigned long long ch_utilization_busy;
    unsigned long long ch_utilization_busy_rx;
    unsigned long long ch_utilization_busy_ext;
    unsigned long long LastUpdatedTime;
    unsigned long long LastUpdatedTimeUsec;
} radio_chan_data_t;

typedef struct {
    char                    frequency_band[64];
    char                    ChannelsInUse[256];
    unsigned int            primary_radio_channel;
    char                    channel_bandwidth[64];
    unsigned int            RadioActivityFactor;
    unsigned int            CarrierSenseThreshold_Exceeded;
    int                     NoiseFloor;
    int                     channelUtil;
    int                     channelInterference;
    ULONG                   radio_BytesSent;
    ULONG                   radio_BytesReceived;
    ULONG                   radio_PacketsSent;
    ULONG                   radio_PacketsReceived;
    ULONG                   radio_ErrorsSent;
    ULONG                   radio_ErrorsReceived;
    ULONG                   radio_DiscardPacketsSent;
    ULONG                   radio_DiscardPacketsReceived;
    ULONG                   radio_InvalidMACCount;
    ULONG                   radio_PacketsOtherReceived;
    INT                     radio_RetransmissionMetirc;
    ULONG                   radio_PLCPErrorCount;
    ULONG                   radio_FCSErrorCount;
    INT                     radio_MaximumNoiseFloorOnChannel;
    INT                     radio_MinimumNoiseFloorOnChannel;
    INT                     radio_MedianNoiseFloorOnChannel;
    ULONG                   radio_StatisticsStartTime;
    unsigned int            radio_Temperature;
} radio_data_t;

#ifdef EM_APP

#define EM_MAX_OPERATING_CLASS 48
#define EM_MAX_CHANNEL_BW_LEN 16
#define EM_MAX_NEIGHBORS 16
#define EM_MAX_RESULTS 32
#define EM_MAX_CHANNELS 64

typedef char marker_name[32];

typedef struct {
    int interval;
    marker_name managed_client_marker;
} ap_metrics_policy_t;

#define EM_MAX_DIS_STA 30
typedef struct {
    int sta_count;
    mac_addr_t disallowed_sta[EM_MAX_DIS_STA];
} steering_disallowed_policy_t;

typedef struct {
    bssid_t bssid;
    bool profile_1_bsta_disallowed;
    bool profile_2_bsta_disallowed;
} backhaul_bss_config_policy_t;

typedef struct {
    bool report_independent_channel_scan;
} channel_scan_reporting_policy_t;

typedef struct {
    mac_addr_t ruid;
    int sta_rcpi_threshold;
    int sta_rcpi_hysteresis;
    int ap_util_threshold;
    bool traffic_stats;
    bool link_metrics;
    bool sta_status;
} radio_metrics_policy_t;

#define EM_MAX_RADIO_POLICY 4
typedef struct {
    int radio_count;
    radio_metrics_policy_t radio_metrics_policy[EM_MAX_RADIO_POLICY];
} radio_metrics_policies_t;

typedef struct {
    ap_metrics_policy_t ap_metric_policy;
    steering_disallowed_policy_t local_steering_dslw_policy;
    steering_disallowed_policy_t btm_steering_dslw_policy;
    backhaul_bss_config_policy_t backhaul_bss_config_policy;
    channel_scan_reporting_policy_t channel_scan_reporting_policy;
    radio_metrics_policies_t radio_metrics_policies;
} em_config_t;

typedef struct {
    mac_addr_t bssid;
    int time_delta;
    int est_mac_rate_down;
    int est_mac_rate_up;
    int rcpi;
} assoc_sta_link_metrics_data_t;

typedef struct {
    int num_bssid;
    assoc_sta_link_metrics_data_t assoc_sta_link_metrics_data[STA_MAX_BSS_ASSOCIATIONS];
} assoc_sta_link_metrics_t;

typedef struct {
    int reason_code;
    mac_addr_t sta_mac;
} error_code_t;

typedef struct {
    mac_addr_t bssid;
    int last_data_downlink_rate;
    int last_data_uplink_rate;
    int utilization_receive;
    int utilization_transmit;
} assoc_sta_ext_link_metrics_data_t;

typedef struct {
    int num_bssid;
    assoc_sta_ext_link_metrics_data_t assoc_sta_ext_link_metrics_data[STA_MAX_BSS_ASSOCIATIONS];
} assoc_sta_ext_link_metrics_t;

typedef struct {
    mac_addr_t sta_mac;
    unsigned char client_type[32];
    assoc_sta_link_metrics_t assoc_sta_link_metrics;
    error_code_t error_code;
    assoc_sta_ext_link_metrics_t assoc_sta_ext_link_metrics;
} per_sta_metrics_t;

typedef struct {
    int vap_index;
    unsigned int sta_count;
    per_sta_metrics_t *per_sta_metrics;
} em_assoc_sta_link_metrics_rsp_t;

typedef struct {
    unsigned char dialog_token;
    size_t size;
    wifi_BeaconReport_t *beacon_repo;
} wifi_hal_rrm_report_t;

#define EM_MAX_BR_DATA 400
typedef struct {
    mac_address_t mac_addr;
    unsigned int data_len;
    unsigned char data[EM_MAX_BR_DATA];
    unsigned int ap_index;
    unsigned int num_br_data;
    int sched_handler_id;
    unsigned char dialog_token;
} sta_beacon_report_reponse_t;

typedef struct {
    mac_address_t mac_addr;
    unsigned char client_type[32];
} sta_client_info_t;

typedef struct {
    UCHAR operating_class;
    UINT num_channels;
    UCHAR channels[EM_MAX_CHANNELS];
} operating_class_t;

typedef struct {
    BOOL perform_fresh_scan;
    UINT num_radios;
    mac_address_t ruid;
    UINT num_operating_classes;
    operating_class_t operating_classes[EM_MAX_OPERATING_CLASS];
} channel_scan_request_t;

typedef struct {
    bssid_t bssid;
    ssid_t ssid;
    CHAR signal_strength;
    CHAR channel_bandwidth[EM_MAX_CHANNEL_BW_LEN];
    UCHAR bss_load_element_present;
    UCHAR bss_color;
    UCHAR channel_utilization;
    USHORT station_count;
} neighbor_bss_t;

typedef struct {
    UCHAR operating_class;
    UCHAR channel;
    UCHAR scan_status;
    CHAR time_stamp[32];
    UCHAR utilization;
    UCHAR noise;
    USHORT num_neighbors;
    neighbor_bss_t neighbors[EM_MAX_NEIGHBORS];
    UINT aggregate_scan_duration;
    UCHAR scan_type;  // 0: Passive, 1: Active
} channel_scan_result_t;

typedef struct {
    mac_address_t ruid;
    UINT num_results;
    channel_scan_result_t results[EM_MAX_RESULTS];
} channel_scan_response_t;

typedef struct {
    mac_addr_t sta_mac;
    int bytes_sent;
    int bytes_rcvd;
    int packets_sent;
    int packets_rcvd;
    int tx_packtes_errs;
    int rx_packtes_errs;
    int retrans_cnt;
} assoc_sta_traffic_stats_t;

typedef struct {
    bssid_t bssid;
    int channel_util;
    int num_of_assoc_stas;
    bool inc_esp_ac_be;
    bool inc_esp_ac_bk;
    bool inc_esp_ac_vo;
    bool inc_esp_ac_vi;
    int esp_ac_be;
    int esp_ac_bk;
    int esp_ac_vo;
    int esp_ac_vi;
    // Extended report
    int unicast_bytes_sent;
    int unicast_bytes_rcvd;
    int multicast_bytes_sent;
    int multicast_bytes_rcvd;
    int broadcast_bytes_sent;
    int broadcast_bytes_rcvd;
} ap_metrics_t;

typedef struct {
    mac_addr_t ruid;
    unsigned char noise;
    unsigned char transmit;
    unsigned char receive_self;
    unsigned char receive_other;
} radio_metrics_t;

typedef struct {
    ap_metrics_t vap_metrics;
    int sta_cnt;
    bool is_sta_traffic_stats_enabled;
    assoc_sta_traffic_stats_t *sta_traffic_stats;
    bool is_sta_link_metrics_enabled;
    per_sta_metrics_t *sta_link_metrics;
} em_vap_metrics_t;

typedef struct {
    int radio_index;
    radio_metrics_t radio_metrics;
    em_vap_metrics_t vap_reports[MAX_NUM_VAP_PER_RADIO];
} em_ap_metrics_report_t;

#endif

#ifdef __cplusplus
}
#endif

#endif // WIFI_BASE_H
