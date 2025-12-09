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

#ifndef WIFI_WEBCONFIG_DML_H
#define WIFI_WEBCONFIG_DML_H

#include "wifi_webconfig.h"
#include "bus.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_XHS_LNF_FLAG_FILE_NAME "/nvram/.bcmwifi_xhs_lnf_enabled"

typedef struct {
    void    *acl_vap_context;
    queue_t* new_entry_queue[MAX_NUM_RADIOS][MAX_NUM_VAP_PER_RADIO];
} acl_data_t;

typedef struct {
    wifi_vap_info_t *mld_vaps[MAX_NUM_RADIOS];
    UINT mld_vap_count;
} mld_group_t;

typedef struct {
    mld_group_t mld_groups[MLD_UNIT_COUNT];
    UINT mld_group_count;
} apmld_map_t;


typedef struct {
    webconfig_t		webconfig;
    wifi_global_config_t    config;
    wifi_hal_capability_t   hal_cap;
    rdk_wifi_radio_t    radios[MAX_NUM_RADIOS];
    active_msmt_t blaster;
    hash_map_t    *assoc_dev_hash_map[MAX_NUM_RADIOS][MAX_NUM_VAP_PER_RADIO];
    pthread_mutex_t assoc_dev_lock;
    acl_data_t acl_data;
    bus_handle_t         handle;
    instant_measurement_config_t harvester;
    queue_t    *csi_data_queue;
    apmld_map_t apmld_map;
} webconfig_dml_t;

typedef struct {
    BOOL    kick_assoc_devices;
    BOOL    multicast_rate;
    BOOL    router_enabled;
    BOOL    bss_count_sta_as_cpe;
    ULONG   associated_devices_highwatermark_threshold;
    ULONG   retry_limit;
    ULONG   long_retry_limit;
    ULONG   txoverflow;
    INT     wps_methods;
    CHAR    wps_pin[128];
}dml_vap_default;

typedef struct {
    BOOL    AutoChannelSupported;
    BOOL    DCSSupported;
    BOOL    ReverseDirectionGrant;
    BOOL    AggregationMSDU;
    BOOL    AmsduTid[MAX_AMSDU_TID];
    BOOL    AutoBlockAck;
    BOOL    DeclineBARequest;
    BOOL    WirelessOnOffButton;
    BOOL    IEEE80211hEnabled;
    BOOL    DFSEnabled;
    BOOL    IGMPSnoopingEnabled;
    BOOL    FrameBurst;
    BOOL    APIsolation;
    CHAR    Alias[32];
    CHAR    ChannelsInUse[32];
    CHAR    TransmitPowerSupported[32];
    CHAR    SupportedStandards[120];
    ULONG   SupportedFrequencyBands;
    ULONG   BasicRate;
    ULONG   MaxBitRate;
    ULONG   ExtensionChannel;
    INT     ThresholdRange;
    INT     ThresholdInUse;
    INT     AutoChannelRefreshPeriod;
    INT     OnOffPushButtonTime;
    INT     MulticastRate;
    INT     MCS;
    ULONG   DFSTimer;
} dml_radio_default;

typedef struct {
    CHAR    RadioPower[32];
} dml_global_default;

typedef struct {
    ULONG PLCPErrorCount;
    ULONG FCSErrorCount;
    ULONG PacketsOtherReceived;
    ULONG StatisticsStartTime;
    INT ActivityFactor_TX;
    INT ActivityFactor_RX;
    INT RetransmissionMetric;
    INT MaximumNoiseFloorOnChannel;
    INT MinimumNoiseFloorOnChannel;
    INT MedianNoiseFloorOnChannel;
    INT RadioStatisticsMeasuringRate;
    INT RadioStatisticsMeasuringInterval;
    INT ReceivedSignalLevelNumberOfEntries;
}__attribute__((packed)) dml_stats_default;

int init(webconfig_dml_t *consumer);
webconfig_dml_t* get_webconfig_dml();
active_msmt_t* get_dml_blaster(void);
active_msmt_t *get_dml_cache_blaster(void);
hash_map_t** get_dml_assoc_dev_hash_map(unsigned int radio_index, unsigned int vap_array_index);
hash_map_t** get_dml_acl_hash_map(unsigned int radio_index, unsigned int vap_index);
queue_t** get_dml_acl_new_entry_queue(unsigned int radio_index, unsigned int vap_index);
void** get_acl_vap_context();
UINT get_num_radio_dml();
void update_apmld_map();
UINT get_num_apmld_dml();
mld_group_t* get_dml_apmld_group(uint8_t apmld_index);
UINT get_total_num_affiliated_ap_dml(mld_group_t *mld_group);
unsigned long get_mld_associated_devices_count(mld_group_t *mld_group);
assoc_dev_data_t *get_mld_associated_device(mld_group_t *mld_group, unsigned int dev_index);
UINT get_total_num_vap_dml();
void get_associated_devices_data(unsigned int radio_index);
unsigned long get_associated_devices_count(wifi_vap_info_t *vap_info);
hash_map_t* get_associated_devices_hash_map(unsigned int vap_index);
queue_t** get_acl_new_entry_queue(wifi_vap_info_t *vap_info);
hash_map_t** get_acl_hash_map(wifi_vap_info_t *vap_info);
wifi_global_config_t *get_dml_cache_global_wifi_config();
wifi_vap_info_map_t* get_dml_cache_vap_map(uint8_t radio_index);
wifi_radio_operationParam_t* get_dml_cache_radio_map(uint8_t radio_index);
wifi_radio_feature_param_t* get_dml_cache_radio_feat_map(uint8_t radio_index);
bool is_dfs_channel_allowed(unsigned int channel);
wifi_vap_info_t *get_dml_cache_vap_info(uint8_t vap_index);
rdk_wifi_vap_info_t *get_dml_cache_rdk_vap_info(uint8_t vap_index);
wifi_vap_security_t * get_dml_cache_sta_security_parameter(uint8_t vapIndex);
wifi_vap_security_t * get_dml_cache_bss_security_parameter(uint8_t vapIndex);
int get_radioIndex_from_vapIndex(unsigned int vap_index, unsigned int *radio_index);
int push_global_config_dml_cache_to_one_wifidb();
int push_wifi_host_sync_to_ctrl_queue();
int push_kick_assoc_to_ctrl_queue(int vap_index) ;
int push_radio_dml_cache_to_one_wifidb();
int push_acl_list_dml_cache_to_one_wifidb(wifi_vap_info_t *vap_info);
wifi_radio_operationParam_t* get_dml_radio_operation_param(uint8_t radio_index);
wifi_vap_info_t* get_dml_vap_parameters(uint8_t vapIndex);
wifi_vap_info_map_t* get_dml_vap_map(uint8_t radio_index);
wifi_global_param_t* get_dml_wifi_global_param(void);
wifi_GASConfiguration_t* get_dml_wifi_gas_config(void);
void set_dml_cache_vap_config_changed(uint8_t vap_index);
int push_prefer_private_ctrl_queue(bool flag);
int push_wps_pin_dml_to_ctrl_queue(unsigned int vap_index, char *wps_pin);
int push_vap_dml_cache_to_one_wifidb();
int push_blaster_config_dml_to_ctrl_queue();
int process_neighbor_scan_dml();
instant_measurement_config_t *get_dml_cache_harvester();
instant_measurement_config_t* get_dml_harvester(void);
int push_harvester_dml_cache_to_one_wifidb();
dml_vap_default *get_vap_default(int vap_index);
dml_radio_default *get_radio_default_obj(int r_index) ;
dml_global_default *get_global_default_obj();
dml_stats_default *get_stats_default_obj(int r_index);
wifi_channelBandwidth_t sync_bandwidth_and_hw_variant(uint32_t variant, wifi_channelBandwidth_t current_bw);
UINT get_max_num_vaps_per_radio_dml(uint32_t radio_index);
rdk_wifi_radio_t* get_dml_cache_radio_map_param(uint8_t radio_index);

#ifdef __cplusplus
}
#endif

#endif // WIFI_WEBCONFIG__DML_H
