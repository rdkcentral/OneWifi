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

#include "rbus.h"
#include "wifi_webconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void    *acl_vap_context;
    queue_t* new_entry_queue[MAX_NUM_RADIOS][MAX_NUM_VAP_PER_RADIO];
} acl_data_t;

typedef struct {
    webconfig_t		webconfig;
    wifi_global_config_t    config;
    wifi_hal_capability_t   hal_cap;
    rdk_wifi_radio_t    radios[MAX_NUM_RADIOS];
    active_msmt_t blaster;
    hash_map_t    *assoc_dev_hash_map[MAX_NUM_RADIOS][MAX_NUM_VAP_PER_RADIO];
    acl_data_t acl_data;
    rbusHandle_t	rbus_handle;
    instant_measurement_config_t harvester;
    queue_t    *csi_data_queue;
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
#ifdef __cplusplus
}
#endif

#endif // WIFI_WEBCONFIG__DML_H
