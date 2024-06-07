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

#ifndef	_WIFI_MON_H_
#define	_WIFI_MON_H_

#include "collection.h"
#include <math.h>
#include "wifi_base.h"

#ifndef WIFI_HAL_VERSION_3
#define MAX_RADIOS  2
#endif

typedef struct {
    unsigned int        rapid_reconnect_threshold;
    wifi_vapstatus_t    ap_status;
} ap_params_t;

typedef struct {
    unsigned char bssid[32];
    hash_map_t *sta_map; //of type sta_data_t
    struct timespec last_sta_update_time;
    ap_params_t ap_params;
    ssid_t                  ssid;
} bssid_data_t;

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
    radio_chan_data_t   *chan_data;
    int num_channels;
    struct timespec *last_update_time_offchannel;
} radio_chan_stats_data_t;

typedef struct {
    CHAR DiagnosticsState[64];
    ULONG ResultCount;
    ULONG resultCountPerRadio[MAX_NUM_RADIOS];
    wifi_neighbor_ap2_t * pResult[MAX_NUM_RADIOS];
    ULONG resultCountPerRadio_onchannel[MAX_NUM_RADIOS];
    wifi_neighbor_ap2_t * pResult_onchannel[MAX_NUM_RADIOS];
    //off-chan results
    ULONG resultCountPerRadio_offchannel[MAX_NUM_RADIOS][MAX_CHANNELS];
    wifi_neighbor_ap2_t * pResult_offchannel[MAX_NUM_RADIOS][MAX_CHANNELS];
    //off-chan aux variables
    struct timespec last_update_time_offchannel[MAX_NUM_RADIOS][MAX_CHANNELS];
    int channel[MAX_NUM_RADIOS][MAX_CHANNELS];
} neighscan_diag_cfg_t;


/*
 * radio_data_t has information about radio stats
 * radio_chan_data_t has information about channel stats, should be replaced by radio_chan_stats_data_t
 * bssid_data_t has information about station data
 * neighscan_diag_cfg_t has information about Neighbour ap results
 * */
typedef struct {
    queue_t             *queue;
    pthread_cond_t      cond;
    pthread_mutex_t     queue_lock;
    pthread_mutex_t     data_lock;
    pthread_t           id;
    bssid_data_t        bssid_data[MAX_VAP];
    radio_data_t        radio_data[MAX_NUM_RADIOS];
    radio_chan_stats_data_t  radio_chan_stats_data[MAX_NUM_RADIOS]; ////New Radio Channel stats
    neighscan_diag_cfg_t neighbor_scan_cfg;
    bool                exit_monitor;
    int last_scanned_channel[MAX_NUM_RADIOS];
    int scan_status[MAX_NUM_RADIOS];
    int scan_results_retries[MAX_NUM_RADIOS];
#ifdef CCSP_COMMON
    unsigned int        upload_period;
    unsigned int        current_poll_iter;
    instant_msmt_t      inst_msmt;
#endif // CCSP_COMMON
    struct timespec     last_signalled_time;
    rssi_t              sta_health_rssi_threshold;
#ifdef CCSP_COMMON
    struct timespec     last_polled_time;
    int                 sysevent_fd;
    unsigned int        sysevent_token;
    ap_params_t         ap_params[MAX_VAP];
    char                cliStatsList[MAX_VAP];
#endif // CCSP_COMMON
    struct scheduler *sched;
#ifdef CCSP_COMMON
    int client_telemetry_id;
    int client_debug_id;
    int inst_msmt_id;
    int curr_chan_util_period;
    int refresh_task_id;
    int vap_status_id;
#endif // CCSP_COMMON
    int radio_diagnostics_id;
#ifdef CCSP_COMMON
    int clientdiag_id[MAX_VAP];
    int clientdiag_sched_arg[MAX_VAP];
    unsigned int clientdiag_sched_interval[MAX_VAP];
    int csi_sched_id;
    unsigned int csi_sched_interval;
#endif // CCSP_COMMON
    bool radio_presence[MAX_NUM_RADIOS];
    bool is_blaster_running;
} wifi_monitor_t;

typedef struct {
    int              ap_index;
    mac_addr_t       mac_addr;
    char             client_ip[IP_STR_LEN];
    char             vap_ip[IP_STR_LEN];
    long             client_ip_age;
} csi_pinger_data_t;

#ifdef CCSP_COMMON
typedef struct {
    unsigned int        interval;
    struct timeval      last_publish_time;
}diag_data_session_t;

typedef struct {
    hash_map_t          *csi_pinger_map; //hash_map_for_csi_pinger
    diag_data_session_t diag_session[MAX_VAP];
    pthread_mutex_t     lock;
} events_monitor_t;

int
wifi_stats_flag_change
    (
        int             ap_index,
        bool            enable,
        int             type
    );
int radio_stats_flag_change(int radio_index, bool enable);
int vap_stats_flag_change(int ap_index, bool enable);
void monitor_enable_instant_msmt(mac_address_t sta_mac, bool enable);
bool monitor_is_instant_msmt_enabled();
void instant_msmt_reporting_period(int pollPeriod);
void instant_msmt_macAddr(char *mac_addr);
void instant_msmt_ttl(int overrideTTL);
void instant_msmt_def_period(int defPeriod);
void SetINSTReportingPeriod(unsigned long pollPeriod);
void SetINSTDefReportingPeriod(int defPeriod);
void SetINSTOverrideTTL(int defTTL);
void SetINSTMacAddress(char *mac_addr);
int GetInstAssocDevSchemaIdBufferSize();
unsigned int GetINSTPollingPeriod();
unsigned int GetINSTOverrideTTL();
unsigned int GetINSTDefReportingPeriod();
int get_dev_stats_for_radio(unsigned int radio_index, radio_data_t *radio_stats);
int get_radio_channel_utilization(unsigned int radio_index, int *chan_util);
sta_data_t *get_stats_for_sta(unsigned int apIndex, mac_addr_t mac);
#endif // CCSP_COMMON

wifi_monitor_t *get_wifi_monitor ();
char *get_formatted_time(char *time);
int init_wifi_monitor();
int  getApIndexfromClientMac(char *check_mac);
void update_ecomode_radios(void);
hash_map_t *get_sta_data_map(unsigned int vap_index);

typedef struct wifi_mon_provider_element wifi_mon_provider_element_t;
typedef struct  wifi_mon_collector_element  wifi_mon_collector_element_t;

typedef int  (* validate_args_t)(wifi_mon_stats_args_t *args);
typedef int  (* generate_stats_clctr_key_t)(wifi_mon_stats_args_t *args, char *key, size_t key_len);
typedef int  (* generate_stats_provider_key_t)(wifi_mon_stats_config_t *config, char *key, size_t key_len);
typedef int  (* execute_stats_api_t)(wifi_mon_collector_element_t *c_elem, wifi_monitor_t *mon_data, unsigned long task_interval_ms);
typedef int  (* get_stats_from_mon_cache_t)(wifi_mon_provider_element_t *p_elem, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache);
typedef int  (* update_collector_args_t)(void *collector_elem);
typedef int  (* stop_scheduler_tasks_t)(wifi_mon_collector_element_t *c_elem);

//New Monitor Implementation
typedef struct {
    hash_map_t *collector_list; //wifi_mon_collector_element_t
} __attribute__((packed)) wifi_apps_coordinator_t;

typedef struct {
    wifi_mon_stats_type_t stats_type;
    validate_args_t       validate_args;
    generate_stats_clctr_key_t  generate_stats_clctr_key;
    generate_stats_provider_key_t generate_stats_provider_key;
    execute_stats_api_t   execute_stats_api;
    get_stats_from_mon_cache_t copy_stats_from_cache;
    update_collector_args_t update_collector_args;
    stop_scheduler_tasks_t stop_scheduler_tasks;
} wifi_mon_stats_descriptor_t;

typedef struct {
    int scan_complete_task_id;
} collector_radio_channel_neighbor_data_t;


struct wifi_mon_collector_element{
    int             collector_task_sched_id;
    unsigned long   collector_task_interval_ms;
    char            key[MON_STATS_KEY_LEN_32];
    bool            task_priority; //if TRUE its high priority
    bool            start_immediately; //if TRUE need to start collection immediately
    hash_map_t *provider_list; //wifi_mon_provider_element_t
    wifi_mon_stats_args_t     *args;
    wifi_mon_stats_descriptor_t  *stat_desc;
    unsigned int    postpone_cnt;
    int             collector_postpone_task_sched_id;
    union {
        collector_radio_channel_neighbor_data_t radio_channel_neighbor_data;
    } u;
} __attribute__((packed));

typedef struct {
    struct timespec last_update_time_offchannel[MAX_CHANNELS];
} neighbour_stats_data_t;

typedef struct {
        struct timespec last_update_time_offchannel[MAX_CHANNELS];
} radio_channel_stats_data_t;

struct wifi_mon_provider_element{
    int             provider_task_sched_id;
    wifi_mon_stats_config_t *mon_stats_config;
    char            key[MON_STATS_KEY_LEN_32];
    wifi_mon_stats_descriptor_t  *stat_desc;
    wifi_provider_response_t *response;
    unsigned long   provider_task_interval_ms;
    bool            start_immediately;
    unsigned int    delay_provider_sec;
    union {
        neighbour_stats_data_t  neighbour_data;
        radio_channel_stats_data_t radio_channel_data;
    } u;
};


hash_map_t *coordinator_get_collector_list();
wifi_apps_coordinator_t *get_apps_coordinator();
int coordinator_check_stats_config(wifi_mon_stats_config_t *mon_stats_config);

wifi_mon_collector_element_t *coordinator_create_collector_elem(wifi_mon_stats_config_t *stats_config, wifi_mon_stats_descriptor_t *stat_desc);
wifi_mon_provider_element_t  *coordinator_create_provider_elem(wifi_mon_stats_config_t * stats_config, wifi_mon_stats_descriptor_t *stat_desc);

int coordinator_create_task(wifi_mon_collector_element_t **collector_elem, wifi_mon_stats_config_t *stats_config, wifi_mon_stats_descriptor_t *stat_desc);
int coordinator_create_collector_task(wifi_mon_collector_element_t *collector_elem);
int coordinator_create_provider_task(wifi_mon_provider_element_t *provider_elem);
int collector_execute_task(void *arg);
int provider_execute_task(void *arg);

int coordinator_update_task(wifi_mon_collector_element_t *collector_elem, wifi_mon_stats_config_t *stats_config);
int coordinator_calculate_clctr_interval(wifi_mon_collector_element_t *collector_elem, wifi_mon_provider_element_t *new_provider_elem , unsigned long *new_interval);
int collector_task_update(wifi_mon_collector_element_t *collector_elem, unsigned long *new_collector_interval);
int provider_task_update(wifi_mon_provider_element_t *provider_elem, unsigned long *new_provider_interval);
void coordinator_free_provider_elem(wifi_mon_provider_element_t **provider_elem);
wifi_mon_stats_descriptor_t *wifi_mon_get_stats_descriptor(wifi_mon_stats_type_t stats_type);
void free_coordinator(hash_map_t *collector_list);

/*Radio Channel*/
int validate_radio_channel_args(wifi_mon_stats_args_t *args);
int generate_radio_channel_clctr_stats_key(wifi_mon_stats_args_t *args, char *key, size_t key_len);
int generate_radio_channel_provider_stats_key(wifi_mon_stats_config_t *config, char *key, size_t key_len);
int execute_radio_channel_api(wifi_mon_collector_element_t *c_elem, wifi_monitor_t *mon_data, unsigned long task_interval_ms);
int copy_radio_channel_stats_from_cache(wifi_mon_provider_element_t *p_elem, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache);
int update_radio_channels_collector_args(void *ce);
int stop_radio_channel_neighbor_scheduler_tasks(wifi_mon_collector_element_t *c_elem);

/*Neighbor Ap*/
int validate_neighbor_ap_args(wifi_mon_stats_args_t *args);
int copy_neighbor_ap_stats_from_cache(wifi_mon_provider_element_t *p_elem, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache);

/*Radio Diagnostics*/
int validate_radio_diagnostic_args(wifi_mon_stats_args_t *args);
int generate_radio_diagnostic_clctr_stats_key(wifi_mon_stats_args_t *args, char *key_str, size_t key_len);
int generate_radio_diagnostic_provider_stats_key(wifi_mon_stats_config_t *config, char *key_str, size_t key_len);
int execute_radio_diagnostic_stats_api(wifi_mon_collector_element_t *c_elem, wifi_monitor_t *mon_data, unsigned long task_interval_ms);
int copy_radio_diagnostic_stats_from_cache(wifi_mon_provider_element_t *p_elem, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache);

/*Associated Client Diagnostics*/
int validate_assoc_client_args(wifi_mon_stats_args_t *args);
int generate_assoc_client_clctr_stats_key(wifi_mon_stats_args_t *args, char *key_str, size_t key_len);
int generate_assoc_client_provider_stats_key(wifi_mon_stats_config_t *config, char *key_str, size_t key_len);
int execute_assoc_client_stats_api(wifi_mon_collector_element_t *c_elem, wifi_monitor_t *mon_data, unsigned long task_interval_ms);
int copy_assoc_client_stats_from_cache(wifi_mon_provider_element_t *p_elem, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache);

/*Radio Temperature*/
int validate_radio_temperature_args(wifi_mon_stats_args_t *args);
int generate_radio_temperature_clctr_stats_key(wifi_mon_stats_args_t *args, char *key_str, size_t key_len);
int generate_radio_temperature_provider_stats_key(wifi_mon_stats_config_t *config, char *key_str, size_t key_len);
int execute_radio_temperature_stats_api(wifi_mon_collector_element_t *c_elem, wifi_monitor_t *mon_data, unsigned long task_interval_ms);
int copy_radio_temperature_stats_from_cache(wifi_mon_provider_element_t *p_elem, void **stats, unsigned int *stat_array_size, wifi_monitor_t *mon_cache);

#endif	//_WIFI_MON_H_
