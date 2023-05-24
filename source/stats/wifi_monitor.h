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

#include "wifi_blaster.h"
#include "collection.h"
#include <math.h>


#ifndef WIFI_HAL_VERSION_3
#define MAX_RADIOS  2
#endif

#ifdef CCSP_COMMON
typedef struct {
    unsigned int        rapid_reconnect_threshold;
    wifi_vapstatus_t    ap_status;
} ap_params_t;
#endif // CCSP_COMMON

typedef struct {
    unsigned char bssid[32];
    hash_map_t *sta_map;
#ifdef CCSP_COMMON
    ap_params_t ap_params;
#endif // CCSP_COMMON
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
} radio_data_t;

#ifdef CCSP_COMMON
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
} radio_chan_data_t;

typedef struct {
    CHAR DiagnosticsState[64];
    ULONG ResultCount;
    ULONG resultCountPerRadio[MAX_NUM_RADIOS];
    wifi_neighbor_ap2_t * pResult[MAX_NUM_RADIOS];
} neighscan_diag_cfg_t;
#endif // CCSP_COMMON

typedef struct {
    //Off channel params
    ULONG TscanMsec;
    ULONG NscanSec;
    ULONG TidleSec;
    ULONG Nchannel;
    int curr_off_channel_scan_period; //holds old value of Nscan
    unsigned int radio_index;
} off_channel_param_t;

typedef struct {
    queue_t             *queue;
    bssid_data_t        bssid_data[MAX_VAP];
#ifdef WIFI_HAL_VERSION_3
    radio_data_t        radio_data[MAX_NUM_RADIOS];
#ifdef CCSP_COMMON
    radio_chan_data_t   radio_channel_data[MAX_NUM_RADIOS];
#endif // CCSP_COMMON
#else
    radio_data_t        radio_data[MAX_RADIOS];
#ifdef CCSP_COMMON
    radio_chan_data_t   radio_channel_data[MAX_RADIOS];
#endif // CCSP_COMMON
#endif // WIFI_HAL_VERSION_3

#ifdef CCSP_COMMON
    neighscan_diag_cfg_t neighbor_scan_cfg;
#endif // CCSP_COMMON
    off_channel_param_t off_channel_cfg[MAX_NUM_RADIOS];
    pthread_cond_t      cond;
    pthread_mutex_t     queue_lock;
    pthread_mutex_t     data_lock;
    pthread_t           id;
    bool                exit_monitor;
    unsigned int        blastReqInQueueCount;
#ifdef CCSP_COMMON
    unsigned int        poll_period;
    unsigned int        upload_period;
    unsigned int        current_poll_iter;
	instant_msmt_t		inst_msmt;
#endif // CCSP_COMMON
    struct timeval      last_signalled_time;
#ifdef CCSP_COMMON
    struct timeval      last_polled_time;
    rssi_t		sta_health_rssi_threshold;
    int                 sysevent_fd;
    unsigned int        sysevent_token;
    ap_params_t      	ap_params[MAX_VAP];
    char 		cliStatsList[MAX_VAP];
    int			count;
    int			maxCount;
    int			instantDefReportPeriod;
    int			instantDefOverrideTTL;
    int			instantPollPeriod;
    bool        instntMsmtenable;
    char        instantMac[MIN_MAC_ADDR_LEN];
#endif // CCSP_COMMON
    struct scheduler *sched;
#ifdef CCSP_COMMON
    int chutil_id;
    int client_telemetry_id;
    int client_debug_id;
    int channel_width_telemetry_id;
    int ap_telemetry_id;
    int inst_msmt_id;
    int curr_chan_util_period;
    int refresh_task_id;
    int associated_devices_id;
    int vap_status_id;
#endif // CCSP_COMMON
    int radio_diagnostics_id;
#if defined (FEATURE_OFF_CHANNEL_SCAN_5G)
    int off_channel_scan_id[MAX_NUM_RADIOS];
#endif //FEATURE_OFF_CHANNEL_SCAN_5G
#ifdef CCSP_COMMON
    int neighbor_scan_id;
    int radio_health_telemetry_logger_id;
    int upload_ap_telemetry_pmf_id;
    int clientdiag_id[MAX_VAP];
    int clientdiag_sched_arg[MAX_VAP];
    unsigned int clientdiag_sched_interval[MAX_VAP];
    int csi_sched_id;
    unsigned int csi_sched_interval;
#endif // CCSP_COMMON
    bool radio_presence[MAX_NUM_RADIOS];
    hash_map_t  *dca_list; //hash_map of wifi_dca_element_t
} wifi_monitor_t;

#ifdef CCSP_COMMON
typedef struct {
    unsigned int        interval;
    struct timeval      last_publish_time;
}diag_data_session_t;

typedef struct {
    queue_t             *csi_queue;
    diag_data_session_t diag_session[MAX_VAP];
    char vap_ip[MAX_VAP][IP_STR_LEN];
    pthread_mutex_t     lock;
} events_monitor_t;

typedef struct {
    bool enable;
    bool subscribed;
    bool mac_is_connected[MAX_CSI_CLIENTS_PER_SESSION];
    int  csi_time_interval;
    int  no_of_mac;
    int  csi_sess_number;
    int  ap_index[MAX_CSI_CLIENTS_PER_SESSION];
    mac_address_t mac_list[MAX_CSI_CLIENTS_PER_SESSION];
    char client_ip[MAX_CSI_CLIENTS_PER_SESSION][IP_STR_LEN];
    long  client_ip_age[MAX_CSI_CLIENTS_PER_SESSION];
    struct timeval last_publish_time[MAX_CSI_CLIENTS_PER_SESSION];
    struct timeval last_snapshot_time;
} __attribute__((__packed__)) csi_session_t;

void csi_update_client_mac_status(mac_address_t mac, bool connected, int ap_idx);
void csi_set_client_mac(char *mac_list, int csi_session_number);
void csi_enable_session(bool enable, int csi_session_number);
void csi_enable_subscription(bool subscribe, int csi_session_number);
void csi_set_interval(int interval, int csi_session_number);
void csi_create_session(int csi_session_number);
void csi_del_session(int csi_sess_number);
void diagdata_set_interval(int interval, unsigned int ap_idx);

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
int get_neighbor_scan_results();
int get_dev_stats_for_radio(unsigned int radio_index, radio_data_t *radio_stats);
int get_radio_channel_utilization(unsigned int radio_index, int *chan_util);
#endif // CCSP_COMMON

wifi_monitor_t *get_wifi_monitor ();
char *get_formatted_time(char *time);
wifi_actvie_msmt_t *get_active_msmt_data();
int init_wifi_monitor();
int  getApIndexfromClientMac(char *check_mac);
void update_ecomode_radios(void);
#endif	//_WIFI_MON_H_
