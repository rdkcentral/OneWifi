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

#ifdef CCSP_COMMON
#include <telemetry_busmessage_sender.h>
#include "cosa_wifi_apis.h"
#include "ccsp_psm_helper.h"
#endif // CCSP_COMMON
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include "collection.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_stubs.h"
#include "wifi_util.h"
#include "wifi_monitor.h"
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <signal.h>
#include <time.h>
#include <sys/un.h>
#include <assert.h>
#include <limits.h>
#ifdef MQTTCM
#include <mqttcm_lib/mqttcm_conn.h>
#endif
#ifdef CCSP_COMMON
#include "ansc_status.h"
#include <sysevent/sysevent.h>
#include "ccsp_base_api.h"
#include "harvester.h"
#include "wifi_passpoint.h"
#include "ccsp_trace.h"
#include "safec_lib_common.h"
#include "ccsp_WifiLog_wrapper.h"
#endif // CCSP_COMMON
#include <sched.h>
#include "scheduler.h"
#include "timespec_macro.h"

#ifdef CCSP_COMMON
#include <netinet/tcp.h>    //Provides declarations for tcp header
#include <netinet/ip.h> //Provides declarations for ip header
#include <arpa/inet.h> // inet_addr
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/stat.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include "wifi_events.h"
#include "common/ieee802_11_defs.h"
#endif // CCSP_COMMON
#include "const.h"
#include "pktgen.h"

#ifndef  UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(_p_)         (void)(_p_)
#endif

#define MIN_MAC_LEN 12
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_FMT_TRIMMED "%02x%02x%02x%02x%02x%02x"
#define MAC_ARG(arg) \
    arg[0], \
    arg[1], \
    arg[2], \
    arg[3], \
    arg[4], \
    arg[5]
#define RADIO_STATS_INTERVAL_MS 30000 //30 seconds
#ifdef MQTTCM
#define MQTTCM_DISABLE_FLAG "/mnt/data/pstore/disable_mqttcm"
#endif

#ifdef CCSP_COMMON
#define RSN_SELECTOR_GET(a) WPA_GET_BE32((const uint8_t *) (a))
#define RSN_SELECTOR(a, b, c, d) \
    ((((uint32_t) (a)) << 24) | (((uint32_t) (b)) << 16) | (((uint32_t) (c)) << 8) | \
     (uint32_t) (d))

#define RSN_CIPHERSUITE_WEP RSN_SELECTOR(0x00, 0x0f, 0xac, 1)
#define RSN_CIPHERSUITE_TKIP RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#define RSN_CIPHERSUITE_CCMP_128 RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
#define RSN_CIPHERSUITE_BIP_CMAC_128 RSN_SELECTOR(0x00, 0x0f, 0xac, 6)

#define RSN_SELECTOR_LEN 4

struct element {
    uint8_t id;
    uint8_t datalen;
    uint8_t data[];
} __attribute__ ((packed));

#define for_each_element(_elem, _data, _datalen)                    \
    for (_elem = (const struct element *) (_data);                  \
        (const u8 *) (_data) + (_datalen) - (const u8 *) _elem >=   \
        (int) sizeof(*_elem) &&                                     \
        (const u8 *) (_data) + (_datalen) - (const u8 *) _elem >=   \
        (int) sizeof(*_elem) + _elem->datalen;                      \
        _elem = (const struct element *) (_elem->data + _elem->datalen))

/*
Copyright (c) 2002-2018, Jouni Malinen <j@w1.fi>
Licensed under the BSD-3 License
*/

#define RSN_AUTH_KEY_MGMT_UNSPEC_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 1)
#define RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#define RSN_AUTH_KEY_MGMT_FT_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 3)
#define RSN_AUTH_KEY_MGMT_FT_PSK RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
#define RSN_AUTH_KEY_MGMT_802_1X_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 5)
#define RSN_AUTH_KEY_MGMT_PSK_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 6)
#define RSN_AUTH_KEY_MGMT_SAE RSN_SELECTOR(0x00, 0x0f, 0xac, 8)
#define RSN_AUTH_KEY_MGMT_FT_SAE RSN_SELECTOR(0x00, 0x0f, 0xac, 9)
#define RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192 RSN_SELECTOR(0x00, 0x0f, 0xac, 12)
#define RSN_AUTH_KEY_MGMT_FT_802_1X_SHA384 RSN_SELECTOR(0x00, 0x0f, 0xac, 13)

struct rsn_data {
    uint8_t ver[2]; /* little endian */
    uint8_t data[];
} __attribute__ ((packed));
#endif

#ifdef CCSP_COMMON
#define NDA_RTA(r) \
  ((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))

bool monitor_initialization_done;

static events_monitor_t g_events_monitor;

int harvester_get_associated_device_info(int vap_index, char **harvester_buf);

extern void* bus_handle;
//extern char g_Subsystem[32];
//#define SINGLE_CLIENT_WIFI_AVRO_FILENAME "WifiSingleClient.avsc"
//#define DEFAULT_INSTANT_REPORT_TIME 0

#define DEFAULT_CHANUTIL_LOG_INTERVAL 900
#define REFRESH_TASK_INTERVAL_MS 5*60*1000 //5 minutes
//#define ASSOCIATED_DEVICE_DIAG_INTERVAL_MS 5000 // 5 seconds
#define CAPTURE_VAP_STATUS_INTERVAL_MS 5000 // 5 seconds
//#define UPLOAD_AP_TELEMETRY_INTERVAL_MS 24*60*60*1000 // 24 Hours

//#define NEIGHBOR_SCAN_RESULT_INTERVAL 5000 //5 seconds
#define Min_LogInterval 300 //5 minutes
#define Max_LogInterval 3600 //60 minutes
#define Min_Chan_Util_LogInterval 5 //5 seconds

#define MIN_TO_MILLISEC 60000
#define SEC_TO_MILLISEC 1000

#define ASSOC_REQ_MAC_HEADER_LEN 24 + 2 + 2 // 4 bytes after mac header reserved for fixed len fields

char *instSchemaIdBuffer = "8b27dafc-0c4d-40a1-b62c-f24a34074914/4388e585dd7c0d32ac47e71f634b579b";
#endif // CCSP_COMMON

static wifi_monitor_t g_monitor_module;
bool             mqttcm_enabled = false;
static wifi_apps_coordinator_t g_apps_coordinator;
wifi_apps_coordinator_t *get_apps_coordinator(void);
hash_map_t * coordinator_get_collector_list(void);

#ifdef CCSP_COMMON
static unsigned msg_id = 1000;
static const char *wifi_health_log = "/rdklogs/logs/wifihealth.txt";
int radio_stats_monitor = 0;
ULONG chan_util_upload_period = 0;
ULONG lastupdatedtime = 0;
ULONG chutil_last_updated_time = 0;
time_t lastpolledtime = 0;

int device_deauthenticated(int apIndex, char *mac, int reason);
int device_associated(int apIndex, wifi_associated_dev_t *associated_dev);
int vapstatus_callback(int apIndex, wifi_vapstatus_t status);
unsigned int get_upload_period  (int);
long get_sys_uptime();
void process_disconnect    (unsigned int ap_index, auth_deauth_dev_t *dev);
BOOL sWiFiDmlvApStatsFeatureEnableCfg = TRUE;//ONE_WIFI
BOOL sWiFiDmlApStatsEnableCfg[WIFI_INDEX_MAX];//ONE_WIFI
INT assocCountThreshold = 0; 
INT assocMonitorDuration = 0;
INT assocGateTime = 0;

INT deauthCountThreshold = 0;
INT deauthMonitorDuration = 0;
INT deauthGateTime = 0;//ONE_WIFI

#if defined (_XB7_PRODUCT_REQ_)
#define FEATURE_CSI_CALLBACK 1
#endif


void get_self_bss_chan_statistics (int radiocnt , UINT *Tx_perc, UINT  *Rx_perc);
int get_chan_util_upload_period(void);
static int refresh_task_period(void *arg);
int associated_device_diagnostics_send_event(void *arg);
static void scheduler_telemetry_tasks(void);
int csi_sendPingData(void * arg);
static int csi_update_pinger(int ap_index, mac_addr_t mac_addr, bool pause_pinger);
static int clientdiag_sheduler_enable(int ap_index);
#endif // CCSP_COMMON

void deinit_wifi_monitor(void);
void SetBlasterMqttTopic(char *mqtt_topic);
int radio_diagnostics(void *arg);


static inline char *to_sta_key    (mac_addr_t mac, sta_key_t key) 
{
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}

#ifdef CCSP_COMMON
BOOL IsWiFiApStatsEnable(UINT uvAPIndex)
{
    return ((sWiFiDmlApStatsEnableCfg[uvAPIndex]) ? TRUE : FALSE);
}

int harvester_get_associated_device_info(int vap_index, char **harvester_buf)
{
    unsigned int pos = 0;
    sta_data_t *sta_data = NULL;
    if (harvester_buf[vap_index] == NULL) {
        wifi_util_dbg_print(WIFI_MON, "%s %d Harvester Buffer is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    pos = snprintf(harvester_buf[vap_index],
                CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*BSS_MAX_NUM_STATIONS,
                "{"
                "\"Version\":\"1.0\","
                "\"AssociatedClientsDiagnostics\":["
                "{"
                "\"VapIndex\":\"%d\","
                "\"AssociatedClientDiagnostics\":[",
                (vap_index+1));
    pthread_mutex_lock(&g_monitor_module.data_lock);
    sta_data = hash_map_get_first(g_monitor_module.bssid_data[vap_index].sta_map);
    while (sta_data != NULL) {
        pos += snprintf(&harvester_buf[vap_index][pos],
                (CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*BSS_MAX_NUM_STATIONS)-pos, "{"
                        "\"MAC\":\"%02x%02x%02x%02x%02x%02x\","
                        "\"MLDMAC\":\"%02x%02x%02x%02x%02x%02x\","
                        "\"MLDEnable\":\"%d\","
                        "\"DownlinkDataRate\":\"%d\","
                        "\"UplinkDataRate\":\"%d\","
                        "\"BytesSent\":\"%lu\","
                        "\"BytesReceived\":\"%lu\","
                        "\"PacketsSent\":\"%lu\","
                        "\"PacketsRecieved\":\"%lu\","
                        "\"Errors\":\"%lu\","
                        "\"RetransCount\":\"%lu\","
                        "\"Acknowledgements\":\"%lu\","
                        "\"SignalStrength\":\"%d\","
                        "\"SNR\":\"%d\","
                        "\"OperatingStandard\":\"%s\","
                        "\"OperatingChannelBandwidth\":\"%s\","
                        "\"AuthenticationFailures\":\"%d\","
                        "\"AuthenticationState\":\"%d\","
                        "\"Active\":\"%d\","
                        "\"InterferenceSources\":\"%s\","
                        "\"DataFramesSentNoAck\":\"%lu\","
                        "\"RSSI\":\"%d\","
                        "\"MinRSSI\":\"%d\","
                        "\"MaxRSSI\":\"%d\","
                        "\"Disassociations\":\"%u\","
                        "\"Retransmissions\":\"%u\""
                        "},",
                        sta_data->dev_stats.cli_MACAddress[0],
                        sta_data->dev_stats.cli_MACAddress[1],
                        sta_data->dev_stats.cli_MACAddress[2],
                        sta_data->dev_stats.cli_MACAddress[3],
                        sta_data->dev_stats.cli_MACAddress[4],
                        sta_data->dev_stats.cli_MACAddress[5],
                        sta_data->dev_stats.cli_MLDAddr[0],
                        sta_data->dev_stats.cli_MLDAddr[1],
                        sta_data->dev_stats.cli_MLDAddr[2],
                        sta_data->dev_stats.cli_MLDAddr[3],
                        sta_data->dev_stats.cli_MLDAddr[4],
                        sta_data->dev_stats.cli_MLDAddr[5],
                        sta_data->dev_stats.cli_MLDEnable,
                        sta_data->dev_stats.cli_MaxDownlinkRate,
                        sta_data->dev_stats.cli_MaxUplinkRate,
                        sta_data->dev_stats.cli_BytesSent,
                        sta_data->dev_stats.cli_BytesReceived,
                        sta_data->dev_stats.cli_PacketsSent,
                        sta_data->dev_stats.cli_PacketsReceived,
                        sta_data->dev_stats.cli_ErrorsSent,
                        sta_data->dev_stats.cli_RetransCount,
                        sta_data->dev_stats.cli_DataFramesSentAck,
                        sta_data->dev_stats.cli_SignalStrength,
                        sta_data->dev_stats.cli_SNR,
                        sta_data->dev_stats.cli_OperatingStandard,
                        sta_data->dev_stats.cli_OperatingChannelBandwidth,
                        sta_data->dev_stats.cli_AuthenticationFailures,
                        sta_data->dev_stats.cli_AuthenticationState,
                        sta_data->dev_stats.cli_Active,
                        sta_data->dev_stats.cli_InterferenceSources,
                        sta_data->dev_stats.cli_DataFramesSentNoAck,
                        sta_data->dev_stats.cli_RSSI,
                        sta_data->dev_stats.cli_MinRSSI,
                        sta_data->dev_stats.cli_MaxRSSI,
                        sta_data->dev_stats.cli_Disassociations,
                        sta_data->dev_stats.cli_Retransmissions);


        sta_data = hash_map_get_next(g_monitor_module.bssid_data[vap_index].sta_map, sta_data);

    }
    pthread_mutex_unlock(&g_monitor_module.data_lock);

    if (harvester_buf[vap_index][pos-1] == ',') {
        pos--;
    }

    snprintf(&harvester_buf[vap_index][pos], (
             CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*BSS_MAX_NUM_STATIONS)-pos,"]"
             "}"
             "]"
             "}");

    wifi_util_dbg_print(WIFI_MON, "%s %d pos : %u Buffer for vap %d updated as %s\n", __func__, __LINE__, pos, vap_index, harvester_buf[vap_index]);
    return RETURN_OK;
}

int get_radio_channel_stats(int radio_index, 
                            wifi_channelStats_t *channel_stats_array, 
                            int *array_size)
{
    wifi_channelStats_t chan_stats = {0};
    if (channel_stats_array == NULL)
    {
        wifi_util_error_print(WIFI_MON, "%s %d channel_stats_array is NULL\n", __func__, __LINE__);
        return -1;
    }
    if (array_size == NULL)
    {
        wifi_util_error_print(WIFI_MON, "%s %d array_size is NULL\n", __func__, __LINE__);
        return -1;
    }
    if (radio_index >= MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_MON, "%s:%d invalid radio_index=%d\n", __func__, __LINE__, radio_index);
        return -1;
    }
    pthread_mutex_lock(&g_monitor_module.data_lock);
    *array_size = 1;
    if (g_monitor_module.radio_chan_stats_data[radio_index].chan_data == NULL)
    {
        wifi_util_error_print(WIFI_MON, "%s %d chan_data is NULL\n", __func__, __LINE__);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return -1;
    }
    chan_stats.ch_in_pool = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_in_pool;
    chan_stats.ch_radar_noise = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_radar_noise;
    chan_stats.ch_number = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_number;
    chan_stats.ch_noise = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_noise;
    chan_stats.ch_max_80211_rssi = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_max_80211_rssi;
    chan_stats.ch_non_80211_noise = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_non_80211_noise;
    chan_stats.ch_utilization = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_utilization;
    chan_stats.ch_utilization_busy_tx = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_utilization_busy_tx;
    chan_stats.ch_utilization_busy_self = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_utilization_busy_self;
    chan_stats.ch_utilization_total = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_utilization_total;
    chan_stats.ch_utilization_busy = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_utilization_busy;
    chan_stats.ch_utilization_busy_rx = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_utilization_busy_rx;
    chan_stats.ch_utilization_busy_ext = g_monitor_module.radio_chan_stats_data[radio_index].chan_data->ch_utilization_busy_ext;
    memcpy(channel_stats_array, &chan_stats, sizeof(wifi_channelStats_t));
    pthread_mutex_unlock(&g_monitor_module.data_lock);
    return 0;
}

BOOL client_fast_reconnect(unsigned int apIndex, char *mac)
{
    extern int assocCountThreshold;
    extern int assocMonitorDuration;
    extern int assocGateTime;
    sta_data_t  *sta;
    hash_map_t  *sta_map;
    struct timeval tv_now;
    unsigned int vap_array_index;

    gettimeofday(&tv_now, NULL);

    if(!assocMonitorDuration) {
        wifi_util_error_print(WIFI_MON, "%s: Client fast reconnection check disabled, assocMonitorDuration:%d \n", __func__, assocMonitorDuration);
        return FALSE;
    }

    wifi_util_dbg_print(WIFI_MON, "%s: Checking for client:%s connection on ap:%d\n", __func__, mac, apIndex);
    getVAPArrayIndexFromVAPIndex(apIndex, &vap_array_index);

    pthread_mutex_lock(&g_monitor_module.data_lock);
    sta_map = g_monitor_module.bssid_data[vap_array_index].sta_map;
    str_tolower(mac);
    sta = (sta_data_t *)hash_map_get(sta_map, mac);
    if (sta == NULL) {
        wifi_util_error_print(WIFI_MON, "%s: Client:%s could not be found on sta map of ap:%d\n", __func__, mac, apIndex);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return FALSE;
    }

    if(sta->gate_time && (tv_now.tv_sec < sta->gate_time)) {
        wifi_util_dbg_print(WIFI_MON, "%s: Blocking burst client connections for few more seconds\n", __func__);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return TRUE;
    } else {
        wifi_util_dbg_print(WIFI_MON, "%s: processing further\n", __func__);
    }

    wifi_util_dbg_print(WIFI_MON, "%s: assocCountThreshold:%d assocMonitorDuration:%d assocGateTime:%d \n", __func__, assocCountThreshold, assocMonitorDuration, assocGateTime);

    if((tv_now.tv_sec - sta->assoc_monitor_start_time) < assocMonitorDuration) {
        sta->reconnect_count++;
        wifi_util_dbg_print(WIFI_MON, "%s: reconnect_count:%d \n", __func__, sta->reconnect_count);
        if(sta->reconnect_count > (UINT)assocCountThreshold) {
            wifi_util_dbg_print(WIFI_MON, "%s: Blocking client connections for assocGateTime:%d \n", __func__, assocGateTime);
            get_stubs_descriptor()->t2_event_d_fn("SYS_INFO_ClientConnBlock", 1);
            sta->reconnect_count = 0;
            sta->gate_time = tv_now.tv_sec + assocGateTime;
            pthread_mutex_unlock(&g_monitor_module.data_lock);
            return TRUE;
        }
    } else {
        sta->assoc_monitor_start_time = tv_now.tv_sec;
        sta->reconnect_count = 0;
        sta->gate_time = 0;
        wifi_util_dbg_print(WIFI_MON, "%s: resetting reconnect_count and assoc_monitor_start_time \n", __func__);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return FALSE;
    }
    pthread_mutex_unlock(&g_monitor_module.data_lock);
    return FALSE;
}

BOOL client_fast_redeauth(unsigned int apIndex, char *mac)
{
    extern int deauthMonitorDuration;
    extern int deauthGateTime;
    sta_data_t  *sta;
    hash_map_t  *sta_map;
    unsigned int vap_array_index;
    struct timeval tv_now;
    gettimeofday(&tv_now, NULL);

    if(!deauthMonitorDuration) {
        wifi_util_error_print(WIFI_MON, "%s: Client fast deauth check disabled, deauthMonitorDuration:%d \n", __func__, deauthMonitorDuration);
        return FALSE;
    }

    wifi_util_dbg_print(WIFI_MON, "%s: Checking for client:%s deauth on ap:%d\n", __func__, mac, apIndex);

    pthread_mutex_lock(&g_monitor_module.data_lock);
    getVAPArrayIndexFromVAPIndex(apIndex, &vap_array_index);
    sta_map = g_monitor_module.bssid_data[vap_array_index].sta_map;
    str_tolower(mac);
    sta = (sta_data_t *)hash_map_get(sta_map, mac);

    if (sta == NULL  ) {
        wifi_util_dbg_print(WIFI_MON, "%s: Client:%s could not be found on sta map of ap:%d,  Blocking client deauth notification\n", __func__, mac, apIndex);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return TRUE;
    }

    if(sta->deauth_gate_time && (tv_now.tv_sec < sta->deauth_gate_time)) {
        wifi_util_dbg_print(WIFI_MON, "%s: Blocking burst client deauth for few more seconds\n", __func__);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return TRUE;
    } else {
        wifi_util_dbg_print(WIFI_MON, "%s: processing further\n", __func__);
    }

    wifi_util_dbg_print(WIFI_MON, "%s: deauthCountThreshold:%d deauthMonitorDuration:%d deauthGateTime:%d \n", __func__, deauthCountThreshold, deauthMonitorDuration, deauthGateTime);

    if((tv_now.tv_sec - sta->deauth_monitor_start_time) < deauthMonitorDuration) {
        sta->redeauth_count++;
        wifi_util_dbg_print(WIFI_MON, "%s: redeauth_count:%d \n", __func__, sta->redeauth_count);
        if(sta->redeauth_count > (UINT)deauthCountThreshold) {
            wifi_util_dbg_print(WIFI_MON, "%s: Blocking client deauth for deauthGateTime:%d \n", __func__, deauthGateTime);
            sta->redeauth_count = 0;
            sta->deauth_gate_time = tv_now.tv_sec + deauthGateTime;
            pthread_mutex_unlock(&g_monitor_module.data_lock);
            return TRUE;
        }
    } else {
        sta->deauth_monitor_start_time = tv_now.tv_sec;
        sta->redeauth_count = 0;
        sta->deauth_gate_time = 0;
        wifi_util_dbg_print(WIFI_MON, "%s: resetting redeauth_count and deauth_monitor_start_time \n", __func__);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return FALSE;
    }
    pthread_mutex_unlock(&g_monitor_module.data_lock);
    return FALSE;
}

#endif // CCSP_COMMON

static char*
macbytes_to_string(mac_address_t mac, unsigned char* string)
{
    sprintf((char *)string, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0] & 0xff,
            mac[1] & 0xff,
            mac[2] & 0xff,
            mac[3] & 0xff,
            mac[4] & 0xff,
            mac[5] & 0xff);
    return (char *)string;
}

#ifdef CCSP_COMMON
static void
reset_client_stats_info(unsigned int apIndex)
{
    sta_data_t      *sta = NULL;
    hash_map_t      *sta_map;
    unsigned int    vap_array_index;

    getVAPArrayIndexFromVAPIndex(apIndex, &vap_array_index);
    sta_map = g_monitor_module.bssid_data[vap_array_index].sta_map;

    sta = hash_map_get_first(sta_map);
    while (sta != NULL) {
        memset((unsigned char *)&sta->dev_stats_last, 0, sizeof(wifi_associated_dev3_t));
        memset((unsigned char *)&sta->dev_stats, 0,  sizeof(wifi_associated_dev3_t));
        sta = hash_map_get_next(sta_map, sta);
    }
}

static void
process_stats_flag_changed(unsigned int ap_index, client_stats_enable_t *flag)
{
    wifi_mgr_t *mgr = get_wifimgr_obj();

    //Device.WiFi.X_RDKCENTRAL-COM_vAPStatsEnable = 0
    if (0 == flag->type) {
        int idx;
        int vap_index;
        int radio;

        write_to_file(wifi_health_log, "WIFI_STATS_FEATURE_ENABLE:%s\n",
                (flag->enable) ? "true" : "false");
        for(idx = 0; idx < (int)getTotalNumberVAPs(); idx++) {
            vap_index = VAP_INDEX(mgr->hal_cap, idx);
            radio = RADIO_INDEX(mgr->hal_cap, idx);
            if (g_monitor_module.radio_presence[radio] == false) {
               continue;
            }
            reset_client_stats_info(vap_index);
        }
    } else if (1 == flag->type) { //Device.WiFi.AccessPoint.<vAP>.X_RDKCENTRAL-COM_StatsEnable = 1
        if (wifi_util_is_vap_index_valid(&mgr->hal_cap.wifi_prop, (int)ap_index)) {
            reset_client_stats_info(ap_index);
            write_to_file(wifi_health_log, "WIFI_STATS_ENABLE_%d:%s\n", ap_index+1,
                    (flag->enable) ? "true" : "false");
        }
    }
}

static void
radio_stats_flag_changed(unsigned int radio_index, client_stats_enable_t *flag)
{
    wifi_mgr_t *mgr = get_wifimgr_obj();
    for(UINT apIndex = 0; apIndex <= getTotalNumberVAPs(); apIndex++)
    {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, apIndex);
        UINT radio = RADIO_INDEX(mgr->hal_cap, apIndex);
        if (g_monitor_module.radio_presence[radio] == false) {
            continue;
        }
        if (radio_index == getRadioIndexFromAp(vap_index))
        {
            reset_client_stats_info(apIndex);
        }
        write_to_file(wifi_health_log, "WIFI_RADIO_STATUS_ENABLE_%d:%s\n", radio_index+1,
                (flag->enable) ? "true" : "false");
    }
}

static void
vap_stats_flag_changed(unsigned int ap_index, client_stats_enable_t *flag)
{
    //Device.WiFi.SSID.<vAP>.Enable = 0
    reset_client_stats_info(ap_index);
    write_to_file(wifi_health_log, "WIFI_VAP_STATUS_ENABLE_%d:%s\n", ap_index+1,
            (flag->enable) ? "true" : "false");
}

/*
 * wifi_stats_flag_change()
 * ap_index vAP
 * enable   true/false
 * type     Device.WiFi.X_RDKCENTRAL-COM_vAPStatsEnable= 0,
 Device.WiFi.AccessPoint.<vAP>.X_RDKCENTRAL-COM_StatsEnable = 1
 */
int wifi_stats_flag_change(int ap_index, bool enable, int type)
{
    wifi_monitor_data_t data;

    memset(&data, 0, sizeof(wifi_monitor_data_t));
    data.id = msg_id++;
    data.ap_index = ap_index;

    data.u.flag.type = type;
    data.u.flag.enable = enable;

    wifi_util_dbg_print(WIFI_MON, "%s:%d: flag changed apIndex=%d enable=%d type=%d\n",
            __func__, __LINE__, ap_index, enable, type);

    push_event_to_monitor_queue(&data, wifi_event_monitor_stats_flag_change, NULL);

    return 0;
}

/*
 * radio_stats_flag_change()
 * ap_index vAP
 * enable   true/false
 * type     Device.WiFi.Radio.<Index>.Enable = 1
 */
int radio_stats_flag_change(int radio_index, bool enable)
{
    wifi_monitor_data_t data;

    memset(&data, 0, sizeof(wifi_monitor_data_t));
    data.id = msg_id++;
    data.ap_index = radio_index;	//Radio_Index = 0, 1
    data.u.flag.enable = enable;

    wifi_util_dbg_print(WIFI_MON, "%s:%d: flag changed radioIndex=%d enable=%d\n",
            __func__, __LINE__, radio_index, enable);

    push_event_to_monitor_queue(&data, wifi_event_monitor_radio_stats_flag_change, NULL);

    return 0;
}

/*
 * vap_stats_flag_change()
 * ap_index vAP
 * enable   true/false
 * type     Device.WiFi.SSID.<vAP>.Enable = 0
 */
int vap_stats_flag_change(int ap_index, bool enable)
{
    wifi_monitor_data_t data;

    memset(&data, 0, sizeof(wifi_monitor_data_t));
    data.id = msg_id++;
    data.ap_index = ap_index;	//vap_Index
    data.u.flag.enable = enable;

    wifi_util_dbg_print(WIFI_MON, "%s:%d: flag changed vapIndex=%d enable=%d \n",
            __func__, __LINE__, ap_index, enable);
    push_event_to_monitor_queue(&data, wifi_event_monitor_vap_stats_flag_change, NULL);


    return 0;
}

int get_sta_stats_info (assoc_dev_data_t *assoc_dev_data) {

    unsigned int vap_array_index;
    if (assoc_dev_data == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: NULL pointer\n", __func__, __LINE__);
        return -1;
    }

    hash_map_t *sta_map = NULL;
    sta_data_t *sta_data = NULL;
    sta_key_t sta_key;

    pthread_mutex_lock(&g_monitor_module.data_lock);

    getVAPArrayIndexFromVAPIndex((unsigned int)assoc_dev_data->ap_index, &vap_array_index);
    sta_map = g_monitor_module.bssid_data[vap_array_index].sta_map;
    memset(sta_key, 0, STA_KEY_LEN);
    to_sta_key(assoc_dev_data->dev_stats.cli_MACAddress, sta_key);

    str_tolower(sta_key);

    sta_data = (sta_data_t *)hash_map_get(sta_map, sta_key);
    if (sta_data == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: NULL pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return -1;
    }

    assoc_dev_data->dev_stats.cli_AuthenticationState = sta_data->dev_stats.cli_AuthenticationState;
    assoc_dev_data->dev_stats.cli_LastDataDownlinkRate = sta_data->dev_stats.cli_LastDataDownlinkRate;
    assoc_dev_data->dev_stats.cli_LastDataUplinkRate = sta_data->dev_stats.cli_LastDataUplinkRate;
    assoc_dev_data->dev_stats.cli_SignalStrength = sta_data->dev_stats.cli_SignalStrength;
    assoc_dev_data->dev_stats.cli_Retransmissions = sta_data->dev_stats.cli_Retransmissions;
    assoc_dev_data->dev_stats.cli_Active = sta_data->dev_stats.cli_Active;
    memcpy(assoc_dev_data->dev_stats.cli_MLDAddr, sta_data->dev_stats.cli_MLDAddr, sizeof(mac_address_t));
    memcpy(assoc_dev_data->dev_stats.cli_OperatingStandard, sta_data->dev_stats.cli_OperatingStandard, sizeof(char)*64);
    memcpy(assoc_dev_data->dev_stats.cli_OperatingChannelBandwidth, sta_data->dev_stats.cli_OperatingChannelBandwidth, sizeof(char)*64);
    assoc_dev_data->dev_stats.cli_SNR = sta_data->dev_stats.cli_SNR;
    memcpy(assoc_dev_data->dev_stats.cli_InterferenceSources, sta_data->dev_stats.cli_InterferenceSources, sizeof(char)*64);
    assoc_dev_data->dev_stats.cli_DataFramesSentAck = sta_data->dev_stats.cli_DataFramesSentAck;
    assoc_dev_data->dev_stats.cli_DataFramesSentNoAck = sta_data->dev_stats.cli_DataFramesSentNoAck;
    assoc_dev_data->dev_stats.cli_BytesSent = sta_data->dev_stats.cli_BytesSent;
    assoc_dev_data->dev_stats.cli_BytesReceived = sta_data->dev_stats.cli_BytesReceived;
    assoc_dev_data->dev_stats.cli_RSSI = sta_data->dev_stats.cli_RSSI;
    assoc_dev_data->dev_stats.cli_MinRSSI = sta_data->dev_stats.cli_MinRSSI;
    assoc_dev_data->dev_stats.cli_MaxRSSI = sta_data->dev_stats.cli_MaxRSSI;
    assoc_dev_data->dev_stats.cli_Disassociations = sta_data->dev_stats.cli_Disassociations;
    assoc_dev_data->dev_stats.cli_AuthenticationFailures = sta_data->dev_stats.cli_AuthenticationFailures;
    assoc_dev_data->dev_stats.cli_PacketsSent = sta_data->dev_stats.cli_PacketsSent;
    assoc_dev_data->dev_stats.cli_PacketsReceived = sta_data->dev_stats.cli_PacketsReceived;
    assoc_dev_data->dev_stats.cli_ErrorsSent = sta_data->dev_stats.cli_ErrorsSent;
    assoc_dev_data->dev_stats.cli_RetransCount = sta_data->dev_stats.cli_RetransCount;
    assoc_dev_data->dev_stats.cli_FailedRetransCount = sta_data->dev_stats.cli_FailedRetransCount;
    assoc_dev_data->dev_stats.cli_RetryCount = sta_data->dev_stats.cli_RetryCount;
    assoc_dev_data->dev_stats.cli_MultipleRetryCount = sta_data->dev_stats.cli_MultipleRetryCount;
    assoc_dev_data->dev_stats.cli_MLDEnable = sta_data->dev_stats.cli_MLDEnable;

    pthread_mutex_unlock(&g_monitor_module.data_lock);
    return 0;
}

int get_sta_stats_for_vap(int ap_index, wifi_associated_dev3_t *assoc_dev_array,
                          unsigned int *output_array_size)
{
    unsigned int vap_array_index;
    unsigned int i = 0;
    hash_map_t *sta_map = NULL;
    sta_data_t *sta_data = NULL;
    mac_addr_str_t assoc_mac, dev_mac;
    pthread_mutex_lock(&g_monitor_module.data_lock);
    getVAPArrayIndexFromVAPIndex((unsigned int)ap_index, &vap_array_index);
    if(assoc_dev_array == NULL) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d: assoc_dev_array is NULL\n", __func__, __LINE__);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return -1;
    }
    sta_map = g_monitor_module.bssid_data[vap_array_index].sta_map;
    if (sta_map == NULL) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d: NULL pointer:ap_index:%d,vap_array_index:%u \n", __func__, __LINE__,ap_index,vap_array_index);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return -1;
    }
    sta_data = hash_map_get_first(sta_map);
    if (sta_data == NULL) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d: NULL pointer:ap_index:%d,vap_array_index:%u \n", __func__, __LINE__,ap_index,vap_array_index);
        *output_array_size=0;
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return 0;
    }
    while (sta_data != NULL && i < 2) { // i < 2 is temporary as HAL_IPC_MAX_STA_SUPPORT_NUM is hardcoded now to 2
        memcpy(&assoc_dev_array[i], &sta_data->dev_stats, sizeof(wifi_associated_dev3_t));
        to_mac_str(assoc_dev_array[i].cli_MACAddress, assoc_mac);
        to_mac_str(sta_data->dev_stats.cli_MACAddress, dev_mac);
        wifi_util_dbg_print(WIFI_MON,"%s:%d assoc_mac:%s,dev_mac:%s,value of i:%d:ap_index:%d,vap_array_index:%u \n", __func__, __LINE__,assoc_mac,dev_mac,i,ap_index,vap_array_index);
        i++;
        sta_data = hash_map_get_next(sta_map, sta_data);
    }
    *output_array_size = i;
    wifi_util_dbg_print(WIFI_MON, "%s:%d:output_array_size is:%u \n", __func__, __LINE__,*output_array_size);
    pthread_mutex_unlock(&g_monitor_module.data_lock);
    return 0;
}
#endif

void send_wifi_disconnect_event_to_ctrl(mac_address_t mac_addr, unsigned int ap_index)
{
    assoc_dev_data_t assoc_data;
    memset(&assoc_data, 0, sizeof(assoc_data));

    memcpy(assoc_data.dev_stats.cli_MACAddress, mac_addr, sizeof(mac_address_t));
    assoc_data.ap_index = ap_index;
    assoc_data.reason = 0;
    push_event_to_ctrl_queue(&assoc_data, sizeof(assoc_data), wifi_event_type_hal_ind, wifi_event_hal_disassoc_device, NULL);
}

#ifdef CCSP_COMMON
sta_data_t *create_sta_data_hash_map(hash_map_t *sta_map, mac_addr_t l_sta_mac)
{
    pthread_mutex_lock(&g_monitor_module.data_lock);
    mac_addr_str_t mac_str = { 0 };
    sta_data_t *sta = NULL;

    sta = (sta_data_t *)malloc(sizeof(sta_data_t));
    if (sta == NULL) {
        wifi_util_error_print(WIFI_MON,"%s:%d malloc allocation failure\r\n", __func__, __LINE__);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return NULL;
    }
    memset(sta, 0, sizeof(sta_data_t));
    memcpy(sta->sta_mac, l_sta_mac, sizeof(mac_addr_t));
    hash_map_put(sta_map, strdup(to_mac_str(l_sta_mac, mac_str)), sta);
    pthread_mutex_unlock(&g_monitor_module.data_lock);
    return sta;
}

hash_map_t *get_sta_data_map(unsigned int vap_index)
{
    pthread_mutex_lock(&g_monitor_module.data_lock);
    unsigned int vap_array_index;
    char vap_name[32] ={0};
    convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop,vap_index,vap_name);
    if (strlen(vap_name) <= 0) {
        wifi_util_error_print(WIFI_MON,"%s:%d wrong vap_index:%d\r\n", __func__, __LINE__, vap_index);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return NULL;
    }
    getVAPArrayIndexFromVAPIndex(vap_index, &vap_array_index);
    pthread_mutex_unlock(&g_monitor_module.data_lock);
    return g_monitor_module.bssid_data[vap_array_index].sta_map;
}

int set_assoc_req_frame_data(frame_data_t *msg)
{
    hash_map_t   *sta_map;
    sta_data_t   *sta;
    struct ieee80211_mgmt *frame;
    mac_addr_str_t mac_str = { 0 };
    char *str;
    time_t frame_timestamp;

    frame = (struct ieee80211_mgmt *)msg->data;
    str = to_mac_str(frame->sa, mac_str);
    if (str == NULL) {
        wifi_util_error_print(WIFI_MON,"%s:%d mac str convert failure\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_MON,"%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d src mac:%s rssi:%d\r\n", __func__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, str, msg->frame.sig_dbm);

    sta_map = get_sta_data_map(msg->frame.ap_index);
    if (sta_map == NULL) {
        wifi_util_error_print(WIFI_MON,"%s:%d sta_data map not found for vap_index:%d\r\n", __func__, __LINE__, msg->frame.ap_index);
        return RETURN_ERR;
    }

    sta = (sta_data_t *)hash_map_get(sta_map, mac_str);
    if (NULL == sta)
    {
        sta = create_sta_data_hash_map(sta_map, frame->sa);
        if(NULL == sta)
        {
            return RETURN_ERR;
        }
    }
    (void)memset(&sta->assoc_frame_data, 0, sizeof(assoc_req_elem_t));
    (void)memcpy(&sta->assoc_frame_data.msg_data, msg, sizeof(frame_data_t));
    (void)time(&frame_timestamp);
    (void)memcpy(&sta->assoc_frame_data.frame_timestamp, &frame_timestamp, sizeof(frame_timestamp));

    return RETURN_OK;
}

int update_assoc_frame_data_entry(unsigned int vap_index)
{
    hash_map_t   *sta_map;
    sta_data_t   *sta;
    time_t       current_timestamp;
    mac_addr_str_t mac_str = { 0 };

    sta_map = get_sta_data_map(vap_index);
    if (sta_map == NULL) {
        wifi_util_error_print(WIFI_MON,"%s:%d sta_data map not found for vap_index:%d\r\n", __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    sta = hash_map_get_first(sta_map);
    while (sta != NULL) {
        if ((sta->connection_authorized == false) && (sta->assoc_frame_data.frame_timestamp != 0)) {
            time(&current_timestamp);

            wifi_util_dbg_print(WIFI_MON,"%s:%d assoc time:%ld, current time:%ld\r\n", __func__, __LINE__, sta->assoc_frame_data.frame_timestamp, current_timestamp);
            wifi_util_dbg_print(WIFI_MON,"%s:%d vap_index:%d sta_mac:%s\r\n", __func__, __LINE__, vap_index, to_mac_str(sta->sta_mac, mac_str));
            //If sta client disconnected and time diff more than 30 seconds then we need to reset client assoc frame data
            if ((current_timestamp - sta->assoc_frame_data.frame_timestamp) > MAX_ASSOC_FRAME_REFRESH_PERIOD) {
                wifi_util_dbg_print(WIFI_MON,"%s:%d assoc time diff:%d\r\n", __func__, __LINE__, (current_timestamp - sta->assoc_frame_data.frame_timestamp));
                memset(&sta->assoc_frame_data, 0, sizeof(assoc_req_elem_t));
            }
        }
        sta = hash_map_get_next(sta_map, sta);
    }

    return RETURN_OK;
}

void update_assoc_frame_all_vap_data_entry(void)
{
    unsigned int index,vap_index;

    wifi_mgr_t *mgr = get_wifimgr_obj();
    for (index = 0; index < getTotalNumberVAPs(); index++) {
        vap_index = VAP_INDEX(mgr->hal_cap, index);
        update_assoc_frame_data_entry(vap_index);
    }
}

static int refresh_assoc_frame_entry(void *arg)
{
    update_assoc_frame_all_vap_data_entry();
    return TIMER_TASK_COMPLETE;
}

void process_deauthenticate	(unsigned int ap_index, auth_deauth_dev_t *dev)
{
    char buff[2048];
    char tmp[128];
    sta_key_t sta_key;

    wifi_util_info_print(WIFI_MON, "%s:%d Device:%s deauthenticated on ap:%d with reason : %d\n", __func__, __LINE__, to_sta_key(dev->sta_mac, sta_key), ap_index, dev->reason);

    /*Wrong password on private, Xfinity Home and LNF SSIDs*/
    if ((dev->reason == 2) && ( isVapPrivate(ap_index) || isVapXhs(ap_index) || isVapLnfPsk(ap_index) ) ) {
        get_formatted_time(tmp);

        snprintf(buff, 2048, "%s WIFI_PASSWORD_FAIL:%d,%s\n", tmp, ap_index + 1, to_sta_key(dev->sta_mac, sta_key));
        /* send telemetry of password failure */
        write_to_file(wifi_health_log, buff);
    }
    /*ARRISXB6-11979 Possible Wrong WPS key on private SSIDs*/
    if ((dev->reason == 2 || dev->reason == 14 || dev->reason == 19) && ( isVapPrivate(ap_index) ))  {
        get_formatted_time(tmp);

        snprintf(buff, 2048, "%s WIFI_POSSIBLE_WPS_PSK_FAIL:%d,%s,%d\n", tmp, ap_index + 1, to_sta_key(dev->sta_mac, sta_key), dev->reason);
        /* send telemetry of WPS failure */
        write_to_file(wifi_health_log, buff);
    }
    /*Calling process_disconnect as station is disconncetd from vAP*/
    process_disconnect(ap_index, dev);
}

#endif // CCSP_COMMON

void process_connect(unsigned int ap_index, auth_deauth_dev_t *dev)
{
    sta_key_t sta_key;
    sta_data_t *sta;
    hash_map_t     *sta_map;
#ifdef CCSP_COMMON
    struct timespec tv_now, t_diff, t_tmp;
    unsigned int i = 0;
    int vap_status = 0;
    wifi_mgr_t *mgr = get_wifimgr_obj();
#endif // CCSP_COMMON
    unsigned int vap_array_index;
    getVAPArrayIndexFromVAPIndex(ap_index, &vap_array_index);

    sta_map = g_monitor_module.bssid_data[vap_array_index].sta_map;
    wifi_util_info_print(WIFI_MON, "sta map: %p Device:%s connected on ap:%d\n", sta_map, to_sta_key(dev->sta_mac, sta_key), ap_index);
    to_sta_key(dev->sta_mac, sta_key);
    str_tolower(sta_key);
    sta = (sta_data_t *)hash_map_get(sta_map, sta_key);
    if (sta == NULL) { /* new client */
        pthread_mutex_lock(&g_monitor_module.data_lock);
        sta = (sta_data_t *)malloc(sizeof(sta_data_t));
        memset(sta, 0, sizeof(sta_data_t));
        memcpy(sta->sta_mac, dev->sta_mac, sizeof(mac_addr_t));
        memcpy(sta->dev_stats.cli_MACAddress, dev->sta_mac, sizeof(mac_addr_t));
        sta->primary_link = 1;
        hash_map_put(sta_map, strdup(sta_key), sta);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
    }

#ifdef CCSP_COMMON
    clock_gettime(CLOCK_MONOTONIC, &tv_now);
    if (timespecisset(&(sta->last_connected_time))) {
        if (timespeccmp(&(sta->last_disconnected_time), &(g_monitor_module.bssid_data[vap_array_index].last_sta_update_time), >)) {//sta disconnected before counter update
            timespecsub(&tv_now, &(sta->last_disconnected_time), &t_diff);
        } else {
            timespecsub(&tv_now, &(g_monitor_module.bssid_data[vap_array_index].last_sta_update_time), &t_diff);
        }
        t_tmp.tv_sec = sta->total_disconnected_time.tv_sec;
        t_tmp.tv_nsec = sta->total_disconnected_time.tv_nsec;
        timespecadd(&t_tmp, &t_diff, &(sta->total_disconnected_time));
    }

    if(!sta->assoc_monitor_start_time)
        sta->assoc_monitor_start_time = tv_now.tv_sec;

    if ((UINT)(tv_now.tv_sec - sta->last_disconnected_time.tv_sec) <= g_monitor_module.bssid_data[i].ap_params.rapid_reconnect_threshold) {
        if (sta->dev_stats.cli_Active == false) {
            wifi_util_dbg_print(WIFI_MON, "Device:%s connected on ap:%d connected within rapid reconnect time\n", to_sta_key(dev->sta_mac, sta_key), ap_index);
            sta->rapid_reconnects++;
        }
    } else {
        wifi_util_dbg_print(WIFI_MON, "Device:%s connected on ap:%d received another connection event\n", to_sta_key(dev->sta_mac, sta_key), ap_index);
    }

    sta->last_connected_time.tv_sec = tv_now.tv_sec;
    sta->last_connected_time.tv_nsec = tv_now.tv_nsec;

    wifi_util_dbg_print(WIFI_MON, "%s:%d total_connected_time %lld ms\n", __func__, __LINE__, (long long)((sta->total_connected_time.tv_sec*1000)+(sta->total_connected_time.tv_nsec/1000000)));
    wifi_util_dbg_print(WIFI_MON, "%s:%d total_disconnected_time %lld ms\n", __func__, __LINE__, (long long)((sta->total_disconnected_time.tv_sec*1000)+(sta->total_disconnected_time.tv_nsec/1000000)));
    

    /* reset stats of client */
    memset((unsigned char *)&sta->dev_stats_last, 0, sizeof(wifi_associated_dev3_t));
#endif // CCSP_COMMON
    memset((unsigned char *)&sta->dev_stats, 0, sizeof(wifi_associated_dev3_t));
    memcpy(&sta->dev_stats, &dev->dev_stats, sizeof(wifi_associated_dev3_t));
    sta->dev_stats.cli_Active = true;
#ifdef CCSP_COMMON
    sta->connection_authorized = true;
    /*To avoid duplicate entries in hash map of different vAPs eg:RDKB-21582
      Also when clients moved away from a vAP and connect back to other vAP this will be usefull*/
    for (i = 0; i < getTotalNumberVAPs(); i++) {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, i);
        UINT radio = RADIO_INDEX(mgr->hal_cap, i);
        if (g_monitor_module.radio_presence[radio] == false) {
            continue;
        }
        if ( vap_index == ap_index)
            continue;
        vap_status = g_monitor_module.bssid_data[vap_index].ap_params.ap_status;
        if (vap_status) {
            sta_map = g_monitor_module.bssid_data[i].sta_map;
            to_sta_key(dev->sta_mac, sta_key);
            str_tolower(sta_key);
            sta = (sta_data_t *)hash_map_get(sta_map, sta_key);
            if ((sta != NULL) && (sta->dev_stats.cli_Active == true)) {
                sta->dev_stats.cli_Active = false;
            } else if ((sta != NULL) && (sta->connection_authorized == true)) {
                sta->connection_authorized = false;
            }
        }
    }
#endif // CCSP_COMMON
}

void process_disconnect	(unsigned int ap_index, auth_deauth_dev_t *dev)
{
    sta_key_t sta_key;
    sta_data_t *sta;
    hash_map_t     *sta_map;
#ifdef CCSP_COMMON
    struct timespec tv_now, t_diff, t_tmp;
    instant_msmt_t msmt;
#endif // CCSP_COMMON
    unsigned int vap_array_index;

    getVAPArrayIndexFromVAPIndex(ap_index, &vap_array_index);
    sta_map = g_monitor_module.bssid_data[vap_array_index].sta_map;
    wifi_util_info_print(WIFI_MON, "Device:%s disconnected on ap:%d\n", to_sta_key(dev->sta_mac, sta_key), ap_index);
    str_tolower(sta_key);
    sta = (sta_data_t *)hash_map_get(sta_map, sta_key);
    if (sta == NULL) {
        wifi_util_info_print(WIFI_MON, "Device:%s could not be found on sta map of ap:%d\n", sta_key, ap_index);
        return;
    }

#ifdef CCSP_COMMON
    clock_gettime(CLOCK_MONOTONIC, &tv_now);
    if (timespeccmp(&(sta->last_connected_time), &(g_monitor_module.bssid_data[vap_array_index].last_sta_update_time), >)) {//sta disconnected before counter update
        timespecsub(&tv_now, &(sta->last_connected_time), &t_diff);
    } else {
        timespecsub(&tv_now, &(g_monitor_module.bssid_data[vap_array_index].last_sta_update_time), &t_diff);
    }
    t_tmp.tv_sec = sta->total_connected_time.tv_sec;
    t_tmp.tv_nsec = sta->total_connected_time.tv_nsec;
    timespecadd(&t_tmp, &t_diff, &(sta->total_connected_time));
    sta->dev_stats.cli_Active = false;
    sta->connection_authorized = false;
    if(!sta->deauth_monitor_start_time)
        sta->deauth_monitor_start_time = tv_now.tv_sec;

    sta->last_disconnected_time.tv_sec = tv_now.tv_sec;
    sta->last_disconnected_time.tv_nsec = tv_now.tv_nsec;
    wifi_util_dbg_print(WIFI_MON, "%s:%d total_connected_time %lld ms\n", __func__, __LINE__, (long long)(sta->total_connected_time.tv_sec*1000)+(sta->total_connected_time.tv_nsec/1000000));
    wifi_util_dbg_print(WIFI_MON, "%s:%d total_disconnected_time %lld ms\n", __func__, __LINE__, (long long)(sta->total_disconnected_time.tv_sec*1000)+(sta->total_disconnected_time.tv_nsec/1000000));


    // stop instant measurements if its going on with this client device
    msmt.ap_index = ap_index;
    memcpy(msmt.sta_mac, dev->sta_mac, sizeof(mac_address_t));
    /* stop the instant measurement only if the client for which instant measuremnt
      is running got disconnected from AP
      */
#else
    sta = hash_map_remove(sta_map, sta_key);
    if (sta != NULL) {
        free(sta);
    }
#endif // CCSP_COMMON
}

#ifdef CCSP_COMMON

int get_neighbor_scan_cfg(int radio_index,
                          wifi_neighbor_ap2_t *neighbor_results,
                          unsigned int *output_array_size)
{
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();

    pthread_mutex_lock(&g_monitor_module.data_lock);
    *output_array_size = monitor_param->neighbor_scan_cfg.resultCountPerRadio[radio_index];
    memcpy(neighbor_results, monitor_param->neighbor_scan_cfg.pResult[radio_index], (*output_array_size)*sizeof(wifi_neighbor_ap2_t));
    pthread_mutex_unlock(&g_monitor_module.data_lock);

    return 0;
}

#endif // CCSP_COMMON

void clear_sta_counters(unsigned int vap_index)
{
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    hash_map_t *sta_map = NULL;
    sta_data_t *temp_sta = NULL;
    unsigned int vap_array_index;

    getVAPArrayIndexFromVAPIndex(vap_index, &vap_array_index);

    sta_map = mon_data->bssid_data[vap_array_index].sta_map;
    if (sta_map != NULL) {
        temp_sta = hash_map_get_first(sta_map);
        while(temp_sta != NULL) {
            temp_sta->good_rssi_time = 0;
            temp_sta->bad_rssi_time = 0;
            temp_sta->rapid_reconnects = 0;
            temp_sta = hash_map_get_next(sta_map, temp_sta);
        }
    }
}

void *monitor_function  (void *data)
{
    char event_buff[16] = {0};
    wifi_monitor_t *proc_data;
    struct timespec time_to_wait;
    struct timespec tv_now;
    wifi_event_t *event;
    wifi_monitor_data_t        *event_data = NULL;
    int rc;
    struct timespec t_start;
    struct timespec interval;
    timespecclear(&t_start);

    /* Send the event to ctrl queue to notify that monitor initialization is done */
    strncpy(event_buff, "Init completed", sizeof(event_buff)-1);
    push_event_to_ctrl_queue(event_buff, (strlen(event_buff) +1), wifi_event_type_command, wifi_event_type_notify_monitor_done, NULL);

#ifdef CCSP_COMMON
    /* Set the monitor_initialization_done flag to notify */
    monitor_initialization_done = true;
#endif // CCSP_COMMON

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    proc_data = (wifi_monitor_t *)data;

    pthread_mutex_lock(&proc_data->queue_lock);
    while (proc_data->exit_monitor == false) {
        clock_gettime(CLOCK_MONOTONIC, &tv_now);

        interval.tv_sec = 0;
        interval.tv_nsec = MONITOR_RUNNING_INTERVAL_IN_MILLISEC * 1000 * 1000;
        timespecadd(&t_start, &interval, &time_to_wait);

        rc = 0;
        if (queue_count(proc_data->queue) == 0) {
            rc = pthread_cond_timedwait(&proc_data->cond, &proc_data->queue_lock, &time_to_wait);
        }

        if ((rc == 0) || (queue_count(proc_data->queue) != 0)) {
            // dequeue data
            while (queue_count(proc_data->queue)) {
                event = queue_pop(proc_data->queue);
                if (event == NULL) {
                    continue;
                }

                pthread_mutex_unlock(&proc_data->queue_lock);

                event_data = event->u.mon_data;

#ifdef CCSP_COMMON
                //Send data to wifi_events library
                events_rbus_publish(event);
#endif // CCSP_COMMON
                switch (event->sub_type) {
#ifdef CCSP_COMMON
                    case wifi_event_monitor_diagnostics:
                        //process_diagnostics(event_data->ap_index, &event_data->.devs);
                    break;
#endif // CCSP_COMMON

                    case wifi_event_monitor_connect:
                        process_connect(event_data->ap_index, &event_data->u.dev);
                    break;

                    case wifi_event_monitor_disconnect:
                        process_disconnect(event_data->ap_index, &event_data->u.dev);
                    break;
#ifdef CCSP_COMMON

                    case wifi_event_monitor_deauthenticate:
                        process_deauthenticate(event_data->ap_index, &event_data->u.dev);
                    break;

                    case wifi_event_monitor_stats_flag_change:
                        process_stats_flag_changed(event_data->ap_index, &event_data->u.flag);
                    break;
                    case wifi_event_monitor_radio_stats_flag_change:
                        radio_stats_flag_changed(event_data->ap_index, &event_data->u.flag);
                    break;
                    case wifi_event_monitor_vap_stats_flag_change:
                        vap_stats_flag_changed(event_data->ap_index, &event_data->u.flag);
                    break;
                    case wifi_event_monitor_csi_pinger:
                        csi_update_pinger(event_data->u.csi_mon.ap_index, event_data->u.csi_mon.mac_addr, event_data->u.csi_mon.pause_pinger);
                    break;
                    case wifi_event_monitor_clientdiag_update_config:
                        clientdiag_sheduler_enable(event_data->ap_index);
                    break;
                    case wifi_event_monitor_assoc_req:
                        set_assoc_req_frame_data(&event_data->u.msg);
                    break;
                    case wifi_event_monitor_start_inst_msmt:
                        g_monitor_module.inst_msmt_id = 1;
                        scheduler_telemetry_tasks();
                    break;
                    case wifi_event_monitor_stop_inst_msmt:
                        g_monitor_module.inst_msmt_id = 0;
                        scheduler_telemetry_tasks();
                    break;
#endif // CCSP_COMMON
                    case wifi_event_monitor_data_collection_config:
                        coordinator_check_stats_config(&event_data->u.mon_stats_config);
                    break;
                    case wifi_event_monitor_started_active_msmt:
                        g_monitor_module.is_blaster_running = true;
                    break;
                    case wifi_event_monitor_stop_active_msmt:
                        g_monitor_module.is_blaster_running = false;
                    break;
                    case wifi_event_monitor_clear_sta_counters:
                        clear_sta_counters(event_data->ap_index);
                    break;
                    default:
                    break;

                }

                destroy_wifi_event(event);

                clock_gettime(CLOCK_MONOTONIC, &proc_data->last_signalled_time);
                pthread_mutex_lock(&proc_data->queue_lock);
            }
        } else if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&proc_data->queue_lock);
            clock_gettime(CLOCK_MONOTONIC, &t_start);
            scheduler_execute(g_monitor_module.sched, t_start, interval.tv_nsec/(1000 * 1000));
            pthread_mutex_lock(&proc_data->queue_lock);
        } else {
            wifi_util_error_print(WIFI_MON,"%s:%d Monitor Thread exited with rc - %d",__func__,__LINE__,rc);
            pthread_mutex_unlock(&proc_data->queue_lock);
            return NULL;
        }

    }
    pthread_mutex_unlock(&proc_data->queue_lock);


    return NULL;
}

#ifdef CCSP_COMMON
static int refresh_task_period(void *arg)
{
    unsigned int    new_upload_period;
    new_upload_period = get_upload_period(g_monitor_module.upload_period);
    if (new_upload_period != g_monitor_module.upload_period) {
        g_monitor_module.upload_period = new_upload_period;
        if (new_upload_period != 0) {
            return TIMER_TASK_COMPLETE;
        } else {
            if (g_monitor_module.client_telemetry_id != 0) {
                scheduler_cancel_timer_task(g_monitor_module.sched, g_monitor_module.client_telemetry_id);
                g_monitor_module.client_telemetry_id = 0;
            }
        }
    }
    return TIMER_TASK_COMPLETE;
}
#endif // CCSP_COMMON

bool is_device_associated(int ap_index, char *mac)
{
    mac_address_t bmac;
    sta_data_t *sta;
    hash_map_t     *sta_map;
    unsigned int vap_array_index;

    getVAPArrayIndexFromVAPIndex((unsigned int)ap_index, &vap_array_index);

    str_to_mac_bytes(mac, bmac);
    sta_map = g_monitor_module.bssid_data[vap_array_index].sta_map;
    sta = hash_map_get_first(sta_map);
    while (sta != NULL) {
        if ((memcmp(sta->sta_mac, bmac, sizeof(mac_address_t)) == 0) && (sta->dev_stats.cli_Active == true)) {
            return true;
        }
        sta = hash_map_get_next(sta_map, sta);
    }
    return false;
}

#ifdef CCSP_COMMON
int timeval_subtract (struct timeval *result, struct timeval *end, struct timeval *start)
{
    if(result == NULL || end == NULL || start == NULL) {
        return 1;
    }
    /* Refer to https://www.gnu.org/software/libc/manual/html_node/Calculating-Elapsed-Time.html" */

    if (end->tv_usec < start->tv_usec) {
        int adjust_sec = (start->tv_usec - end->tv_usec) / 1000000 + 1;
        start->tv_usec -= 1000000 * adjust_sec;
        start->tv_sec += adjust_sec;
    }
    if (end->tv_usec - start->tv_usec > 1000000) {
        int adjust_sec = (end->tv_usec - start->tv_usec) / 1000000;
        start->tv_usec += 1000000 * adjust_sec;
        start->tv_sec -= adjust_sec;
    }


    result->tv_sec = end->tv_sec - start->tv_sec;
    result->tv_usec = end->tv_usec - start->tv_usec;

    return (end->tv_sec < start->tv_sec);
}
#endif // CCSP_COMMON

int  getApIndexfromClientMac(char *check_mac)
{
    unsigned int i=0;
    unsigned char tmpmac[18];
    wifi_mgr_t *mgr = get_wifimgr_obj();

    if(check_mac == NULL) {
        wifi_util_error_print(WIFI_MON, "%s: Null arguments %p \n",__func__, check_mac);
        return -1;
    }

    macbytes_to_string((unsigned char *)check_mac, tmpmac);
    for (i = 0; i < getTotalNumberVAPs(); i++) {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, i);
        UINT radio = RADIO_INDEX(mgr->hal_cap, i);
        if (g_monitor_module.radio_presence[radio] == false) {
            continue;
        }

        if (is_device_associated(vap_index, (char *)tmpmac) == true) {
            return vap_index;
        }
    }
    return -1;
}

#ifdef CCSP_COMMON
static void rtattr_parse(struct rtattr *table[], int max, struct rtattr *rta, int len)
{
    unsigned short type;
    if(table == NULL || rta == NULL) {
        wifi_util_error_print(WIFI_MON, "%s: Null arguments %p %p\n",__func__,table, rta);
        return;
    }
    memset(table, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        type = rta->rta_type;
        if (type <= max)
            table[type] = rta;
        rta = RTA_NEXT(rta, len);
    }
}

int getlocalIPAddress(char *ifname, char *ip, bool af_family)
{
    struct {
        struct nlmsghdr n;
        struct ifaddrmsg r;
    } req;

    int status;
    char buf[16384];
    struct nlmsghdr *nlm;
    struct ifaddrmsg *rtmp;
    unsigned char family;

    struct rtattr * table[__IFA_MAX+1];
    int fd;
    char if_name[IFNAMSIZ] = {'\0'};

    if(ifname == NULL || ip == NULL) {
        wifi_util_error_print(WIFI_MON, "%s: Null arguments %p %p\n",__func__, ifname, ip);
        return -1;
    }

    fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0 ) {
        wifi_util_error_print(WIFI_MON, "Socket error\n");
        return -1;
    }

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_REQUEST;
    req.n.nlmsg_type = RTM_GETADDR;
    if(af_family) {
        req.r.ifa_family = AF_INET;
        family = AF_INET;
    } else {
        req.r.ifa_family = AF_INET6;
        family = AF_INET6;
    }
    status = send(fd, &req, req.n.nlmsg_len, 0);
    if(status<0) {
        wifi_util_error_print(WIFI_MON, "Send error\n");
        close(fd);
        return -1;
    }

    status = recv(fd, buf, sizeof(buf), 0);
    if(status<0) {
        wifi_util_error_print(WIFI_MON, "receive error\n");
        close(fd);
        return -1;
    }

    for(nlm = (struct nlmsghdr *)buf; status > (int)sizeof(*nlm);){
        int len = nlm->nlmsg_len;
        int req_len = len - sizeof(*nlm);

        if (req_len<0 || len>status || !NLMSG_OK(nlm, status)) {
            wifi_util_error_print(WIFI_MON, "length error\n");
            close(fd);
            return -1;
        }
        rtmp = (struct ifaddrmsg *)NLMSG_DATA(nlm);
        rtattr_parse(table, IFA_MAX, IFA_RTA(rtmp), nlm->nlmsg_len - NLMSG_LENGTH(sizeof(*rtmp)));
        if(rtmp->ifa_index) {
            if_indextoname(rtmp->ifa_index, if_name);
            if(!strcasecmp(ifname, if_name) && table[IFA_ADDRESS]) {
                inet_ntop(family, RTA_DATA(table[IFA_ADDRESS]), ip, 64);
                close(fd);
                return 0;
            }
        }
        status -= NLMSG_ALIGN(len);
        nlm = (struct nlmsghdr*)((char*)nlm + NLMSG_ALIGN(len));
    }
    close(fd);
    return -1;
}

int csi_getInterfaceAddress(unsigned char *tmpmac, char *ip, char *interface, bool *af_family)
{
    int ret;
    unsigned char mac[18];

    if(tmpmac == NULL || ip == NULL || interface == NULL || af_family == NULL) {
        wifi_util_error_print(WIFI_MON, "%s: Null arguments %p %p %p %p\n",__func__, tmpmac, ip, interface, af_family);
        return -1;
    }
    macbytes_to_string((unsigned char*)tmpmac, mac);
    ret = csi_getClientIpAddress(mac, ip, interface, 1);
    if(ret < 0 ) {
        wifi_util_error_print(WIFI_MON, "Not able to find v4 address\n");
    }
    else {
        *af_family = TRUE;
        return 0;
    }
    ret = csi_getClientIpAddress(mac, ip, interface, 0);
    if(ret < 0) {
        *af_family = FALSE;
        wifi_util_error_print(WIFI_MON, "Not able to find v4 or v6 addresses\n");
        return -1;
    }
    return 0;
}

int csi_getClientIpAddress(char *mac, char *ip, char *interface, int check)
{
    struct {
        struct nlmsghdr n;
        struct ndmsg r;
    } req;

    int status;
    char buf[16384];
    struct nlmsghdr *nlm;
    struct ndmsg *rtmp;
    struct rtattr * table[NDA_MAX+1];
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    char if_name[IFNAMSIZ] = {'\0'};
    unsigned char tmp_mac[17];
    unsigned char af_family;

    if(mac == NULL || ip == NULL || interface == NULL) {
        wifi_util_error_print(WIFI_MON, "%s: Null arguments %p %p %p\n",__func__, mac, ip, interface);
        return -1;
    }
    if (fd < 0 ) {
        wifi_util_error_print(WIFI_MON, "Socket error\n");
        return -1;
    }
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_REQUEST;
    req.n.nlmsg_type = RTM_GETNEIGH;
    if(check)  {
        req.r.ndm_family = AF_INET;
        af_family =  AF_INET;
    } else {
        req.r.ndm_family = AF_INET6;
        af_family = AF_INET6;
    }

    status = send(fd, &req, req.n.nlmsg_len, 0);
    if (status < 0) {
        wifi_util_error_print(WIFI_MON, "Socket send error\n");
        close(fd);
        return -1;
    }

    status = recv(fd, buf, sizeof(buf), 0);
    if (status < 0) {
        wifi_util_error_print(WIFI_MON, "Socket receive error\n");
        close(fd);
        return -1;
    }

    for(nlm = (struct nlmsghdr *)buf; status > (int)sizeof(*nlm);){
        int len = nlm->nlmsg_len;
        int req_len = len - sizeof(*nlm);

        if (req_len<0 || len>status || !NLMSG_OK(nlm, status)) {
            wifi_util_error_print(WIFI_MON, "packet length error\n");
            close(fd);
            return -1;
        }

        rtmp = (struct ndmsg *)NLMSG_DATA(nlm);
        rtattr_parse(table, NDA_MAX, NDA_RTA(rtmp), nlm->nlmsg_len - NLMSG_LENGTH(sizeof(*rtmp)));

        if(rtmp->ndm_state & NUD_REACHABLE || rtmp->ndm_state & NUD_STALE) {
            if(table[NDA_LLADDR]) {
                unsigned char *addr =  RTA_DATA(table[NDA_LLADDR]);
                macbytes_to_string(addr,tmp_mac);
                if(!strcasecmp((char *)tmp_mac, mac)) {
                    if(table[NDA_DST] && rtmp->ndm_ifindex) {
                        inet_ntop(af_family, RTA_DATA(table[NDA_DST]), ip, 64);
                        if_indextoname(rtmp->ndm_ifindex, if_name);
                        strncpy(interface, if_name, IFNAMSIZ);
                        close(fd);
                        return 0;
                    }
                }
            }
        }
        status -= NLMSG_ALIGN(len);
        nlm = (struct nlmsghdr*)((char*)nlm + NLMSG_ALIGN(len));
    }
    close(fd);
    return -1;
}

unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    if(ptr == NULL) {
        wifi_util_error_print(WIFI_MON, "%s: Null arguments %p\n",__func__, ptr);
        return 0;
    }

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int frame_icmpv4_ping(char *buffer, char *dest_ip, char *source_ip)
{
    char *data;
    int buffer_size;
    //ip header
    struct iphdr *ip = (struct iphdr *) buffer;
    static int pingCount = 1;
    //ICMP header
    struct icmphdr *icmp = (struct icmphdr *) (buffer + sizeof (struct iphdr));
    if(buffer == NULL || dest_ip == NULL || source_ip == NULL) {
        wifi_util_error_print(WIFI_MON, "%s: Null arguments %p %p %p\n",__func__, buffer, dest_ip, source_ip);
        return 0;
    }
    data = buffer + sizeof(struct iphdr) + sizeof(struct icmphdr);
    strcpy(data , "stats ping");
    buffer_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + strlen(data);

    //ICMP_HEADER
    //
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = (unsigned short) getpid();
    icmp->un.echo.sequence = pingCount++;
    icmp->checksum = csum ((unsigned short *) (icmp), sizeof (struct icmphdr) + strlen(data));

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons (sizeof (struct iphdr) + sizeof (struct icmphdr) + strlen(data));
    ip->ttl = 8;
    ip->frag_off = 0;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr (source_ip);
    ip->daddr = inet_addr (dest_ip);
    ip->check = 0;
    ip->id = htonl (54321);
    ip->check = csum ((unsigned short *) (ip), sizeof(struct iphdr));

    return buffer_size;
}

int frame_icmpv6_ping(char *buffer, char *dest_ip, char *source_ip)
{
    char *data;
    int buffer_size;
    struct ip6_hdr* ip  = (struct ip6_hdr*) buffer;
    struct icmp6_hdr* icmp = (struct icmp6_hdr*)(buffer + sizeof(struct ip6_hdr));

    //v6 pseudo header for icmp6 checksum 
    struct ip6_pseu
    {
        struct in6_addr ip6e_src;
        struct in6_addr ip6e_dst;
        uint16_t ip6e_len;
        uint8_t  pad;
        uint8_t  ip6e_nxt;
    };
    char sample[1024] = {0};
    struct ip6_pseu* pseu = (struct ip6_pseu*)sample;

    data = (char *)(buffer + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr));
    strcpy(data, "stats ping");
    buffer_size = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + strlen(data);
    icmp->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp->icmp6_code = 0;

    pseu->pad = 0x00;
    pseu->ip6e_nxt = IPPROTO_ICMPV6;

    ip->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
    ip->ip6_plen = htons(sizeof(struct icmp6_hdr)+strlen(data));
    ip->ip6_nxt = IPPROTO_ICMPV6;
    ip->ip6_hlim = 255;

    pseu->ip6e_len = htons(sizeof(struct icmp6_hdr)+strlen(data));

    inet_pton(AF_INET6, source_ip, &(ip->ip6_src));
    inet_pton(AF_INET6, dest_ip, &(ip->ip6_dst));
    pseu->ip6e_src = ip->ip6_src;
    pseu->ip6e_dst = ip->ip6_dst;

    memcpy(sample+sizeof(struct ip6_pseu), icmp, sizeof(struct icmp6_hdr)+strlen(data));
    icmp->icmp6_cksum = 0;
    icmp->icmp6_cksum = csum ((unsigned short* )sample, sizeof(struct ip6_pseu)+sizeof(struct icmp6_hdr)+strlen(data));

    return buffer_size;
}

static bool isValidIpAddress(char *ipAddress, bool af_family)
{
    struct sockaddr_in sa;
    unsigned char family;
    if(ipAddress==NULL)    {
        return FALSE;
    }
    if(af_family)    {
        family = AF_INET;
    }    else    {
        family = AF_INET6;
    }
    int result = inet_pton(family, ipAddress, &(sa.sin_addr));
    return (result == 1);
}

static void send_ping_data(int ap_idx, unsigned char *mac, char *client_ip, char *vap_ip, long *client_ip_age, bool refresh)
{
    char        cli_interface_str[16];
    char        buffer[1024] = {0};
    int         frame_len;
    int rc = 0;
    bool af_family = TRUE;
    char        src_ip_str[IP_STR_LEN];
    char        cli_ip_str[IP_STR_LEN];

    if(mac == NULL ) {
        wifi_util_error_print(WIFI_MON, "%s: Mac is NULL\n",__func__);
        return;
    }

    memset (buffer, 0, sizeof(buffer));
    frame_len = 0;
    if(ap_idx < 0 || mac == NULL) {
        return;
    }
    wifi_util_info_print(WIFI_MON, "%s: Got the csi client for index  %02x..%02x\n",__func__,mac[0], mac[5]);
    if(refresh) {
        //Find the interface through which this client was seen
        rc = csi_getInterfaceAddress(mac, cli_ip_str, cli_interface_str, &af_family); //pass mac_addr_t
        if(rc<0)
        {
            wifi_util_error_print(WIFI_MON, "%s Failed to get ipv4 client address\n",__func__);
            return;
        } else {
            if(isValidIpAddress(cli_ip_str, af_family)) {
                *client_ip_age = 0;
                strncpy(client_ip, cli_ip_str, IP_STR_LEN);
                wifi_util_info_print(WIFI_MON, "%s Returned ipv4 client address is %s interface %s \n",__func__,  cli_ip_str, cli_interface_str );
            } else {
                wifi_util_error_print(WIFI_MON, "%s Was not a valid client ip string\n", __func__);
                return;
            }
        }
        //Get the ip address of the interface
        if(*vap_ip == '\0') {
            rc = getlocalIPAddress(cli_interface_str, src_ip_str, af_family);
            if(rc<0) {
                wifi_util_error_print(WIFI_MON, "%s Failed to get ipv4 address\n",__func__);
                return;
            } else {
                if(isValidIpAddress(src_ip_str, af_family)) {
                    strncpy(vap_ip, src_ip_str, IP_STR_LEN);
                    wifi_util_info_print(WIFI_MON, "%s Returned interface ip addr is %s\n", __func__,src_ip_str);
                } else {
                    wifi_util_error_print(WIFI_MON, "%s Was not a valid client ip string\n", __func__);
                    return;
                }
            }
        }
    } else {
        strncpy(src_ip_str, vap_ip, IP_STR_LEN);
        strncpy(cli_ip_str, client_ip, IP_STR_LEN);
    }
    //build a layer 3 packet , tcp ping
    if(af_family) {
        frame_len = frame_icmpv4_ping(buffer, (char *)&cli_ip_str, (char *)&src_ip_str);
        //send buffer
        if(frame_len) {
#if (defined (_XB7_PRODUCT_REQ_) && !defined (_COSA_BCM_ARM_))
            wifi_sendDataFrame(ap_idx,
                    (unsigned char*)mac,
                    (unsigned char*)buffer,
                    frame_len,
                    TRUE,
                    WIFI_ETH_TYPE_IP,
                    wifi_data_priority_be);
#else
            wifi_hal_sendDataFrame(ap_idx,
                    (unsigned char*)mac,
                    (unsigned char*)buffer,
                    frame_len,
                    TRUE,
                    WIFI_ETH_TYPE_IP,
                    wifi_data_priority_be);
#endif
        }
    } else {
        frame_len = frame_icmpv6_ping(buffer, (char *)&cli_ip_str, (char *)&src_ip_str);
        //send buffer
        if(frame_len) {
#if (defined (_XB7_PRODUCT_REQ_) && !defined (_COSA_BCM_ARM_))
            wifi_sendDataFrame(ap_idx,
                    (unsigned char*)mac,
                    (unsigned char*)buffer,
                    frame_len,
                    TRUE,
                    WIFI_ETH_TYPE_IP6,
                    wifi_data_priority_be);
#else
            wifi_hal_sendDataFrame(ap_idx,
                    (unsigned char*)mac,
                    (unsigned char*)buffer,
                    frame_len,
                    TRUE,
                    WIFI_ETH_TYPE_IP,
                    wifi_data_priority_be);
#endif
        }
    }
}

static int update_pinger_map(int ap_index, mac_addr_t mac_addr, bool remove)
{
    csi_pinger_data_t *pinger_data = NULL;
    mac_addr_str_t mac_str = { 0 };

    if (g_events_monitor.csi_pinger_map == NULL) {
        wifi_util_error_print(WIFI_MON, "%s %d: NULL pinger map\n", __func__, __LINE__);
        return -1;
    }

    to_mac_str((unsigned char *)mac_addr, mac_str);
    if (remove) {
        pinger_data = (csi_pinger_data_t *)hash_map_get(g_events_monitor.csi_pinger_map, mac_str);
        if (pinger_data != NULL) {
            wifi_util_info_print(WIFI_MON, "%s %d: Disabling Pinger for mac %s\n", __func__, __LINE__, mac_str);
            pinger_data = hash_map_remove(g_events_monitor.csi_pinger_map, mac_str);
            if (pinger_data != NULL) {
                free(pinger_data);
                return 0;
            }
        }
    } else {
        pinger_data = (csi_pinger_data_t *)malloc(sizeof(csi_pinger_data_t));
        memset(pinger_data, 0, sizeof(csi_pinger_data_t));
        pinger_data->ap_index = ap_index;
        memcpy(pinger_data->mac_addr, mac_addr, sizeof(mac_addr_t));
        wifi_util_info_print(WIFI_MON, "%s %d: Enabling Pinger for mac %s\n", __func__, __LINE__, mac_str);
        hash_map_put(g_events_monitor.csi_pinger_map, strdup(mac_str), pinger_data);
    }

    return 0;
}

static int csi_update_pinger(int ap_index, mac_addr_t mac_addr, bool pause_pinger)
{
    unsigned int csi_time_interval = CSI_PING_INTERVAL;

    if (update_pinger_map(ap_index, mac_addr, pause_pinger) < 0) {
        wifi_util_error_print(WIFI_MON, "%s %d: Unable to start Pinger\n", __func__, __LINE__);
        return -1;
    }
    if (hash_map_count(g_events_monitor.csi_pinger_map) == 0) {
        scheduler_cancel_timer_task(g_monitor_module.sched, g_monitor_module.csi_sched_id);
        g_monitor_module.csi_sched_id = 0;
        return 0;
    } else if (g_monitor_module.csi_sched_id == 0) {
        wifi_util_info_print(WIFI_MON, "%s %d: Scheduling Pinger\n", __func__, __LINE__);
        scheduler_add_timer_task(g_monitor_module.sched, TRUE,
                &(g_monitor_module.csi_sched_id), csi_sendPingData,
                NULL, csi_time_interval, 0, FALSE);
    }
    return 0;
}

int csi_sendPingData(void *arg)
{
    bool refresh = FALSE;
    void* pCsiClientIpAge   = NULL;

    csi_pinger_data_t *pinger_data = NULL;
    if (g_events_monitor.csi_pinger_map == NULL) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d Null pinger map\n", __func__, __LINE__);
        return TIMER_TASK_COMPLETE;
    }
    pinger_data  = (csi_pinger_data_t *)hash_map_get_first(g_events_monitor.csi_pinger_map);
    while(pinger_data != NULL) {
        wifi_util_dbg_print(WIFI_MON, "%s: Adding Mac for csi collection %02x..%02x ap_idx %d\n",__func__, pinger_data->mac_addr[0], pinger_data->mac_addr[5], pinger_data->ap_index);
        if((pinger_data->client_ip[0] != '\0') && ((pinger_data->client_ip_age*CSI_PING_INTERVAL)  <= IPREFRESH_PERIOD_IN_MILLISECONDS) && (pinger_data->vap_ip[0] != '\0')) {
            refresh  = FALSE;
        } else {
            refresh = TRUE;
        }
        pCsiClientIpAge = &pinger_data->client_ip_age;
        send_ping_data(pinger_data->ap_index, (unsigned char *)pinger_data->mac_addr,
                pinger_data->client_ip, pinger_data->vap_ip, pCsiClientIpAge, refresh);
        pinger_data->client_ip_age++;
        pinger_data  = (csi_pinger_data_t *)hash_map_get_next(g_events_monitor.csi_pinger_map, pinger_data);
    }
    return TIMER_TASK_COMPLETE;
}

static int clientdiag_sheduler_enable(int ap_index)
{
    unsigned int clientdiag_interval;
    unsigned int vap_array_index;

    getVAPArrayIndexFromVAPIndex((unsigned int)ap_index, &vap_array_index);

    pthread_mutex_lock(&g_events_monitor.lock);
    clientdiag_interval = g_events_monitor.diag_session[vap_array_index].interval;
    pthread_mutex_unlock(&g_events_monitor.lock);

    if (clientdiag_interval != 0) {
        if (g_monitor_module.clientdiag_id[vap_array_index] == 0) {
            scheduler_add_timer_task(g_monitor_module.sched, FALSE,
                    &(g_monitor_module.clientdiag_id[vap_array_index]), associated_device_diagnostics_send_event,
                    (void *)&(g_monitor_module.clientdiag_sched_arg[vap_array_index]), clientdiag_interval, 0, FALSE);
        } else {
            if (g_monitor_module.clientdiag_sched_interval[vap_array_index] != clientdiag_interval) {
                g_monitor_module.clientdiag_sched_interval[vap_array_index] = clientdiag_interval;
                scheduler_update_timer_task_interval(g_monitor_module.sched,
                        g_monitor_module.clientdiag_id[vap_array_index], clientdiag_interval);
            }
        }
    } else {
        if (g_monitor_module.clientdiag_id[vap_array_index] != 0) {
            scheduler_cancel_timer_task(g_monitor_module.sched,
                    g_monitor_module.clientdiag_id[vap_array_index]);
            g_monitor_module.clientdiag_id[vap_array_index] = 0;
        }
    }
    return 0;
}

int diagdata_set_interval(int interval, unsigned int ap_idx)
{
    wifi_monitor_data_t data;
    unsigned int vap_array_index;
    int ret = RETURN_ERR;

    if(ap_idx >= MAX_VAP) {
        wifi_util_error_print(WIFI_MON, "%s: ap_idx %d not valid\n",__func__, ap_idx);
    }

    getVAPArrayIndexFromVAPIndex(ap_idx, &vap_array_index);

    pthread_mutex_lock(&g_events_monitor.lock);
    g_events_monitor.diag_session[vap_array_index].interval = interval;
    wifi_util_dbg_print(WIFI_MON, "%s: ap_idx %d configuring inteval %d\n", __func__, ap_idx, interval);
    pthread_mutex_unlock(&g_events_monitor.lock);

    memset(&data, 0, sizeof(wifi_monitor_data_t));
    data.id = msg_id++;
    data.ap_index = ap_idx;

    ret = push_event_to_monitor_queue(&data, wifi_event_monitor_clientdiag_update_config, NULL);
    if (ret == RETURN_ERR) {
        wifi_util_error_print(WIFI_MON, "%s:%d Error in sending request to monitor queue\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int associated_device_diagnostics_send_event(void* arg)
{
    int *ap_index;
    wifi_event_t *event = NULL;
    if (arg == NULL) {
        wifi_util_error_print(WIFI_MON, "%s(): Error arg NULL\n",__func__);
        return TIMER_TASK_ERROR;
    }

    event = create_wifi_event(sizeof(wifi_monitor_data_t), wifi_event_type_monitor, wifi_event_monitor_diagnostics);
    if (event == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: memory allocation for event failed.\n", __func__, __LINE__);
        return TIMER_TASK_ERROR;
    }

    ap_index = (int *) arg;
    event->u.mon_data->ap_index = *ap_index;

    events_rbus_publish(event);

    destroy_wifi_event(event);

    return TIMER_TASK_COMPLETE;
}

int get_chan_util_upload_period()
{
    int logInterval = DEFAULT_CHANUTIL_LOG_INTERVAL;//Default Value 15mins.

    wifi_global_param_t *global_param = get_wifidb_wifi_global_param();

    if (global_param == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d Global Param is Null, updating the default value \n",__FUNCTION__,__LINE__);
        return logInterval;
    }

    if ((global_param->whix_chutility_loginterval < Min_Chan_Util_LogInterval) || (global_param->whix_chutility_loginterval > Max_LogInterval)) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d Global channel utility loginterval is not in limit, updating the default value\n",__FUNCTION__,__LINE__);
        return logInterval;
    }

    logInterval = global_param->whix_chutility_loginterval;
    wifi_util_dbg_print(WIFI_MON, "Exiting %s:%d loginterval = %d \n",__FUNCTION__,__LINE__,logInterval);
    return logInterval;
}

static int readLogInterval()
{
    int logInterval = Max_LogInterval;//Default Value 60mins.
    wifi_global_param_t *global_param = get_wifidb_wifi_global_param();

    if (global_param == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d Global Param is Null \n",__FUNCTION__,__LINE__);
        return logInterval;
    }

    if ((global_param->whix_log_interval < Min_LogInterval) || (global_param->whix_log_interval > Max_LogInterval)) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d Global loginterval is not in limit, updating the default value\n",__FUNCTION__,__LINE__);
        return logInterval;
    }

    logInterval = global_param->whix_log_interval;
    wifi_util_dbg_print(WIFI_MON, "Exiting %s:%d loginterval = %d \n",__FUNCTION__,__LINE__,logInterval);
    return logInterval;
}

#endif // CCSP_COMMON


int get_radio_data(int radio_index, wifi_radioTrafficStats2_t *radio_traffic_stats)
{
    pthread_mutex_lock(&g_monitor_module.data_lock);
    if (g_monitor_module.radio_data[radio_index].NoiseFloor != 0) {
        radio_traffic_stats->radio_NoiseFloor = g_monitor_module.radio_data[radio_index].NoiseFloor;
    } else {
        radio_traffic_stats->radio_NoiseFloor = -90;
    }
    radio_traffic_stats->radio_ActivityFactor = g_monitor_module.radio_data[radio_index].RadioActivityFactor;
    radio_traffic_stats->radio_CarrierSenseThreshold_Exceeded = g_monitor_module.radio_data[radio_index].CarrierSenseThreshold_Exceeded;
    radio_traffic_stats->radio_ChannelUtilization = g_monitor_module.radio_data[radio_index].channelUtil;
    radio_traffic_stats->radio_BytesSent = g_monitor_module.radio_data[radio_index].radio_BytesSent;
    radio_traffic_stats->radio_BytesReceived = g_monitor_module.radio_data[radio_index].radio_BytesReceived;
    radio_traffic_stats->radio_PacketsSent = g_monitor_module.radio_data[radio_index].radio_PacketsSent;
    radio_traffic_stats->radio_PacketsReceived = g_monitor_module.radio_data[radio_index].radio_PacketsReceived;
    radio_traffic_stats->radio_ErrorsSent = g_monitor_module.radio_data[radio_index].radio_ErrorsSent;
    radio_traffic_stats->radio_ErrorsReceived = g_monitor_module.radio_data[radio_index].radio_ErrorsReceived;
    radio_traffic_stats->radio_DiscardPacketsSent = g_monitor_module.radio_data[radio_index].radio_DiscardPacketsSent;
    radio_traffic_stats->radio_DiscardPacketsReceived = g_monitor_module.radio_data[radio_index].radio_DiscardPacketsReceived;
    radio_traffic_stats->radio_RetransmissionMetirc = g_monitor_module.radio_data[radio_index].radio_RetransmissionMetirc;
    radio_traffic_stats->radio_PLCPErrorCount = g_monitor_module.radio_data[radio_index].radio_PLCPErrorCount;
    radio_traffic_stats->radio_FCSErrorCount = g_monitor_module.radio_data[radio_index].radio_FCSErrorCount;
    radio_traffic_stats->radio_MaximumNoiseFloorOnChannel = g_monitor_module.radio_data[radio_index].radio_MaximumNoiseFloorOnChannel;
    radio_traffic_stats->radio_MinimumNoiseFloorOnChannel = g_monitor_module.radio_data[radio_index].radio_MinimumNoiseFloorOnChannel;
    radio_traffic_stats->radio_MedianNoiseFloorOnChannel = g_monitor_module.radio_data[radio_index].radio_MedianNoiseFloorOnChannel;
    radio_traffic_stats->radio_StatisticsStartTime = g_monitor_module.radio_data[radio_index].radio_StatisticsStartTime;
    pthread_mutex_unlock(&g_monitor_module.data_lock);

    return 0;
}

int radio_diagnostics(void *arg)
{
    wifi_radioTrafficStats2_t radioTrafficStats;
    //char            ChannelsInUse[256] = {0};
    char            RadioFreqBand[64] = {0};
#ifdef CCSP_COMMON
    char            RadioChanBand[64] = {0};
#endif // CCSP_COMMON
    static unsigned int radiocnt = 0;
    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radiocnt);
    wifi_freq_bands_t band_enum;

    if (g_monitor_module.is_blaster_running == true) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d Active Measurement is running, skipping radio diagnostics...\n",__func__,__LINE__);
        return TIMER_TASK_COMPLETE;
    }

    wifi_util_dbg_print(WIFI_MON, "%s : %d getting radio Traffic stats for Radio %d\n",__func__,__LINE__, radiocnt);
    memset(&radioTrafficStats, 0, sizeof(wifi_radioTrafficStats2_t));
    memset(&g_monitor_module.radio_data[radiocnt], 0, sizeof(radio_data_t));

    if (radioOperation != NULL) {
        if(radioOperation->enable) {

#ifdef CCSP_COMMON
            if (wifi_getRadioTrafficStats2(radiocnt, &radioTrafficStats) == RETURN_OK) {
                /* update the g_active_msmt with the radio data */
                g_monitor_module.radio_data[radiocnt].NoiseFloor = radioTrafficStats.radio_NoiseFloor;
                g_monitor_module.radio_data[radiocnt].RadioActivityFactor = radioTrafficStats.radio_ActivityFactor;
                g_monitor_module.radio_data[radiocnt].CarrierSenseThreshold_Exceeded = radioTrafficStats.radio_CarrierSenseThreshold_Exceeded;
                g_monitor_module.radio_data[radiocnt].channelUtil = radioTrafficStats.radio_ChannelUtilization;
                g_monitor_module.radio_data[radiocnt].radio_BytesSent = radioTrafficStats.radio_BytesSent;
                g_monitor_module.radio_data[radiocnt].radio_BytesReceived = radioTrafficStats.radio_BytesReceived;
                g_monitor_module.radio_data[radiocnt].radio_PacketsSent = radioTrafficStats.radio_PacketsSent;
                g_monitor_module.radio_data[radiocnt].radio_PacketsReceived = radioTrafficStats.radio_PacketsReceived;
                g_monitor_module.radio_data[radiocnt].radio_ErrorsSent = radioTrafficStats.radio_ErrorsSent;
                g_monitor_module.radio_data[radiocnt].radio_ErrorsReceived = radioTrafficStats.radio_ErrorsReceived;
                g_monitor_module.radio_data[radiocnt].radio_DiscardPacketsSent = radioTrafficStats.radio_DiscardPacketsSent;
                g_monitor_module.radio_data[radiocnt].radio_DiscardPacketsReceived = radioTrafficStats.radio_DiscardPacketsReceived;
                g_monitor_module.radio_data[radiocnt].radio_InvalidMACCount = radioTrafficStats.radio_InvalidMACCount;
                g_monitor_module.radio_data[radiocnt].radio_PacketsOtherReceived = radioTrafficStats.radio_PacketsOtherReceived;
                g_monitor_module.radio_data[radiocnt].radio_RetransmissionMetirc = radioTrafficStats.radio_RetransmissionMetirc;
                g_monitor_module.radio_data[radiocnt].radio_PLCPErrorCount = radioTrafficStats.radio_PLCPErrorCount;
                g_monitor_module.radio_data[radiocnt].radio_FCSErrorCount = radioTrafficStats.radio_FCSErrorCount;
                g_monitor_module.radio_data[radiocnt].radio_MaximumNoiseFloorOnChannel = radioTrafficStats.radio_MaximumNoiseFloorOnChannel;
                g_monitor_module.radio_data[radiocnt].radio_MinimumNoiseFloorOnChannel = radioTrafficStats.radio_MinimumNoiseFloorOnChannel;
                g_monitor_module.radio_data[radiocnt].radio_MedianNoiseFloorOnChannel = radioTrafficStats.radio_MedianNoiseFloorOnChannel;
                g_monitor_module.radio_data[radiocnt].radio_StatisticsStartTime = radioTrafficStats.radio_StatisticsStartTime;
#if 0
                /* When we trigger below API then Broadcom driver internally trigger offchannel scan.
                *  We don't want this offchannel scan at every 30 seconds. So, for resolution of
                *  this issue we commented out below API.
                */
                wifi_getRadioChannelsInUse (radiocnt, ChannelsInUse);
                strncpy((char *)&g_monitor_module.radio_data[radiocnt].ChannelsInUse, ChannelsInUse,sizeof(ChannelsInUse));
#endif
                g_monitor_module.radio_data[radiocnt].primary_radio_channel = radioOperation->channel;

                band_enum = radioOperation->band;
                if (freq_band_conversion(&band_enum, (char *)RadioFreqBand, sizeof(RadioFreqBand), ENUM_TO_STRING) != RETURN_OK)
                {
                    wifi_util_error_print(WIFI_MON,"%s:%d: frequency band conversion failed\n", __func__, __LINE__);
                } else {
                    strncpy((char *)&g_monitor_module.radio_data[radiocnt].frequency_band, RadioFreqBand, sizeof(RadioFreqBand));
                    g_monitor_module.radio_data[radiocnt].frequency_band[sizeof(g_monitor_module.radio_data[radiocnt].frequency_band)-1] = '\0';
                    wifi_util_dbg_print(WIFI_MON, "%s:%d: Frequency band is  %s\n", __func__, __LINE__, RadioFreqBand);
                }

                wifi_getRadioOperatingChannelBandwidth(radiocnt,RadioChanBand);
                strncpy((char *)&g_monitor_module.radio_data[radiocnt].channel_bandwidth, RadioChanBand,sizeof(RadioChanBand));
                wifi_util_dbg_print(WIFI_MON, "%s:%d: channelbandwidth is  %s\n", __func__, __LINE__, RadioChanBand);
            } else {
                wifi_util_error_print(WIFI_MON, "%s : %d wifi_getRadioTrafficStats2 failed for rdx : %d\n",__func__,__LINE__,radiocnt);
            }
#endif // CCSP_COMMON
        } else {
            wifi_util_dbg_print(WIFI_MON, "%s : %d Radio : %d is not enabled\n",__func__,__LINE__,radiocnt);
        }
    } else {
        wifi_util_error_print(WIFI_MON, "%s : %d Failed to get getRadioOperationParam for rdx : %d\n",__func__,__LINE__,radiocnt);
    }
    radiocnt++;
    if (radiocnt >= getNumberRadios()) {
        radiocnt = 0;
        return TIMER_TASK_COMPLETE;
    }
    return TIMER_TASK_CONTINUE;
}

#ifdef CCSP_COMMON
bool active_sta_connection_status(int ap_index, char *mac)
{
    sta_data_t  *sta;
    hash_map_t  *sta_map;
    unsigned int vap_array_index;

    if (mac == NULL) {
        wifi_util_dbg_print(WIFI_MON,"%s:%d input mac adrress is NULL for ap_index:%d\n", __func__, __LINE__, ap_index);
        return false;
    }

    getVAPArrayIndexFromVAPIndex(ap_index, &vap_array_index);

    sta_map = g_monitor_module.bssid_data[vap_array_index].sta_map;
    if (sta_map == NULL) {
        wifi_util_dbg_print(WIFI_MON,"%s:%d: return, stamap is NULL for vap:%d\n", __func__, __LINE__, ap_index);
        return false;
    }
    str_tolower(mac);
    sta = (sta_data_t *)hash_map_get(sta_map, mac);

    if (sta == NULL) {
        wifi_util_dbg_print(WIFI_MON,"%s:%d: return, sta:%s is not part of hashmap on vap:%d\n", __func__, __LINE__, mac, ap_index);
        return false;
    } else if(sta->connection_authorized != true) {
        wifi_util_dbg_print(WIFI_MON,"%s:%d: return, sta:%s is not ACTIVE on vap:%d\n", __func__, __LINE__, mac, ap_index);
        return false;
    }
    return true;
}

int device_disassociated(int ap_index, char *mac, int reason)
{
    wifi_monitor_data_t data;
    assoc_dev_data_t assoc_data;
    greylist_data_t greylist_data;
    unsigned int mac_addr[MAC_ADDR_LEN];
    mac_address_t grey_list_mac;
    bool is_sta_active;

    if (mac == NULL) {
        wifi_util_dbg_print(WIFI_MON,"%s:%d input mac adrress is NULL for ap_index:%d reason:%d\n", __func__, __LINE__, ap_index, reason);
        return -1;
    }

    if (reason == WLAN_RADIUS_GREYLIST_REJECT) {
        wifi_util_dbg_print(WIFI_MON,"Device disassociated due to Greylist\n");
        greylist_data.reason = reason;

        str_to_mac_bytes(mac, grey_list_mac);
        memcpy(greylist_data.sta_mac, &grey_list_mac, sizeof(mac_address_t));
        wifi_util_dbg_print(WIFI_MON," sending Greylist mac to  ctrl queue %s\n",mac);
        push_event_to_ctrl_queue(&greylist_data, sizeof(greylist_data), wifi_event_type_hal_ind, wifi_event_radius_greylist, NULL);

    }

    is_sta_active = active_sta_connection_status(ap_index, mac);

    memset(&data, 0, sizeof(wifi_monitor_data_t));
    data.id = msg_id++;

    data.ap_index = ap_index;
    sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            &mac_addr[0], &mac_addr[1], &mac_addr[2],
            &mac_addr[3], &mac_addr[4], &mac_addr[5]);
    data.u.dev.sta_mac[0] = mac_addr[0]; data.u.dev.sta_mac[1] = mac_addr[1]; data.u.dev.sta_mac[2] = mac_addr[2];
    data.u.dev.sta_mac[3] = mac_addr[3]; data.u.dev.sta_mac[4] = mac_addr[4]; data.u.dev.sta_mac[5] = mac_addr[5];
    data.u.dev.reason = reason;

    push_event_to_monitor_queue(&data, wifi_event_monitor_disconnect, NULL);

    if (is_sta_active == false) {
        wifi_util_dbg_print(WIFI_MON,"%s:%d: sta[%s] not connected with ap:[%d]\r\n", __func__, __LINE__, mac, ap_index);
        return 0;
    }

    memset(&assoc_data, 0, sizeof(assoc_dev_data_t));
    assoc_data.dev_stats.cli_MACAddress[0] = mac_addr[0]; assoc_data.dev_stats.cli_MACAddress[1] = mac_addr[1];
    assoc_data.dev_stats.cli_MACAddress[2] = mac_addr[2]; assoc_data.dev_stats.cli_MACAddress[3] = mac_addr[3];
    assoc_data.dev_stats.cli_MACAddress[4] = mac_addr[4]; assoc_data.dev_stats.cli_MACAddress[5] = mac_addr[5];
    assoc_data.ap_index = ap_index;
    assoc_data.reason = reason;

    wifi_util_info_print(WIFI_MON, "%s:%d:Device diaassociated on interface:%d mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
          __func__, __LINE__, ap_index,
          assoc_data.dev_stats.cli_MACAddress[0], assoc_data.dev_stats.cli_MACAddress[1], assoc_data.dev_stats.cli_MACAddress[2],
          assoc_data.dev_stats.cli_MACAddress[3], assoc_data.dev_stats.cli_MACAddress[4], assoc_data.dev_stats.cli_MACAddress[5]);
    push_event_to_ctrl_queue(&assoc_data, sizeof(assoc_data), wifi_event_type_hal_ind, wifi_event_hal_disassoc_device, NULL);

    return 0;
}

int radius_eap_failure_callback(unsigned int apIndex, int reason)
{
    radius_eap_data_t radius_eap_data;
    radius_eap_data.apIndex = apIndex;
    radius_eap_data.failure_reason = reason;

    //Push event to ctrl queue and handle it in whix app
    push_event_to_ctrl_queue(&radius_eap_data, sizeof(radius_eap_data), wifi_event_type_hal_ind, wifi_event_radius_eap_failure, NULL);
    return 0;
}

int vapstatus_callback(int apIndex, wifi_vapstatus_t status)
{
    hash_map_t *sta_map      = NULL;
    hash_map_t *temp_sta_map = NULL;
    sta_data_t *sta          = NULL;
    sta_key_t  sta_key;

    wifi_util_dbg_print(WIFI_MON,"%s called for %d and status %d \n",__func__, apIndex, status);
    g_monitor_module.bssid_data[apIndex].ap_params.ap_status = status;

    if (status != wifi_vapstatus_down) {
        return 0;
    }

    pthread_mutex_lock(&g_monitor_module.data_lock);

    sta_map = g_monitor_module.bssid_data[apIndex].sta_map;
    if (sta_map == NULL) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d sta_map is NULL for apIndex %d\n", __func__, __LINE__, apIndex);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return 0;
    }

    temp_sta_map = hash_map_clone(sta_map, sizeof(sta_data_t));
    if (temp_sta_map == NULL) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d Failed to clone hash map\n", __func__, __LINE__);
        pthread_mutex_unlock(&g_monitor_module.data_lock);
        return -1;
    }

    hash_map_cleanup(sta_map);

    pthread_mutex_unlock(&g_monitor_module.data_lock);

    if (temp_sta_map != NULL) {
        sta = hash_map_get_first(temp_sta_map);
        while (sta != NULL) {
            to_sta_key(sta->sta_mac, sta_key);
            send_wifi_disconnect_event_to_ctrl(sta->sta_mac, apIndex);
            wifi_util_info_print(WIFI_MON, "%s:%d ClientMac:%s disconnected from ap:%d\n", __func__, __LINE__, sta_key, apIndex);
            sta = hash_map_get_next(temp_sta_map, sta);
        }
        hash_map_destroy(temp_sta_map);
    }

    return 0;
}

int device_deauthenticated(int ap_index, char *mac, int reason)
{
    wifi_monitor_data_t data;
    unsigned int mac_addr[MAC_ADDR_LEN];
    greylist_data_t greylist_data;
    assoc_dev_data_t assoc_data;
    mac_address_t grey_list_mac;
    bool is_sta_active;

    if (mac == NULL) {
        wifi_util_dbg_print(WIFI_MON,"%s:%d input mac adrress is NULL for ap_index:%d reason:%d\n", __func__, __LINE__, ap_index, reason);
        return -1;
    }

    if (reason == WLAN_RADIUS_GREYLIST_REJECT) {
        str_to_mac_bytes(mac, grey_list_mac);
        wifi_util_dbg_print(WIFI_MON,"Device disassociated due to Greylist\n");
        greylist_data.reason = reason;
        memcpy(greylist_data.sta_mac, &grey_list_mac, sizeof(mac_address_t));
        wifi_util_dbg_print(WIFI_MON,"Sending Greylist mac to ctrl queue %s\n",mac);
        push_event_to_ctrl_queue(&greylist_data, sizeof(greylist_data), wifi_event_type_hal_ind, wifi_event_radius_greylist, NULL);

    }

    is_sta_active = active_sta_connection_status(ap_index, mac);

    memset(&data, 0, sizeof(wifi_monitor_data_t));
    data.id = msg_id++;

    data.ap_index = ap_index;
    sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            &mac_addr[0], &mac_addr[1], &mac_addr[2],
            &mac_addr[3], &mac_addr[4], &mac_addr[5]);
    data.u.dev.sta_mac[0] = mac_addr[0]; data.u.dev.sta_mac[1] = mac_addr[1]; data.u.dev.sta_mac[2] = mac_addr[2];
    data.u.dev.sta_mac[3] = mac_addr[3]; data.u.dev.sta_mac[4] = mac_addr[4]; data.u.dev.sta_mac[5] = mac_addr[5];
    data.u.dev.reason = reason;

    push_event_to_monitor_queue(&data, wifi_event_monitor_deauthenticate, NULL);

    if (is_sta_active == false) {
        wifi_util_dbg_print(WIFI_MON,"%s:%d: sta[%s] not connected with ap:[%d]\r\n", __func__, __LINE__, mac, ap_index);
        return 0;
    }

    memset(&assoc_data, 0, sizeof(assoc_dev_data_t));
    assoc_data.ap_index = ap_index;
    assoc_data.dev_stats.cli_MACAddress[0] = mac_addr[0]; assoc_data.dev_stats.cli_MACAddress[1] = mac_addr[1];
    assoc_data.dev_stats.cli_MACAddress[2] = mac_addr[2]; assoc_data.dev_stats.cli_MACAddress[3] = mac_addr[3];
    assoc_data.dev_stats.cli_MACAddress[4] = mac_addr[4]; assoc_data.dev_stats.cli_MACAddress[5] = mac_addr[5];
    assoc_data.reason = reason;
    wifi_util_info_print(WIFI_MON, "%s:%d:  Device deauthenticated on interface:%d mac:%02x:%02x:%02x:%02x:%02x:%02x with reason %d\n",
          __func__, __LINE__, ap_index,
          assoc_data.dev_stats.cli_MACAddress[0], assoc_data.dev_stats.cli_MACAddress[1], assoc_data.dev_stats.cli_MACAddress[2],
          assoc_data.dev_stats.cli_MACAddress[3], assoc_data.dev_stats.cli_MACAddress[4], assoc_data.dev_stats.cli_MACAddress[5], reason);

    push_event_to_ctrl_queue(&assoc_data, sizeof(assoc_data), wifi_event_type_hal_ind, wifi_event_hal_disassoc_device, NULL);


    return 0;
}

static void
get_key_mgmt(const uint8_t *s, char *key_mgmt_buff, size_t buff_size)
{
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_UNSPEC_802_1X) {
        strncpy(key_mgmt_buff, "wpa-eap", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X) {
        strncpy(key_mgmt_buff, "wpa-psk", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_802_1X) {
        strncpy(key_mgmt_buff, "ft-eap", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_PSK) {
        strncpy(key_mgmt_buff, "ft-psk", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_802_1X_SHA384) {
        strncpy(key_mgmt_buff, "ft-eap-sha384", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_802_1X_SHA256) {
        strncpy(key_mgmt_buff, "wpa-eap-sha256", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_PSK_SHA256) {
        strncpy(key_mgmt_buff, "wpa-psk-sha256", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_SAE) {
        strncpy(key_mgmt_buff, "sae", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_SAE) {
        strncpy(key_mgmt_buff, "ft-sae", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192) {
        strncpy(key_mgmt_buff, "wpa-eap-suite-b-192", buff_size - 1);
        return;
    }

    return;
}

static void get_cipher_suite(const uint8_t *s, char *buff, size_t buff_size)
{
    if (RSN_SELECTOR_GET(s) == RSN_CIPHERSUITE_WEP) {
        strncpy(buff, "wep", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_CIPHERSUITE_TKIP) {
        strncpy(buff, "tkip", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_CIPHERSUITE_CCMP_128) {
        strncpy(buff, "ccmp-128", buff_size - 1);
        return;
    }
    if (RSN_SELECTOR_GET(s) == RSN_CIPHERSUITE_BIP_CMAC_128) {
        strncpy(buff, "bip-cmac-128", buff_size - 1);
        return;
    }

    return;
}

static void
ie_parse_rsn(const uint8_t *ie, size_t len, assoc_dev_data_t *data)
{
    const uint8_t *pos;
    unsigned int i, left, cnt;
    struct rsn_data *rd = (struct rsn_data *)ie;

    if (WPA_GET_LE16(rd->ver) != 1) {
        wifi_util_error_print(WIFI_MON, "%s:%d Unkown RSN IE version [%d]\n", __func__, __LINE__, WPA_GET_LE16(rd->ver));
        return;
    }
    left = len - sizeof(rd->ver);
    pos = rd->data;

    if (left < 12) {
        wifi_util_error_print(WIFI_MON, "%s:%d RSN IE is too short [%d] for key_mgmt and cipher suite\n", __func__, __LINE__, left);
        return;
    }

    // Skip group_cipher
    left -= RSN_SELECTOR_LEN;
    pos += RSN_SELECTOR_LEN;

    // Parse pairwise_cipher
    cnt = WPA_GET_LE16(pos);
    left -= 2;
    pos += 2;
    if (cnt == 0 || cnt > left / RSN_SELECTOR_LEN) {
        wifi_util_error_print(WIFI_MON, "%s:%d Wrong cipher suite count[%d]. left/4[%d]\n", __func__, __LINE__, cnt, left/RSN_SELECTOR_LEN);
        return;
    }

    memset(data->conn_security.pairwise_cipher, 0, sizeof(data->conn_security.pairwise_cipher));
    get_cipher_suite(pos, data->conn_security.pairwise_cipher, sizeof(data->conn_security.pairwise_cipher));
    wifi_util_dbg_print(WIFI_MON, "%s:%d cipher_suite[%s]\n", __func__, __LINE__, data->conn_security.pairwise_cipher);
    for (i = 0; i < cnt; i++)
    {
        pos += RSN_SELECTOR_LEN;
        left -= RSN_SELECTOR_LEN;
    }

    if (left < 2) {
        wifi_util_error_print(WIFI_MON, "%s:%d No key_mgmt. Left [%d]\n", __func__, __LINE__, left);
        return;
    }
    cnt = WPA_GET_LE16(pos);
    left -= 2;
    pos += 2;
    if (cnt == 0 || cnt > left / RSN_SELECTOR_LEN) {
        wifi_util_error_print(WIFI_MON, "%s:%d Wrong key_mgmt count[%d]. left/4[%d]\n", __func__, __LINE__, cnt, left/RSN_SELECTOR_LEN);
        return;
    }

    memset(data->conn_security.wpa_key_mgmt, 0, sizeof(data->conn_security.wpa_key_mgmt));
    get_key_mgmt(pos, data->conn_security.wpa_key_mgmt, sizeof(data->conn_security.wpa_key_mgmt));
    wifi_util_dbg_print(WIFI_MON, "%s:%d key_mgmt[%s]\n", __func__, __LINE__, data->conn_security.wpa_key_mgmt);
}

static void parse_assoc_ies(const uint8_t *ies, size_t ies_len, assoc_dev_data_t *data)
{
    const struct element *elem;

    if (!ies || ies_len == 0)
        return;

    for_each_element(elem, ies, ies_len) {
        switch (elem->id) {
            case WLAN_EID_RSN:
                ie_parse_rsn(elem->data, elem->datalen, data);
                break;
            default:
                break;
        }
    }
}

static void get_client_assoc_frame(int ap_index, wifi_associated_dev_t *associated_dev, frame_data_t *frame_buff)
{
    sta_data_t *sta;
    char mac_addr[MAC_STR_LEN];

    hash_map_t     *sta_map = get_sta_data_map(ap_index);
    if(sta_map != NULL) {
        snprintf(mac_addr, MAC_STR_LEN, MAC_FMT, MAC_ARG(associated_dev->cli_MACAddress));
        sta = (sta_data_t *)hash_map_get(sta_map, mac_addr);
    } else {
        wifi_util_error_print(WIFI_MON,"%s:%d sta_map not found for ap_index:%d\n", __func__, __LINE__, ap_index);
        return;
    }

    if (sta != NULL) {
        if (sta->assoc_frame_data.msg_data.frame.len != 0) {
            memcpy(frame_buff, &sta->assoc_frame_data.msg_data, sizeof(frame_data_t));
            return;
        } else {
            wifi_util_error_print(WIFI_MON,"%s:%d assoc req frame not found for vap_index:%d: sta_mac:%s time:%ld\r\n",
                    __func__, __LINE__, ap_index, mac_addr, sta->assoc_frame_data.frame_timestamp);
            return;
        }
    } else {
        wifi_util_error_print(WIFI_MON,"%s:%d sta not found for mac:%s\n", __func__, __LINE__, mac_addr);
        return;
    }
}

int device_associated(int ap_index, wifi_associated_dev_t *associated_dev)
{
    wifi_monitor_data_t data;
    assoc_dev_data_t assoc_data;
    wifi_radioTrafficStats2_t chan_stats;
    frame_data_t frame;
    int radio_index;
    char vap_name[32];

    memset(&assoc_data, 0, sizeof(assoc_data));
    memset(&data, 0, sizeof(wifi_monitor_data_t));
    memset(&frame, 0, sizeof(wifi_frame_t));

    data.id = msg_id++;

    data.ap_index = ap_index;
    //data->u.dev.reason = reason;

    data.u.dev.sta_mac[0] = associated_dev->cli_MACAddress[0]; data.u.dev.sta_mac[1] = associated_dev->cli_MACAddress[1];
    data.u.dev.sta_mac[2] = associated_dev->cli_MACAddress[2]; data.u.dev.sta_mac[3] = associated_dev->cli_MACAddress[3];
    data.u.dev.sta_mac[4] = associated_dev->cli_MACAddress[4]; data.u.dev.sta_mac[5] = associated_dev->cli_MACAddress[5];

    wifi_util_info_print(WIFI_MON, "%s:%d:Device associated on interface:%d mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
            __func__, __LINE__, ap_index,
            data.u.dev.sta_mac[0], data.u.dev.sta_mac[1], data.u.dev.sta_mac[2],
            data.u.dev.sta_mac[3], data.u.dev.sta_mac[4], data.u.dev.sta_mac[5]);


    convert_vap_index_to_name(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, ap_index, vap_name);
    radio_index = convert_vap_name_to_radio_array_index(&((wifi_mgr_t *)get_wifimgr_obj())->hal_cap.wifi_prop, vap_name);
    get_radio_data(radio_index, &chan_stats);
    get_client_assoc_frame(ap_index, associated_dev, &frame);

    memcpy(assoc_data.dev_stats.cli_MACAddress, data.u.dev.sta_mac, sizeof(mac_address_t));
    assoc_data.dev_stats.cli_SignalStrength = associated_dev->cli_SignalStrength;
    assoc_data.dev_stats.cli_RSSI = associated_dev->cli_RSSI;
    assoc_data.dev_stats.cli_AuthenticationState = associated_dev->cli_AuthenticationState;
    assoc_data.dev_stats.cli_LastDataDownlinkRate = associated_dev->cli_LastDataDownlinkRate;

    assoc_data.dev_stats.cli_LastDataUplinkRate = associated_dev->cli_LastDataUplinkRate;
    assoc_data.dev_stats.cli_SignalStrength = associated_dev->cli_SignalStrength;
    assoc_data.dev_stats.cli_Retransmissions = associated_dev->cli_Retransmissions;
    assoc_data.dev_stats.cli_Active = associated_dev->cli_Active;

    if (associated_dev->cli_SNR != 0) {
        assoc_data.dev_stats.cli_SNR = associated_dev->cli_SNR;
    } else {
        assoc_data.dev_stats.cli_SNR = associated_dev->cli_RSSI - chan_stats.radio_NoiseFloor;
    }

    assoc_data.dev_stats.cli_DataFramesSentAck = associated_dev->cli_DataFramesSentAck;
    assoc_data.dev_stats.cli_DataFramesSentNoAck = associated_dev->cli_DataFramesSentNoAck;
    assoc_data.dev_stats.cli_BytesSent = associated_dev->cli_BytesSent;
    assoc_data.dev_stats.cli_BytesReceived = associated_dev->cli_BytesReceived;
    assoc_data.dev_stats.cli_MinRSSI = associated_dev->cli_MinRSSI;
    assoc_data.dev_stats.cli_MaxRSSI = associated_dev->cli_MaxRSSI;
    assoc_data.dev_stats.cli_Disassociations = associated_dev->cli_Disassociations;
    assoc_data.dev_stats.cli_AuthenticationFailures = associated_dev->cli_AuthenticationFailures;
    snprintf(assoc_data.dev_stats.cli_OperatingStandard, sizeof(assoc_data.dev_stats.cli_OperatingStandard),"%s", associated_dev->cli_OperatingStandard);
    snprintf(assoc_data.dev_stats.cli_OperatingChannelBandwidth, sizeof(assoc_data.dev_stats.cli_OperatingChannelBandwidth),"%s", associated_dev->cli_OperatingChannelBandwidth);
    snprintf(assoc_data.dev_stats.cli_InterferenceSources, sizeof(assoc_data.dev_stats.cli_InterferenceSources),"%s", associated_dev->cli_InterferenceSources);

    if (frame.frame.len != 0) {
        parse_assoc_ies((uint8_t *)(frame.data + ASSOC_REQ_MAC_HEADER_LEN),
            (size_t)(frame.frame.len - ASSOC_REQ_MAC_HEADER_LEN), &assoc_data);
    }
    else {
        wifi_util_dbg_print(WIFI_MON, "%s:%d Cannot parse assoc ies: frame len is 0\n", __func__, __LINE__);
    }

    assoc_data.ap_index = data.ap_index;
    push_event_to_ctrl_queue(&assoc_data, sizeof(assoc_data), wifi_event_type_hal_ind, wifi_event_hal_assoc_device, NULL);

    memcpy(&data.u.dev.dev_stats, &assoc_data.dev_stats, sizeof(wifi_associated_dev3_t));
    push_event_to_monitor_queue(&data, wifi_event_monitor_connect, NULL);

    return 0;
}

static void scheduler_telemetry_tasks(void)
{
    if (!g_monitor_module.inst_msmt_id) {
        g_monitor_module.curr_chan_util_period = get_chan_util_upload_period();

        //5 minutes
        if (g_monitor_module.refresh_task_id == 0) {
            scheduler_add_timer_task(g_monitor_module.sched, FALSE, &g_monitor_module.refresh_task_id, refresh_task_period,
                    NULL, REFRESH_TASK_INTERVAL_MS, 0, FALSE);
        }
        if (g_monitor_module.radio_diagnostics_id == 0) {
            //RADIO_STATS_INTERVAL - 30 seconds
            scheduler_add_timer_task(g_monitor_module.sched, FALSE, &g_monitor_module.radio_diagnostics_id, radio_diagnostics, NULL,
                    RADIO_STATS_INTERVAL_MS, 0, FALSE);
        }
    } else {
        if (g_monitor_module.refresh_task_id != 0) {
            scheduler_cancel_timer_task(g_monitor_module.sched, g_monitor_module.refresh_task_id);
            g_monitor_module.refresh_task_id = 0;
        }

        if (g_monitor_module.radio_diagnostics_id != 0) {
            scheduler_cancel_timer_task(g_monitor_module.sched, g_monitor_module.radio_diagnostics_id);
            g_monitor_module.radio_diagnostics_id = 0;
        }
        if (g_monitor_module.client_telemetry_id != 0) {
            scheduler_cancel_timer_task(g_monitor_module.sched, g_monitor_module.client_telemetry_id);
            g_monitor_module.client_telemetry_id = 0;
        }
    }
}
#endif // CCSP_COMMON

void update_ecomode_radios()
{
    unsigned int radio;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (radio = 0; radio < getNumberRadios(); radio++)
    {
        g_monitor_module.radio_presence[radio] = mgr->hal_cap.wifi_prop.radio_presence[radio];
    }
}
#ifdef MQTTCM
static bool
wbm_mqttcm_init(void)
{
    bool ret = true;

    if(!mqttcm_conn_init())
    {
       wifi_util_error_print(WIFI_MON,"%s: Failed to initialize wbm mqttcm  module for pushing stats to broker",__func__);
       ret = false;
    }
    return ret;
}

static void
wbm_mqttcm_stop(void)
{
    wifi_util_info_print(WIFI_MON, "Closing MQTT connection.");

    if(!mqttcm_conn_finish())
    {
        wifi_util_error_print(WIFI_MON,"%s: Failed to uninitialize Mqttcm configuration from wbm",__func__);
    }
}
#endif

int init_wifi_monitor()
{
    unsigned int i = 0;
    pthread_condattr_t cond_attr;
#ifdef CCSP_COMMON
    wifi_mgr_t *mgr = get_wifimgr_obj();
    unsigned int uptimeval = 0;
    int rssi;
    UINT vap_index, radio;
#endif // CCSP_COMMON
    //Initialize MQTTCM
    wifi_util_info_print(WIFI_MON,"%s:%d Monitor init\n", __func__, __LINE__);
#ifdef MQTTCM
    if (access(MQTTCM_DISABLE_FLAG, F_OK) != 0)
    {
       mqttcm_enabled = true;
    }
    wifi_util_info_print(WIFI_MON,"wbm is running by mqttcm enabled %s",mqttcm_enabled?"true":"false");
    if (mqttcm_enabled && !wbm_mqttcm_init())
    {
       wifi_util_error_print(WIFI_MON,"Initializing wbm (Failed to start MQTT)");
       return -1;
    }
#endif
    update_ecomode_radios();
#if CCSP_COMMON
    memset(g_monitor_module.cliStatsList, 0, MAX_VAP);
    g_monitor_module.upload_period = get_upload_period(60);//Default value 60
    uptimeval=get_sys_uptime();
    chan_util_upload_period = get_chan_util_upload_period();
    wifi_util_dbg_print(WIFI_MON, "%s:%d system uptime val is %ld and upload period is %d in secs\n",
             __FUNCTION__,__LINE__,uptimeval,(g_monitor_module.upload_period*60));
    if (get_vap_dml_parameters(RSSI_THRESHOLD, &rssi) != ANSC_STATUS_SUCCESS) {
        g_monitor_module.sta_health_rssi_threshold = -65;
    } else {
        g_monitor_module.sta_health_rssi_threshold = rssi;
    }
    for (i = 0; i < getTotalNumberVAPs(); i++) {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, i);
        radio = RADIO_INDEX(mgr->hal_cap, i);
        if (g_monitor_module.radio_presence[radio] == false) {
            continue;
        }
        // update rapid reconnect time limit if changed
        wifi_front_haul_bss_t *vap_bss_info = Get_wifi_object_bss_parameter(vap_index);
        if(vap_bss_info != NULL) {
            g_monitor_module.bssid_data[i].ap_params.rapid_reconnect_threshold = vap_bss_info->rapidReconnThreshold;
            wifi_util_dbg_print(WIFI_MON, "%s:..rapidReconnThreshold:%d vapIndex:%d \n", __FUNCTION__, vap_bss_info->rapidReconnThreshold, i);
        } else {
            wifi_util_dbg_print(WIFI_MON, "%s: wrong vapIndex:%d \n", __FUNCTION__, i);
        }
    }
#endif // CCSP_COMMON

    clock_gettime(CLOCK_MONOTONIC, &g_monitor_module.last_signalled_time);
#ifdef CCSP_COMMON
    clock_gettime(CLOCK_MONOTONIC, &g_monitor_module.last_polled_time);
#endif // CCSP_COMMON
    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&g_monitor_module.cond, &cond_attr);
    pthread_condattr_destroy(&cond_attr);
    pthread_mutex_init(&g_monitor_module.queue_lock, NULL);
    pthread_mutex_init(&g_monitor_module.data_lock, NULL);

    for (i = 0; i < getTotalNumberVAPs(); i++) {
        g_monitor_module.bssid_data[i].sta_map = hash_map_create();
        if (g_monitor_module.bssid_data[i].sta_map == NULL) {
            deinit_wifi_monitor();
            wifi_util_error_print(WIFI_MON, "sta map create error\n");
            return -1;
        }
    }

    g_monitor_module.queue = queue_create();
    if (g_monitor_module.queue == NULL) {
        deinit_wifi_monitor();
        wifi_util_error_print(WIFI_MON, "monitor queue create error\n");
        return -1;
    }

    g_monitor_module.sched = scheduler_init();
    if (g_monitor_module.sched == NULL) {
        deinit_wifi_monitor();
        wifi_util_error_print(WIFI_MON, "monitor scheduler init error\n");
        return -1;
    }

    g_apps_coordinator.collector_list = hash_map_create();
    if (g_apps_coordinator.collector_list == NULL) {
        deinit_wifi_monitor();
        wifi_util_error_print(WIFI_MON, "collector list hash map create failed\n");
        return -1;
    }
#ifdef CCSP_COMMON

    g_monitor_module.client_telemetry_id = 0;
    g_monitor_module.refresh_task_id = 0;
#endif // CCSP_COMMON
    g_monitor_module.radio_diagnostics_id = 0;

#ifdef CCSP_COMMON
    g_monitor_module.csi_sched_id = 0;
    g_monitor_module.csi_sched_interval = 0;
    for (i = 0; i < getTotalNumberVAPs(); i++) {
        vap_index = VAP_INDEX(mgr->hal_cap, i);
        radio = RADIO_INDEX(mgr->hal_cap, i);
        if (g_monitor_module.radio_presence[radio] == false) {
            continue;
        }
        g_monitor_module.clientdiag_id[i] = 0;
        g_monitor_module.clientdiag_sched_arg[i] = vap_index;
        g_monitor_module.clientdiag_sched_interval[i] = 0;
    }
#endif // CCSP_COMMON

#ifdef CCSP_COMMON
    scheduler_telemetry_tasks();
#else
    //RADIO_STATS_INTERVAL - 30 seconds
    scheduler_add_timer_task(g_monitor_module.sched, FALSE, &g_monitor_module.radio_diagnostics_id, radio_diagnostics, NULL,
        RADIO_STATS_INTERVAL_MS, 0, FALSE);
#endif // CCSP_COMMON

#ifdef CCSP_COMMON
    pthread_mutex_init(&g_events_monitor.lock, NULL);
    g_events_monitor.csi_pinger_map = hash_map_create();
    if (g_events_monitor.csi_pinger_map == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d NULL pinger map\n", __func__, __LINE__);
        return -1;
    }
#endif // CCSP_COMMON

    g_monitor_module.exit_monitor = false;
    /* Initializing the lock for active measurement g_active_msmt.lock */

#if CCSP_COMMON
    wifi_hal_newApAssociatedDevice_callback_register(device_associated);
    wifi_vapstatus_callback_register(vapstatus_callback);
    wifi_hal_apDeAuthEvent_callback_register(device_deauthenticated);
    wifi_hal_apDisassociatedDevice_callback_register(device_disassociated);
    wifi_hal_radius_eap_failure_callback_register(radius_eap_failure_callback);
    scheduler_add_timer_task(g_monitor_module.sched, FALSE, NULL, refresh_assoc_frame_entry, NULL, (MAX_ASSOC_FRAME_REFRESH_PERIOD * 1000), 0, FALSE);
#endif // CCSP_COMMON

    wifi_util_dbg_print(WIFI_MON, "%s:%d Wi-Fi monitor is initialized successfully\n", __func__, __LINE__);

    return 0;
}

int start_wifi_monitor ()
{
    unsigned int i;
    UINT vap_index, radio;
#ifdef CCSP_COMMON
    //ONEWIFI To avoid the st
        //Cleanup all CSI clients configured in driver
    unsigned char def_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif // CCSP_COMMON
    wifi_mgr_t *mgr = get_wifimgr_obj();

    onewifi_pktgen_uninit();

    for (i = 0; i < getTotalNumberVAPs(); i++) {
        /*TODO CID: 110946 Out-of-bounds access - Fix in QTN code*/
        vap_index = VAP_INDEX(mgr->hal_cap, i);
        radio = RADIO_INDEX(mgr->hal_cap, i);
        if (g_monitor_module.radio_presence[radio] == false) {
            continue;
        }
        wifi_front_haul_bss_t *vap_bss_info = Get_wifi_object_bss_parameter(vap_index);
        if (vap_bss_info != NULL) {
            mac_addr_str_t mac_str;
            memcpy(g_monitor_module.bssid_data[i].bssid, vap_bss_info->bssid, sizeof(mac_address_t));
            wifi_util_dbg_print(WIFI_MON, "%s:%d vap_bss_info->bssid is %s for vap %d", __func__,__LINE__,to_mac_str(g_monitor_module.bssid_data[i].bssid, mac_str), vap_index);
        }

#ifdef CCSP_COMMON
        //ONEWIFI To avoid the segmentation Fault
        //Cleanup all CSI clients configured in driver
        wifi_enableCSIEngine(vap_index, def_mac, FALSE);
#endif // CCSP_COMMON
    }

    pthread_attr_t attr;
    pthread_attr_t *attrp = NULL;

    attrp = &attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED );
    if (pthread_create(&g_monitor_module.id, attrp, monitor_function, &g_monitor_module) != 0) {
        if(attrp != NULL)
            pthread_attr_destroy( attrp );
        deinit_wifi_monitor();
        wifi_util_error_print(WIFI_MON, "monitor thread create error\n");
        return -1;
    }

    wifi_util_dbg_print(WIFI_MON, "%s:%d Monitor thread is started successfully\n", __func__, __LINE__);

    if(attrp != NULL)
        pthread_attr_destroy( attrp );

#ifdef CCSP_COMMON
    g_monitor_module.sysevent_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "wifiMonitor", &g_monitor_module.sysevent_token);
    if (g_monitor_module.sysevent_fd < 0) {
        wifi_util_error_print(WIFI_MON, "%s:%d: Failed to open sysevent\n", __func__, __LINE__);
    } else {
        wifi_util_info_print(WIFI_MON, "%s:%d: Opened sysevent\n", __func__, __LINE__);
    }
    if (initparodusTask() == -1) {
        //wifi_util_dbg_print(WIFI_MON, "%s:%d: Failed to initialize paroduc task\n", __func__, __LINE__);

    }
#endif // CCSP_COMMON

    return 0;
}

void deinit_wifi_monitor()
{
    unsigned int i;
    sta_data_t *sta, *temp_sta;
    char key[64] = {0};
    hash_map_t *collector_list = NULL;
#ifdef MQTTCM
    if (mqttcm_enabled) {
       wbm_mqttcm_stop();
    }
#endif
#ifdef CCSP_COMMON
    csi_pinger_data_t *pinger_data = NULL, *tmp_pinger_data = NULL;
    mac_addr_str_t mac_str = { 0 };
    sysevent_close(g_monitor_module.sysevent_fd, g_monitor_module.sysevent_token);
#endif // CCSP_COMMON
    if(g_monitor_module.queue != NULL)
        queue_destroy(g_monitor_module.queue);

    scheduler_deinit(&(g_monitor_module.sched));
#ifdef CCSP_COMMON
    if(g_events_monitor.csi_pinger_map != NULL) {
        pinger_data = hash_map_get_first(g_events_monitor.csi_pinger_map);
        while (pinger_data != NULL) {
            to_mac_str((unsigned char *)pinger_data->mac_addr, mac_str);
            pinger_data = hash_map_get_next(g_events_monitor.csi_pinger_map, pinger_data);
            tmp_pinger_data = hash_map_remove(g_events_monitor.csi_pinger_map, mac_str);
            if (tmp_pinger_data !=  NULL)
            {
                free(tmp_pinger_data);
            }
        }
        hash_map_destroy(g_events_monitor.csi_pinger_map);
    }
    pthread_mutex_destroy(&g_events_monitor.lock);
#endif // CCSP_COMMON

    collector_list = coordinator_get_collector_list();

    if (collector_list != NULL) {
       free_coordinator(collector_list);
    }

    for (i = 0; i < getTotalNumberVAPs(); i++) {
        if(g_monitor_module.bssid_data[i].sta_map != NULL) {
            sta = hash_map_get_first(g_monitor_module.bssid_data[i].sta_map);
            while (sta != NULL) {
                memset(key, 0, sizeof(key));
                to_sta_key(sta->sta_mac, key);
                sta = hash_map_get_next(g_monitor_module.bssid_data[i].sta_map, sta);
                temp_sta = hash_map_remove(g_monitor_module.bssid_data[i].sta_map, key);
                if (temp_sta != NULL) {
                    free(temp_sta);
                }
            }
            hash_map_destroy(g_monitor_module.bssid_data[i].sta_map);
        }
    }
    pthread_mutex_destroy(&g_monitor_module.queue_lock);
    pthread_mutex_destroy(&g_monitor_module.data_lock);
    pthread_cond_destroy(&g_monitor_module.cond);

    /* destory the active measurement g_active_msmt.lock */
}

#ifdef CCSP_COMMON
char* GetInstAssocDevSchemaIdBuffer()
{
    return instSchemaIdBuffer;
}

int GetInstAssocDevSchemaIdBufferSize()
{
    int len = 0;
    if(instSchemaIdBuffer) {
        len = strlen(instSchemaIdBuffer);
    }

    return len;
}
#endif // CCSP_COMMON 

#ifdef CCSP_COMMON
/* This function returns the system uptime at the time of init */
long get_sys_uptime()
{
    struct sysinfo s_info;
    int error = sysinfo(&s_info);
    if(error != 0) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d: Error reading sysinfo %d \n", __func__, __LINE__,error);
    }
    return s_info.uptime;
}

/*
  The get_upload_period takes two arguments iteration and oldInterval.
  Because, it will return old interval value if check is less than 5mins.
  */
 unsigned int get_upload_period  (int oldInterval)
 {
     FILE *fp;
     char buff[64];
     char *ptr;
     int logInterval=oldInterval;
     struct timeval polling_time = {0};
     time_t  time_gap = 0;
     gettimeofday(&polling_time, NULL);

     if ((fp = fopen("/tmp/upload", "r")) == NULL) {
     /* Minimum LOG Interval we can set is 300 sec, just verify every 5 mins any change in the LogInterval
        if any change in log_interval do the calculation and dump the VAP status */
          time_gap = polling_time.tv_sec - lastpolledtime;
          if ( time_gap >= 300 )
          {
               logInterval=readLogInterval();
               lastpolledtime = polling_time.tv_sec;
          }
          return logInterval;
     }

     fgets(buff, 64, fp);
     if ((ptr = strchr(buff, '\n')) != NULL) {
         *ptr = 0;
     }
     fclose(fp);

     return atoi(buff);
}
#endif // CCSP_COMMON

wifi_monitor_t *get_wifi_monitor()
{
    return &g_monitor_module;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : isVapEnabled                                                  */
/*                                                                               */
/* DESCRIPTION   : This function checks whether AP is enabled or not             */
/*                                                                               */
/* INPUT         : wlanIndex - AP index                                          */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : TRUE / FALSE                                                  */
/*                                                                               */
/*********************************************************************************/

int isVapEnabled (int wlanIndex)
{

    wifi_front_haul_bss_t *vap_bss_info = Get_wifi_object_bss_parameter(wlanIndex);
    if (vap_bss_info != NULL) {

        if (vap_bss_info->enabled == FALSE) {
            wifi_util_dbg_print(WIFI_MON, "ERROR> Wifi AP Not enabled for Index: %d\n", wlanIndex );
            return -1;
        }
    }

    return 0;
}

#ifdef CCSP_COMMON
sta_data_t *get_stats_for_sta(unsigned int apIndex, mac_addr_t mac)
{
    sta_data_t  *sta;
    hash_map_t  *sta_map;
    unsigned int vap_array_index;

    getVAPArrayIndexFromVAPIndex(apIndex, &vap_array_index);

    pthread_mutex_lock(&g_monitor_module.data_lock);
    sta_map = g_monitor_module.bssid_data[vap_array_index].sta_map;

    sta = hash_map_get_first(sta_map);
    while (sta != NULL) {
        if (memcmp(mac, sta->sta_mac, sizeof(mac_addr_t)) == 0) {
            pthread_mutex_unlock(&g_monitor_module.data_lock);
            return sta;
        }
        sta = hash_map_get_next(sta_map, sta);
    }

    pthread_mutex_unlock(&g_monitor_module.data_lock);
    return NULL;
}
#endif //CCSP_COMMON

int get_dev_stats_for_radio(unsigned int radio_index, radio_data_t *radio_stats)
{
    if (radio_index < getNumberRadios()) {
        memcpy(radio_stats, &g_monitor_module.radio_data[radio_index], sizeof(radio_data_t));
        return RETURN_OK;
    } else {
        wifi_util_error_print(WIFI_MON, "%s : %d wrong radio index:%d\n", __func__, __LINE__, radio_index);
    }

    return RETURN_ERR;
}

#ifdef CCSP_COMMON
int get_radio_channel_utilization(unsigned int radio_index, int *chan_util)
{
    int ret = RETURN_ERR;
    radio_data_t radio_stats;
    memset(&radio_stats, 0, sizeof(radio_stats));

    ret = get_dev_stats_for_radio(radio_index, &radio_stats);
    if (ret == RETURN_OK) {
        *chan_util = radio_stats.channelUtil;
    }

    return ret;
}
#endif // CCSP_COMMON

int coordinator_calculate_clctr_interval(wifi_mon_collector_element_t *collector_elem, wifi_mon_provider_element_t *new_provider_elem , unsigned long *new_interval)
{
    wifi_mon_provider_element_t *provider_elem = NULL;
    unsigned long temp_new_interval = 0;

    if (collector_elem->provider_list == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: APP list is NULL\n", __func__,__LINE__);
        return RETURN_ERR;
    }
    if (new_provider_elem == NULL || new_interval == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: new_provider_elem or new_interval NULL\n", __func__,__LINE__);
        return RETURN_ERR;
    }

    temp_new_interval = new_provider_elem->provider_task_interval_ms;

    //Traverse through the providers
    provider_elem = hash_map_get_first(collector_elem->provider_list);
    while (provider_elem != NULL) {
        if (strncmp(new_provider_elem->key, provider_elem->key, strlen(new_provider_elem->key)) != 0) {
            if (temp_new_interval > provider_elem->provider_task_interval_ms) {
                temp_new_interval = provider_elem->provider_task_interval_ms;
            }
        }
        provider_elem = hash_map_get_next(collector_elem->provider_list, provider_elem);
    }

    *new_interval = temp_new_interval;

    return RETURN_OK;
}


#define POSTPONE_TIME 200 //ms
#define MAX_POSTPONE_EXECUTION  (30000/POSTPONE_TIME) //scan can time up to 30 seconds

int collector_postpone_execute_task(void *arg)
{
    wifi_mon_collector_element_t *elem = (wifi_mon_collector_element_t *)arg;
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    int id = elem->collector_postpone_task_sched_id;

    if ((mon_data->scan_status[elem->args->radio_index] == 1) && (elem->postpone_cnt < MAX_POSTPONE_EXECUTION)) {
        wifi_util_dbg_print(WIFI_MON, "%s : %d scan running postpone collector : %s\n",__func__,__LINE__, elem->key);
        scheduler_add_timer_task(mon_data->sched, FALSE, &id, collector_postpone_execute_task, arg, POSTPONE_TIME, 1, FALSE);
        elem->collector_postpone_task_sched_id = id;
        elem->postpone_cnt++;
    } else {
        elem->collector_postpone_task_sched_id = 0;
        elem->postpone_cnt = 0;
        wifi_util_dbg_print(WIFI_MON, "%s : %d Executing collector task key : %s\n",__func__,__LINE__, elem->key);
        if (elem->stat_desc->execute_stats_api == NULL || elem->stat_desc->execute_stats_api(elem, mon_data, elem->collector_task_interval_ms) != RETURN_OK) {
            wifi_util_error_print(WIFI_MON, "%s : %d collector execution failed for %s\n",__func__,__LINE__, elem->key);
            return RETURN_ERR;
        }
        wifi_util_dbg_print(WIFI_MON, "%s : %d Execution completed for collector task key : %s\n",__func__,__LINE__, elem->key);
    }

    return RETURN_OK;
}

int collector_execute_task(void *arg)
{
    wifi_mon_collector_element_t *elem = (wifi_mon_collector_element_t *)arg;
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    int id = elem->collector_postpone_task_sched_id;

    if (elem->stat_desc->stats_type == mon_stats_type_radio_channel_stats || 
            elem->stat_desc->stats_type == mon_stats_type_neighbor_stats) {
        if (mon_data->scan_status[elem->args->radio_index] == 1) {
            if (elem->collector_postpone_task_sched_id == 0) {
                wifi_util_dbg_print(WIFI_MON, "%s : %d scan running postpone collector : %s\n",__func__,__LINE__, elem->key);
                scheduler_add_timer_task(mon_data->sched, FALSE, &id, collector_postpone_execute_task, arg, POSTPONE_TIME, 1, FALSE);
                elem->collector_postpone_task_sched_id = id;
                elem->postpone_cnt++;
            }
            return RETURN_OK;
        }
    }
    elem->postpone_cnt = 0;
    wifi_util_dbg_print(WIFI_MON, "%s : %d Executing collector task key : %s\n",__func__,__LINE__, elem->key);
    if (elem->stat_desc->execute_stats_api == NULL || elem->stat_desc->execute_stats_api(elem, mon_data, elem->collector_task_interval_ms) != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s : %d collector execution failed for %s\n",__func__,__LINE__, elem->key);
        return RETURN_ERR;
    }
    wifi_util_dbg_print(WIFI_MON, "%s : %d Execution completed for collector task key : %s\n",__func__,__LINE__, elem->key);

    return RETURN_OK;
}


int provider_execute_task(void *arg)
{
    wifi_mon_provider_element_t *elem = (wifi_mon_provider_element_t *)arg;
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    void *stat_pointer = NULL;
    unsigned int stat_array_size = 0;
    wifi_event_route_t route;
    wifi_provider_response_t *response = NULL;

    wifi_util_dbg_print(WIFI_MON, "%s : %d Executing provider task key : %s\n",__func__,__LINE__, elem->key);
    if (elem->stat_desc->copy_stats_from_cache == NULL || elem->stat_desc->copy_stats_from_cache(elem, &stat_pointer, &stat_array_size, mon_data) != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s : %d provider execution failed for %s\n",__func__,__LINE__, elem->key);
        return RETURN_ERR;
    }

    response = (wifi_provider_response_t *)calloc(1, sizeof(wifi_provider_response_t));
    if (response == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: Memory allocation failed for response for %s\n", __FUNCTION__, __LINE__, elem->key);
        free(stat_pointer);
        return RETURN_ERR;
    }

    // put all collected data to response structure
    memcpy(&response->args, &elem->mon_stats_config->args, sizeof(wifi_mon_stats_args_t));
    response->stat_pointer = stat_pointer;
    response->data_type = elem->mon_stats_config->data_type;
    response->stat_array_size = stat_array_size;

    memset(&route, 0, sizeof(wifi_event_route_t));
    if (elem->mon_stats_config->inst != 0) {
        route.u.inst_bit_map = elem->mon_stats_config->inst;
        route.dst = wifi_sub_component_apps;
    } else {
        route.dst = wifi_sub_component_core;
    }
    push_monitor_response_event_to_ctrl_queue(response, sizeof(wifi_provider_response_t), wifi_event_type_monitor, wifi_event_monitor_provider_response, &route);

    elem->response = response;
    free(elem->response);
    elem->response = NULL;
    free(stat_pointer);
    stat_pointer = NULL;
    wifi_util_dbg_print(WIFI_MON, "%s : %d Execution completed for provider task key : %s\n",__func__,__LINE__, elem->key);

    return RETURN_OK;
}


int coordinator_create_collector_task(wifi_mon_collector_element_t *collector_elem)
{
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    int id = collector_elem->collector_task_sched_id;

    scheduler_add_timer_task(mon_data->sched, collector_elem->task_priority, &id, collector_execute_task,
            (void *)collector_elem, collector_elem->collector_task_interval_ms, 0, collector_elem->start_immediately);
    collector_elem->collector_task_sched_id = id;
    return RETURN_OK;
}

int coordinator_create_provider_task_delay(void *arg)
{
    wifi_mon_provider_element_t *provider_elem = (wifi_mon_provider_element_t *)arg;
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();

    scheduler_add_timer_task(mon_data->sched, provider_elem->mon_stats_config->task_priority, &provider_elem->provider_task_sched_id, provider_execute_task,
            (void *)provider_elem, provider_elem->provider_task_interval_ms, 0, provider_elem->start_immediately);

    return TIMER_TASK_COMPLETE;
}

int coordinator_create_provider_task(wifi_mon_provider_element_t *provider_elem)
{
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();

    if (provider_elem->delay_provider_sec == 0) {
        scheduler_add_timer_task(mon_data->sched, provider_elem->mon_stats_config->task_priority, &provider_elem->provider_task_sched_id, provider_execute_task,
                (void *)provider_elem, provider_elem->provider_task_interval_ms, 0, provider_elem->start_immediately);
    } else {
        scheduler_add_timer_task(mon_data->sched, 0, NULL, coordinator_create_provider_task_delay,
            (void *)provider_elem, provider_elem->delay_provider_sec * 1000, 1, 0);
    }
    return RETURN_OK;
}


wifi_mon_collector_element_t * coordinator_create_collector_elem(wifi_mon_stats_config_t *stats_config, wifi_mon_stats_descriptor_t *stat_desc)
{
    wifi_mon_collector_element_t *collector_elem = NULL;

    if (stat_desc->generate_stats_clctr_key == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: stat_desc->generate_stats_clctr_key is NULL\n", __func__,__LINE__);
        return NULL;
    }

    collector_elem = (wifi_mon_collector_element_t *)calloc(1, sizeof(wifi_mon_collector_element_t));
    if (collector_elem == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: calloc failed for collector elem\n", __func__,__LINE__);
        return NULL;
    }

    collector_elem->stat_desc = stat_desc;
    collector_elem->stat_desc->generate_stats_clctr_key(&stats_config->args, collector_elem->key, sizeof(collector_elem->key));
    collector_elem->collector_task_interval_ms = stats_config->interval_ms;
    collector_elem->task_priority = stats_config->task_priority;
    collector_elem->start_immediately = stats_config->start_immediately;

    collector_elem->args = (wifi_mon_stats_args_t *)calloc(1, sizeof(wifi_mon_stats_args_t));
    if (collector_elem->args == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: calloc failed for args\n", __func__,__LINE__);
        free(collector_elem);
        return NULL;
    }

    memcpy(collector_elem->args, &stats_config->args, sizeof(wifi_mon_stats_args_t));

    return collector_elem;
}

wifi_mon_provider_element_t  *coordinator_create_provider_elem(wifi_mon_stats_config_t * stats_config, wifi_mon_stats_descriptor_t *stat_desc)
{
    wifi_mon_provider_element_t *provider_elem = NULL;
    wifi_mon_stats_descriptor_t *provider_stat_desc = NULL;

    if (stats_config == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: stats_config is NULL\n", __func__,__LINE__);
        return NULL;
    }

    provider_elem = (wifi_mon_provider_element_t *)calloc(1, sizeof(wifi_mon_provider_element_t));
    if (provider_elem == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: calloc failed for provider elem\n", __func__,__LINE__);
        return NULL;
    }

    provider_stat_desc = (wifi_mon_stats_descriptor_t *)wifi_mon_get_stats_descriptor(stats_config->data_type);
    if (provider_stat_desc == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: Invalid stats_type %d from app %d\n", __func__,__LINE__, stats_config->data_type, stats_config->inst);
        free(provider_elem);
        return NULL;
    }

    provider_elem->stat_desc = provider_stat_desc;

    provider_elem->delay_provider_sec= stats_config->delay_provider_sec;
    provider_elem->stat_desc->generate_stats_provider_key(stats_config, provider_elem->key, sizeof(provider_elem->key));
    provider_elem->provider_task_interval_ms = stats_config->interval_ms;
    provider_elem->start_immediately = stats_config->start_immediately;

    provider_elem->mon_stats_config = (wifi_mon_stats_config_t *)calloc(1, sizeof(wifi_mon_stats_config_t));
    if (provider_elem->mon_stats_config == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: calloc failed for mon_stats_config\n", __func__,__LINE__);
        free(provider_elem);
        return NULL;
    }

    memcpy(provider_elem->mon_stats_config, stats_config, sizeof(wifi_mon_stats_config_t));

    return provider_elem;
}

void coordinator_free_provider_elem(wifi_mon_provider_element_t **provider_elem)
{
    wifi_util_dbg_print(WIFI_MON, "%s:%d\n", __func__,__LINE__);
    if ((*provider_elem) != NULL) {
        if ((*provider_elem)->mon_stats_config != NULL) {
            free((*provider_elem)->mon_stats_config);
            (*provider_elem)->mon_stats_config = NULL;
        }

        if ((*provider_elem)->response != NULL) {
            free((*provider_elem)->response);
            (*provider_elem)->response = NULL;
        }

        free(*provider_elem);
        *provider_elem = NULL;
    }
    return;
}

void coordinator_free_collector_elem(wifi_mon_collector_element_t **collector_elem)
{
    wifi_util_dbg_print(WIFI_MON, "%s:%d\n", __func__,__LINE__);
    if ((*collector_elem) != NULL) {
        if ((*collector_elem)->args != NULL) {
            free((*collector_elem)->args);
            (*collector_elem)->args = NULL;
        }
        free(*collector_elem);
        *collector_elem = NULL;
    }
    return;
}

int coordinator_create_task(wifi_mon_collector_element_t **collector_elem, wifi_mon_stats_config_t *stats_config, wifi_mon_stats_descriptor_t *stat_desc)
{
    if (collector_elem == NULL || stats_config == NULL || stat_desc == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: Null pointer\n", __func__,__LINE__);
        return RETURN_ERR;
    }

    wifi_mon_provider_element_t *provider_elem = NULL;
    *collector_elem = coordinator_create_collector_elem(stats_config, stat_desc);
    if (*collector_elem == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: coordinator_create_collector_elem failed\n", __func__,__LINE__);
        return RETURN_ERR;
    }

    if (coordinator_create_collector_task(*collector_elem) != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s:%d: coordinator_create_collector_task failed\n", __func__,__LINE__);
        coordinator_free_collector_elem(collector_elem);
        return RETURN_ERR;
    }

    (*collector_elem)->provider_list = hash_map_create();
    if ((*collector_elem)->provider_list == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: hash map failed for provider list\n", __func__,__LINE__);
        coordinator_free_collector_elem(collector_elem);
        return RETURN_ERR;
    }

    provider_elem = coordinator_create_provider_elem(stats_config, stat_desc);
    if (provider_elem == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: coordinator_create_provider_elem failed\n", __func__,__LINE__);
        return RETURN_ERR;
    }
    char* key_copy = strdup(provider_elem->key);
    if (key_copy == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: strdup failed\n", __func__,__LINE__);
        coordinator_free_provider_elem(&provider_elem);
        return RETURN_ERR;
    }

    if (hash_map_put((*collector_elem)->provider_list, key_copy, provider_elem) != 0) {
        wifi_util_error_print(WIFI_MON, "%s:%d: hash_map_put failed\n", __func__,__LINE__);
        coordinator_free_provider_elem(&provider_elem);
        return RETURN_ERR;
    }

    if (stat_desc->copy_stats_from_cache != NULL) {
        if (coordinator_create_provider_task(provider_elem) != RETURN_OK) {
            wifi_util_error_print(WIFI_MON, "%s:%d: coordinator_create_provider_task failed\n", __func__,__LINE__);
            coordinator_free_provider_elem(&provider_elem);
            return RETURN_ERR;
        }
    } else {
        provider_elem->provider_task_sched_id = 0;
    }

    return RETURN_OK;
}

int collector_task_update(wifi_mon_collector_element_t *collector_elem, unsigned long *new_collector_interval)
{
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();

    collector_elem->collector_task_interval_ms = *new_collector_interval;
    wifi_util_info_print(WIFI_MON, "%s:%d: New collector interval : %d for key : %s\n", __func__,__LINE__, collector_elem->collector_task_interval_ms, collector_elem->key);

    if (collector_elem->stat_desc->update_collector_args != NULL) {
        collector_elem->stat_desc->update_collector_args((void*)collector_elem);
    }

    scheduler_update_timer_task_interval(mon_data->sched, collector_elem->collector_task_sched_id,  collector_elem->collector_task_interval_ms);
    return RETURN_OK;
}

int provider_task_update(wifi_mon_provider_element_t *provider_elem, unsigned long *new_provider_interval)
{
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    provider_elem->provider_task_interval_ms = *new_provider_interval;

    wifi_util_info_print(WIFI_MON, "%s:%d: New Provider interval : %d for key : %s\n", __func__,__LINE__, provider_elem->provider_task_interval_ms, provider_elem->key);
    if (provider_elem->provider_task_sched_id != 0) {
        scheduler_update_timer_task_interval(mon_data->sched, provider_elem->provider_task_sched_id, provider_elem->provider_task_interval_ms);
    }

    return RETURN_OK;
}

int coordinator_update_task(wifi_mon_collector_element_t *collector_elem, wifi_mon_stats_config_t *stats_config)
{
    if (collector_elem == NULL || collector_elem->stat_desc == NULL || collector_elem->provider_list == NULL || stats_config == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: Null pointer\n", __func__,__LINE__);
        return RETURN_ERR;
        }
    unsigned long new_collector_interval = 0;
    wifi_mon_provider_element_t *dup_provider_elem = NULL;
    dup_provider_elem = coordinator_create_provider_elem(stats_config, collector_elem->stat_desc);
    if (dup_provider_elem == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: coordinator_create_provider_elem failed\n", __func__,__LINE__);
        return RETURN_ERR;
    }

    if (coordinator_calculate_clctr_interval(collector_elem, dup_provider_elem, &new_collector_interval) != RETURN_OK) {
        coordinator_free_provider_elem(&dup_provider_elem);
        return RETURN_ERR;
    }

    collector_task_update(collector_elem, &new_collector_interval);

    wifi_mon_provider_element_t *provider_elem = (wifi_mon_provider_element_t *)hash_map_get(collector_elem->provider_list, dup_provider_elem->key);
    if (provider_elem == NULL) {
        provider_elem = dup_provider_elem;
        char* key_copy = strdup(provider_elem->key);
        if (key_copy == NULL) {
            wifi_util_error_print(WIFI_MON, "%s:%d: strdup failed\n", __func__,__LINE__);
            coordinator_free_provider_elem(&dup_provider_elem);
            return RETURN_ERR;
        }

        if (hash_map_put(collector_elem->provider_list, key_copy, provider_elem) != 0) {
            wifi_util_error_print(WIFI_MON, "%s:%d: hash_map_put failed\n", __func__,__LINE__);
            coordinator_free_provider_elem(&dup_provider_elem);
            return RETURN_ERR;
        }

        if (collector_elem->stat_desc->copy_stats_from_cache != NULL) {
            if (coordinator_create_provider_task(provider_elem) != RETURN_OK) {
                wifi_util_error_print(WIFI_MON, "%s:%d: coordinator_create_provider_task failed\n", __func__,__LINE__);
                coordinator_free_provider_elem(&provider_elem);
                return RETURN_ERR;
            }
        }
    } else {
        memcpy(provider_elem->mon_stats_config, dup_provider_elem->mon_stats_config, sizeof(wifi_mon_stats_config_t));
        provider_task_update(provider_elem, &dup_provider_elem->provider_task_interval_ms);
        coordinator_free_provider_elem(&dup_provider_elem);
    }

    return RETURN_OK;
}


int coordinator_stop_task(wifi_mon_collector_element_t **collector_elem, wifi_mon_stats_config_t *stats_config)
{
    char  key[MON_STATS_KEY_LEN_32];
    wifi_mon_provider_element_t *provider_elem = NULL, *dup_provider_elem = NULL;
    hash_map_t  *collector_list = coordinator_get_collector_list();
    wifi_monitor_t *mon_data = (wifi_monitor_t *)get_wifi_monitor();
    unsigned long new_collector_interval = 0;
    unsigned int count = 0;

    (*collector_elem)->stat_desc->generate_stats_provider_key(stats_config, key, sizeof(key));

    provider_elem = (wifi_mon_provider_element_t *)hash_map_get((*collector_elem)->provider_list, key);
    if (provider_elem == NULL) {
        return RETURN_OK;
    } else {
        wifi_util_dbg_print(WIFI_MON, "%s:%d: remove provider task key : %s\n", __func__,__LINE__, provider_elem->key);
        if (provider_elem->provider_task_sched_id != 0) {
            scheduler_cancel_timer_task(mon_data->sched, provider_elem->provider_task_sched_id);
        }
        hash_map_remove((*collector_elem)->provider_list, key);
        coordinator_free_provider_elem(&provider_elem);
        count = hash_map_count((*collector_elem)->provider_list);
        if (count == 0) {
            wifi_util_info_print(WIFI_MON, "%s:%d: Provider list is empty, remove collector task key : %s\n", __func__,__LINE__, (*collector_elem)->key);
            scheduler_cancel_timer_task(mon_data->sched, (*collector_elem)->collector_task_sched_id);
            scheduler_cancel_timer_task(mon_data->sched, (*collector_elem)->collector_postpone_task_sched_id);
            (*collector_elem)->collector_postpone_task_sched_id = 0;
            if ((*collector_elem)->stat_desc->stop_scheduler_tasks == NULL || (*collector_elem)->stat_desc->stop_scheduler_tasks((*collector_elem)) != RETURN_OK) {
                wifi_util_error_print(WIFI_MON, "%s : %d Failed to stop task\n", __func__, __LINE__);
            }
            hash_map_remove(collector_list, (*collector_elem)->key);
            if ((*collector_elem)->provider_list != NULL) {
              hash_map_destroy((*collector_elem)->provider_list);
            }
            coordinator_free_collector_elem(collector_elem);
        } else {
            new_collector_interval = 0;
            dup_provider_elem = hash_map_get_first((*collector_elem)->provider_list);
            while (dup_provider_elem != NULL) {
                if (new_collector_interval == 0 || new_collector_interval > dup_provider_elem->provider_task_interval_ms) {
                    new_collector_interval = dup_provider_elem->provider_task_interval_ms;
                }
                dup_provider_elem = hash_map_get_next((*collector_elem)->provider_list, dup_provider_elem);
            }
            if (new_collector_interval == 0) {
                wifi_util_error_print(WIFI_MON, "%s %d invalid interval : %d\n",__func__,__LINE__, new_collector_interval);
                return RETURN_ERR;
            }
            collector_task_update(*collector_elem, &new_collector_interval);
        }
    }

    return RETURN_OK;
}

int coordinator_check_stats_config(wifi_mon_stats_config_t *mon_stats_config)
{
    hash_map_t *collector_list = NULL;
    wifi_mon_collector_element_t *collector_elem = NULL;
    char stats_key[MON_STATS_KEY_LEN_32] = {0};
    wifi_mon_stats_descriptor_t *stat_desc = NULL;

    if (stats_common_args_validation(mon_stats_config) != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s:%d: common args validation failed. stats_type %d  interval_ms %d from app %d\n", __func__,__LINE__,
                                    mon_stats_config->data_type, mon_stats_config->interval_ms, mon_stats_config->inst);
        return RETURN_ERR;
    }

    stat_desc = (wifi_mon_stats_descriptor_t *)wifi_mon_get_stats_descriptor(mon_stats_config->data_type);
    if (stat_desc == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: Invalid stats_type %d from app %d\n", __func__,__LINE__, mon_stats_config->data_type, mon_stats_config->inst);
        return RETURN_ERR;
    }

    if (stat_desc->validate_args(&mon_stats_config->args) != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s:%d: args validation failed for stats_type %d from app %d\n", __func__,__LINE__,
                                    mon_stats_config->data_type,mon_stats_config->inst);
        return RETURN_ERR;
    }

    if (stat_desc->generate_stats_clctr_key(&mon_stats_config->args, stats_key, sizeof(stats_key)) != RETURN_OK) {
        wifi_util_error_print(WIFI_MON, "%s:%d: stats key generation failed for stats_type %d from app %d\n", __func__,__LINE__, mon_stats_config->data_type, mon_stats_config->inst);
        return RETURN_ERR;
    }

    collector_list = coordinator_get_collector_list();
    if (collector_list == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: Failed to get collector list\n", __func__,__LINE__);
        return RETURN_ERR;
    }
    collector_elem = (wifi_mon_collector_element_t *)hash_map_get(collector_list, stats_key);
    if (collector_elem == NULL) {
        if (mon_stats_config->req_state == mon_stats_request_state_start) {
            if (coordinator_create_task(&collector_elem, mon_stats_config, stat_desc) != RETURN_OK) {
                wifi_util_error_print(WIFI_MON, "%s:%d: create task failed for key : %s for app  %d\n", __func__,__LINE__, stats_key, mon_stats_config->inst);
                return RETURN_ERR;
            }
            char *key_copy = strdup(stats_key);
            if (key_copy == NULL) {
                wifi_util_error_print(WIFI_MON, "%s:%d: Failed to duplicate key\n", __func__,__LINE__);
                return RETURN_ERR;
            }
            hash_map_put(collector_list, key_copy, collector_elem);
            wifi_util_info_print(WIFI_MON, "%s:%d: created task for key : %s for app  %d\n", __func__,__LINE__, stats_key, mon_stats_config->inst);
        } else {
            wifi_util_error_print(WIFI_MON, "%s:%d: Task is not running. Request state %d is not expected\n", __func__,__LINE__, mon_stats_config->req_state);
            return RETURN_ERR;
        }
    } else {
        if (mon_stats_config->req_state == mon_stats_request_state_start) {
            if (coordinator_update_task(collector_elem, mon_stats_config) != RETURN_OK) {
                wifi_util_error_print(WIFI_MON, "%s:%d: update task failed for key : %s for app  %d\n", __func__,__LINE__, stats_key, mon_stats_config->inst);
                return RETURN_ERR;
            }
            wifi_util_dbg_print(WIFI_MON, "%s:%d: updated task for key : %s for app  %d\n", __func__,__LINE__, stats_key, mon_stats_config->inst);
        } else {
            if (coordinator_stop_task(&collector_elem, mon_stats_config) != RETURN_OK) {
                wifi_util_error_print(WIFI_MON, "%s:%d: stop task failed for key : %s for app  %d\n", __func__,__LINE__, stats_key, mon_stats_config->inst);
                return RETURN_ERR;
            }
            wifi_util_dbg_print(WIFI_MON, "%s:%d: stopped the task for key : %s for app  %d\n", __func__,__LINE__, stats_key, mon_stats_config->inst);
        }
    }

    return RETURN_OK;
}

wifi_apps_coordinator_t *get_apps_coordinator()
{
    return &g_apps_coordinator;
}

hash_map_t *coordinator_get_collector_list()
{
    wifi_apps_coordinator_t *apps_coordinator = get_apps_coordinator();

    return apps_coordinator->collector_list;
}

void free_provider_list(wifi_mon_collector_element_t *coll_elem)
{
    wifi_mon_provider_element_t *provider_elem, *temp_provider;
    char key[MON_STATS_KEY_LEN_32] = {0};
    if (coll_elem->provider_list != NULL) {
        provider_elem = hash_map_get_first(coll_elem->provider_list);
        while (provider_elem != NULL) {
            memset(key, 0, sizeof(key));
            provider_elem->stat_desc->generate_stats_provider_key(provider_elem->mon_stats_config, key, sizeof(key));
            provider_elem = hash_map_get_next(coll_elem->provider_list, provider_elem);
            temp_provider = hash_map_remove(coll_elem->provider_list, key);
            if (temp_provider != NULL) {
                coordinator_free_provider_elem(&temp_provider);
            }
        }
        hash_map_destroy(coll_elem->provider_list);
    }
}


void free_coordinator(hash_map_t *collector_list)
{
    wifi_mon_collector_element_t *coll_elem = NULL, *temp_collector = NULL;
    char key[MON_STATS_KEY_LEN_32] = {0};
    if(collector_list != NULL) {
        coll_elem = hash_map_get_first(collector_list);
        while (coll_elem != NULL) {
            free_provider_list(coll_elem);
            memset(key, 0, sizeof(key));
            coll_elem->stat_desc->generate_stats_clctr_key(coll_elem->args, key, sizeof(key));
            coll_elem = hash_map_get_next(collector_list, coll_elem);
            temp_collector = hash_map_remove(collector_list, key);
            if (temp_collector != NULL) {
                coordinator_free_collector_elem(&temp_collector);
            }
        }
        hash_map_destroy(collector_list);
    }
}

