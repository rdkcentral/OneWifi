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
#include "wifi_blaster.h"
#include "wifi_events.h"
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <signal.h>
#include <time.h>
#include <sys/un.h>
#include <assert.h>
#include <limits.h>
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
#include "wifi_apps_mgr.h"

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

void calculate_throughput();

#define WIFI_BLASTER_POST_STEP_TIMEOUT 100  // ms
#define WIFI_BLASTER_CPU_THRESHOLD     90   // percentage
#define WIFI_BLASTER_MEM_THRESHOLD     8096 // Kb
#define WIFI_BLASTER_CPU_CALC_PERIOD   1    // seconds

#ifndef CCSP_COMMON
#define WIFI_BLASTER_WAKEUP_LIMIT 2
#endif // CCSP_COMMON

#define blaster_app_sample_blaster 10
#define LINUX_PROC_MEMINFO_FILE  "/proc/meminfo"
#define LINUX_PROC_LOADAVG_FILE  "/proc/loadavg"
#define LINUX_PROC_STAT_FILE     "/proc/stat"

static void config_sample_blaster(wifi_monitor_data_t *data);

wifi_actvie_msmt_t *get_wifi_blaster()
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr;
    wifi_app_t *wifi_app =  NULL;

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_blaster);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }

    return &wifi_app->data.u.blaster.g_active_msmt;
}

unsigned int *get_sample_count()
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr;
    wifi_app_t *wifi_app =  NULL;

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return 0;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_blaster);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return 0;
    }
    return &wifi_app->data.u.blaster.SampleCount;
}

static inline char *to_sta_key    (mac_addr_t mac, sta_key_t key)
{
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}

bool is_blaster_device_associated(int ap_index, mac_address_t sta_mac)
{
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    assoc_dev_data_t *sta = NULL;
    sta_key_t sta_key;

    rdk_vap_info = get_wifidb_rdk_vap_info(ap_index);
    if(rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s: Failed to get rdk_vap_info from vap index %d\n", __func__, ap_index);
        return false;
    }
    if (rdk_vap_info->associated_devices_map == NULL) {
        wifi_util_error_print(WIFI_BLASTER,"%s:%d NULL  associated_devices_map  pointer  for  %d\n", __func__, __LINE__, rdk_vap_info->vap_index);
        return false;
    }

    wifi_util_error_print(WIFI_BLASTER, "%s: sta_mac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);

    to_sta_key(sta_mac, sta_key);
    sta = (assoc_dev_data_t *) hash_map_get(rdk_vap_info->associated_devices_map, sta_key);
    if (sta == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s: Failed to get sta from vap index %d\n", __func__, ap_index);
        return false;
    }
    else {
        return true;
    }

    return false;
}

static bool DeviceCpuUtil_DataGet(unsigned int *util_cpu)
{
    FILE *fp;
    char buff[256] = {};
    char token[] = "cpu ";
    uint64_t hz_user, hz_nice, hz_system, hz_idle;
    static uint64_t prev_hz_user, prev_hz_nice, prev_hz_system, prev_hz_idle;
    static bool init = true;
    uint64_t hz_total;
    double busy;

    if ((fp = fopen(LINUX_PROC_STAT_FILE, "r")) == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER, "Failed to open file: %s\n", LINUX_PROC_STAT_FILE);
        *util_cpu = 0;
        return false;
    }

    while (fgets(buff, sizeof(buff), fp) != NULL) {

        if (strncmp(buff, token, sizeof(token) - 1) != 0) {
            continue;
        }

#ifdef _64BIT_ARCH_SUPPORT_
        sscanf(buff, "cpu %lu %lu %lu %lu", &hz_user, &hz_nice, &hz_system, &hz_idle);
#else
        sscanf(buff, "cpu %llu %llu %llu %llu", &hz_user, &hz_nice, &hz_system, &hz_idle);
#endif

        if (init == true) {

            *util_cpu = 0;
            prev_hz_user = hz_user;
            prev_hz_nice = hz_nice;
            prev_hz_system = hz_system;
            prev_hz_idle = hz_idle;
            init = false;

            break;
        }

        hz_total = (hz_user - prev_hz_user) + (hz_nice - prev_hz_nice) + (hz_system - prev_hz_system) + (hz_idle - prev_hz_idle);
        busy = (1.0 - ((double)(hz_idle - prev_hz_idle) / (double)hz_total)) * 100.0;
        *util_cpu = (unsigned int) (busy + 0.5);

        prev_hz_user = hz_user;
        prev_hz_nice = hz_nice;
        prev_hz_system = hz_system;
        prev_hz_idle = hz_idle;

        break;
    }

    fclose(fp);
    return true;
}

void blaster_str_to_mac_bytes (char *key, mac_addr_t bmac) {
    unsigned int mac[6];

    wifi_util_dbg_print(WIFI_BLASTER, "%s: value of key is %s and strlen of key is %d\n", __func__, key, strlen(key));

    if (strlen(key) == 0) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s:%d: Input mac address is empty.\n", __func__, __LINE__);
        return;
    }

    if(strlen(key) > MIN_MAC_LEN)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "%s: Entered in if\n", __func__);
        sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    }
    else
        sscanf(key, "%02x%02x%02x%02x%02x%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
               bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
               bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

    wifi_util_error_print(WIFI_BLASTER, "%s: bmac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, bmac[0], bmac[1], bmac[2], bmac[3], bmac[4], bmac[5]);
}

static void active_msmt_log_message( blaster_log_level_t level,char *fmt, ...)
{
    va_list args;
    char msg[1024] = {};

    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

#ifdef CCSP_COMMON
switch(level){
    case BLASTER_INFO_LOG:
        CcspTraceInfo((msg));
        break;
    case BLASTER_DEBUG_LOG:
        CcspTraceDebug((msg));
        break;
    default:
        break;
}
#endif // CCSP_COMMON

    wifi_util_dbg_print(WIFI_BLASTER, msg);
}

static char *active_msmt_status_to_str(active_msmt_status_t status)
{
    switch (status)
    {
        case ACTIVE_MSMT_STATUS_SUCCEED:
            return "SUCCEED";
        case ACTIVE_MSMT_STATUS_CANCELED:
            return "CANCELED";
        case ACTIVE_MSMT_STATUS_FAILED:
            return "FAILED";
        case ACTIVE_MSMT_STATUS_BUSY:
            return "BUSY";
        case ACTIVE_MSMT_STATUS_NO_CLIENT:
            return "NO_CLIENT";
        case ACTIVE_MSMT_STATUS_SLEEP_CLIENT:
            return "SLEEP_CLIENT";
        case ACTIVE_MSMT_STATUS_WRONG_ARG:
            return "WRONG_ARG";
        default:
            return "UNDEFINED";
    }
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : getCurrentTimeInMicroSeconds                                  */
/*                                                                               */
/* DESCRIPTION   : This function returns the current time in micro seconds       */
/*                                                                               */
/* INPUT         : NONE                                                          */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : timestamp in micro seconds                                    */
/*                                                                               */
/*********************************************************************************/

unsigned long getCurrentTimeInMicroSeconds()
{
    struct timespec timer_usec;
    long long int timestamp_usec; /* timestamp in microsecond */

    if (!clock_gettime(CLOCK_MONOTONIC, &timer_usec)) {
        timestamp_usec = ((long long int) timer_usec.tv_sec) * 1000000ll +
          (long long int) (timer_usec.tv_nsec / 1000);
    } else {
        timestamp_usec = -1;
    }
    return timestamp_usec;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : WaitForDuration                                               */
/*                                                                               */
/* DESCRIPTION   : This function makes the calling thread to wait for particular */
/*                 time interval                                                 */
/*                                                                               */
/* INPUT         : timeInMs - time to wait                                       */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : TRUE / FALSE                                                  */
/*                                                                               */
/*********************************************************************************/

int WaitForDuration (int timeInMs)
{
    struct timespec   ts;
    pthread_condattr_t  cond_attr;
    pthread_cond_t      cond;
    pthread_mutex_t     mutex = PTHREAD_MUTEX_INITIALIZER;
    int     ret;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&cond, &cond_attr);
    pthread_condattr_destroy(&cond_attr);
    clock_gettime(CLOCK_MONOTONIC, &ts);

    /* Add wait duration*/
    if ( timeInMs > 1000 ) {
        ts.tv_sec += (timeInMs/1000);
    } else {
        ts.tv_nsec = ts.tv_nsec + (timeInMs*CONVERT_MILLI_TO_NANO);
        ts.tv_sec = ts.tv_sec + ts.tv_nsec / 1000000000L;
        ts.tv_nsec = ts.tv_nsec % 1000000000L;
    }
    pthread_mutex_lock(&mutex);
    ret = pthread_cond_timedwait(&cond, &mutex, &ts);
    pthread_mutex_unlock(&mutex);

    return ret;
}


static void active_msmt_set_status_desc(const char *func, unsigned char *plan_id, unsigned int step_id,
    unsigned char *dst_mac, char *msg)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    char mac[MAC_ADDRESS_LENGTH] = {};

    memset(&g_active_msmt->status_desc, 0, sizeof(g_active_msmt->status_desc));

    if (strlen((char *)dst_mac) != MAC_ADDRESS_LENGTH - 1) {
        snprintf(mac, sizeof(mac), MAC_FMT_TRIMMED, MAC_ARG(dst_mac));
    } else {
        strncpy(mac, (char *)dst_mac, sizeof(mac) - 1);
    }

    snprintf(g_active_msmt->status_desc, sizeof(g_active_msmt->status_desc),
        "Plan[%s] Step[%d] Mac[%s] FW[] Node[] Status[%s] %s",
        (char *)plan_id ?: "", step_id, mac, active_msmt_status_to_str(g_active_msmt->status), msg ?: "");

    wifi_util_dbg_print(WIFI_BLASTER, "%s: %s\n", func, g_active_msmt->status_desc);
}

static void active_msmt_report_error(const char *func, unsigned char *plan_id, active_msmt_step_t *step,
    char *msg, active_msmt_status_t status)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    SetActiveMsmtStatus(__func__, status);
    active_msmt_set_status_desc(func, plan_id, step->StepId, step->DestMac, msg);

    SetActiveMsmtPlanID((char *)plan_id);
    g_active_msmt->curStepData.ApIndex = 0;
    g_active_msmt->curStepData.StepId = step->StepId;
    stream_client_msmt_data(true);
}

static void active_msmt_set_step_status(const char *func, ULONG StepIns, active_msmt_step_status_t value)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "%s: updating stepIns to %d step: %d\n", func, value, StepIns);

    g_active_msmt->active_msmt.StepInstance[StepIns] = value;
}

static void active_msmt_report_all_steps(active_msmt_t *cfg, char *msg, active_msmt_status_t status)
{
    // Send MQTT report for all configured steps
    for (unsigned int i = 0; i < MAX_STEP_COUNT; i++) {
        if (strlen((char *) cfg->Step[i].DestMac) != 0) {
            active_msmt_report_error(__func__, cfg->PlanId, &cfg->Step[i], msg, status);
            continue;
        }
    }
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : process_active_msmt_diagnostics                               */
/*                                                                               */
/* DESCRIPTION   : This function update the station info with the global monitor */
/*                 data info which gets uploaded to the AVRO schema              */
/*                                                                               */
/* INPUT         : ap_index - AP index                                           */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/
void process_active_msmt_diagnostics (int ap_index)
{
    hash_map_t *blaster_map = NULL;
    blaster_hashmap_t *sta = NULL;
    sta_key_t       sta_key;
    unsigned int count = 0;
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "%s : %d  apindex : %d \n",__func__,__LINE__,ap_index);

    blaster_map = g_active_msmt->active_msmt_map;
    if (blaster_map == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL active_blaster-data map\n", __func__, __LINE__);
        return;
    }

    to_sta_key(g_active_msmt->curStepData.DestMac, sta_key);
    str_tolower(sta_key);

    sta = (blaster_hashmap_t *)hash_map_get(blaster_map, sta_key);

    if (sta == NULL) {
        /* added the data in sta map for offline clients */
        wifi_util_dbg_print(WIFI_BLASTER, "%s : %d station info is null \n",__func__,__LINE__);
        sta = (blaster_hashmap_t *) malloc (sizeof(blaster_hashmap_t));
        if (sta == NULL) {
            return;
        }
        memset(sta, 0, sizeof(blaster_hashmap_t));
        pthread_mutex_lock(&g_active_msmt->lock);
        memcpy(&sta->sta_mac, g_active_msmt->curStepData.DestMac, sizeof(mac_addr_t));
        hash_map_put(blaster_map, strdup(sta_key), sta);

        if (ap_index == -1) {
            sta->sta_active_msmt_data = (active_msmt_data_t *) calloc (g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples,sizeof(active_msmt_data_t));
            if (sta->sta_active_msmt_data == NULL) {
                wifi_util_error_print(WIFI_BLASTER, "%s : %d allocating sta_active_msmt_data failed for offline clients\n",__func__,__LINE__);
            }
            pthread_mutex_unlock(&g_active_msmt->lock);
            return;
        }
        pthread_mutex_unlock(&g_active_msmt->lock);

    } else {
          if (ap_index == -1) {
              if (sta->sta_active_msmt_data == NULL) {
                  sta->sta_active_msmt_data = (active_msmt_data_t*) calloc (g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples,sizeof(active_msmt_data_t));
                  if (sta->sta_active_msmt_data == NULL) {
                      wifi_util_error_print(WIFI_BLASTER, "%s : %d memory allocation failed for offline clients\n",__func__,__LINE__);
                      return;
                  }
              }
            return;
          }

        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d copying mac : " MAC_FMT " to station info\n", __func__, __LINE__,
                MAC_ARG(g_active_msmt->curStepData.DestMac));
        memcpy(&sta->sta_mac, g_active_msmt->curStepData.DestMac, sizeof(mac_addr_t));
    }
    wifi_util_dbg_print(WIFI_BLASTER, "%s : %d allocating memory for sta_active_msmt_data \n",__func__,__LINE__);
    sta->sta_active_msmt_data = (active_msmt_data_t *) calloc (g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples,sizeof(active_msmt_data_t));

    if (sta->sta_active_msmt_data == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s : %d allocating memory for sta_active_msmt_data failed\n",__func__,__LINE__);
        /*CID: 146766 Dereference after null check*/
        return;
    }

    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d Number of sample %d for client [" MAC_FMT "]\n", __FUNCTION__, __LINE__,
         g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples, MAC_ARG(g_active_msmt->curStepData.DestMac));

    if (g_active_msmt->active_msmt_data != NULL) {
        for (count = 0; count < g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples; count++) {
            sta->sta_active_msmt_data[count].rssi = g_active_msmt->active_msmt_data[count].rssi;
            sta->sta_active_msmt_data[count].TxPhyRate = g_active_msmt->active_msmt_data[count].TxPhyRate;
            sta->sta_active_msmt_data[count].RxPhyRate = g_active_msmt->active_msmt_data[count].RxPhyRate;
            sta->sta_active_msmt_data[count].SNR = g_active_msmt->active_msmt_data[count].SNR;
            sta->sta_active_msmt_data[count].ReTransmission = g_active_msmt->active_msmt_data[count].ReTransmission;
            sta->sta_active_msmt_data[count].MaxRxRate = g_active_msmt->active_msmt_data[count].MaxRxRate;
            sta->sta_active_msmt_data[count].MaxTxRate = g_active_msmt->active_msmt_data[count].MaxTxRate;
            strncpy(sta->sta_active_msmt_data[count].Operating_standard, g_active_msmt->active_msmt_data[count].Operating_standard,OPER_BUFFER_LEN);
            strncpy(sta->sta_active_msmt_data[count].Operating_channelwidth, g_active_msmt->active_msmt_data[count].Operating_channelwidth,OPER_BUFFER_LEN);
            sta->sta_active_msmt_data[count].throughput = g_active_msmt->active_msmt_data[count].throughput;

            active_msmt_log_message(BLASTER_DEBUG_LOG, "count[%d] : standard[%s] chan_width[%s] Retransmission [%d]"
                "RSSI[%d] TxRate[%lu Mbps] RxRate[%lu Mbps] SNR[%d] throughput[%.5lf Mbps]"
                "MaxTxRate[%d] MaxRxRate[%d]\n",
                count, sta->sta_active_msmt_data[count].Operating_standard,
                sta->sta_active_msmt_data[count].Operating_channelwidth,
                sta->sta_active_msmt_data[count].ReTransmission,
                sta->sta_active_msmt_data[count].rssi, sta->sta_active_msmt_data[count].TxPhyRate,
                sta->sta_active_msmt_data[count].RxPhyRate, sta->sta_active_msmt_data[count].SNR,
                sta->sta_active_msmt_data[count].throughput,
                sta->sta_active_msmt_data[count].MaxTxRate,
                sta->sta_active_msmt_data[count].MaxRxRate);
        }
    }
    wifi_util_dbg_print(WIFI_BLASTER, "%s : %d exiting the function\n",__func__,__LINE__);
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : SetActiveMsmtPktSize                                          */
/*                                                                               */
/* DESCRIPTION   : This function set the size of packet configured for           */
/*                 Active Measurement                                            */
/*                                                                               */
/* INPUT         : PktSize - size of packet                                      */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void SetActiveMsmtPktSize(unsigned int PktSize)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Active Measurement Packet Size Changed to %d \n", __func__, __LINE__,PktSize);
    g_active_msmt->active_msmt.ActiveMsmtPktSize = PktSize;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : SetActiveMsmtSampleDuration                                   */
/*                                                                               */
/* DESCRIPTION   : This function set the sample duration configured for          */
/*                 Active Measurement                                            */
/*                                                                               */
/* INPUT         : Duration - duration between samples                           */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void SetActiveMsmtSampleDuration(unsigned int Duration)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Active Measurement Sample Duration Changed to %d \n", __func__, __LINE__,Duration);
    g_active_msmt->active_msmt.ActiveMsmtSampleDuration = Duration;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : SetActiveMsmtNumberOfSamples                                  */
/*                                                                               */
/* DESCRIPTION   : This function set the count of sample configured for          */
/*                 Active Measurement                                            */
/*                                                                               */
/* INPUT         : NoOfSamples - count of samples                                */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void SetActiveMsmtNumberOfSamples(unsigned int NoOfSamples)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Active Measurement Number of Samples Changed %d \n", __func__, __LINE__,NoOfSamples);
    g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples = NoOfSamples;
}

int ActiveMsmtConfValidation(active_msmt_t *cfg)
{
    int len;
    char msg[256] = {};

    if (!cfg->PlanId || ((len = strlen((char *)cfg->PlanId) < 1) || len > PLAN_ID_LENGTH - 2)) {
        snprintf(msg, sizeof(msg), "Invalid length of PlanID [%d]. Expected in range [1..%d]",
            len, PLAN_ID_LENGTH - 2);
        goto Error;
    }

    if ((cfg->ActiveMsmtNumberOfSamples < 1) || (cfg->ActiveMsmtNumberOfSamples > 100)) {
        snprintf(msg, sizeof(msg), "Invalid Sample count [%d]. Expected in range [1..100]",
            cfg->ActiveMsmtNumberOfSamples);
        goto Error;
    }

    if ((cfg->ActiveMsmtSampleDuration < 1000) || (cfg->ActiveMsmtSampleDuration > 10000)) {
        snprintf(msg, sizeof(msg), "Invalid Duration [%d]ms. Expected in range [1000..10000]",
            cfg->ActiveMsmtSampleDuration);
        goto Error;
    }

    if ((cfg->ActiveMsmtSampleDuration / cfg->ActiveMsmtNumberOfSamples) < 100) {
        snprintf(msg, sizeof(msg), "Invalid Duration/Sample_count ratio [%d/%d = %d]ms. Expected >= 100",
            cfg->ActiveMsmtSampleDuration, cfg->ActiveMsmtNumberOfSamples,
            cfg->ActiveMsmtSampleDuration / cfg->ActiveMsmtNumberOfSamples);
        goto Error;
    }

    if (cfg->ActiveMsmtPktSize < 64 || cfg->ActiveMsmtPktSize > 1470) {
        snprintf(msg, sizeof(msg), "Invalid Packet size [%d]bytes. Expected in range [64..1470]",
            cfg->ActiveMsmtPktSize);
        goto Error;
    }

    for (unsigned int i = 0; i < MAX_STEP_COUNT; i++) {
        len = strlen((char *) cfg->Step[i].DestMac);

        /* MAC could be 0 or XXXXXXXXXXXX */
        if (len != 0 && len != MAC_ADDRESS_LENGTH - 1) {
            snprintf(msg, sizeof(msg), "Invalid MAC address [%s]", cfg->Step[i].DestMac);
            active_msmt_report_error(__func__, cfg->PlanId, &cfg->Step[i], msg, ACTIVE_MSMT_STATUS_WRONG_ARG);
            active_msmt_set_step_status(__func__, i, ACTIVE_MSMT_STEP_INVALID);
            continue;
        }

        if (cfg->Step[i].StepId < 0 || cfg->Step[i].StepId > INT_MAX) {
            snprintf(msg, sizeof(msg), "Invalid StepID [%d]. Expected in range [0..INT_MAX]", cfg->Step[i].StepId);
            active_msmt_report_error(__func__, cfg->PlanId, &cfg->Step[i], msg, ACTIVE_MSMT_STATUS_WRONG_ARG);
            active_msmt_set_step_status(__func__, i, ACTIVE_MSMT_STEP_INVALID);
            continue;
        }
    }

    SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SUCCEED);

    return RETURN_OK;

Error:
    active_msmt_report_all_steps(cfg, msg, ACTIVE_MSMT_STATUS_WRONG_ARG);

    return RETURN_ERR;
}

static bool active_msmt_step_inst_is_configured(char *dst_mac)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_t *cfg = &g_active_msmt->active_msmt;

    for (unsigned int i = 0; i < MAX_STEP_COUNT; i++) {
        if (strlen((char *)cfg->Step[i].DestMac) != 0) {
            char mac[MAC_ADDRESS_LENGTH] = {};

            snprintf(mac, sizeof(mac), MAC_FMT_TRIMMED, MAC_ARG(cfg->Step[i].DestMac));

            if (strcasecmp(dst_mac, mac) == 0) {
                active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d: MAC [%s] is configured at Step:%d\n", __func__, __LINE__, dst_mac, i);
                return true;
            }
        }
    }

    return false;
}

static unsigned int active_msmt_step_inst_get_available(unsigned int StepIns)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_t *cfg = &g_active_msmt->active_msmt;

    if (strlen((char *)cfg->Step[StepIns].DestMac) == 0) {
        return StepIns;
    }

    for (unsigned int i = StepIns + 1; i < MAX_STEP_COUNT; i++) {
        if (strlen((char *) cfg->Step[i].DestMac) == 0) {
            return i;
        }
    }

    return StepIns;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : SetActiveMsmtStepID                                           */
/*                                                                               */
/* DESCRIPTION   : This function set the Step Identifier configured for          */
/*                 Active Measurement                                            */
/*                                                                               */
/* INPUT         : StepId - Step Identifier                                      */
/*                 StepIns - Step Instance                                       */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void SetActiveMsmtStepID(unsigned int StepId, ULONG StepIns)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Active Measurement Step Id Changed to %d for ins : %d\n", __func__, __LINE__,StepId,StepIns);
    g_active_msmt->active_msmt.Step[StepIns].StepId = StepId;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : SetActiveMsmtStepDstMac                                       */
/*                                                                               */
/* DESCRIPTION   : This function set the Step Destination Mac configured for     */
/*                 Active Measurement                                            */
/*                                                                               */
/* INPUT         : DstMac - Step Destination Mac                                 */
/*                 StepIns - Step Instance                                       */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void SetActiveMsmtStepDstMac(char *DstMac, ULONG StepIns)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    mac_address_t bmac;
    int i;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    active_msmt_t *cfg = &g_active_msmt->active_msmt;
    wifi_ctrl_t *ctrl = &mgr->ctrl;

    if (cfg->StepInstance[StepIns] == ACTIVE_MSMT_STEP_INVALID) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Active Measurement Step: %d is invalid. Skipping...\n",
            __func__, __LINE__, StepIns);
        return;
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Active Measurement Step Destination Mac changed to %s for step ins : %d\n", __func__, __LINE__,DstMac,StepIns);

    blaster_str_to_mac_bytes(DstMac, bmac);
    cfg->Step[StepIns].ApIndex = -1;

    memset(cfg->Step[StepIns].DestMac, 0, sizeof(mac_address_t));
    memcpy(cfg->Step[StepIns].DestMac, bmac, sizeof(mac_address_t));

    active_msmt_set_step_status(__func__, StepIns, ACTIVE_MSMT_STEP_PENDING);

    for (i = 0; i < (int)getTotalNumberVAPs(); i++) {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, i);

        if (is_blaster_device_associated(vap_index, bmac)  == true) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: found client %s on ap %d\n", __func__, __LINE__, DstMac,vap_index);
            cfg->Step[StepIns].ApIndex = vap_index;
            return;
        }
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: client %s not found \n", __func__, __LINE__, DstMac);

    if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        char msg[256] = {};

        snprintf(msg, sizeof(msg), "Failed to find MAC in STA associated list");
        active_msmt_report_error(__func__, cfg->PlanId, &cfg->Step[StepIns], msg, ACTIVE_MSMT_STATUS_NO_CLIENT);

        /* Set status as succeed back to be able to procceed other Steps */
        SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SUCCEED);
    } else {

        g_active_msmt->curStepData.ApIndex = -1;
        g_active_msmt->curStepData.StepId = cfg->Step[StepIns].StepId;
        memcpy(g_active_msmt->curStepData.DestMac, cfg->Step[StepIns].DestMac, sizeof(mac_address_t));

        /*
        * process_active_msmt_diagnostics and stream_client_msmt_data, both has mutex lock *
        * and unlock.  If anything entered this critical region with holding mutex lock,   *
        * then its waiting to unlock causing infinite loop.  To avoid this loop, we are    *
        * unlocking mutex for the critical region code.                                    *
        */
        pthread_mutex_unlock(&g_active_msmt->lock);
        process_active_msmt_diagnostics(cfg->Step[StepIns].ApIndex);
        stream_client_msmt_data(true);
        pthread_mutex_lock(&g_active_msmt->lock);
    }

    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d no need to start pktgen for offline client: %s\n" ,__FUNCTION__, __LINE__, DstMac);
    active_msmt_set_step_status(__func__, StepIns, ACTIVE_MSMT_STEP_INVALID);
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : SetActiveMsmtStepSrcMac                                       */
/*                                                                               */
/* DESCRIPTION   : This function set the Step Source Mac configured for          */
/*                 Active Measurement                                            */
/*                                                                               */
/* INPUT         : SrcMac - Step Source Mac                                      */
/*                 StepIns - Step Instance                                       */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void SetActiveMsmtStepSrcMac(char *SrcMac, ULONG StepIns)
{
    mac_address_t bmac;
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Active Measurement Step Src Mac changed to %s for ins : %d\n", __func__, __LINE__,SrcMac,StepIns);
    blaster_str_to_mac_bytes(SrcMac, bmac);
    memset(g_active_msmt->active_msmt.Step[StepIns].SrcMac, 0, sizeof(mac_address_t));
    memcpy(g_active_msmt->active_msmt.Step[StepIns].SrcMac, bmac, sizeof(mac_address_t));
}

static void active_msmt_queue_push(active_msmt_queue_t **q, active_msmt_t *data)
{
    active_msmt_queue_t **it = q;

    for (; it && *it; it = &(*it)->next);

    if ((*it = calloc(1, sizeof(active_msmt_queue_t))) == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s:%d Unable to allocate memory!\n", __func__, __LINE__);
        return;
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Pushing [%s] to queue\n", __func__, __LINE__, data->PlanId);
    memcpy(&(*it)->data, data, sizeof(active_msmt_t));
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : GetActiveMsmtPktSize                                          */
/*                                                                               */
/* DESCRIPTION   : This function returns the size of the packet configured       */
/*                 for Active Measurement                                        */
/*                                                                               */
/* INPUT         : NONE                                                          */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : size of the packet                                            */
/*                                                                               */
/*********************************************************************************/

unsigned int GetActiveMsmtPktSize()
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    return g_active_msmt->active_msmt.ActiveMsmtPktSize;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : GetActiveMsmtSampleDuration                                   */
/*                                                                               */
/* DESCRIPTION   : This function returns the duration between the samples        */
/*                 configured for Active Measurement                             */
/*                                                                               */
/* INPUT         : NONE                                                          */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : duration between samples                                      */
/*                                                                               */
/*********************************************************************************/

unsigned int GetActiveMsmtSampleDuration()
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    return g_active_msmt->active_msmt.ActiveMsmtSampleDuration;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : GetActiveMsmtNumberOfSamples                                  */
/*                                                                               */
/* DESCRIPTION   : This function returns the count of samples configured         */
/*                 for Active Measurement                                        */
/*                                                                               */
/* INPUT         : NONE                                                          */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : Sample count                                                  */
/*                                                                               */
/*********************************************************************************/

unsigned int GetActiveMsmtNumberOfSamples()
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    return g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples;
}
/* Active Measurement Step & Plan GET calls */

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : GetActiveMsmtStepID                                           */
/*                                                                               */
/* DESCRIPTION   : This function returns the Step Identifier configured          */
/*                 for Active Measurement                                        */
/*                                                                               */
/* INPUT         : NONE                                                          */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : Step Identifier                                               */
/*                                                                               */
/*********************************************************************************/
unsigned int GetActiveMsmtStepID()
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    return g_active_msmt->curStepData.StepId;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : GetActiveMsmtPlanID                                           */
/*                                                                               */
/* DESCRIPTION   : This function returns the Plan Id configured for              */
/*                 Active Measurement                                            */
/*                                                                               */
/* INPUT         : pPlanId                                                       */
/*                                                                               */
/* OUTPUT        : Plan ID                                                       */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/
void GetActiveMsmtPlanID(unsigned int *pPlanID)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    if (pPlanID != NULL) {
        memcpy(pPlanID, g_active_msmt->active_msmt.PlanId, strlen((char *)g_active_msmt->active_msmt.PlanId));
    }
    return;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : GetActiveMsmtStepSrcMac                                       */
/*                                                                               */
/* DESCRIPTION   : This function returns the Step Source Mac configured for      */
/*                 Active Measurement                                            */
/*                                                                               */
/* INPUT         : pStepSrcMac                                                   */
/*                                                                               */
/* OUTPUT        : Step Source Mac                                               */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/
void GetActiveMsmtStepSrcMac(mac_address_t pStepSrcMac)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    if (pStepSrcMac != NULL) {
        memcpy(pStepSrcMac, g_active_msmt->curStepData.SrcMac, sizeof(mac_address_t));
    }
    return;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : GetActiveMsmtStepDestMac                                      */
/*                                                                               */
/* DESCRIPTION   : This function returns the Step Destination Mac configured for */
/*                 Active Measurement                                            */
/*                                                                               */
/* INPUT         : pStepDstMac                                                   */
/*                                                                               */
/* OUTPUT        : Step Destination Mac                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/
void GetActiveMsmtStepDestMac(mac_address_t pStepDstMac)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    if (pStepDstMac != NULL) {
        memcpy(pStepDstMac, g_active_msmt->curStepData.DestMac, sizeof(mac_address_t));
    }
    return;
}


/* Active Measurement SET Calls */

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : SetActiveMsmtEnable                                           */
/*                                                                               */
/* DESCRIPTION   : This function set the status of Active Measurement            */
/*                                                                               */
/* INPUT         : enable - flag to enable/ disable Active Measurement           */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void SetActiveMsmtEnable(bool enable)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_log_message(BLASTER_INFO_LOG, "%s:%d: changing the Active Measurement Flag to %s\n", __func__, __LINE__,(enable ? "true" : "false"));
    g_active_msmt->active_msmt.ActiveMsmtEnable = enable;
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : SetActiveMsmtPlanID                                           */
/*                                                                               */
/* DESCRIPTION   : This function set the Plan Identifier configured for          */
/*                 Active Measurement                                            */
/*                                                                               */
/* INPUT         : pPlanID - Plan Idetifier                                      */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void SetActiveMsmtPlanID(char *pPlanID)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    if (pPlanID == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d pPlanID is NULL\n", __func__, __LINE__);
        return;
    }

    unsigned int planid_len = 0;
    planid_len = strlen(pPlanID);
    if (planid_len > PLAN_ID_LENGTH) { 
        wifi_util_error_print(WIFI_BLASTER, "%s:%d Plan ID is not in range\n", __func__, __LINE__);
        return;
    }

    memset((char *)g_active_msmt->active_msmt.PlanId, '\0', PLAN_ID_LENGTH);
    strncpy((char *)g_active_msmt->active_msmt.PlanId, pPlanID,planid_len);
    g_active_msmt->active_msmt.PlanId[strlen((char *)g_active_msmt->active_msmt.PlanId)] = '\0';

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Plan id updated as %s\n", __func__, __LINE__, (char *)g_active_msmt->active_msmt.PlanId);
}


/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : SetBlasterMqttTopic                                           */
/*                                                                               */
/* DESCRIPTION   : This function set the MQTT topic configured for               */
/*                 Blaster                                                       */
/*                                                                               */
/* INPUT         : BlasterMqttTopic - MQTT Topic for Blaster                     */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void SetBlasterMqttTopic(char *mqtt_topic)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    if (mqtt_topic == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d MQTT Topic is NULL\n", __func__, __LINE__);
        return;
    }
    unsigned int mqtt_len = 0;
    mqtt_len = strlen(mqtt_topic);
    if (mqtt_len > MAX_MQTT_TOPIC_LEN) {
        wifi_util_error_print(WIFI_BLASTER, "%s:%d MQTT Topic length is not in range\n", __func__, __LINE__);
        return;
    }
    memset(g_active_msmt->active_msmt.blaster_mqtt_topic, '\0', MAX_MQTT_TOPIC_LEN);

    strncpy((char *)g_active_msmt->active_msmt.blaster_mqtt_topic, mqtt_topic, mqtt_len);
    g_active_msmt->active_msmt.blaster_mqtt_topic[strlen((char *)g_active_msmt->active_msmt.blaster_mqtt_topic)] = '\0';
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Active Measurement topic changed %s\n", __func__, __LINE__, g_active_msmt->active_msmt.blaster_mqtt_topic);
}

void SetActiveMsmtStatus(const char *func, active_msmt_status_t status)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "%s: active msmt status changed %s -> %s\n", func,
        active_msmt_status_to_str(g_active_msmt->status), active_msmt_status_to_str(status));
    g_active_msmt->status = status;
}

void ResetActiveMsmtStepInstances(void)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_t *cfg = &g_active_msmt->active_msmt;

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Reseting active msmt step instances\n", __func__, __LINE__);

    for (int StepCount = 0; StepCount < MAX_STEP_COUNT; StepCount++) {
        cfg->StepInstance[StepCount] = ACTIVE_MSMT_STEP_DONE;
        memset(&cfg->Step[StepCount], 0, sizeof(active_msmt_step_t));
    }
}

#if defined (_PP203X_PRODUCT_REQ_)
static void convert_channel_width_to_str(wifi_channelBandwidth_t cw, char *str, size_t len)
{
    static const char arr_str[][8] =
    {
        "20",
        "40",
        "80",
        "160",
#ifdef CONFIG_IEEE80211BE
        "320",
#endif /* CONFIG_IEEE80211BE */
    };
    static const wifi_channelBandwidth_t arr_enum[] =
    {
        WIFI_CHANNELBANDWIDTH_20MHZ,
        WIFI_CHANNELBANDWIDTH_40MHZ,
        WIFI_CHANNELBANDWIDTH_80MHZ,
        WIFI_CHANNELBANDWIDTH_160MHZ,
#ifdef CONFIG_IEEE80211BE
        WIFI_CHANNELBANDWIDTH_320MHZ,
#endif /* CONFIG_IEEE80211BE */
    };

    for (size_t i = 0; i < ARRAY_SIZE(arr_enum); i++) {
        if (arr_enum[i] == cw) {
            snprintf(str, len, "%s", arr_str[i]);
            break;
        }
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d %d converted to %s\n",__func__,__LINE__, cw, str);
}

static void convert_variant_to_str(wifi_ieee80211Variant_t variant, char *str, size_t len)
{
    static const char arr_str[][8] =
    {
        "a",
        "b",
        "g",
        "n",
        "ac",
        "ax",
#ifdef CONFIG_IEEE80211BE
        "be",
#endif /* CONFIG_IEEE80211BE */
    };
    static const wifi_ieee80211Variant_t arr_enum[] =
    {
        WIFI_80211_VARIANT_A,
        WIFI_80211_VARIANT_B,
        WIFI_80211_VARIANT_G,
        WIFI_80211_VARIANT_N,
        WIFI_80211_VARIANT_AC,
        WIFI_80211_VARIANT_AX,
#ifdef CONFIG_IEEE80211BE
        WIFI_80211_VARIANT_BE,
#endif /* CONFIG_IEEE80211BE */
    };

    for (size_t i = 0; i < ARRAY_SIZE(arr_enum); i++) {
        if ((arr_enum[i] & variant) == arr_enum[i]) {
            snprintf(str, len, "%s,", arr_str[i]);
        }
    }

    str[strlen(str) - 1] = '\0';
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d 0x%X converted to %s\n",__func__,__LINE__, variant, str);
}
#endif // _PP203X_PRODUCT_REQ_

static bool DeviceMemory_DataGet(uint32_t *util_mem)
{
    const char *filename = LINUX_PROC_MEMINFO_FILE;
    FILE *proc_file = NULL;
    char buf[256] = {'\0'};
    uint32_t mem_total = 0;
    uint32_t mem_free = 0;

    proc_file = fopen(filename, "r");
    if (proc_file == NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER,"Failed opening file: %s\n", filename);
        return false;
    }

    while (fgets(buf, sizeof(buf), proc_file) != NULL)
    {
        if (strncmp(buf, "MemTotal:", strlen("MemTotal:")) == 0)
        {
            if (sscanf(buf, "MemTotal: %u", &mem_total) != 1)
                goto parse_error;
        } else if (strncmp(buf, "MemFree:", strlen("MemFree:")) == 0) {
            if (sscanf(buf, "MemFree: %u", &mem_free) != 1)
                goto parse_error;
        }
    }
    wifi_util_dbg_print(WIFI_BLASTER," Returned MemTotal is %d and MemFree is %d\n", mem_total, mem_free);
    *util_mem = mem_total - mem_free;
    fclose(proc_file);
    return true;

parse_error:
    fclose(proc_file);
    wifi_util_dbg_print(WIFI_BLASTER,"Error parsing %s.\n", filename);
    return false;
}

static bool DeviceLoad_DataGet(active_msmt_resources_t *res)
{
    int32_t     rc;
    const char  *filename = LINUX_PROC_LOADAVG_FILE;
    FILE        *proc_file = NULL;

    proc_file = fopen(filename, "r");
    if (proc_file == NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER,"Parsing device stats (Failed to open %s)\n", filename);
        return false;
    }

    rc = fscanf(proc_file,
            "%lf %lf %lf",
            &res->cpu_one,
            &res->cpu_five,
            &res->cpu_fifteen);

    fclose(proc_file);

    wifi_util_dbg_print(WIFI_BLASTER," Returned %d and Parsed device load %0.2f %0.2f %0.2f\n", rc,
            res->cpu_one,
            res->cpu_five,
            res->cpu_fifteen);

    return true;
}

/* Calculate CPU util during specified period */
static bool active_msmt_calc_cpu_util(unsigned int period, unsigned int *util_cpu)
{
    if (DeviceCpuUtil_DataGet(util_cpu) == false)
        return false;

    sleep(period);

    if (DeviceCpuUtil_DataGet(util_cpu) == false)
        return false;

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Calculated CPU util: %u%%\n", __func__, __LINE__, *util_cpu);

    return true;
}

void SetBlasterTraceContext(char *traceParent, char *traceState)
{
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    if (traceParent == NULL || traceState == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s:%d Trace is NULL\n", __func__, __LINE__);
        return;
    }
    snprintf((char *)g_active_msmt->active_msmt.t_header.traceParent, sizeof(g_active_msmt->active_msmt.t_header.traceParent), "%s", traceParent);
    snprintf((char *)g_active_msmt->active_msmt.t_header.traceState, sizeof(g_active_msmt->active_msmt.t_header.traceState), "%s", traceState);
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Traceparent is:%s and TraceSate:%s \n", __func__, __LINE__,g_active_msmt->active_msmt.t_header.traceParent,g_active_msmt->active_msmt.t_header.traceState);
}


/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : WiFiBlastClient                                               */
/*                                                                               */
/* DESCRIPTION   : This function starts the active measurement process to        */
/*                 start the pktgen and to calculate the throughput for a        */
/*                 particular client                                             */
/*                                                                               */
/* INPUT         : ClientMac - MAC address of the client                         */
/*                 apIndex - AP index                                            */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void WiFiBlastClient(void)
{
    char macStr[18] = {'\0'};
    char *telemetry_buf = NULL;
    unsigned int StepCount = 0;
    int apIndex = 0;
    unsigned int NoOfSamples = 0, oldNoOfSamples = 0;
    wifi_interface_name_t *interface_name = NULL;
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    radio_data_t *radio_stats = NULL;
    wifi_ctrl_t *g_wifi_ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_t *cfg = &g_active_msmt->active_msmt;
    wifi_radio_operationParam_t* radioOperation;
    int radio_index;
    char msg[256] = {};
    wifi_apps_mgr_t *apps_mgr;
    wifi_app_t *wifi_app =  NULL;

    apps_mgr = &g_wifi_ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_blaster);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }
    g_active_msmt->num_req_count = 0;
    g_active_msmt->num_res_count = 0;
    for (StepCount = 0; StepCount < MAX_STEP_COUNT; StepCount++) {

        if (g_active_msmt->num_req_count != g_active_msmt->num_res_count){
            StepCount --;
            continue;
        }

        pthread_mutex_lock(&g_active_msmt->lock);

        if (cfg->ActiveMsmtEnable == false) {
            for (StepCount = StepCount; StepCount < MAX_STEP_COUNT; StepCount++) {
                cfg->StepInstance[StepCount] = ACTIVE_MSMT_STEP_DONE;
            }
            active_msmt_log_message(BLASTER_INFO_LOG, "ActiveMsmtEnable changed from TRUE to FALSE"
                "Setting remaining [%d] step count to 0 and STOPPING further processing\n",
                (MAX_STEP_COUNT - StepCount));
            pthread_mutex_unlock(&g_active_msmt->lock);
            break;
        }

        NoOfSamples = GetActiveMsmtNumberOfSamples();

        if (oldNoOfSamples != NoOfSamples) {
            wifi_app->data.u.blaster.frameCountSample = (pktGenFrameCountSamples *)realloc(wifi_app->data.u.blaster.frameCountSample, (NoOfSamples + 1) * sizeof(pktGenFrameCountSamples));

            if (wifi_app->data.u.blaster.frameCountSample == NULL) {
                wifi_util_error_print(WIFI_BLASTER, "Memory allocation failed for frameCountSample\n");
                pthread_mutex_unlock(&g_active_msmt->lock);
                break;
            }

            memset(wifi_app->data.u.blaster.frameCountSample, 0, (NoOfSamples + 1) * sizeof(pktGenFrameCountSamples));
            oldNoOfSamples = NoOfSamples;
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Size for frameCountSample changed to %d\n", __func__, __LINE__, NoOfSamples);
        }

        if (cfg->StepInstance[StepCount] == ACTIVE_MSMT_STEP_PENDING) {
            mac_address_t bmac;

            wifi_util_dbg_print(WIFI_BLASTER,"%s : %d processing StepCount : %d \n",__func__,__LINE__,StepCount);
            apIndex = cfg->Step[StepCount].ApIndex;

            /*TODO RDKB-34680 CID: 154402,154401  Data race condition*/
            g_active_msmt->curStepData.ApIndex = apIndex;
            wifi_util_error_print(WIFI_BLASTER, "Value of apindex is %d \n", apIndex);
            g_active_msmt->curStepData.StepId = cfg->Step[StepCount].StepId;

            memcpy(g_active_msmt->curStepData.DestMac, cfg->Step[StepCount].DestMac, sizeof(mac_address_t));

            wifi_util_dbg_print(WIFI_BLASTER,"%s:%d copied mac address " MAC_FMT " to current step info\n", __func__, __LINE__,
                MAC_ARG(g_active_msmt->curStepData.DestMac));

            wifi_util_error_print(WIFI_BLASTER, "Value of cfg->Step[StepCount].DestMac is %s\n", cfg->Step[StepCount].DestMac);

            if (isVapEnabled(apIndex) != 0) {
                wifi_util_error_print(WIFI_BLASTER, "ERROR running wifiblaster: Init Failed\n" );
                pthread_mutex_unlock(&g_active_msmt->lock);
                continue;
            }
            bmac[0] = g_active_msmt->curStepData.DestMac[0]; bmac[1] = g_active_msmt->curStepData.DestMac[1];
            bmac[2] = g_active_msmt->curStepData.DestMac[2]; bmac[3] = g_active_msmt->curStepData.DestMac[3];
            bmac[4] = g_active_msmt->curStepData.DestMac[4]; bmac[5] = g_active_msmt->curStepData.DestMac[5];

            wifi_util_error_print(WIFI_BLASTER, "%s: bmac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, bmac[0], bmac[1], bmac[2], bmac[3], bmac[4], bmac[5]);
            /* WiFiBlastClient is derefered task, so client could disconnect
             * before it starts
             */
            if (is_blaster_device_associated(apIndex, bmac) == false) {

                if (g_wifi_ctrl->network_mode == rdk_dev_mode_type_ext) {

                    snprintf(msg, sizeof(msg), "The MAC is disconnected in traffic gen");
                    active_msmt_report_error(__func__, cfg->PlanId, &cfg->Step[StepCount], msg, ACTIVE_MSMT_STATUS_NO_CLIENT);

                    /* Set status as succeed back to be able to procceed other Steps */
                    SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SUCCEED);
                } else {
                    /*
                    * process_active_msmt_diagnostics and stream_client_msmt_data, both has mutex lock *
                    * and unlock.  If anything entered this critical region with holding mutex lock,   *
                    * then its waiting to unlock causing infinite loop.  To avoid this loop, we are    *
                    * unlocking mutex for the critical region code.                                    *
                    */
                    pthread_mutex_unlock(&g_active_msmt->lock);
                    process_active_msmt_diagnostics(apIndex);
                    stream_client_msmt_data(true);
                    pthread_mutex_lock(&g_active_msmt->lock);
                }

                active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d no need to start pktgen for offline client: %s\n" ,__FUNCTION__, __LINE__, (char *)g_active_msmt->curStepData.DestMac);
                active_msmt_set_step_status(__func__, StepCount, ACTIVE_MSMT_STEP_INVALID);
                pthread_mutex_unlock(&g_active_msmt->lock);
                continue;
            }

            if ((radio_index = get_radio_index_for_vap_index(&(get_wifimgr_obj())->hal_cap.wifi_prop, apIndex)) == RETURN_ERR ||
                (radioOperation = getRadioOperationParam(radio_index)) == NULL) {

                active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d Unable to get radio params for %d\n", __func__, __LINE__, radio_index);
                pthread_mutex_unlock(&g_active_msmt->lock);
                continue;
            }
            radio_stats = (radio_data_t *) malloc (sizeof(radio_data_t));
            if (get_dev_stats_for_radio(radio_index, radio_stats) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Error getting radio datas\n", __func__, __LINE__);
                pthread_mutex_unlock(&g_active_msmt->lock);
                continue;
            }
            if (radio_stats->primary_radio_channel != radioOperation->channel) {
                if (g_wifi_ctrl->network_mode == rdk_dev_mode_type_ext) {

                    snprintf(msg, sizeof(msg), "Failed to fill in radio stats");
                    active_msmt_report_error(__func__, cfg->PlanId, &cfg->Step[StepCount], msg, ACTIVE_MSMT_STATUS_FAILED);

                    /* Set status as succeed back to be able to procceed other Steps */
                    SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SUCCEED);
                } else {
                    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Calling process_active_msmt_diagnostics\n", __func__, __LINE__);
                    /*
                    * process_active_msmt_diagnostics and stream_client_msmt_data, both has mutex lock *
                    * and unlock.  If anything entered this critical region with holding mutex lock,   *
                    * then its waiting to unlock causing infinite loop.  To avoid this loop, we are    *
                    * unlocking mutex for the critical region code.                                    *
                    */
                    pthread_mutex_unlock(&g_active_msmt->lock);
                    process_active_msmt_diagnostics(apIndex);
                    stream_client_msmt_data(true);
                    pthread_mutex_lock(&g_active_msmt->lock);
                }

                active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d No radio data for %d channel\n" ,__FUNCTION__, __LINE__, radioOperation->channel);
                active_msmt_set_step_status(__func__, StepCount, ACTIVE_MSMT_STEP_INVALID);
                pthread_mutex_unlock(&g_active_msmt->lock);
                continue;
            }

            if ((interface_name = get_interface_name_for_vap_index(apIndex, &g_wifi_mgr->hal_cap.wifi_prop)) == NULL) {
                wifi_util_error_print(WIFI_BLASTER, "%s:%d Unable to get ifname for %d\n", __func__, __LINE__, apIndex);
                pthread_mutex_unlock(&g_active_msmt->lock);
                continue;
            }

            snprintf(macStr, sizeof(macStr), MAC_FMT, MAC_ARG(g_active_msmt->curStepData.DestMac));

            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d:\n=========START THE TEST=========\n", __func__, __LINE__);
            active_msmt_log_message(BLASTER_DEBUG_LOG, "\n=========START THE TEST=========\n");
            active_msmt_log_message(BLASTER_INFO_LOG, "Blaster test is initiated for Dest mac [%s]\n", macStr);;
            active_msmt_log_message(BLASTER_INFO_LOG, "Interface [%s], Send Duration: [%d msecs], Packet Size: [%d bytes], Sample count: [%d]\n",
                    interface_name, GetActiveMsmtSampleDuration(), GetActiveMsmtPktSize(), GetActiveMsmtNumberOfSamples());

            /* start blasting the packets to calculate the throughput */
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Calling pktGen_BlastClient\n", __func__, __LINE__);
            g_active_msmt->num_req_count ++;
            g_active_msmt->reponse_received = false;
            pktGen_BlastClient(macStr, interface_name);
            telemetry_buf = malloc(sizeof(char)*1024);
            if (telemetry_buf == NULL) {
                wifi_util_error_print(WIFI_BLASTER,"%s:%d telemetry_buf allocation failed\r\n", __func__, __LINE__);
                if (radio_stats != NULL) {
                    free(radio_stats);
                    radio_stats = NULL;
                }
                pthread_mutex_unlock(&g_active_msmt->lock);
                return;
            }
            memset(telemetry_buf, 0, sizeof(char)*1024);
            snprintf(telemetry_buf, sizeof(char)*1024, "%s %s",g_active_msmt->active_msmt.t_header.traceParent, g_active_msmt->active_msmt.t_header.traceState);
            get_stubs_descriptor()->t2_event_s_fn("TRACE_WIFIBLAST_STARTS", telemetry_buf);

            if (g_active_msmt->status == ACTIVE_MSMT_STATUS_SUCCEED) {
                active_msmt_set_status_desc(__func__, cfg->PlanId, cfg->Step[StepCount].StepId,
                    cfg->Step[StepCount].DestMac, NULL);
            }
            cfg->StepInstance[StepCount] = ACTIVE_MSMT_STEP_DONE;
        }
        pthread_mutex_unlock(&g_active_msmt->lock);
    }

    if ((wifi_app->data.u.blaster.frameCountSample) != NULL) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s : %d freeing memory for frameCountSample \n",__func__,__LINE__);
        free(wifi_app->data.u.blaster.frameCountSample);
        wifi_app->data.u.blaster.frameCountSample = NULL;
    }

    if (g_wifi_ctrl->network_mode == rdk_dev_mode_type_ext) {
        g_wifi_mgr->ctrl.webconfig_state |= ctrl_webconfig_state_blaster_cfg_complete_rsp_pending;
        wifi_util_dbg_print(WIFI_BLASTER, "%s : %d  Extender Mode Activated. Updated the blaster state as complete\n", __func__, __LINE__);
    }

    if (radio_stats != NULL) {
        free(radio_stats);
        radio_stats = NULL;
    }
    if (telemetry_buf != NULL) {
        free(telemetry_buf);
        telemetry_buf = NULL;
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s : %d exiting the function\n",__func__,__LINE__);
}

static void *active_msmt_worker(void *ctx)
{
    int oldcanceltype;
    char *telemetry_buf = NULL;
    active_msmt_t *cfg;
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_queue_t *it = g_active_msmt->queue;
    active_msmt_t *act_msmt = &g_active_msmt->active_msmt;
    active_msmt_status_t status;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    wifi_ctrl_t *ctrl = &mgr->ctrl;
    char msg[256] = {};
    bool report = false;

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldcanceltype);
    UNREFERENCED_PARAMETER(ctx);

    pthread_mutex_lock(&g_active_msmt->lock);
    g_active_msmt->is_running = true;
    wifi_monitor_data_t *data;
    data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_BLASTER,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        pthread_mutex_unlock(&g_active_msmt->lock);
        return NULL;
    }
    memset(data, 0, sizeof(wifi_monitor_data_t));
    strncpy((char *) data->u.msg.data, "active_msmt started", sizeof(MAX_FRAME_SZ)-1);
    push_event_to_monitor_queue(data, wifi_event_monitor_started_active_msmt, NULL);
    pthread_mutex_unlock(&g_active_msmt->lock);

    while (true) {

        pthread_mutex_lock(&g_active_msmt->lock);

        if (it == NULL) {
            g_active_msmt->is_running = false;
            memset(data, 0, sizeof(wifi_monitor_data_t));
            strncpy((char *) data->u.msg.data, "active_msmt stoped", sizeof(MAX_FRAME_SZ)-1);
            push_event_to_monitor_queue(data, wifi_event_monitor_stop_active_msmt, NULL);
            telemetry_buf = malloc(sizeof(char)*1024);
            if (telemetry_buf == NULL) {
                wifi_util_error_print(WIFI_BLASTER,"%s:%d telemetry_buf allocation failed\r\n", __func__, __LINE__);
                if (data != NULL) {
                    free(data);
                    data = NULL;
                }
                pthread_mutex_unlock(&g_active_msmt->lock);
                return NULL;
            }
            memset(telemetry_buf, 0, sizeof(char)*1024);
            snprintf(telemetry_buf, sizeof(char)*1024, "%s %s",g_active_msmt->active_msmt.t_header.traceParent, g_active_msmt->active_msmt.t_header.traceState);
            get_stubs_descriptor()->t2_event_s_fn("TRACE_WIFIBLAST_NOT_ENABLED", telemetry_buf);
            wifi_util_dbg_print(WIFI_BLASTER,"%s:%d blast is disabled\n", __func__, __LINE__);
            if (telemetry_buf != NULL) {
                free(telemetry_buf);
                telemetry_buf = NULL;
            }
            pthread_mutex_unlock(&g_active_msmt->lock);
            break;
        }

        cfg = &it->data;
        telemetry_buf = malloc(sizeof(char)*1024);
        if (telemetry_buf == NULL) {
            wifi_util_error_print(WIFI_BLASTER,"%s:%d telemetry_buf allocation failed\r\n", __func__, __LINE__);
            if (data != NULL) {
                free(data);
                data = NULL;
            }
            pthread_mutex_unlock(&g_active_msmt->lock);
            return NULL;
        }
        memset(telemetry_buf, 0, sizeof(char)*1024);
        wifi_util_info_print(WIFI_BLASTER, "active_msmt_worker: trace headers are %s and %s \n",cfg->t_header.traceParent, cfg->t_header.traceState);
        SetBlasterTraceContext(cfg->t_header.traceParent, cfg->t_header.traceState);
        snprintf(telemetry_buf, sizeof(char)*1024, "%s %s",g_active_msmt->active_msmt.t_header.traceParent, g_active_msmt->active_msmt.t_header.traceState);
        get_stubs_descriptor()->t2_event_s_fn("TRACE_WIFIBLAST_ENABLED", telemetry_buf);
        wifi_util_dbg_print(WIFI_BLASTER,"%s:%d blast is enabled\n", __func__, __LINE__);
        if (telemetry_buf != NULL) {
            free(telemetry_buf);
            telemetry_buf = NULL;
        }
        SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SUCCEED);
        ResetActiveMsmtStepInstances();

        if (ctrl->network_mode == rdk_dev_mode_type_ext) {

            if (ActiveMsmtConfValidation(cfg) != RETURN_OK) {
                wifi_util_error_print(WIFI_BLASTER, "%s:%d Active measurement conf is invalid!\n", __func__, __LINE__);
                mgr->ctrl.webconfig_state |= ctrl_webconfig_state_blaster_cfg_complete_rsp_pending;

                g_active_msmt->queue = it->next;
                free(it);
                it = g_active_msmt->queue;

                pthread_mutex_unlock(&g_active_msmt->lock);
                continue;
            }

            SetActiveMsmtSampleDuration(cfg->ActiveMsmtSampleDuration / cfg->ActiveMsmtNumberOfSamples);
            SetBlasterMqttTopic((char *)cfg->blaster_mqtt_topic);
        } else {
            SetActiveMsmtSampleDuration(cfg->ActiveMsmtSampleDuration);
        }

        SetActiveMsmtPktSize(cfg->ActiveMsmtPktSize);
        SetActiveMsmtNumberOfSamples(cfg->ActiveMsmtNumberOfSamples);
        SetActiveMsmtPlanID((char *)cfg->PlanId);
        wifi_util_info_print(WIFI_BLASTER, "active_msmt_worker: trace headers are %s and %s \n",cfg->t_header.traceParent, cfg->t_header.traceState);
        SetBlasterTraceContext(cfg->t_header.traceParent, cfg->t_header.traceState);
        wifi_util_info_print(WIFI_BLASTER, "Done Setting SetBlasterTraceContext\n");

        for (unsigned int i = 0; i < MAX_STEP_COUNT; i++) {
            if(strlen((char *) cfg->Step[i].DestMac) != 0) {
                SetActiveMsmtStepID(cfg->Step[i].StepId, i);
                SetActiveMsmtStepDstMac((char *)cfg->Step[i].DestMac, i);
                SetActiveMsmtStepSrcMac((char *)cfg->Step[i].SrcMac, i);
            }
        }

        SetActiveMsmtEnable(cfg->ActiveMsmtEnable);

        if (DeviceMemory_DataGet(&act_msmt->ActiveMsmtResources.util_mem) != true ||
            DeviceLoad_DataGet(&act_msmt->ActiveMsmtResources) != true ||
            active_msmt_calc_cpu_util(WIFI_BLASTER_CPU_CALC_PERIOD, &act_msmt->ActiveMsmtResources.util_cpu) != true) {

            snprintf(msg, sizeof(msg), "Failed to fill in health stats");
            status = ACTIVE_MSMT_STATUS_FAILED;
            report = true;

        } else if (act_msmt->ActiveMsmtResources.util_cpu > WIFI_BLASTER_CPU_THRESHOLD) {

            snprintf(msg, sizeof(msg), "Skip because of high CPU usage [%u]%%. Threshold [%d]%%",
                act_msmt->ActiveMsmtResources.util_cpu, WIFI_BLASTER_CPU_THRESHOLD);
            status = ACTIVE_MSMT_STATUS_BUSY;
            report = true;

        } else if (act_msmt->ActiveMsmtResources.util_mem < WIFI_BLASTER_MEM_THRESHOLD) {

            snprintf(msg, sizeof(msg), "Skip because of low free RAM memory [%u]KB.  Threshold [%d]KB",
                act_msmt->ActiveMsmtResources.util_mem, WIFI_BLASTER_MEM_THRESHOLD);
            status = ACTIVE_MSMT_STATUS_BUSY;
            report = true;
        }

        if (report == true) {

            if (ctrl->network_mode == rdk_dev_mode_type_ext) {
                active_msmt_report_all_steps(cfg, msg, status);
            }

            active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d %s\n" ,__FUNCTION__, __LINE__, msg);
            mgr->ctrl.webconfig_state |= ctrl_webconfig_state_blaster_cfg_complete_rsp_pending;

            g_active_msmt->queue = it->next;
            free(it);
            it = g_active_msmt->queue;
            report = false;

            pthread_mutex_unlock(&g_active_msmt->lock);
            continue;
        }

        pthread_mutex_unlock(&g_active_msmt->lock);

        active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d Starting to proceed PlanId [%s]\n", __func__, __LINE__, cfg->PlanId);
        WiFiBlastClient();

        pthread_mutex_lock(&g_active_msmt->lock);
        g_active_msmt->queue = it->next;
        free(it);
        it = g_active_msmt->queue;
        pthread_mutex_unlock(&g_active_msmt->lock);
    }

    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d Exit\n", __func__, __LINE__);

    free(data);
    data = NULL;
    return NULL;
}

static int push_blaster_config_event_to_monitor_queue(wifi_mon_stats_request_state_t state)
{
    // Send appropriate configs to monitor queue(stats, radio)
    wifi_monitor_data_t *data;
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    wifi_util_dbg_print(WIFI_BLASTER, "Entering %s\n", __func__);
    data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_BLASTER,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(data, 0, sizeof(wifi_monitor_data_t));
    data->u.mon_stats_config.req_state = state;
    data->u.mon_stats_config.inst = wifi_app_inst_blaster;
    data->u.mon_stats_config.args.vap_index = g_active_msmt->curStepData.ApIndex;
    wifi_util_error_print(WIFI_BLASTER,"%s:%d Blaster config values vap_index = %d\n", __func__, __LINE__, g_active_msmt->curStepData.ApIndex);
    config_sample_blaster(data);

    if (NULL != data) {
        free(data);
        data = NULL;
    }
    return RETURN_OK;
}

static void blaster_route(wifi_event_route_t *route)
{
    memset(route, 0, sizeof(wifi_event_route_t));
    route->dst = wifi_sub_component_mon;
    route->u.inst_bit_map = wifi_app_inst_blaster;
}

static void config_sample_blaster(wifi_monitor_data_t *data)
{
    wifi_event_route_t route;
    wifi_util_error_print(WIFI_BLASTER, "Entering %s\n", __func__);
    blaster_route(&route);
    data->u.mon_stats_config.data_type = mon_stats_type_associated_device_stats;
    data->u.mon_stats_config.interval_ms = GetActiveMsmtSampleDuration();
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Interval is %lu\n", __func__, __LINE__, data->u.mon_stats_config.interval_ms);
    data->u.mon_stats_config.args.app_info = blaster_app_sample_blaster;
    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
}

/*********************************************************************************/
/*                                                                               */
/* FUNCTION NAME : pktGen_BlastClient                                            */
/*                                                                               */
/* DESCRIPTION   : This function uses the pktgen utility and calculates the      */
/*                 throughput                                                    */
/*                                                                               */
/* INPUT         : vargp - ptr to variable arguments                             */
/*                                                                               */
/* OUTPUT        : NONE                                                          */
/*                                                                               */
/* RETURN VALUE  : NONE                                                          */
/*                                                                               */
/*********************************************************************************/

void pktGen_BlastClient (char *dst_mac, wifi_interface_name_t *ifname)
{
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Entered in \n", __func__, __LINE__);
    wifi_ctrl_t *ctrl = get_wifictrl_obj();
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    char msg[256] = {};
    active_msmt_step_t *step = &g_active_msmt->curStepData;
    radio_data_t *radio_stats[MAX_NUM_RADIOS];
    wifi_apps_mgr_t *apps_mgr;
    wifi_app_t *wifi_app =  NULL;

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        g_active_msmt->num_res_count++;
        return;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_blaster);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        g_active_msmt->num_res_count++;
        return;
    }

    for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        radio_stats[radio_index] = (radio_data_t *) malloc (sizeof(radio_data_t));
        memset(radio_stats[radio_index],0, sizeof(radio_data_t));
        if (get_dev_stats_for_radio(radio_index, (radio_data_t *)radio_stats[radio_index]) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Error getting radio datas\n", __func__, __LINE__);
            continue;
        }
    }

    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d Start pktGen utility and analyse received samples for active clients [" MAC_FMT_TRIMMED "]\n",
        __FUNCTION__, __LINE__,  MAC_ARG(g_active_msmt->curStepData.DestMac));


#if defined (DUAL_CORE_XB3)
    wifi_setClientDetailedStatisticsEnable(getRadioIndexFromAp(index), TRUE);
#endif

    if (onewifi_pktgen_start_wifi_blast((char *)ifname, dst_mac, GetActiveMsmtPktSize()) != ONEWIFI_PKTGEN_STATUS_SUCCEED) {

        snprintf(msg, sizeof(msg), "Failed to run Traffic generator");

        if (ctrl->network_mode == rdk_dev_mode_type_ext) {

            SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_FAILED);
            active_msmt_set_status_desc(__func__, g_active_msmt->active_msmt.PlanId, step->StepId, step->DestMac, msg);
        }

        active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d %s\n", __func__, __LINE__, msg);
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if (radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        g_active_msmt->num_res_count++;
        return;
    }

    /* allocate memory for the dynamic variables */
    g_active_msmt->active_msmt_data = (active_msmt_data_t *)calloc(GetActiveMsmtNumberOfSamples() + 1, sizeof(active_msmt_data_t));

    if (g_active_msmt->active_msmt_data == NULL) {
#if defined (DUAL_CORE_XB3)
        wifi_setClientDetailedStatisticsEnable(getRadioIndexFromAp(index), FALSE);
#endif
        active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d  ERROR> Memory allocation failed for active_msmt_data\n", __func__, __LINE__);
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if (radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        g_active_msmt->num_res_count++;
        return;
    }
    push_blaster_config_event_to_monitor_queue(mon_stats_request_state_start);
    wifi_app->data.u.blaster.blaster_start = getCurrentTimeInMicroSeconds();
    WaitForDuration(((g_active_msmt->active_msmt.ActiveMsmtSampleDuration) * (g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples + 2)) + (5 * WIFI_BLASTER_POST_STEP_TIMEOUT));

    if (g_active_msmt->num_res_count != g_active_msmt->num_req_count && (g_active_msmt->reponse_received == false)) {
        push_blaster_config_event_to_monitor_queue(mon_stats_request_state_stop);
        if (onewifi_pktgen_stop_wifi_blast() != RETURN_OK) {
            wifi_util_error_print(WIFI_BLASTER, "%s:%d: Failed to stop pktgen\n", __FUNCTION__, __LINE__);
        }
        g_active_msmt->num_res_count = g_active_msmt->num_req_count;
    }

    for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        if (radio_stats[radio_index] != NULL){
            free(radio_stats[radio_index]);
            radio_stats[radio_index] = NULL;
        }
    }
    return;
}

static void sample_blaster(wifi_provider_response_t *provider_response)
{
    mac_address_t bmac;
    wifi_associated_dev3_t *dev_conn = NULL;
    sta_data_t *assoc_stats = NULL;
    bool is_associated = false;
    wifi_ctrl_t *ctrl = get_wifictrl_obj();
    char msg[256] = {};
    assoc_stats = (sta_data_t *) provider_response->stat_pointer;
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_step_t *step = &g_active_msmt->curStepData;
    unsigned int *SampleCount = get_sample_count();
    wifi_apps_mgr_t *apps_mgr;
    wifi_app_t *wifi_app =  NULL;
#ifndef CCSP_COMMON
    int sleep_mode = 0;
    int wakeup_cnt = 0;
    unsigned long prevSentAck = 0;
#endif

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        g_active_msmt->num_res_count++;
        return;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_blaster);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        g_active_msmt->num_res_count++;
        return;
    }

    int index = g_active_msmt->curStepData.ApIndex;
    int radio_index = get_radio_index_for_vap_index(&(get_wifimgr_obj())->hal_cap.wifi_prop, index);
#if defined (_PP203X_PRODUCT_REQ_)
    wifi_radio_operationParam_t* radioOperation = NULL;
    radioOperation = getRadioOperationParam(radio_index);
#endif //_PP203X_PRODUCT_REQ_

    bmac[0] = g_active_msmt->curStepData.DestMac[0]; bmac[1] = g_active_msmt->curStepData.DestMac[1];
    bmac[2] = g_active_msmt->curStepData.DestMac[2]; bmac[3] = g_active_msmt->curStepData.DestMac[3];
    bmac[4] = g_active_msmt->curStepData.DestMac[4]; bmac[5] = g_active_msmt->curStepData.DestMac[5];

    wifi_util_error_print(WIFI_BLASTER, "%s: bmac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, bmac[0], bmac[1], bmac[2], bmac[3], bmac[4], bmac[5]);
    wifi_util_error_print(WIFI_BLASTER, "%s: sample count is %d and total number of sampls given %d\n", __func__, *SampleCount, GetActiveMsmtNumberOfSamples());

    /* sampling */

if ( *SampleCount <= (GetActiveMsmtNumberOfSamples())) {

#ifdef CCSP_COMMON
    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s : %d WIFI_HAL enabled, calling wifi_getApAssociatedClientDiagnosticResult\n",__func__,__LINE__);
#endif // CCSP_COMMON

    if (radio_index != RETURN_ERR) {
        wifi_util_error_print(WIFI_BLASTER, "%s: bmac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, bmac[0], bmac[1], bmac[2], bmac[3], bmac[4], bmac[5]);
        wifi_util_error_print(WIFI_BLASTER, "%s: provider_response->stat_array_size %u\n", __func__, provider_response->stat_array_size);
        for (unsigned int count = 0; count < provider_response->stat_array_size; count++) {
            wifi_util_error_print(WIFI_BLASTER, "%s: provider mac is %02x:%02x:%02x:%02x:%02x:%02x \n", __func__, assoc_stats[count].sta_mac[0], assoc_stats[count].sta_mac[1],
                assoc_stats[count].sta_mac[2], assoc_stats[count].sta_mac[3], assoc_stats[count].sta_mac[4], assoc_stats[count].sta_mac[5]);
            if (!memcmp(bmac, assoc_stats[count].sta_mac, sizeof(mac_address_t))) {
                is_associated = true;
                dev_conn = &assoc_stats[count].dev_stats;
                g_active_msmt->reponse_received = TRUE;
#ifndef CCSP_COMMON
                sleep_mode = assoc_stats[count].sleep_mode;
#endif //CCSP_COMMON
                wifi_util_error_print(WIFI_BLASTER, "%s: bmac is %02x:%02x:%02x:%02x:%02x:%02x found \n", __func__, bmac[0], bmac[1], bmac[2], bmac[3], bmac[4], bmac[5]);
                break;
            }
        }
        if(is_associated){
            is_associated = false;
#ifndef CCSP_COMMON
            if (sleep_mode && (prevSentAck == dev_conn->cli_DataFramesSentAck) && wakeup_cnt < WIFI_BLASTER_WAKEUP_LIMIT) {
                wakeup_cnt++;
            } else if (sleep_mode && wakeup_cnt >= WIFI_BLASTER_WAKEUP_LIMIT) {
                snprintf(msg, sizeof(msg), "The client is in sleeping mode");

                SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SLEEP_CLIENT);
                active_msmt_set_status_desc(__func__, g_active_msmt->active_msmt.PlanId, step->StepId, step->DestMac, msg);
                active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d %s\n", __func__, __LINE__, msg);
                g_active_msmt->num_res_count++;
                return;
            }

            prevSentAck = dev_conn->cli_DataFramesSentAck;
#endif // CCSP_COMMON

            if (wifi_app->data.u.blaster.frameCountSample == NULL) {
                wifi_util_error_print(WIFI_BLASTER, "%s:%d Framecount sample is NULL \n", __func__, __LINE__);
                return;
            }

            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].WaitAndLatencyInMs = ((getCurrentTimeInMicroSeconds () - wifi_app->data.u.blaster.blaster_start) / 1000);
            active_msmt_log_message(BLASTER_DEBUG_LOG, "PKTGEN_WAIT_IN_MS duration : %lu and value of getcurrent time is %lu and value of blaster_start is %lu \n", ((getCurrentTimeInMicroSeconds () - wifi_app->data.u.blaster.blaster_start)/1000), getCurrentTimeInMicroSeconds (), wifi_app->data.u.blaster.blaster_start);

            g_active_msmt->active_msmt_data[*SampleCount].rssi = dev_conn->cli_RSSI;
            g_active_msmt->active_msmt_data[*SampleCount].TxPhyRate = dev_conn->cli_LastDataDownlinkRate;
            g_active_msmt->active_msmt_data[*SampleCount].RxPhyRate = dev_conn->cli_LastDataUplinkRate;
            g_active_msmt->active_msmt_data[*SampleCount].SNR = dev_conn->cli_SNR;
#ifdef CCSP_COMMON
            g_active_msmt->active_msmt_data[*SampleCount].ReTransmission = dev_conn->cli_Retransmissions;
            g_active_msmt->active_msmt_data[*SampleCount].MaxTxRate = dev_conn->cli_MaxDownlinkRate;
            g_active_msmt->active_msmt_data[*SampleCount].MaxRxRate = dev_conn->cli_MaxUplinkRate;
#else
            g_active_msmt->active_msmt_data[*SampleCount].RetransCount = dev_conn->cli_RetransCount;
#endif // CCSP_COMMON
#if defined (_PP203X_PRODUCT_REQ_)
            if (radioOperation != NULL) {
                convert_channel_width_to_str(radioOperation->channelWidth, g_active_msmt->active_msmt_data[*SampleCount].Operating_channelwidth, OPER_BUFFER_LEN);
                convert_variant_to_str(radioOperation->variant, g_active_msmt->active_msmt_data[*SampleCount].Operating_standard, OPER_BUFFER_LEN);
            }
#else
            if (strstr(dev_conn->cli_OperatingStandard, "802.11") != NULL) {
                sscanf(dev_conn->cli_OperatingStandard, "802.11%2s", g_active_msmt->active_msmt_data[*SampleCount].Operating_standard);
            } else {
                snprintf(g_active_msmt->active_msmt_data[*SampleCount].Operating_standard, OPER_BUFFER_LEN, dev_conn->cli_OperatingStandard);
            }
            snprintf(g_active_msmt->active_msmt_data[*SampleCount].Operating_channelwidth, OPER_BUFFER_LEN, dev_conn->cli_OperatingChannelBandwidth);
#endif //_PP203X_PRODUCT_REQ_

            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentAck = dev_conn->cli_DataFramesSentAck;
#ifdef CCSP_COMMON
            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentTotal = dev_conn->cli_PacketsSent + dev_conn->cli_DataFramesSentNoAck;
#endif // CCSP_COMMON

            wifi_util_dbg_print(WIFI_BLASTER,"samplecount[%d] : PacketsSentAck[%lu] PacketsSentTotal[%lu]"
                    " WaitAndLatencyInMs[%d ms] RSSI[%d] TxRate[%lu Mbps] RxRate[%lu Mbps] SNR[%d]"
                    "chanbw [%s] standard [%s] MaxTxRate[%d] MaxRxRate[%d]\n",
                    *SampleCount, dev_conn->cli_DataFramesSentAck, (dev_conn->cli_PacketsSent + dev_conn->cli_DataFramesSentNoAck),
                    (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].WaitAndLatencyInMs, dev_conn->cli_RSSI, dev_conn->cli_LastDataDownlinkRate, dev_conn->cli_LastDataUplinkRate, dev_conn->cli_SNR,g_active_msmt->active_msmt_data[*SampleCount].Operating_channelwidth ,g_active_msmt->active_msmt_data[*SampleCount].Operating_standard,g_active_msmt->active_msmt_data[*SampleCount].MaxTxRate, g_active_msmt->active_msmt_data[*SampleCount].MaxRxRate);
            } else {

                if (ctrl->network_mode == rdk_dev_mode_type_ext) {
                    active_msmt_status_t status;

                    if (is_blaster_device_associated(index, bmac) == false) {
                        snprintf(msg, sizeof(msg), "The MAC is disconnected");
                        status = ACTIVE_MSMT_STATUS_NO_CLIENT;
                    }
                    else {
                        snprintf(msg, sizeof(msg), "Failed to fill in client stats");
                        status = ACTIVE_MSMT_STATUS_FAILED;
                    }

                    SetActiveMsmtStatus(__func__, status);
                    active_msmt_set_status_desc(__func__, g_active_msmt->active_msmt.PlanId, step->StepId, step->DestMac, msg);
                }

#ifdef CCSP_COMMON
                active_msmt_log_message(BLASTER_DEBUG_LOG, "%s : %d Unable to get provider response for : %s\n",__func__,__LINE__,g_active_msmt->curStepData.DestMac);
                (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentTotal = 0;
#else
                wifi_util_dbg_print(WIFI_BLASTER,"%s:%d ow_mesh_ext_get_device_stats failed for mac:%s\n",__func__,__LINE__,g_active_msmt->curStepData.DestMac);
#endif // CCSP_COMMON
                (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentAck = 0;
                (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].WaitAndLatencyInMs = 0;
                g_active_msmt->num_res_count++;
                return;
            }
        } else {
            active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d radio_index is invalid. So, client is treated as offline\n",__func__, __LINE__);
#ifdef CCSP_COMMON
            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentTotal = 0;
#endif // CCSP_COMMON
            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].PacketsSentAck = 0;
            (wifi_app->data.u.blaster.frameCountSample)[*SampleCount].WaitAndLatencyInMs = 0;
            strncpy(g_active_msmt->active_msmt_data[*SampleCount].Operating_standard, "NULL",OPER_BUFFER_LEN);
            strncpy(g_active_msmt->active_msmt_data[*SampleCount].Operating_channelwidth, "NULL",OPER_BUFFER_LEN);
            push_blaster_config_event_to_monitor_queue(mon_stats_request_state_stop);
            g_active_msmt->num_res_count++;
            return;
        }
        wifi_app->data.u.blaster.blaster_start = getCurrentTimeInMicroSeconds ();
        *SampleCount += 1;
}
    if (dev_conn != NULL){
        //free(dev_conn);
        dev_conn = NULL;
    }
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Sample count value = %d\n", __func__, __LINE__, *SampleCount);
    if (*SampleCount == g_active_msmt->active_msmt.ActiveMsmtNumberOfSamples + 1){
        push_blaster_config_event_to_monitor_queue(mon_stats_request_state_stop);
        *SampleCount = 0;
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: calling calculate_throughput\n", __func__, __LINE__);
        calculate_throughput();
    }
}

void calculate_throughput()
{
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Entered in \n", __func__, __LINE__);
    unsigned long totalduration = 0;
    double  Sum = 0, AvgThroughput = 0;
    char *telemetry_buf = NULL;
    radio_data_t *radio_stats = NULL;
    wifi_ctrl_t *g_wifi_ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    unsigned int SampleCount = 0;
    wifi_apps_mgr_t *apps_mgr;
    wifi_app_t *wifi_app =  NULL;

    apps_mgr = &g_wifi_ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        g_active_msmt->num_res_count++;
        return;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_blaster);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        g_active_msmt->num_res_count++;
        return;
    }

#ifdef CCSP_COMMON
    unsigned long DiffsamplesAck = 0, Diffsamples = 0, TotalAckSamples = 0, TotalSamples = 0;
    double  tp = 0, AckRate = 0, AckSum = 0, Rate = 0, AvgAckThroughput = 0;
#endif // CCSP_COMMON

    int index = g_active_msmt->curStepData.ApIndex;
    int radio_index = get_radio_index_for_vap_index(&(get_wifimgr_obj())->hal_cap.wifi_prop, index);
    radio_stats = (radio_data_t *) malloc (sizeof(radio_data_t));
    if (get_dev_stats_for_radio(radio_index, radio_stats) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Error getting radio datas\n", __func__, __LINE__);
    }

#if defined (DUAL_CORE_XB3)
    wifi_setClientDetailedStatisticsEnable(getRadioIndexFromAp(index), FALSE);
#endif

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: calculating the throughput\n", __func__, __LINE__);
#ifdef CCSP_COMMON
    // Analyze samples and get Throughput
    for (SampleCount = 0; SampleCount < GetActiveMsmtNumberOfSamples() ; SampleCount++) {
        DiffsamplesAck = (wifi_app->data.u.blaster.frameCountSample)[SampleCount+1].PacketsSentAck - (wifi_app->data.u.blaster.frameCountSample)[SampleCount].PacketsSentAck;
        Diffsamples = (wifi_app->data.u.blaster.frameCountSample)[SampleCount+1].PacketsSentTotal - (wifi_app->data.u.blaster.frameCountSample)[SampleCount].PacketsSentTotal;

        if ((wifi_app->data.u.blaster.frameCountSample)[SampleCount+1].WaitAndLatencyInMs != 0) {
            tp = (double)(DiffsamplesAck*8*GetActiveMsmtPktSize());              //number of bits
            wifi_util_dbg_print(WIFI_BLASTER,"tp = [%f bits]\n", tp );
            tp = tp/1000000;                //convert to Mbits
            wifi_util_dbg_print(WIFI_BLASTER,"tp = [%f Mb]\n", tp );
            AckRate = (tp/(wifi_app->data.u.blaster.frameCountSample)[SampleCount+1].WaitAndLatencyInMs) * 1000;                        //calculate bitrate in the unit of Mbpms
            tp = (double)(Diffsamples*8*GetActiveMsmtPktSize());         //number of bits
            wifi_util_dbg_print(WIFI_BLASTER,"tp = [%f bits]\n", tp );
            tp = tp/1000000;                //convert to Mbits
            wifi_util_dbg_print(WIFI_BLASTER,"tp = [%f Mb]\n", tp );
            Rate = (tp/(wifi_app->data.u.blaster.frameCountSample)[SampleCount+1].WaitAndLatencyInMs) * 1000;                   //calculate bitrate in the unit of Mbpms
        } else {
            AckRate = 0;
            Rate = 0;
        }

        /* updating the throughput in the global variable */
        g_active_msmt->active_msmt_data[SampleCount].throughput = AckRate;

        wifi_util_dbg_print(WIFI_BLASTER,"Sample[%d]   DiffsamplesAck[%lu]   Diffsamples[%lu]   BitrateAckPackets[%.5f Mbps]   BitrateTotalPackets[%.5f Mbps]\n", SampleCount, DiffsamplesAck, Diffsamples, AckRate, Rate );
        AckSum += AckRate;
        Sum += Rate;
        TotalAckSamples += DiffsamplesAck;
        TotalSamples += Diffsamples;

        totalduration += (wifi_app->data.u.blaster.frameCountSample)[SampleCount+1].WaitAndLatencyInMs;
    }
    AvgAckThroughput = AckSum/GetActiveMsmtNumberOfSamples();
    AvgThroughput = Sum/GetActiveMsmtNumberOfSamples();
    active_msmt_log_message(BLASTER_DEBUG_LOG, "\nTotal number of ACK Packets = %lu   Total number of Packets = %lu   Total Duration = %lu ms\n", TotalAckSamples, TotalSamples, totalduration );
    active_msmt_log_message(BLASTER_DEBUG_LOG, "Calculated Average : ACK Packets Throughput[%.2lf Mbps]  Total Packets Throughput[%.2lf Mbps]\n\n", AvgAckThroughput, AvgThroughput );
#else

    /* Actual count of samples is N+1. MQTT report operates with [1, N+1] samples.
     * The 0 sample is involved to provide ability to get delta for PacketsSentAck & ReTransmission
     */

    for (SampleCount = 1; SampleCount < GetActiveMsmtNumberOfSamples() + 1; SampleCount++) {
        uint64_t bits_diff;

        /* PacketsSentAck could be 0 for few samples due to the sleep mode */
        if (!(wifi_app->data.u.blaster.frameCountSample)[SampleCount].PacketsSentAck) {
            continue;
        }

        bits_diff = ((wifi_app->data.u.blaster.frameCountSample)[SampleCount].PacketsSentAck - (wifi_app->data.u.blaster.frameCountSample)[SampleCount - 1].PacketsSentAck) * 8;

        /* Analytics for MQTT report */
        g_active_msmt->active_msmt_data[SampleCount - 1].throughput = (bits_diff / 1000.0) / (wifi_app->data.u.blaster.frameCountSample)[SampleCount].WaitAndLatencyInMs;
        g_active_msmt->active_msmt_data[SampleCount - 1].ReTransmission = g_active_msmt->active_msmt_data[SampleCount].RetransCount -
            g_active_msmt->active_msmt_data[SampleCount - 1].RetransCount;

        /* Analytics for logs */
        totalduration += (wifi_app->data.u.blaster.frameCountSample)[SampleCount].WaitAndLatencyInMs;
        Sum += g_active_msmt->active_msmt_data[SampleCount - 1].throughput;
    }

    AvgThroughput = Sum / GetActiveMsmtNumberOfSamples();
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d Total duration: %lu ms, Avg Throughput: %.2lf Mbps\n", __func__, __LINE__, totalduration, AvgThroughput);
#endif // CCSP_COMMON

    if (onewifi_pktgen_stop_wifi_blast() != RETURN_OK) {
        wifi_util_error_print(WIFI_BLASTER, "%s:%d: Failed to stop pktgen\n", __FUNCTION__, __LINE__);
    }
    telemetry_buf = malloc(sizeof(char)*1024);
    if (telemetry_buf == NULL) {
        wifi_util_error_print(WIFI_BLASTER,"%s:%d telemetry_buf allocation failed\r\n", __func__, __LINE__);
        if(radio_stats != NULL){
            free(radio_stats);
            radio_stats = NULL;
        }
        return;
    }
    memset(telemetry_buf, 0, sizeof(char)*1024);
    snprintf(telemetry_buf, sizeof(char)*1024, "%s %s",g_active_msmt->active_msmt.t_header.traceParent, g_active_msmt->active_msmt.t_header.traceState);
    get_stubs_descriptor()->t2_event_s_fn("TRACE_WIFIBLAST_ENDS", telemetry_buf);

    if (g_active_msmt->status == ACTIVE_MSMT_STATUS_SUCCEED) {
        /* calling process_active_msmt_diagnostics to update the station info */
        active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d calling process_active_msmt_diagnostics\n", __func__, __LINE__);
        process_active_msmt_diagnostics(index);
    }

    /* calling stream_client_msmt_data to upload the data to AVRO schema */
    active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d calling stream_client_msmt_data\n", __func__, __LINE__);
    stream_client_msmt_data(true);

    if (g_active_msmt->status != ACTIVE_MSMT_STATUS_SUCCEED) {
        SetActiveMsmtStatus(__func__, ACTIVE_MSMT_STATUS_SUCCEED);
    }
    /* Set CPU free for a while */
    WaitForDuration(WIFI_BLASTER_POST_STEP_TIMEOUT);

    if(radio_stats != NULL){
        free(radio_stats);
        radio_stats = NULL;
    }

    if (telemetry_buf != NULL) {
        free(telemetry_buf);
        telemetry_buf = NULL;
    }
    g_active_msmt->num_res_count++;
    return;
}
/* This function process the active measurement step info
  from the active_msmt_monitor thread and calls wifiblaster.
*/
void process_active_msmt_step(active_msmt_t *cfg)
{
    pthread_t id;
    pthread_attr_t attr;
    pthread_attr_t *attrp = NULL;
    wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
    active_msmt_t *act_msmt = &g_active_msmt->active_msmt;
    wifi_ctrl_t *ctrl = get_wifictrl_obj();

    active_msmt_log_message(BLASTER_INFO_LOG, "%s:%d: calling process_active_msmt_step\n",__func__, __LINE__);
    pthread_mutex_lock(&g_active_msmt->lock);

    if (g_active_msmt->is_running == true && !strncasecmp((char *)cfg->PlanId, (char *)act_msmt->PlanId, strlen((char *)cfg->PlanId))) {

        if (cfg->ActiveMsmtEnable == false) {
            act_msmt->ActiveMsmtEnable = false;

            active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d: Canceling %s\n",__func__, __LINE__, cfg->PlanId);
            pthread_mutex_unlock(&g_active_msmt->lock);

            return;
        }

        if (ctrl->network_mode == rdk_dev_mode_type_ext && ActiveMsmtConfValidation(cfg) != RETURN_OK) {

            wifi_util_error_print(WIFI_BLASTER, "%s:%d Active measurement conf for %s is invalid!\n", __func__, __LINE__, cfg->PlanId);
            act_msmt->ActiveMsmtEnable = false;
            pthread_mutex_unlock(&g_active_msmt->lock);

            return;
        }

        active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d: Changing configuration for PlanId [%s]\n",__func__, __LINE__, cfg->PlanId);

        /* Cloud could update SampleDuration, PktSize, NumberOfSamples during
         * sampling
         */

        if (ctrl->network_mode == rdk_dev_mode_type_ext) {
            SetActiveMsmtSampleDuration(cfg->ActiveMsmtSampleDuration / cfg->ActiveMsmtNumberOfSamples);
        } else {
            SetActiveMsmtSampleDuration(cfg->ActiveMsmtSampleDuration);
        }

        SetActiveMsmtPktSize(cfg->ActiveMsmtPktSize);
        SetActiveMsmtNumberOfSamples(cfg->ActiveMsmtNumberOfSamples);

        /* Cloud could only extend the previous PlanId request with new set of
         * steps. Old ones couldn't be overwritten
         */

        for (unsigned int i = 0; i < MAX_STEP_COUNT; i++) {

            if (strlen((char *) cfg->Step[i].DestMac) != 0 &&
                active_msmt_step_inst_is_configured((char *)cfg->Step[i].DestMac) == false) {

                unsigned int StepIns = active_msmt_step_inst_get_available(i);

                SetActiveMsmtStepID(cfg->Step[i].StepId, StepIns);
                SetActiveMsmtStepDstMac((char *)cfg->Step[i].DestMac, StepIns);
                SetActiveMsmtStepSrcMac((char *)cfg->Step[i].SrcMac, StepIns);
            }
        }

        pthread_mutex_unlock(&g_active_msmt->lock);

        return;
    }

    active_msmt_queue_push(&g_active_msmt->queue, cfg);

    if (g_active_msmt->is_running == false) {

        attrp = &attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        if (pthread_create(&id, attrp, active_msmt_worker, NULL) != 0) {
            active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d: Fail to spawn 'active_msmt_worker' thread errno: %d - %s\n",
                __FUNCTION__, __LINE__, errno, strerror(errno));

            if(attrp != NULL) {
                pthread_attr_destroy(attrp);
            }

            pthread_mutex_unlock(&g_active_msmt->lock);
            return;
        }

        active_msmt_log_message(BLASTER_DEBUG_LOG, "%s:%d: Sucessfully created thread for starting blast\n", __FUNCTION__, __LINE__);

        if(attrp != NULL) {
            pthread_attr_destroy(attrp);
        }
    }

    pthread_mutex_unlock(&g_active_msmt->lock);
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: exiting this function\n",__func__, __LINE__);
}

int webconfig_blaster_app_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    wifi_mgr_t *mgr = get_wifimgr_obj();

    if ((mgr == NULL) || (data == NULL)) {
        wifi_util_error_print(WIFI_BLASTER,"%s %d Mgr or Data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    mgr->blaster_config_global = data->blaster;

    /* If Device operating in POD mode, Send the blaster status as new to the cloud */
    if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        /* MQTT Topic is required to publish data to QM */
        if (strcmp((char *)mgr->blaster_config_global.blaster_mqtt_topic, "") == 0)
        {
            wifi_util_error_print(WIFI_BLASTER, "%s %d MQTT topic seems empty\n", __func__, __LINE__);
            return RETURN_ERR;
        }
    }
    else if (ctrl->network_mode == rdk_dev_mode_type_gw) {
            wifi_util_info_print(WIFI_BLASTER, "GW doesnot dependant on MQTT topic\n");
    }

    process_active_msmt_step(&data->blaster);

    return RETURN_OK;
}

void process_blaster(wifi_app_t *app, wifi_event_t *event)
{
    int ret = RETURN_OK;
    wifi_util_dbg_print(WIFI_BLASTER,"%s:%d Entering \n", __func__, __LINE__);
    webconfig_subdoc_data_t *data = NULL;
    data = event->u.webconfig_data;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if(ctrl == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s:%d Unable to get ctrl object\n", __func__, __LINE__);
        return;
    }
    ret = webconfig_blaster_app_apply(ctrl, &data->u.decoded);
    if(ret != RETURN_OK) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s:%d webconfig_blaster_apply is returned error \n", __func__, __LINE__);
        return;
    }
}


void handle_blaster_provider_response(wifi_app_t *app, wifi_event_t *event)
{
    if (event == NULL) {
        wifi_util_error_print(WIFI_BLASTER,"%s:%d input event is NULL\r\n", __func__, __LINE__);
        return;
    }
    wifi_provider_response_t    *provider_response;
    provider_response = (wifi_provider_response_t *)event->u.provider_response;

    switch (provider_response->args.app_info) {
        case blaster_app_sample_blaster: {
                wifi_actvie_msmt_t  *g_active_msmt = get_wifi_blaster();
                if (g_active_msmt->num_res_count != g_active_msmt->num_req_count) {
                    sample_blaster(provider_response);
                }
                break;
            }
        default:
            wifi_util_error_print(WIFI_BLASTER, "%s:%d Inside default\n", __func__, __LINE__);
            break;
    }
}
void handle_blaster_webconfig_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->u.webconfig_data->type) {
        case webconfig_subdoc_type_blaster:
            process_blaster(app, event);
            break;
        default:
            break;
    }
}

void handle_blaster_monitor_event(wifi_app_t *app, wifi_event_t *event)
{
    if (event == NULL) {
        wifi_util_error_print(WIFI_BLASTER,"%s:%d input event is NULL\r\n", __func__, __LINE__);
        return;
    }

    switch (event->sub_type) {
        case wifi_event_monitor_provider_response:
            handle_blaster_provider_response(app, event);
            break;
        default:
            wifi_util_error_print(WIFI_BLASTER, "%s:%d Inside default\n", __func__, __LINE__);
            break;
    }
}

#ifdef ONEWIFI_BLASTER_APP_SUPPORT
int blaster_event(wifi_app_t *app, wifi_event_t *event)
{

    switch (event->event_type) {
        case wifi_event_type_webconfig:
            handle_blaster_webconfig_event(app, event);
            break;
        case wifi_event_type_monitor:
            handle_blaster_monitor_event(app, event);
            break;
        default:
            break;
    }
    return RETURN_OK;
}

int blaster_init(wifi_app_t *app, unsigned int create_flag)
{
    wifi_util_dbg_print(WIFI_BLASTER, "Entered in blaster_init\n");
    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    app->data.u.blaster.g_active_msmt.active_msmt_map = hash_map_create();
    pthread_mutex_init(&app->data.u.blaster.g_active_msmt.lock, NULL);
    if (onewifi_pktgen_init() != RETURN_OK) {
        wifi_util_error_print(WIFI_BLASTER, "%s:%d Pktgen support is missed!\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int blaster_deinit(wifi_app_t *app)
{
    push_blaster_config_event_to_monitor_queue(mon_stats_request_state_stop);
    pthread_mutex_destroy(&app->data.u.blaster.g_active_msmt.lock);
    return RETURN_OK;
}
#endif
