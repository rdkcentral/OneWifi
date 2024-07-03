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

#ifndef _WIFI_BLASTER_H_
#define _WIFI_BLASTER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include "wifi_base.h"

#define OPER_BUFFER_LEN 64
#define BUFF_LEN_MIN OPER_BUFFER_LEN
#define BUFF_LEN_MAX 1024
#define MAX_NUMBER_OF_CLIENTS                   10      /* Define it to 10 for now. Shall be updated based on the capacity of pktgen & device */
#define MAC_ADDRESS_STR_LEN                             17
#define MAX_RADIO_INDEX                                 2
#define RADIO0_INTERFACE_NAME                   "ath0"          /* 2.4 Ghz */
#define RADIO1_INTERFACE_NAME                   "ath1"          /* 5 Ghz */
#define CONVERT_MILLI_TO_NANO           1000000
#define BITS_TO_MEGABITS                        1000000

#define CHCOUNT2                                        11
#define CHCOUNT5                                        25

#ifdef ENABLE_DEBUG_PRINTS
#define DEBUG_PRINT(x)                                  printf x
#else
#define DEBUG_PRINT(x)
#endif
#define CRITICAL_PRINT

typedef struct wifi_app wifi_app_t;
typedef struct _pktGenFrameCountSamples {
        ULONG   PacketsSentAck;
        ULONG   PacketsSentTotal;
        int             WaitAndLatencyInMs;             //Wait duration + API Latency in millsecs
} pktGenFrameCountSamples;

typedef enum {
    BLASTER_INFO_LOG   = 0,
    BLASTER_DEBUG_LOG
} blaster_log_level_t;

typedef struct active_msmt_data {
    unsigned int   MaxTxRate;
    unsigned int   MaxRxRate;
    int            rssi;
    unsigned long  TxPhyRate;
    unsigned long  RxPhyRate;
    int            SNR;
    int            ReTransmission;
    double         throughput;
    char           Operating_standard[OPER_BUFFER_LEN + 1];
    char           Operating_channelwidth[OPER_BUFFER_LEN + 1];
    mac_address_t  cli_MACAddress;
#ifndef CCSP_COMMON
    unsigned long  RetransCount;
#endif // CCSP_COMMON
} active_msmt_data_t;

typedef struct {
    mac_address_t       sta_mac;
    active_msmt_data_t  *sta_active_msmt_data;
} blaster_hashmap_t;

typedef enum
{
    ACTIVE_MSMT_STATUS_SUCCEED      = 0,                /* The test is finished successfully */
    ACTIVE_MSMT_STATUS_CANCELED     = 1,                /* The request was canceled */
    ACTIVE_MSMT_STATUS_FAILED       = 2,                /* Internal error happened */
    ACTIVE_MSMT_STATUS_BUSY         = 3,                /* The device is overloaded (CPU; RAM mem) */
    ACTIVE_MSMT_STATUS_NO_CLIENT    = 4,                /* The client is not found */
    ACTIVE_MSMT_STATUS_WRONG_ARG    = 5,                /* Incorrect argument value */
    ACTIVE_MSMT_STATUS_SLEEP_CLIENT = 6,                /* The client is in sleeping mode */
    ACTIVE_MSMT_STATUS_UNDEFINED
} active_msmt_status_t;

typedef struct active_msmt_queue_t active_msmt_queue_t;

struct active_msmt_queue_t {
    active_msmt_t data;
    active_msmt_queue_t *next;
};

typedef struct {
    pthread_mutex_t                lock;
    active_msmt_t                  active_msmt;
    active_msmt_step_t             curStepData;
    active_msmt_data_t             *active_msmt_data;
    active_msmt_status_t           status;
    char                           status_desc[512];
    bool                           is_running;
    active_msmt_queue_t            *queue;
    hash_map_t                     *active_msmt_map;
    int                            num_req_count;
    int                            num_res_count;
    bool                           reponse_received;
} wifi_actvie_msmt_t;

typedef struct {
    unsigned int                   SampleCount;
    unsigned long                  blaster_start;
    wifi_actvie_msmt_t             g_active_msmt;
    pktGenFrameCountSamples        *frameCountSample;
} blaster_data_t;
/* prototype for Active Measurement */

/* Active Measurement GET calls */
/*unsigned int GetActiveMsmtPktSize();
unsigned int GetActiveMsmtSampleDuration();
unsigned int GetActiveMsmtNumberOfSamples();
*/

/* Active Measurement SET calls */
void SetActiveMsmtEnable(bool enable);
void SetActiveMsmtPktSize(unsigned int PktSize);
void SetActiveMsmtSampleDuration(unsigned int Duration);
void SetActiveMsmtNumberOfSamples(unsigned int NoOfSamples);
void SetActiveMsmtStatus(const char *func, active_msmt_status_t status);

/* Active Measurement Step & Plan SET calls */
void SetActiveMsmtStepDstMac(char *DstMac, ULONG StepIns);
void SetActiveMsmtStepSrcMac(char *SrcMac, ULONG StepIns);
void SetActiveMsmtStepID(unsigned int StepId, ULONG StepIns);
void SetActiveMsmtPlanID(char *pPlanID);

/* Active Measurement Step & Plan GET calls */
unsigned int GetActiveMsmtStepID();
void GetActiveMsmtPlanID(unsigned int *pPlanID);
void GetActiveMsmtStepSrcMac(mac_address_t pStepSrcMac);
void GetActiveMsmtStepDestMac(mac_address_t pStepDstMac);

int ActiveMsmtConfValidation(active_msmt_t *cfg);
void ResetActiveMsmtStepInstances(void);

unsigned long getCurrentTimeInMicroSeconds();
int isVapEnabled (int wlanIndex);
int WaitForDuration (int timeInMs);
void pktGen_BlastClient (char *dest_mac, wifi_interface_name_t *ifname);
void WiFiBlastClient(void);
void process_active_msmt_diagnostics (int ap_index);

void stream_client_msmt_data(bool ActiveMsmtFlag);
wifi_actvie_msmt_t *get_wifi_blaster();

#ifdef __cplusplus
}
#endif

#endif //_WIFI_BLASTER_H_
