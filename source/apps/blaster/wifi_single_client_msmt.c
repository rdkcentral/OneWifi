 /****************************************************************************
  If not stated otherwise in this file or this component's LICENSE
  file the following copyright and licenses apply:

  Copyright 2020 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

 ****************************************************************************/

#ifdef CCSP_COMMON
#include <avro.h>
#endif // CCSP_COMMON
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#ifdef CCSP_COMMON
#include "cosa_apis.h"
#endif // CCSP_COMMON
#include "wifi_hal.h"
#include "collection.h"
#include "wifi_monitor.h"
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/un.h>
#include <assert.h>
#include <uuid/uuid.h>
#ifdef MQTTCM
#include <mqttcm_lib/mqttcm_conn.h>
#endif
#ifdef CCSP_COMMON
#include "ansc_status.h"
#include <sysevent/sysevent.h>
#include "ccsp_base_api.h"
#include "harvester.h"
#include "ccsp_WifiLog_wrapper.h"
#include "ccsp_trace.h"
#endif // CCSP_COMMON
#include "platform-logger.h"
#include "ext_blaster.pb-c.h"
#include "qm_conn.h"
#include "wifi_util.h"
#include "wifi_mgr.h"
#include "wifi_stubs.h"
#include "wifi_blaster.h"
#include "const.h"
#define PROTOBUF_MAC_SIZE 13


// UUID - 8b27dafc-0c4d-40a1-b62c-f24a34074914

// HASH - 4388e585dd7c0d32ac47e71f634b579b

#ifdef CCSP_COMMON
static void to_plan_id (unsigned char *PlanId, unsigned char Plan[])
{
    int i=0;
    if (PlanId == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s %d PlanId is NULL\n", __func__, __LINE__);
        return;
    }
    for (i=0; i < 16; i++) {
        sscanf((char*)PlanId,"%2hhx",(char*)&Plan[i]);
        PlanId += 2;
    }
}
#endif // CCSP_COMMON

static void to_plan_char(unsigned char *plan, unsigned char *key)
{
    int i = 0;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    int size = (ctrl->network_mode == rdk_dev_mode_type_gw) ? 16 : 36;
    for(i=0; i<size; i++)
    {
        sscanf((char*)plan,"%c",(char*)&key[i]);
        plan++;
    }
}

#ifdef CCSP_COMMON

/* Active Measurement Data values */

// UUID - 96673104-5a8b-4976-82dd-b204f13dfeee

// HASH - 43a46540f87428b5ca3a090dcd00f68b

uint8_t ACTHASHVAL[16] = {0x43, 0xa4, 0x65, 0x40, 0xf8, 0x74, 0x28, 0xb5,
                          0xca, 0x3a, 0x09, 0x0d, 0xcd, 0x00, 0xf6, 0x8b
                         };

uint8_t ACTUUIDVAL[16] = {0x96, 0x67, 0x31, 0x04, 0x5a, 0x8b, 0x49, 0x76,
                          0x82, 0xdd, 0xb2, 0x04, 0xf1, 0x3d, 0xfe, 0xee
                         };

// local data, load it with real data if necessary
#define MAX_BUFF_SIZE  20480
#define MAX_STR_LEN    32

#define MAGIC_NUMBER      0x85
#define MAGIC_NUMBER_SIZE 1
#define SCHEMA_ID_LENGTH  32
#define MAC_KEY_LEN 13
#define  ARRAY_SZ(x)    (sizeof(x) / sizeof((x)[0]))
#endif // CCSP_COMMON

#define PLAN_ID_LENGTH_POD 48

#ifdef CCSP_COMMON
typedef enum {
    single_client_msmt_type_all,
    single_client_msmt_type_all_per_bssid,
    single_client_msmt_type_one,
} single_client_msmt_type_t;
#endif // CCSP_COMMON

static char *to_sta_key    (mac_addr_t mac, sta_key_t key) {
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}
extern bool             mqttcm_enabled;
#ifdef CCSP_COMMON
static void printBlastMetricData(single_client_msmt_type_t msmtType, wifi_actvie_msmt_t *blaster_stats,
                                blaster_hashmap_t *staData, bool activeClient, const char *callerFunc)
{
    int RadioCount = 0, radioIdx = 0, sampleCount = 0;
    int Count = GetActiveMsmtNumberOfSamples();
    unsigned char PlanId[PLAN_ID_LENGTH] = {0};
    static char *radio_arr[3] = {"radio_2_4G", "radio_5G", "radio_6G"};
    char freqBand[MAX_STR_LEN] = {0}, chanBw[MAX_STR_LEN] = {0};

    CcspTraceDebug(("debug called from %s\n", callerFunc));

    if (blaster_stats == NULL || staData == NULL)
    {
        CcspTraceError(("%s:%d: Debug function failed as NULL data received\n", __FUNCTION__, __LINE__));
        return;
    }

    /* ID */
    to_plan_char(blaster_stats->active_msmt.PlanId, PlanId);
    CcspTraceInfo(("\n\tplanID:\t[%s]\n \tstepID:\t[%d]\n",
                PlanId, blaster_stats->curStepData.StepId));

    if (activeClient)
    {
        radio_data_t *radio_stats[MAX_NUM_RADIOS];

        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            radio_stats[radio_index] = (radio_data_t *) malloc (sizeof(radio_data_t));
            if (radio_stats[radio_index] == NULL) {
                wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: radio_stats is NULL\n", __func__, __LINE__);
            }
            memset(radio_stats[radio_index],0, sizeof(radio_data_t));
            if (get_dev_stats_for_radio(radio_index, (radio_data_t *)radio_stats[radio_index]) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Error getting radio datas\n", __func__, __LINE__);
                continue;
            }
        }
        /* Radio Data */
        for(RadioCount = 0; RadioCount < (int)getNumberRadios(); RadioCount++)
        {
            CcspTraceInfo(("===== RADIO METRICS ====\n"));
            CcspTraceInfo(("{\n\t radioId: %s,\n\t NoiseFloor: %d,\n\t ChanUtil: %d,\n\t "
                                "activityFactor: %d,\n\t careerSenseThresholdExceed: %d,\n\t channelsInUse: %s\n}\n",
                                radio_arr[RadioCount], radio_stats[RadioCount]->NoiseFloor,
                                radio_stats[RadioCount]->channelUtil,
                                radio_stats[RadioCount]->RadioActivityFactor,
                                radio_stats[RadioCount]->CarrierSenseThreshold_Exceeded,
                                radio_stats[RadioCount]->ChannelsInUse));
        }

        /* Operating Channel metrics */
        if (blaster_stats->curStepData.ApIndex >= 0)
        {
            radioIdx = getRadioIndexFromAp(blaster_stats->curStepData.ApIndex);
            if ( strstr("20MHz", staData->sta_active_msmt_data[0].Operating_channelwidth))
            {
                snprintf(chanBw, MAX_STR_LEN, "\"%s\"", "set to _20MHz");
            }
            else if ( strstr("40MHz", staData->sta_active_msmt_data[0].Operating_channelwidth) )
            {
                snprintf(chanBw, MAX_STR_LEN, "\"%s\"", "set to _40MHz");
            }
            else if ( strstr("80MHz", staData->sta_active_msmt_data[0].Operating_channelwidth) )
            {
                snprintf(chanBw, MAX_STR_LEN, "\"%s\"", "set to _80MHz");
            }
            else if ( strstr("160MHz", staData->sta_active_msmt_data[0].Operating_channelwidth) )
            {
                snprintf(chanBw, MAX_STR_LEN, "\"%s\"", "set to _160MHz");
            }

            if (strstr("2.4GHz", radio_stats[radioIdx]->frequency_band))
            {
                snprintf(freqBand, MAX_STR_LEN, "\"%s\"", "2.4GHz, set to _2_4GHz");
            }
            else if (strstr("5GHz", radio_stats[radioIdx]->frequency_band))
            {
                snprintf(freqBand, MAX_STR_LEN, "\"%s\"", "5GHz, set to _5GHz");
            }
            else if (strstr("6GHz", radio_stats[radioIdx]->frequency_band))
            {
                snprintf(freqBand, MAX_STR_LEN, "\"%s\"", "6GHz, set to _6GHz");
            }
            CcspTraceInfo(("{\n\tOperatingStandard: %s,\n\tOperatingChannel: %d,\n\t"
                                "OperatingChannelBandwidth: %s,\n\tFreqBand: %s\n}\n",
                                staData->sta_active_msmt_data[0].Operating_standard,
                                radio_stats[radioIdx]->primary_radio_channel,
                                chanBw, freqBand));

        } else {
            CcspTraceInfo(("{\n\tOperatingStandard: %s,\n\tOperatingChannel: 0,\n\t"
                                "OperatingChannelBandwidth: %s,\n\tFreqBand: %s\n}\n",
                                "Not defined, set to NULL", "set to NULL", "frequency_band set to NULL"));
        }

        /* Client Blast metrics */
        CcspTraceInfo(("===== Client [%02x:%02x:%02x:%02x:%02x:%02x] Blast Metrics =====\n",
                        staData->sta_mac[0], staData->sta_mac[1],
                        staData->sta_mac[2], staData->sta_mac[3],
                        staData->sta_mac[4], staData->sta_mac[5]));

        /* TX metrics */
        CcspTraceInfo(("{\n\ttx_retransmissions: %d,\n \tmax_tx_rate: %d\n}\n",
                       staData->sta_active_msmt_data[Count-1].ReTransmission - staData->sta_active_msmt_data[0].ReTransmission,
                       staData->sta_active_msmt_data[0].MaxTxRate));

        for (sampleCount = 0; sampleCount < Count; sampleCount++)
        {
            CcspTraceInfo(("{\n \t SampleCount: %d\n \t\t{signalStrength: %d,\n"
                                "\t\tSNR: %d,\n \t\ttx_phy_rate: %ld,\n \t\trx_phy_rate: %ld,\n"
                                "\t\tthroughput: %lf }\n}\n", sampleCount, staData->sta_active_msmt_data[sampleCount].rssi,
                                staData->sta_active_msmt_data[sampleCount].SNR,
                                staData->sta_active_msmt_data[sampleCount].TxPhyRate,
                                staData->sta_active_msmt_data[sampleCount].RxPhyRate,
                                staData->sta_active_msmt_data[sampleCount].throughput));
        }
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
    }
}
#endif // CCSP_COMMON

void upload_single_client_active_msmt_data(blaster_hashmap_t *sta_info)
{
#ifdef CCSP_COMMON
    char *telemetry_buf = NULL;
    const char * serviceName = "wifi";
    const char * dest = "event:raw.kestrel.reports.WifiSingleClientActiveMeasurement";
    const char * contentType = "avro/binary"; // contentType "application/json", "avro/binary"
    unsigned char PlanId[PLAN_ID_LENGTH];
    uuid_t transaction_id;
    char trans_id[37];
    FILE *fp;
    char *buff;
    int size;
    int sampleCount = 0;
    int RadioCount = 0;
    sta_key_t sta_key;
    int Count = GetActiveMsmtNumberOfSamples();
    int radio_idx = 0;

    blaster_hashmap_t  *sta_data;
    blaster_hashmap_t  *sta_del = NULL;
    wifi_actvie_msmt_t *blaster;
    radio_data_t *radio_stats[MAX_NUM_RADIOS];
    single_client_msmt_type_t msmt_type;
    avro_writer_t writer;
    avro_schema_t inst_msmt_schema = NULL;
    avro_schema_error_t error = NULL;
    avro_value_iface_t  *iface = NULL;
    avro_value_t  adr = {0};
    avro_value_t  adrField = {0};
    avro_value_t optional  = {0};

    blaster = (wifi_actvie_msmt_t *)get_wifi_blaster();

    if(blaster == NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: wifi blaster active msmt data is null \n", __func__, __LINE__);
        return;
    }

    if (blaster->active_msmt_map == NULL) {
        if (sta_info != NULL) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Invalid arguments\n", __func__, __LINE__);
            return;
        } else {
            msmt_type = single_client_msmt_type_all;
        }
    } else {

        if (sta_info == NULL) {
            msmt_type = single_client_msmt_type_all_per_bssid;
        } else {
            msmt_type = single_client_msmt_type_one;
        }
    }

    for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        radio_stats[radio_index] = (radio_data_t *) malloc (sizeof(radio_data_t));
        if (radio_stats[radio_index] == NULL) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: radio_stats is NULL\n", __func__, __LINE__);
        }
        memset(radio_stats[radio_index],0, sizeof(radio_data_t));
        if (get_dev_stats_for_radio(radio_index, (radio_data_t *)radio_stats[radio_index]) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Error getting radio datas\n", __func__, __LINE__);
            continue;
        }
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Measurement Type: %d\n", __func__, __LINE__, msmt_type);
    CcspTraceDebug(("%s:%d: Measurement Type: %d\n", __func__, __LINE__, msmt_type));

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: opening the schema file %s\n", __func__, __LINE__, WIFI_SINGLE_CLIENT_BLASTER_AVRO_FILENAME);
    /* open schema file */
    fp = fopen (WIFI_SINGLE_CLIENT_BLASTER_AVRO_FILENAME , "rb");

    if (fp == NULL)
    {
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Unable to open schema file: %s\n", __func__, __LINE__, WIFI_SINGLE_CLIENT_BLASTER_AVRO_FILENAME);
        return;
    }
    else
    {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: successfully opened schema file: %s\n", __func__, __LINE__, WIFI_SINGLE_CLIENT_BLASTER_AVRO_FILENAME);
    }

    /* seek through file and get file size*/
    fseek(fp , 0L , SEEK_END);
    size = ftell(fp);
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: size of %s is %d \n", __func__, __LINE__,WIFI_SINGLE_CLIENT_BLASTER_AVRO_FILENAME,size);

    if (size < 0)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: ftell error\n", __func__, __LINE__);
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        fclose(fp);
        return;
    }
    /*back to the start of the file*/
    rewind(fp);

    /* allocate memory for entire content */
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: allocating memory for entire content\n", __func__, __LINE__);
    buff = (char *) malloc(size + 1);

    if (buff == NULL)
    {
        if (fp)
        {
            fclose(fp);
            fp = NULL;
        }
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: allocating memory for entire content failed\n", __func__, __LINE__);
        /*CID: 146754 Dereference after null check*/
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        return;
    }

    memset(buff, 0, size + 1);

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: copying the content of the file \n", __func__, __LINE__);

    /* copy the file into the buffer */
    if (1 != fread(buff , size, 1 , fp))
    {
        if (fp)
        {
            fclose(fp);
            fp = NULL;
        }
        free(buff);
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Unable to read schema file: %s\n", __func__, __LINE__, WIFI_SINGLE_CLIENT_BLASTER_AVRO_FILENAME);
        CcspTraceError(("%s:%d: !ERROR! Unable to read schema file: %s\n", __func__, __LINE__, WIFI_SINGLE_CLIENT_BLASTER_AVRO_FILENAME));
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        return ;
    }

    buff[size]='\0';
    fclose(fp);

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: calling avro_schema_from_json \n", __func__, __LINE__);
    if (avro_schema_from_json(buff, strlen(buff), &inst_msmt_schema, &error))
    {
        free(buff);
        buff = NULL;
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Unable to parse active measurement schema, len: %d, error:%s\n", __func__, __LINE__, size, avro_strerror());
        return;
    }

    if(buff)
    {
        free(buff);
        buff = NULL;
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: generate an avro class from our schema and get a pointer to the value interface \n", __func__, __LINE__);
    //generate an avro class from our schema and get a pointer to the value interface
    iface = avro_generic_class_from_schema(inst_msmt_schema);

    avro_schema_decref(inst_msmt_schema);

    buff = malloc(MAX_BUFF_SIZE);
    memset(buff, 0, MAX_BUFF_SIZE);
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: filling MAGIC NUMBER in buff[0] \n", __func__, __LINE__);
    //generate an avro class from our schema and get a pointer to the value interface
    buff[0] = MAGIC_NUMBER; /* fill MAGIC number = Empty, i.e. no Schema ID */

    memcpy( &buff[MAGIC_NUMBER_SIZE], ACTUUIDVAL, sizeof(ACTUUIDVAL));
    memcpy( &buff[MAGIC_NUMBER_SIZE + sizeof(ACTUUIDVAL)], ACTHASHVAL, sizeof(ACTHASHVAL));

    writer = avro_writer_memory((char*)&buff[MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH], MAX_BUFF_SIZE - MAGIC_NUMBER_SIZE - SCHEMA_ID_LENGTH);
    avro_writer_reset(writer);
    avro_generic_value_new(iface, &adr);

    // timestamp - long
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: timestamp \n", __func__, __LINE__);
    avro_value_get_by_name(&adr, "header", &adrField, NULL);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    avro_value_get_by_name(&adrField, "timestamp", &adrField, NULL);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    avro_value_set_branch(&adrField, 1, &optional);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    struct timeval ts;
    gettimeofday(&ts, NULL);

    int64_t tstamp_av_main = ((int64_t) (ts.tv_sec) * 1000000) + (int64_t) ts.tv_usec;

    //Set timestamp value in the report
    tstamp_av_main = tstamp_av_main/1000;
    avro_value_set_long(&optional, tstamp_av_main );

    // uuid - fixed 16 bytes
    uuid_generate_random(transaction_id);
    uuid_unparse(transaction_id, trans_id);
    unsigned char PlanId_hex[16];
    int loop = 0;
    memset(PlanId_hex, '\0', 16);
    to_plan_id(blaster->active_msmt.PlanId, PlanId_hex);
    for (loop =0; loop < 16; loop++) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d:planid in hex[%d] : %2hhx\n", __func__, __LINE__, loop, PlanId_hex[loop]);
    }

    to_plan_char(PlanId_hex, PlanId);
    for (loop =0; loop < 16; loop++) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d:planid in character[%d] : %c\n", __func__, __LINE__, loop, PlanId_hex[loop]);
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Plan Id is %s\n", __func__, __LINE__,PlanId);
    avro_value_get_by_name(&adr, "header", &adrField, NULL);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    avro_value_get_by_name(&adrField, "plan_id", &adrField, NULL);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    avro_value_set_branch(&adrField, 1, &optional);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    //Set uuid value in the report
    avro_value_set_fixed(&optional, PlanId, 16);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    wifi_util_dbg_print(WIFI_BLASTER, "Report transaction uuid generated is %s\n", trans_id);
    platform_trace_warning(WIFI_BLASTER, "Single client report transaction uuid generated is %s\n", trans_id );

    avro_value_get_by_name(&adr, "header", &adrField, NULL);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    avro_value_get_by_name(&adrField, "step_id", &adrField, NULL);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    avro_value_set_branch(&adrField, 1, &optional);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    wifi_util_dbg_print(WIFI_BLASTER, "%s : %d setting the step Id : %d\n",__func__,__LINE__,blaster->curStepData.StepId);
    avro_value_set_int(&optional, blaster->curStepData.StepId);

    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    const char *macStr = NULL;
    char CpemacStr[32] = {0};

    //cpe_id block
    /* MAC - Get CPE mac address, do it only pointer is NULL */
    if ( macStr == NULL )
    {
        macStr = getDeviceMac();
        if (macStr != NULL) {
            strncpy( CpemacStr, macStr, sizeof(CpemacStr));
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: RDK_LOG_DEBUG, Received DeviceMac from Atom side: %s\n",__func__, __LINE__, macStr);
            CcspTraceInfo(("%s-%d Received DeviceMac from Atom side: %s\n", __FUNCTION__, __LINE__, macStr));
        }
        else {
            wifi_util_error_print(WIFI_BLASTER, "%s:%d: RDK_LOG_DEBUG, Device MAC Received as NULL\n", __func__, __LINE__);
            CcspTraceError(("%s-%d Device MAC Received as NULL\n", __func__, __LINE__));
        }
    }

    char CpeMacHoldingBuf[ 20 ] = {0};
    unsigned char CpeMacid[ 7 ] = {0};
    unsigned int k;

    for (k = 0; k < 6; k++ )
    {
        /* copy 2 bytes */
        CpeMacHoldingBuf[ k * 2 ] = CpemacStr[ k * 2 ];
        CpeMacHoldingBuf[ k * 2 + 1 ] = CpemacStr[ k * 2 + 1 ];
        CpeMacid[ k ] = (unsigned char)strtol(&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
    }

    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);

    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "mac_address", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_fixed(&optional, CpeMacid, 6);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    unsigned char *pMac = (unsigned char*)CpeMacid;
    wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, mac_address = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] );
    CcspTraceInfo(("CPE MAC address = 0x%02X:0x%02X:0x%02X:0x%02X:0x%02X:0x%02X\n",
        pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5]));

    //Data Field block
    wifi_util_dbg_print(WIFI_BLASTER, "data field\n");
    avro_value_get_by_name(&adr, "data", &adrField, NULL);
    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    //Current Device Report Field
    avro_value_t drField = {0};

    wifi_util_dbg_print(WIFI_BLASTER, "updating sta_data\n");
    sta_data = sta_info;

    if(sta_data == NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "sta_data is empty\n");
    }
    else
    {
        //device_mac - fixed 6 bytes
        wifi_util_dbg_print(WIFI_BLASTER, "adding cli_MACAddress field %02x%02x%02x%02x%02x%02x\n",\
                            sta_data->sta_mac[0], sta_data->sta_mac[1], sta_data->sta_mac[2],\
                            sta_data->sta_mac[3],sta_data->sta_mac[4],sta_data->sta_mac[5]);
        avro_value_get_by_name(&adrField, "client_mac", &drField, NULL);
        if (CHK_AVRO_ERR) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_branch(&drField, 1, &optional);
        if (CHK_AVRO_ERR) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_fixed(&optional, sta_data->sta_mac, 6);
        if (CHK_AVRO_ERR) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
    }

    //Polling Period
    wifi_util_dbg_print(WIFI_BLASTER, "adding sampling_interval field\n");
    avro_value_get_by_name(&adr, "data", &adrField, NULL);
    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    avro_value_get_by_name(&adrField, "sampling_interval", &drField, NULL);
    avro_value_set_int(&drField, GetActiveMsmtSampleDuration());
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d sampling interval : %d\n", __func__, __LINE__, GetActiveMsmtSampleDuration());
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    //packet_size
    wifi_util_dbg_print(WIFI_BLASTER, "adding packet_size field\n");
    avro_value_get_by_name(&adr, "data", &adrField, NULL);
    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    avro_value_get_by_name(&adrField, "packet_size", &drField, NULL);
    avro_value_set_int(&drField, GetActiveMsmtPktSize());
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: packet size : %d type : %d\n", __func__, __LINE__,GetActiveMsmtPktSize(), avro_value_get_type(&adrField));
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }


    //Blast metrics block
    if (msmt_type == single_client_msmt_type_one) {
        sta_data = sta_info;
    } else {
        sta_data = hash_map_get_first(blaster->active_msmt_map);
    }

    avro_value_get_by_name(&adrField, "blast_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "BlastRadioMetrics", &drField, NULL);
    wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, BlastRadioMetrics\tType: %d\n", avro_value_get_type(&adrField));
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    //args: (/* msmt_type */, /* radioStruct */, /* sta struct */, /* msmt struct */ /* 1 or 0*/, /* __func__ */);
    printBlastMetricData(msmt_type, blaster, sta_data, true, __FUNCTION__);

    avro_value_t rdr = {0};
    avro_value_t brdrField = {0};
    for(RadioCount = 0; RadioCount < (int)getNumberRadios(); RadioCount++)
    {
        avro_value_append(&drField, &rdr, NULL);

        //radio
        avro_value_get_by_name(&rdr, "radio", &brdrField, NULL);
        if ( CHK_AVRO_ERR ) {
             wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_branch(&brdrField, 1, &optional);
        if ( CHK_AVRO_ERR ) {
             wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        if (RadioCount == 0)
        {
            wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, radio number set to : \"%s\"\n", "radio_2_4G");
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "radio_2_4G"));
        }
        else if (RadioCount == 1)
        {
            wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, radio number set to : \"%s\"\n", "radio_5G");
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "radio_5G"));
        }

        //noise_floor
        avro_value_get_by_name(&rdr, "noise_floor", &brdrField, NULL);
        if ( CHK_AVRO_ERR ) {
             wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_branch(&brdrField, 1, &optional);
        if ( CHK_AVRO_ERR ) {
             wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }

        if (radio_stats[RadioCount] != NULL) //Noise floor
        {
           avro_value_set_int(&optional, (int)radio_stats[RadioCount]->NoiseFloor);
        }
        else
        {
           avro_value_set_int(&optional, 0);
        }
        wifi_util_dbg_print(WIFI_BLASTER,"RDK_LOG_DEBUG, noise_floor : %d \tType: %d\n", radio_stats[RadioCount]->NoiseFloor,avro_value_get_type(&optional));

        //channel_utilization
        avro_value_get_by_name(&rdr, "channel_utilization", &brdrField, NULL);
        avro_value_set_branch(&brdrField, 1, &optional);
        if (radio_stats[RadioCount] != NULL)
        {
            avro_value_set_float(&optional, (float)radio_stats[RadioCount]->channelUtil);
        }
        else
        {
            avro_value_set_float(&optional, 0);
        }
        wifi_util_dbg_print(WIFI_BLASTER,"RDK_LOG_DEBUG, channel_utilization : %d \tType: %d\n", radio_stats[RadioCount]->channelUtil,avro_value_get_type(&optional));
        //activity_factor
        avro_value_get_by_name(&rdr, "activity_factor", &brdrField, NULL);
        avro_value_set_branch(&brdrField, 1, &optional);

        if (radio_stats[RadioCount] != NULL) //Noise floor
        {
            avro_value_set_int(&optional, (int)radio_stats[RadioCount]->RadioActivityFactor);
        }
        else
        {
            avro_value_set_int(&optional, 0);
        }
        wifi_util_dbg_print(WIFI_BLASTER,"RDK_LOG_DEBUG, activity_factor : %d \tType: %d\n", radio_stats[RadioCount]->RadioActivityFactor,avro_value_get_type(&optional));

        //carrier_sense_threshold_exceeded
        avro_value_get_by_name(&rdr, "carrier_sense_threshold_exceeded", &brdrField, NULL);
        avro_value_set_branch(&brdrField, 1, &optional);

        if (radio_stats[RadioCount] != NULL)
        {
            avro_value_set_int(&optional, (int)radio_stats[RadioCount]->CarrierSenseThreshold_Exceeded);
        }
        else
        {
            avro_value_set_int(&optional, 0);
        }
        wifi_util_dbg_print(WIFI_BLASTER,"RDK_LOG_DEBUG, carrier_sense_threshold_exceeded : %d \tType: %d\n", radio_stats[RadioCount]->CarrierSenseThreshold_Exceeded,avro_value_get_type(&optional));
        //channels_in_use
        avro_value_get_by_name(&rdr, "channels_in_use", &brdrField, NULL);
        avro_value_set_branch(&brdrField, 1, &optional);

        if (radio_stats[RadioCount] != NULL)
        {
            if (strlen(radio_stats[RadioCount]->ChannelsInUse) == 0)
            {
                avro_value_set_null(&optional);
            } else {
                avro_value_set_string(&optional, radio_stats[RadioCount]->ChannelsInUse);
            }
        }
        wifi_util_dbg_print(WIFI_BLASTER,"RDK_LOG_DEBUG, channels_in_use : %s \tType: %d\n", radio_stats[RadioCount]->ChannelsInUse,avro_value_get_type(&optional));
    }
    // operating_standards
    avro_value_get_by_name(&adrField, "blast_metrics", &drField, NULL);
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "operating_standards", &drField, NULL);
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    avro_value_set_branch(&drField, 1, &optional);
    wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, operating_standard\tType: %d\n", avro_value_get_type(&optional));
    //Patch HAL values if necessary
    if ( blaster->curStepData.ApIndex < 0)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, operating_standard = \"%s\"\n", "Not defined, set to NULL" );
        avro_value_set_null(&optional);
    }
    else
    {
        wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, operating_standard = \"%s\"\n", sta_data->sta_active_msmt_data[0].Operating_standard);
        avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional),
        sta_data->sta_active_msmt_data[0].Operating_standard));
    }
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    // operating channel bandwidth
    avro_value_get_by_name(&adrField, "blast_metrics", &drField, NULL);
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "operating_channel_bandwidth", &drField, NULL);
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    avro_value_set_branch(&drField, 1, &optional);
    wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, operating_channel_bandwidth\tType: %d\n", avro_value_get_type(&optional));
    //Patch HAL values if necessary
    if ( blaster->curStepData.ApIndex < 0)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "set to NULL" );
        avro_value_set_null(&optional);
    }
    else
    {
        if ( strstr("20MHz", sta_data->sta_active_msmt_data[0].Operating_channelwidth))
        {
            wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "set to _20MHz" );
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_20MHz"));
        }
        else if ( strstr("40MHz", sta_data->sta_active_msmt_data[0].Operating_channelwidth) )
        {
            wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "set to _40MHz" );
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_40MHz"));
        }
        else if ( strstr("80MHz", sta_data->sta_active_msmt_data[0].Operating_channelwidth) )
        {
            wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "set to _80MHz" );
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_80MHz"));
        }
        else if ( strstr("160MHz", sta_data->sta_active_msmt_data[0].Operating_channelwidth) )
        {
            wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, operating_channel_bandwidth = \"%s\"\n", "set to _160MHz" );
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_160MHz"));
        }
    }
    if ( CHK_AVRO_ERR ) {
         wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    radio_idx = getRadioIndexFromAp(blaster->curStepData.ApIndex);
    // channel #
    avro_value_get_by_name(&adrField, "blast_metrics", &drField, NULL);
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "channel", &drField, NULL);
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    avro_value_set_branch(&drField, 1, &optional);
    if (blaster->curStepData.ApIndex >= 0)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, channel = %d\n", radio_stats[radio_idx]->primary_radio_channel);
        wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, channel\tType: %d\n", avro_value_get_type(&optional));
        avro_value_set_int(&optional, radio_stats[radio_idx]->primary_radio_channel);
    }
    else
    {
        wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, channel = 0\n");
        wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, channel\tType: %d\n", avro_value_get_type(&optional));
        avro_value_set_int(&optional, 0);
    }
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    // frequency band
    avro_value_get_by_name(&adrField, "blast_metrics", &drField, NULL);
    if ( CHK_AVRO_ERR ) {
       wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "frequency_band", &drField, NULL);
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    avro_value_set_branch(&drField, 1, &optional);
    wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, frequency_band\tType: %d\n", avro_value_get_type(&optional));
    //Patch HAL values if necessary
    if (blaster->curStepData.ApIndex < 0)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, frequency_band set to NULL\n");
        avro_value_set_null(&optional);
    }
    else
    {
        if (strstr("2.4GHz", radio_stats[radio_idx]->frequency_band))
        {
            wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, frequency_band = \"%s\"\n", "2.4GHz, set to _2_4GHz" );
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_2_4GHz" ));
        }
        else if (strstr("5GHz", radio_stats[radio_idx]->frequency_band))
        {
            wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, frequency_band = \"%s\"\n", "5GHz, set to _5GHz" );
            avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_5GHz" ));
        }
    }
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    //tx_retransmissions
    avro_value_get_by_name(&adrField, "blast_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "tx_retransmissions", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    if ((blaster != NULL) && (sta_data != NULL))
    {
        avro_value_set_int(&optional, (sta_data->sta_active_msmt_data[Count-1].ReTransmission - sta_data->sta_active_msmt_data[0].ReTransmission));
    }
    else
    {
        avro_value_set_int(&optional, 0);
    }
    wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, tx_retransmissions = %d\n",(sta_data->sta_active_msmt_data[Count-1].ReTransmission - sta_data->sta_active_msmt_data[0].ReTransmission));

    //max_tx_rate
    avro_value_get_by_name(&adrField, "blast_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "max_tx_rate", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    if ((blaster != NULL) && (sta_data != NULL))
    {
        avro_value_set_int(&optional, sta_data->sta_active_msmt_data[0].MaxTxRate);
    }
    else
    {
        avro_value_set_int(&optional, 0);
    }
    wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, maximum TX rate = %d\n",sta_data->sta_active_msmt_data[0].MaxTxRate);

    //max_rx_rate
    avro_value_get_by_name(&adrField, "blast_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "max_rx_rate", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    if ((blaster != NULL) && (sta_data != NULL))
    {
        avro_value_set_int(&optional, sta_data->sta_active_msmt_data[0].MaxRxRate);
    }
    else
    {
        avro_value_set_int(&optional, 0);
    }
    wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, maximum RX rate = %d\n",sta_data->sta_active_msmt_data[0].MaxRxRate);

    //Array of device reports
    avro_value_get_by_name(&adrField, "blast_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "BlastMetricsArrayOfReadings", &drField, NULL);
    wifi_util_dbg_print(WIFI_BLASTER, "RDK_LOG_DEBUG, BlastMetricsArrayOfReading\tType: %d\n", avro_value_get_type(&adrField));
    if ( CHK_AVRO_ERR ) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    //Device Report for wifi-blaster array of readings
    avro_value_t dr = {0};
    avro_value_t bdrField = {0}; //Used for array readings per blast

    for (sampleCount = 0; sampleCount < Count; sampleCount++)
    {
        avro_value_append(&drField, &dr, NULL);

        wifi_util_dbg_print(WIFI_BLASTER, "%s : %d count = %d signal_strength= %d\n",__func__,__LINE__,sampleCount,sta_data->sta_active_msmt_data[sampleCount].rssi);
        avro_value_get_by_name(&dr, "signal_strength", &bdrField, NULL);
        if ( CHK_AVRO_ERR ) {
             wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_branch(&bdrField, 1, &optional);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_int(&optional, (int)sta_data->sta_active_msmt_data[sampleCount].rssi);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }

        //snr
        wifi_util_dbg_print(WIFI_BLASTER, "%s : %d count = %d snr= %d\n",__func__,__LINE__,sampleCount,sta_data->sta_active_msmt_data[sampleCount].SNR);
        avro_value_get_by_name(&dr, "snr", &bdrField, NULL);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_branch(&bdrField, 1, &optional);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_int(&optional, (int)sta_data->sta_active_msmt_data[sampleCount].SNR);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }

        //tx_phy_rate
        wifi_util_dbg_print(WIFI_BLASTER, "%s : %d count = %d tx_phy_rate = %d\n",__func__,__LINE__,sampleCount,sta_data->sta_active_msmt_data[sampleCount].TxPhyRate);
        avro_value_get_by_name(&dr, "tx_phy_rate", &bdrField, NULL);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_branch(&bdrField, 1, &optional);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_int(&optional, (int)sta_data->sta_active_msmt_data[sampleCount].TxPhyRate );
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }

        //rx_phy_rate
        wifi_util_dbg_print(WIFI_BLASTER, "%s : %d count = %d rx_phy_rate = %d\n",__func__,__LINE__,sampleCount,sta_data->sta_active_msmt_data[sampleCount].RxPhyRate);
        avro_value_get_by_name(&dr, "rx_phy_rate", &bdrField, NULL);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_branch(&bdrField, 1, &optional);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_int(&optional, (int)sta_data->sta_active_msmt_data[sampleCount].RxPhyRate);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }

        //throughput
        wifi_util_dbg_print(WIFI_BLASTER, "%s : %d count = %d throughput = %lf\n",__func__,__LINE__,sampleCount,sta_data->sta_active_msmt_data[sampleCount].throughput);
        avro_value_get_by_name(&dr, "throughput", &bdrField, NULL);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_branch(&bdrField, 1, &optional);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
        avro_value_set_float(&optional, (float)sta_data->sta_active_msmt_data[sampleCount].throughput);
        if ( CHK_AVRO_ERR ) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        }
    }
    /* free the sta_data->sta_active_msmt_data allocated memory */
    if (sta_data->sta_active_msmt_data != NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "%s : %d memory freed for sta_active_msmt_data\n",__func__,__LINE__);
        free(sta_data->sta_active_msmt_data);
        sta_data->sta_active_msmt_data = NULL;
    }

    /* free the sta_data allocated memory for offline clients and remove from hash map*/
    if ( blaster->curStepData.ApIndex < 0)
    {
        if (sta_data != NULL)
        {
            pthread_mutex_lock(&blaster->lock);
            sta_del = (blaster_hashmap_t *) hash_map_remove(blaster->active_msmt_map, to_sta_key(sta_data->sta_mac, sta_key));
            pthread_mutex_unlock(&blaster->lock);
            if (sta_del != NULL)
            {
                wifi_util_dbg_print(WIFI_BLASTER, "%s : %d removed offline client %s from sta_map\n",__func__,__LINE__, sta_del->sta_mac);
            }
            free(sta_data);
            sta_data = NULL;
        }
    }

    /* check for writer size, if buffer is almost full, skip trailing linklist */
    avro_value_sizeof(&adr, (size_t*)&size);
    if (CHK_AVRO_ERR) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    //Thats the end of that
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Writing the avro values \n", __func__, __LINE__);
    avro_value_write(writer, &adr);
    if (CHK_AVRO_ERR) {
         wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    wifi_util_dbg_print(WIFI_BLASTER, "AVRO packing done\n");
    CcspTraceInfo(("%s-%d AVRO packing done\n", __FUNCTION__, __LINE__));
#if 0
    char *json;
    if (!avro_value_to_json(&adr, 1, &json))
    {
        wifi_util_dbg_print(WIFI_BLASTER,"json is %s\n", json);
        free(json);
    }
#endif
    for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        if(radio_stats[radio_index] != NULL){
            free(radio_stats[radio_index]);
            radio_stats[radio_index] = NULL;
        }
    }
    //Free up memory
    avro_value_decref(&adr);
    avro_writer_free(writer);

    size += MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH;
    wifi_util_dbg_print(WIFI_BLASTER, ":%s TraceParent:%s, TraceState:%s \n", __func__,blaster->active_msmt.t_header.traceParent, blaster->active_msmt.t_header.traceState);
    sendWebpaMsg((char *)(serviceName),  (char *)(dest), trans_id, blaster->active_msmt.t_header.traceParent, blaster->active_msmt.t_header.traceState, (char *)(contentType), buff, size);//ONE_WIFI TBD
    telemetry_buf = malloc(sizeof(char)*1024);
    if (telemetry_buf == NULL) {
        wifi_util_error_print(WIFI_BLASTER,"%s:%d telemetry_buf allocation failed\r\n", __func__, __LINE__);
        return;
    }
    memset(telemetry_buf, 0, sizeof(char)*1024);
    snprintf(telemetry_buf, sizeof(char)*1024, "%s %s",blaster->active_msmt.t_header.traceParent, blaster->active_msmt.t_header.traceState);
    get_stubs_descriptor()->t2_event_s_fn("TRACE_WIFIBLAST_REPORT_SENT", telemetry_buf);
    wifi_util_dbg_print(WIFI_BLASTER, "Creation of Telemetry record is successful\n");
    CcspTraceInfo(("%s-%d Blaster report successfully sent to Parodus WebPA component\n", __FUNCTION__, __LINE__));
    if (telemetry_buf != NULL) {
        free(telemetry_buf);
        telemetry_buf = NULL;
    }
#endif // CCSP_COMMON
}

typedef struct blaster_report_pb {
    size_t  len;   /* Length of the serialized protobuf */
    void    *buf;  /* Allocated pointer for serialized data */
} blaster_report_pb_t;

static void ext_blaster_report_device_struct_free(ExtBlaster__WifiBlastResult__DeviceMetrics *wb_dm_pb)
{
    if (wb_dm_pb == NULL) {
        return;
    }

    free(wb_dm_pb->client_mac);
    free(wb_dm_pb->throughput_samples);
    free(wb_dm_pb->tx_packet_retransmissions);
    free(wb_dm_pb);
}

static void ext_blaster_report_radio_struct_free(ExtBlaster__WifiBlastResult__RadioMetrics *wb_rm_pb)
{
    free(wb_rm_pb);
}

static void ext_blaster_report_health_struct_free(ExtBlaster__WifiBlastResult__HealthMetrics *wb_hm_pb)
{
    if (wb_hm_pb == NULL) {
        return;
    }

    free(wb_hm_pb->load_avg);
    free(wb_hm_pb);
}

static void ext_blaster_report_status_struct_free(ExtBlaster__WifiBlastResult__Status *status)
{
    if (status == NULL) {
        return;
    }

    free(status->description);
    free(status);
}

static ExtBlaster__WifiBlastResult__Status* ExtBlaster_report_status_struct_create()
{
    ExtBlaster__WifiBlastResult__Status *res_status;
    wifi_actvie_msmt_t *blaster;

    if ((blaster = (wifi_actvie_msmt_t *)get_wifi_blaster()) == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s:%d: wifi blaster active msmt data is null\n", __func__, __LINE__);
        return NULL;
    }

    res_status = calloc(1, sizeof(*res_status));
    if (res_status == NULL) {
      wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to allocate Status memory\n", __func__);
      return NULL;
    }

    ext_blaster__wifi_blast_result__status__init(res_status);

    switch (blaster->status) {
        case ACTIVE_MSMT_STATUS_UNDEFINED:
            res_status->code = EXT_BLASTER__RESULT_CODE__RESULT_CODE_UNDEFINED;
            break;
        case ACTIVE_MSMT_STATUS_SUCCEED:
            res_status->code = EXT_BLASTER__RESULT_CODE__RESULT_CODE_SUCCEED;
            break;
        default:
            res_status->code = EXT_BLASTER__RESULT_CODE__RESULT_CODE_ERROR;
            break;
    }

    res_status->description = strdup(blaster->status_desc);
    if (res_status->description == NULL)
    {
      wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to allocate Description memory\n", __func__);
      free(res_status);
      return NULL;
    }

    return res_status;
}

static void ext_blaster_report_pb_struct_free(ExtBlaster__WifiBlastResult *wb_res_pb)
{
    if (wb_res_pb == NULL)
        return;

    ext_blaster_report_device_struct_free(wb_res_pb->device_metrics);
    ext_blaster_report_health_struct_free(wb_res_pb->health_metrics);
    ext_blaster_report_radio_struct_free(wb_res_pb->radio_metrics);
    ext_blaster_report_status_struct_free(wb_res_pb->status);
    free(wb_res_pb->plan_id);
    free(wb_res_pb);
}


static ExtBlaster__WifiBlastResult__HealthMetrics__LoadAvg* ExtBlaster_report_load_avg_struct_create()
{
    ExtBlaster__WifiBlastResult__HealthMetrics__LoadAvg *LoadAvg_Protbuf;
    LoadAvg_Protbuf = calloc(1, sizeof(*LoadAvg_Protbuf));
    wifi_actvie_msmt_t *act_msmt = get_wifi_blaster();
    active_msmt_resources_t *res = &act_msmt->active_msmt.ActiveMsmtResources;

    if (LoadAvg_Protbuf == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to allocate HealthMetrics__LoadAvg memory\n", __func__);
        return NULL;
    }
    ext_blaster__wifi_blast_result__health_metrics__load_avg__init(LoadAvg_Protbuf);

    LoadAvg_Protbuf->one = res->cpu_one;
    LoadAvg_Protbuf->has_one = true;
    LoadAvg_Protbuf->five = res->cpu_five;
    LoadAvg_Protbuf->has_five = true;
    LoadAvg_Protbuf->fifteen = res->cpu_fifteen;
    LoadAvg_Protbuf->has_fifteen = true;

    return LoadAvg_Protbuf;
}

static ExtBlaster__WifiBlastResult__HealthMetrics* ExtBlaster_report_health_struct_create()
{
    ExtBlaster__WifiBlastResult__HealthMetrics *HealthMtrx_Protbuf;
    wifi_actvie_msmt_t *act_msmt = get_wifi_blaster();
    active_msmt_resources_t *res = &act_msmt->active_msmt.ActiveMsmtResources;

    HealthMtrx_Protbuf = calloc(1, sizeof(*HealthMtrx_Protbuf));
    if (HealthMtrx_Protbuf == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to allocate HealthMetrics memory\n", __func__);
        return NULL;
    }

    ext_blaster__wifi_blast_result__health_metrics__init(HealthMtrx_Protbuf);

    HealthMtrx_Protbuf->cpu_util = res->util_cpu;
    HealthMtrx_Protbuf->has_cpu_util = true;
    HealthMtrx_Protbuf->mem_util = res->util_mem;
    HealthMtrx_Protbuf->has_mem_util = true;
    HealthMtrx_Protbuf->load_avg = ExtBlaster_report_load_avg_struct_create();
    if (HealthMtrx_Protbuf->load_avg == NULL) {
        free(HealthMtrx_Protbuf);
        return NULL;
    }

    return HealthMtrx_Protbuf;
}

static ExtBlaster__RadioBandType ExtBlaster_report_wifi_band_get(char * band_desc)
{
    ExtBlaster__RadioBandType band;

    if (strstr("2.4GHz", band_desc))
        band = EXT_BLASTER__RADIO_BAND_TYPE__BAND2G;
    else if (strstr("5GHz", band_desc))
        band = EXT_BLASTER__RADIO_BAND_TYPE__BAND5G;
    else if (strstr("5GL", band_desc))
        band = EXT_BLASTER__RADIO_BAND_TYPE__BAND5GL;
    else if (strstr("5GU", band_desc))
        band = EXT_BLASTER__RADIO_BAND_TYPE__BAND5GU;
    else
        band = EXT_BLASTER__RADIO_BAND_TYPE__BAND_UNKNOWN;

    return band;
}

static ExtBlaster__WiFiStandard ExtBlaster_report_wifi_standard_get(wifi_ieee80211Variant_t variant)
{
    ExtBlaster__WiFiStandard standard;

    if (variant & WIFI_80211_VARIANT_A)
        standard = EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_A;
    else if (variant & WIFI_80211_VARIANT_B)
        standard = EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_B;
    else if (variant & WIFI_80211_VARIANT_G)
        standard = EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_G;
    else if (variant & WIFI_80211_VARIANT_N)
        standard = EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_N;
    else if (variant & WIFI_80211_VARIANT_AC)
        standard = EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_AC;
    else if (variant & WIFI_80211_VARIANT_AX)
        standard = EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_AX;
    else
        standard = EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_UNKNOWN;

    return standard;
}

static ExtBlaster__ChanWidth ExtBlaster_report_wifi_chanwidth_get(char * width)
{
    ExtBlaster__ChanWidth chan_w;

    if(strstr("20MHz", width))
        chan_w = EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_20MHZ;
    else if(strstr("40MHz", width))
        chan_w = EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_40MHZ;
    else if(strstr("80MHz", width))
        chan_w = EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_80MHZ;
    else if(strstr("160MHz", width))
        chan_w = EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_160MHZ;
    else
        chan_w = EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_UNKNOWN;

    return chan_w;
}
static ExtBlaster__WifiBlastResult__RadioMetrics* ExtBlaster_report_radio_struct_create(blaster_hashmap_t *sta_data)
{
    ExtBlaster__WifiBlastResult__RadioMetrics *RadioMetrics_protbuf;
    radio_data_t *radio_stats[MAX_NUM_RADIOS];
    wifi_ieee80211Variant_t wifi_variant;
    int ap_index = 0;
    int num_of_samples = GetActiveMsmtNumberOfSamples();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    bool twoG80211axEnable = false;
#ifdef CCSP_COMMON
    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
    twoG80211axEnable = rfc_pcfg->twoG80211axEnable_rfc;
#endif // CCSP_COMMON

    for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        radio_stats[radio_index] = (radio_data_t *) malloc (sizeof(radio_data_t));
        if (radio_stats[radio_index] == NULL) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: radio_stats is NULL\n", __func__, __LINE__);
        }
        memset(radio_stats[radio_index],0, sizeof(radio_data_t));
        if (get_dev_stats_for_radio(radio_index, (radio_data_t *)radio_stats[radio_index]) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Error getting radio datas\n", __func__, __LINE__);
            continue;
        }
    }

    ap_index = getApIndexfromClientMac((char *)sta_data->sta_mac);
    vap_svc_t *ext_svc;
    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    if (ext_svc == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: EXT SVC is NULL\n", __func__, __LINE__);
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        return NULL;
    }
    int connected_radio_index = 0;
    connected_radio_index = get_radio_index_for_vap_index(ext_svc->prop, ap_index);

    if (connected_radio_index == -1) {
        wifi_util_error_print(WIFI_BLASTER, "%s:%d: Radio index returned as error %u\n", __func__, __LINE__, connected_radio_index);
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        return NULL;
    }

    if (wifiStandardStrToEnum(sta_data->sta_active_msmt_data[num_of_samples-1].Operating_standard, &wifi_variant,connected_radio_index, twoG80211axEnable) != TRUE) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: wifiStandardStrToEnum Failed\n", __func__, __LINE__);
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        return NULL;
    }

    RadioMetrics_protbuf = calloc(1, sizeof(*RadioMetrics_protbuf));
    if (RadioMetrics_protbuf == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to allocate RadioMetrics memory\n", __func__);
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if(radio_stats[radio_index] != NULL){
                free(radio_stats[radio_index]);
                radio_stats[radio_index] = NULL;
            }
        }
        return NULL;
    }

    ext_blaster__wifi_blast_result__radio_metrics__init(RadioMetrics_protbuf);

    RadioMetrics_protbuf->activity_factor = (int)radio_stats[connected_radio_index]->RadioActivityFactor;
    RadioMetrics_protbuf->has_activity_factor = true;
    RadioMetrics_protbuf->carriersense_threshold_exceeded = (int)radio_stats[connected_radio_index]->CarrierSenseThreshold_Exceeded;
    RadioMetrics_protbuf->has_carriersense_threshold_exceeded = true;
    RadioMetrics_protbuf->noise_floor = (int)radio_stats[connected_radio_index]->NoiseFloor;
    RadioMetrics_protbuf->has_noise_floor = true;
    RadioMetrics_protbuf->channel_utilization = (uint)radio_stats[connected_radio_index]->channelUtil;
    RadioMetrics_protbuf->has_channel_utilization = true;
    RadioMetrics_protbuf->channel = radio_stats[connected_radio_index]->primary_radio_channel;
    RadioMetrics_protbuf->has_channel = true;
    RadioMetrics_protbuf->wifi_standard = ExtBlaster_report_wifi_standard_get(wifi_variant);
    RadioMetrics_protbuf->has_wifi_standard = true;
    RadioMetrics_protbuf->chan_width = ExtBlaster_report_wifi_chanwidth_get(sta_data->sta_active_msmt_data[num_of_samples-1].Operating_channelwidth);
    RadioMetrics_protbuf->has_chan_width = true;
    RadioMetrics_protbuf->radio_band = ExtBlaster_report_wifi_band_get(radio_stats[connected_radio_index]->frequency_band);
    RadioMetrics_protbuf->has_radio_band = true;
    wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: Returned data is Activity Factor %d, CS Threshold %d, NF %d, Ch. Util %d, Channel %d, Standard %d, Ch. Width %d, Radio Band %d\n",
                                 __func__, __LINE__, RadioMetrics_protbuf->activity_factor, RadioMetrics_protbuf->carriersense_threshold_exceeded,
                                 RadioMetrics_protbuf->noise_floor, RadioMetrics_protbuf->channel_utilization, RadioMetrics_protbuf->channel, RadioMetrics_protbuf->wifi_standard,
                                 RadioMetrics_protbuf->chan_width, RadioMetrics_protbuf->radio_band);

    for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        if(radio_stats[radio_index] != NULL){
            free(radio_stats[radio_index]);
            radio_stats[radio_index] = NULL;
        }
    }

    return RadioMetrics_protbuf;
}

static int ExtBlaster_device_metrics_blast_sample_fill(
        ExtBlaster__WifiBlastResult__DeviceMetrics *DMetric_pbuf, blaster_hashmap_t *cli_data)
{
    int count;
    int num_of_samples = GetActiveMsmtNumberOfSamples();

    if (num_of_samples <= 0) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Invalid number of samples is received [%d]\n", __func__, num_of_samples);
        return -1;
    }

    DMetric_pbuf->throughput_samples = calloc(num_of_samples, sizeof(*DMetric_pbuf->throughput_samples));
    if (DMetric_pbuf->throughput_samples == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to allocate throughput_samples memory\n", __func__);
        return -1;
    }

    DMetric_pbuf->tx_packet_retransmissions = calloc(num_of_samples,
            sizeof(*DMetric_pbuf->tx_packet_retransmissions));
    if (DMetric_pbuf->tx_packet_retransmissions == NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to allocate tx_packet_retransmissions memory\n", __func__);
        free(DMetric_pbuf->throughput_samples);
        DMetric_pbuf->throughput_samples = NULL;
        return -1;
    }

    DMetric_pbuf->n_throughput_samples = num_of_samples;
    DMetric_pbuf->n_tx_packet_retransmissions = num_of_samples;
    wifi_util_dbg_print(WIFI_BLASTER,"%s: Returned Throughput samples and PKT retrans %d\n", __func__, num_of_samples);
    for (count = 0; count < num_of_samples; count++)
    {
        DMetric_pbuf->throughput_samples[count] = cli_data->sta_active_msmt_data[count].throughput;
        DMetric_pbuf->tx_packet_retransmissions[count] = cli_data->sta_active_msmt_data[count].ReTransmission;
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Returned Throughput Samples and Tx Pkt Retransmissions for Sample-ID %d are %lf and %llu\n", __func__, count, DMetric_pbuf->throughput_samples[count], DMetric_pbuf->tx_packet_retransmissions[count]);
    }
  return 0;
}

static ExtBlaster__WifiBlastResult__DeviceMetrics* ExtBlaster_report_device_struct_create(blaster_hashmap_t *sta_data)
{
    ExtBlaster__WifiBlastResult__DeviceMetrics *DevMetrics_protbuf;
    int sampleCount = GetActiveMsmtNumberOfSamples();

    DevMetrics_protbuf = calloc(1, sizeof(*DevMetrics_protbuf));
    if (DevMetrics_protbuf == NULL) {
      wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to allocate DeviceMetrics memory\n", __func__);
      return NULL;
    }

    ext_blaster__wifi_blast_result__device_metrics__init(DevMetrics_protbuf);
    DevMetrics_protbuf->client_mac = (char *)malloc(PROTOBUF_MAC_SIZE);
    if (DevMetrics_protbuf->client_mac == NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to allocate Client MAC memory\n", __func__);
        free(DevMetrics_protbuf);
        return NULL;
    }
    memset(DevMetrics_protbuf->client_mac,'\0', PROTOBUF_MAC_SIZE);
    snprintf(DevMetrics_protbuf->client_mac, PROTOBUF_MAC_SIZE, "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx", sta_data->sta_mac[0], sta_data->sta_mac[1], sta_data->sta_mac[2], sta_data->sta_mac[3], sta_data->sta_mac[4], sta_data->sta_mac[5]);
    DevMetrics_protbuf->rssi = (int)sta_data->sta_active_msmt_data[sampleCount-1].rssi;
    DevMetrics_protbuf->has_rssi = true;
    DevMetrics_protbuf->rx_phyrate = (int)sta_data->sta_active_msmt_data[sampleCount-1].RxPhyRate;
    DevMetrics_protbuf->has_rx_phyrate = true;
    DevMetrics_protbuf->tx_phyrate = (int)sta_data->sta_active_msmt_data[sampleCount-1].TxPhyRate;
    DevMetrics_protbuf->has_tx_phyrate = true;
    DevMetrics_protbuf->snr = (int)sta_data->sta_active_msmt_data[sampleCount-1].SNR;
    DevMetrics_protbuf->has_snr = true;
    wifi_util_dbg_print(WIFI_BLASTER,"%s: Client MAC: %s \n", __func__, DevMetrics_protbuf->client_mac);
    wifi_util_dbg_print(WIFI_BLASTER,"%s: Returned RSSI is %d, rx_phyrate is %d, tx_phyrate is %d, snr is %d\n", __func__, DevMetrics_protbuf->rssi, DevMetrics_protbuf->rx_phyrate, DevMetrics_protbuf->tx_phyrate, DevMetrics_protbuf->snr);

    // fill blast device details
    if (ExtBlaster_device_metrics_blast_sample_fill(DevMetrics_protbuf, sta_data) != 0)
    {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed ExtBlaster_device_metrics_blast_sample_fill\n", __func__);
        free(DevMetrics_protbuf->client_mac);
        free(DevMetrics_protbuf);
        DevMetrics_protbuf = NULL;
        return NULL;
    }

    return DevMetrics_protbuf;
}

static int ExtBlaster_report_metrics_struct_create(ExtBlaster__WifiBlastResult *wb_res_pb, blaster_hashmap_t *station_info)
{
    ExtBlaster__WifiBlastResult__HealthMetrics *Health_metrics_pb;
    ExtBlaster__WifiBlastResult__RadioMetrics *Radio_metrics_pb;
    ExtBlaster__WifiBlastResult__DeviceMetrics *Device_metrics_pb;

    Health_metrics_pb = ExtBlaster_report_health_struct_create();
    if (Health_metrics_pb == NULL) {
        return -1;
    }

    Radio_metrics_pb = ExtBlaster_report_radio_struct_create(station_info);
    if (Radio_metrics_pb == NULL) {
        ext_blaster_report_health_struct_free(Health_metrics_pb);
        return -1;
    }

    Device_metrics_pb = ExtBlaster_report_device_struct_create(station_info);
    if (Device_metrics_pb == NULL)
    {
        ext_blaster_report_health_struct_free(Health_metrics_pb);
        ext_blaster_report_radio_struct_free(Radio_metrics_pb);
        return -1;
    }

    wb_res_pb->health_metrics = Health_metrics_pb;
    wb_res_pb->device_metrics = Device_metrics_pb;
    wb_res_pb->radio_metrics = Radio_metrics_pb;

    return 0;
}

static ExtBlaster__WifiBlastResult* ExtBlaster_report_pb_struct_create(blaster_hashmap_t *sta_data)
{
    ExtBlaster__WifiBlastResult *Result_protbuf;
    struct timeval ts;
    unsigned char PlanId[PLAN_ID_LENGTH_POD];
    wifi_actvie_msmt_t *blaster;

    blaster = (wifi_actvie_msmt_t *)get_wifi_blaster();

    if(blaster == NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "%s:%d: wifi blaster active msmt data is null \n", __func__, __LINE__);
        return NULL;
    }

    Result_protbuf = calloc(1, sizeof(*Result_protbuf));
    if (Result_protbuf == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to allocate WifiBlastResult memory\n", __func__);
        return NULL;
    }

    //bssid_data = bssid_info;
    //sta_data = sta_info;

    ext_blaster__wifi_blast_result__init(Result_protbuf);

    memset(PlanId, 0, sizeof(PlanId));

    gettimeofday(&ts, NULL);
    int64_t tstamp_av_main = ((int64_t) (ts.tv_sec) * 1000000) + (int64_t) ts.tv_usec;
    //Set timestamp value in the report
    tstamp_av_main = tstamp_av_main/1000;

    to_plan_char(blaster->active_msmt.PlanId, PlanId);

    Result_protbuf->time_stamp = tstamp_av_main;
    Result_protbuf->has_time_stamp = true;
    Result_protbuf->step_id = blaster->curStepData.StepId;
    Result_protbuf->has_step_id = true;
    Result_protbuf->plan_id = strdup((char *)PlanId);
    if (Result_protbuf->plan_id == NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Failed to strdup PlanID\n", __func__);
        free(Result_protbuf);
        return NULL;
    }

    wifi_util_dbg_print(WIFI_BLASTER,"%s: PlanID %s, StepID %d\n", __func__, Result_protbuf->plan_id, Result_protbuf->step_id);

    if (blaster->status == ACTIVE_MSMT_STATUS_SUCCEED &&
        ExtBlaster_report_metrics_struct_create(Result_protbuf, sta_data) != 0)
    {
        ext_blaster_report_pb_struct_free(Result_protbuf);
        return NULL;
    }

    Result_protbuf->status = ExtBlaster_report_status_struct_create();
    if (Result_protbuf->status == NULL) {
        ext_blaster_report_pb_struct_free(Result_protbuf);
        return NULL;
    }

    return Result_protbuf;
}

static void ExtBlaster_report_pb_print_dbg(blaster_report_pb_t  *serialized_buff)
{
    ExtBlaster__WifiBlastResult *blast_res;
    ExtBlaster__WifiBlastResult__HealthMetrics *h_metrics;
    ExtBlaster__WifiBlastResult__HealthMetrics__LoadAvg *h_metrics_load_avg;
    ExtBlaster__WifiBlastResult__RadioMetrics *r_metrics;
    ExtBlaster__WifiBlastResult__DeviceMetrics *d_metrics;
    void *blast_res_buf = serialized_buff->buf;
    uint32_t count;
    uint64_t retrans_sum = 0;
    double throughput_sum = 0.0;
    c_item_t *item;
    char *chan_width;
    char *wifi_standard;
    char *radio_band;

    c_item_t map_wbm_chanwidth[] = {
        C_ITEM_STR( EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_20MHZ,          "HT20" ),
        C_ITEM_STR( EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_40MHZ,          "HT40" ),
        C_ITEM_STR( EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_40MHZ_ABOVE,    "HT40+" ),
        C_ITEM_STR( EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_40MHZ_BELOW,    "HT40-" ),
        C_ITEM_STR( EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_80MHZ,          "HT80" ),
        C_ITEM_STR( EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_160MHZ,         "HT160" ),
        C_ITEM_STR( EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_80_PLUS_80MHZ,  "HT80+80" ),
        C_ITEM_STR( EXT_BLASTER__CHAN_WIDTH__CHAN_WIDTH_UNKNOWN,        "Unknown" )
    };

    c_item_t map_wbm_hwmode[] = {
        C_ITEM_STR( EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_A,      "11a" ),
        C_ITEM_STR( EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_B,      "11b" ),
        C_ITEM_STR( EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_G,      "11g" ),
        C_ITEM_STR( EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_N,      "11n" ),
        C_ITEM_STR( EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_AC,     "11ac"),
        C_ITEM_STR( EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_80211_AX,     "11ax"),
        C_ITEM_STR( EXT_BLASTER__WI_FI_STANDARD__WIFI_STD_UNKNOWN,      "unknown" ),
    };

    c_item_t map_wbm_radiotype[] = {
        C_ITEM_STR( EXT_BLASTER__RADIO_BAND_TYPE__BAND2G,               "2.4G" ),
        C_ITEM_STR( EXT_BLASTER__RADIO_BAND_TYPE__BAND5G,               "5G" ),
        C_ITEM_STR( EXT_BLASTER__RADIO_BAND_TYPE__BAND5GL,              "5GL" ),
        C_ITEM_STR( EXT_BLASTER__RADIO_BAND_TYPE__BAND5GU,              "5GU" ),
        C_ITEM_STR( EXT_BLASTER__RADIO_BAND_TYPE__BAND_UNKNOWN,         "Unknown" ),
    };

    blast_res = ext_blaster__wifi_blast_result__unpack(NULL, serialized_buff->len,
        (const uint8_t *)blast_res_buf);
    if (blast_res == NULL) {
        wifi_util_error_print(WIFI_BLASTER, "%s:%d Failed to unpack blast result\n", __func__, __LINE__);
        return;
    }

    h_metrics = blast_res->health_metrics;
    r_metrics = blast_res->radio_metrics;
    d_metrics = blast_res->device_metrics;

    wifi_util_dbg_print(WIFI_BLASTER, "********** WiFi Blaster Test Protobuf Results **********\n");
    wifi_util_dbg_print(WIFI_BLASTER, "Plan[%s] Step[%d] Finished_Time_Stamp[%llu] Status[%d]\n",
         blast_res->plan_id, blast_res->step_id, blast_res->time_stamp, blast_res->status->code);
    wifi_util_dbg_print(WIFI_BLASTER, "Desc: %s\n", blast_res->status->description);

    if (blast_res->status->code != EXT_BLASTER__RESULT_CODE__RESULT_CODE_SUCCEED) {
        goto Error;
    }

    if ((h_metrics != NULL) && (h_metrics->load_avg != NULL))
    {
        h_metrics_load_avg = h_metrics->load_avg;
        wifi_util_dbg_print(WIFI_BLASTER, "Health: CPU_util[%u]%% Mem_free[%u]KB CPU_load_avg(1/5/15)[%0.2f/%0.2f/%0.2f]\n",
             h_metrics->cpu_util, h_metrics->mem_util,
             h_metrics_load_avg->one, h_metrics_load_avg->five, h_metrics_load_avg->fifteen);
    }

    if (r_metrics != NULL)
    {
        item = c_get_item_by_key(map_wbm_chanwidth, r_metrics->chan_width);
        chan_width = (char *)item->data;
        item = c_get_item_by_key(map_wbm_hwmode, r_metrics->wifi_standard);
        wifi_standard = (char *)item->data;
        item = c_get_item_by_key(map_wbm_radiotype, r_metrics->radio_band);
        radio_band = (char *)item->data;

        wifi_util_dbg_print(WIFI_BLASTER, "Radio: Noise_floor[%d]db Channel_Util[%u]%% Activity_factor[%u]%% "
             "Carriersense_Threshold_Exceeded[%u]%%\n",
             r_metrics->noise_floor, r_metrics->channel_utilization, r_metrics->activity_factor,
             r_metrics->carriersense_threshold_exceeded);
        wifi_util_dbg_print(WIFI_BLASTER, "   Channel[%u] Channel_Width[%s] Radio_band[%s] Wifi_Standard[%s]\n",
             r_metrics->channel, chan_width, radio_band, wifi_standard);
    }

    if (d_metrics != NULL)
    {
        wifi_util_dbg_print(WIFI_BLASTER, "Device: Client_Mac[%s] RSSI[%d]db Tx_Phyrate[%u] Rx_Phyrate[%u] SNR[%d]\n",
             d_metrics->client_mac, d_metrics->rssi, d_metrics->tx_phyrate, d_metrics->rx_phyrate,
             d_metrics->snr);

        for (count = 0; count < d_metrics->n_throughput_samples; count++)
        {
            wifi_util_dbg_print(WIFI_BLASTER, "Sample[%d] Throughput[%f]Mbps, TxRetrans[%llu]\n",
                 count + 1, d_metrics->throughput_samples[count],
                 d_metrics->tx_packet_retransmissions[count]);
            retrans_sum += d_metrics->tx_packet_retransmissions[count];
            throughput_sum += d_metrics->throughput_samples[count];
        }
        wifi_util_dbg_print(WIFI_BLASTER, "Average throughput[%f]Mbps. Summ of retransmissions[%llu]\n",
            throughput_sum / d_metrics->n_throughput_samples, retrans_sum);
    }

Error:
    wifi_util_dbg_print(WIFI_BLASTER, "***********************************************\n");
    ext_blaster__wifi_blast_result__free_unpacked(blast_res, NULL);
}

void pod_upload_single_client_active_msmt_data(blaster_hashmap_t *sta_info)
{
    ExtBlaster__WifiBlastResult *Result_pbuf;
    blaster_report_pb_t *report_pb;
    void *buf = NULL;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    char *mqtt_topic = (char *)mgr->blaster_config_global.blaster_mqtt_topic;
    qm_response_t res;

    wifi_util_dbg_print(WIFI_BLASTER, "%s: Enter\n", __func__);
    report_pb = calloc(1, sizeof(*report_pb));
    if (report_pb == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s: Failed to allocate xle_wbm_report_pb_t memory\n", __func__);
        return;
    }

    Result_pbuf = ExtBlaster_report_pb_struct_create(sta_info);
    if (Result_pbuf == NULL) {
        goto Error;
    }
    wifi_util_dbg_print(WIFI_BLASTER, "%s: Struct create done\n", __func__);

    report_pb->len = ext_blaster__wifi_blast_result__get_packed_size(Result_pbuf);
    if (report_pb->len == 0) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s: Invalid packed size for result buff\n", __func__);
        goto Error;
    }
    wifi_util_dbg_print(WIFI_BLASTER, "%s: Packed Size is %d\n", __func__, report_pb->len);

    buf = calloc(1, report_pb->len);
    if (buf == NULL) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s: Failed to allocate buf memory\n", __func__);
        goto Error;
    }

    report_pb->len = ext_blaster__wifi_blast_result__pack(Result_pbuf, buf);
    if (report_pb->len <= 0) {
        wifi_util_dbg_print(WIFI_BLASTER, "%s: Failed to pack result protobuf! Lengh [%zu]\n", __func__, report_pb->len);
        goto Error;
    }
    report_pb->buf = buf;
    wifi_util_dbg_print(WIFI_BLASTER, "%s: Packed buf is %s\n", __func__, (char *)report_pb->buf);

    //Send the Data
    if (!mqttcm_enabled && !qm_conn_get_status(NULL)) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Cannot connect to QM (QM not running?)\n", __func__);
        goto Error;
    }
    
    ext_blaster_report_pb_struct_free(Result_pbuf);

    wifi_util_dbg_print(WIFI_BLASTER,"%s: Publishing message with msg len: %zu, to topic: %s\n", __func__, report_pb->len, mqtt_topic);
    if (!mqttcm_enabled && !qm_conn_send_direct(QM_REQ_COMPRESS_IF_CFG, mqtt_topic, report_pb->buf, report_pb->len, &res)) {
        wifi_util_dbg_print(WIFI_BLASTER,"%s: Error sending message\n", __func__);
     }
#ifdef MQTTCM
    else if(mqttcm_enabled && !mqttcm_conn_msg_process(report_pb->buf, report_pb->len, true, mqtt_topic, "0"))
    {
        wifi_util_error_print(WIFI_BLASTER,"%s:Messages published to broker from WBM failed",__func__);
    }
#endif
    else {
        ExtBlaster_report_pb_print_dbg(report_pb);
    }

    if (report_pb != NULL) {
        free(report_pb->buf);
        free(report_pb);
        report_pb = NULL;
    }
    return;
Error:
    ext_blaster_report_pb_struct_free(Result_pbuf);
    free(report_pb);
    free(buf);
    return;
}
/* This function calls the ODP streamer function with station and radio data.
   If ActiveMsmtFlag is true then the streamer for active measurement is called or
   streamer for instant measurement has been triggered.
*/

void stream_client_msmt_data(bool ActiveMsmtFlag)
{
    if (ActiveMsmtFlag)
    {
        wifi_actvie_msmt_t *act_monitor;
        wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
        blaster_hashmap_t *sta = NULL;
        hash_map_t *blaster_map = NULL;
        sta_key_t sta_key;

        act_monitor = (wifi_actvie_msmt_t *)get_wifi_blaster();
        if(act_monitor == NULL) {
            wifi_util_error_print(WIFI_BLASTER, "%s: Failed to get act_monitor\n", __func__);
            return;
        }

        blaster_map = act_monitor->active_msmt_map;
        if (blaster_map == NULL) {
            wifi_util_error_print(WIFI_BLASTER,"%s:%d NULL active_blaster-data map\n", __func__, __LINE__);
            return;
        }

        to_sta_key(act_monitor->curStepData.DestMac, sta_key);
        sta = (blaster_hashmap_t *) hash_map_get(blaster_map, sta_key);

        if (sta == NULL) {
            wifi_util_error_print(WIFI_BLASTER, "%s: Failed to get hash_map\n", __func__);
            return;
        }

        if (ctrl->network_mode == rdk_dev_mode_type_gw) {
            upload_single_client_active_msmt_data(sta);
        } else if (act_monitor->status != ACTIVE_MSMT_STATUS_SUCCEED && ctrl->network_mode == rdk_dev_mode_type_ext) {
            pod_upload_single_client_active_msmt_data(sta);
        }
    }
}
