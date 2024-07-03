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
#include <avro.h>
#endif // CCSP_COMMON
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "harvester.h"
#include <sys/time.h>
#include "collection.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_harvester.h"
#include "wifi_monitor.h"
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/un.h>
#include <assert.h>
#include <limits.h>
#include <uuid/uuid.h>
#include "wifi_webconfig.h"
#ifdef CCSP_COMMON
#include "ansc_status.h"
#include <sysevent/sysevent.h>
#include "ccsp_base_api.h"
#include "wifi_passpoint.h"
#include "ccsp_trace.h"
#include "safec_lib_common.h"
#include "ccsp_WifiLog_wrapper.h"
#include "platform-logger.h"
#endif // CCSP_COMMON

#ifdef CCSP_COMMON
typedef enum {
    single_client_msmt_type_all,
    single_client_msmt_type_all_per_bssid,
    single_client_msmt_type_one,
} single_client_msmt_type_t;
#endif // CCSP_COMMON

void process_instant_msmt_stop();
static wifi_harvester_t g_harvester_module;

#define DEFAULT_INSTANT_REPORT_TIME 0
#define DEFAULT_INSTANT_POLL_TIME 5
#define MAX_BUFF_SIZE  20480
#define MAGIC_NUMBER      0x85
#define MAGIC_NUMBER_SIZE 1
#define SCHEMA_ID_LENGTH  32
#define MAC_KEY_LEN 13
#define harvester_app_start_process_instant_msmt_monitor 0
#define harvester_app_stop_process_instant_msmt_monitor 1
#define harvester_app_radio_data 2

uint8_t HASHVAL[16] = {0x43, 0x88, 0xe5, 0x85, 0xdd, 0x7c, 0x0d, 0x32,
                       0xac, 0x47, 0xe7, 0x1f, 0x63, 0x4b, 0x57, 0x9b
                      };

uint8_t UUIDVAL[16] = {0x8b, 0x27, 0xda, 0xfc, 0x0c, 0x4d, 0x40, 0xa1,
                       0xb6, 0x2c, 0xf2, 0x4a, 0x34, 0x07, 0x49, 0x14
                      };

char Report_Source[] = "wifi";
char CPE_TYPE_STR[] = "Gateway";

static inline char *to_sta_key    (mac_addr_t mac, sta_key_t key)
{
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}

bool is_harvester_device_associated(int ap_index, mac_address_t sta_mac)
{
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    assoc_dev_data_t *sta = NULL;
    sta_key_t sta_key;

    rdk_vap_info = get_wifidb_rdk_vap_info(ap_index);
    if(rdk_vap_info == NULL) {
        wifi_util_error_print(WIFI_HARVESTER, "%s: Failed to get rdk_vap_info from vap index %d\n", __func__, ap_index);
        return false;
    }
    if (rdk_vap_info->associated_devices_map == NULL) {
        wifi_util_error_print(WIFI_HARVESTER,"%s:%d NULL  associated_devices_map  pointer  for  %d\n", __func__, __LINE__, rdk_vap_info->vap_index);
        return false;
    }

    wifi_util_error_print(WIFI_HARVESTER, "%s: sta_mac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);

    to_sta_key(sta_mac, sta_key);
    sta = (assoc_dev_data_t *) hash_map_get(rdk_vap_info->associated_devices_map, sta_key);
    if (sta == NULL) {
        wifi_util_error_print(WIFI_HARVESTER, "%s: Failed to get sta from vap index %d\n", __func__, ap_index);
        return false;
    }
    else {
        return true;
    }

    return false;
}

static void harvester_route(wifi_event_route_t *route)
{
    memset(route, 0, sizeof(wifi_event_route_t));
    route->dst = wifi_sub_component_mon;
    route->u.inst_bit_map = wifi_app_inst_harvester;
}

static void config_process_instant_msmt_monitor(wifi_monitor_data_t *data)
{
    wifi_event_route_t route;
    wifi_util_error_print(WIFI_HARVESTER, "Entering %s\n", __func__);
    harvester_route(&route);
    data->u.mon_stats_config.args.vap_index = g_harvester_module.inst_msmt.ap_index;
    data->u.mon_stats_config.data_type = mon_stats_type_associated_device_stats;
    data->u.mon_stats_config.interval_ms = (g_harvester_module.instantPollPeriod * 1000);
    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d Interval is %lu\n", __func__, __LINE__, data->u.mon_stats_config.interval_ms);
    data->u.mon_stats_config.args.app_info = harvester_app_start_process_instant_msmt_monitor;
    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
}

static int push_harvester_config_event_to_monitor_queue(wifi_mon_stats_request_state_t state)
{
    // Send appropriate configs to monitor queue(stats, radio)
    wifi_monitor_data_t *data;
    wifi_util_dbg_print(WIFI_HARVESTER, "Entering %s\n", __func__);
    data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_HARVESTER,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(data, 0, sizeof(wifi_monitor_data_t));
    data->u.mon_stats_config.req_state = state;
    config_process_instant_msmt_monitor(data);

    if (NULL != data) {
        free(data);
        data = NULL;
    }
    return RETURN_OK;
}

#ifdef CCSP_COMMON

void upload_single_client_msmt_data(sta_data_t *sta_info)
{
    const char * serviceName = "wifi";
    const char * dest = "event:raw.kestrel.reports.WifiSingleClient";
    const char * contentType = "avro/binary"; // contentType "application/json", "avro/binary"
    uuid_t transaction_id;
    char trans_id[37];
    FILE *fp;
    char *buff;
    int size;
    sta_data_t  *sta_data;
    single_client_msmt_type_t msmt_type;

    avro_writer_t writer;
    avro_schema_t inst_msmt_schema = NULL;
    avro_schema_error_t error = NULL;
    avro_value_iface_t  *iface = NULL;
    avro_value_t  adr = {0}; /*RDKB-7463, CID-33353, init before use */
    avro_value_t  adrField = {0}; /*RDKB-7463, CID-33485, init before use */
    avro_value_t optional  = {0};

    if (sta_info == NULL) {
        wifi_util_error_print(WIFI_HARVESTER, "%s:%d: Invalid arguments\n", __func__, __LINE__);
        return;
    } else {
        msmt_type = single_client_msmt_type_one;
    }

    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Measurement Type: %d\n", __func__, __LINE__, msmt_type);

    /* open schema file */
    fp = fopen (WIFI_SINGLE_CLIENT_AVRO_FILENAME , "rb");
    if (fp == NULL)
    {
        wifi_util_error_print(WIFI_HARVESTER, "%s:%d: Unable to open schema file: %s\n", __func__, __LINE__, WIFI_SINGLE_CLIENT_AVRO_FILENAME);
        return;
    }

    /* seek through file and get file size*/
    fseek(fp , 0L , SEEK_END);
    size = ftell(fp);
    if(size < 0)
    {
        wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: ftell error\n", __func__, __LINE__);
        fclose(fp);
        return;
    }
    /*back to the start of the file*/
    rewind(fp);

    /* allocate memory for entire content */
    buff = malloc(size + 1);
    memset(buff, 0, size + 1);

    /* copy the file into the buffer */
    if (1 != fread(buff , size, 1 , fp))
    {
        fclose(fp);
        free(buff);
        wifi_util_error_print(WIFI_HARVESTER, "%s:%d: Unable to read schema file: %s\n", __func__, __LINE__, WIFI_SINGLE_CLIENT_AVRO_FILENAME);
        return ;
    }
    buff[size]='\0';
    fclose(fp);

    if (avro_schema_from_json(buff, strlen(buff), &inst_msmt_schema, &error))
    {
        free(buff);
        wifi_util_error_print(WIFI_HARVESTER, "%s:%d: Unable to parse steering schema, len: %d, error:%s\n", __func__, __LINE__, size, avro_strerror());
        return;
    }
    free(buff);

    //generate an avro class from our schema and get a pointer to the value interface
    iface = avro_generic_class_from_schema(inst_msmt_schema);

    avro_schema_decref(inst_msmt_schema);

    buff = malloc(MAX_BUFF_SIZE);
    memset(buff, 0, MAX_BUFF_SIZE);
    buff[0] = MAGIC_NUMBER; /* fill MAGIC number = Empty, i.e. no Schema ID */

    memcpy( &buff[MAGIC_NUMBER_SIZE], UUIDVAL, sizeof(UUIDVAL));
    memcpy( &buff[MAGIC_NUMBER_SIZE + sizeof(UUIDVAL)], HASHVAL, sizeof(HASHVAL));

    writer = avro_writer_memory((char*)&buff[MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH], MAX_BUFF_SIZE - MAGIC_NUMBER_SIZE - SCHEMA_ID_LENGTH);
    avro_writer_reset(writer);
    avro_generic_value_new(iface, &adr);

    // timestamp - long
    avro_value_get_by_name(&adr, "header", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "timestamp", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    struct timeval ts;
    gettimeofday(&ts, NULL);

    int64_t tstamp_av_main = ((int64_t) (ts.tv_sec) * 1000000) + (int64_t) ts.tv_usec;

    tstamp_av_main = tstamp_av_main/1000;
    avro_value_set_long(&optional, tstamp_av_main );

    // uuid - fixed 16 bytes
    uuid_generate_random(transaction_id);
    uuid_unparse(transaction_id, trans_id);

    avro_value_get_by_name(&adr, "header", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "uuid", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_fixed(&optional, transaction_id, 16);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    wifi_util_dbg_print(WIFI_HARVESTER, "Report transaction uuid generated is %s\n", trans_id);
    platform_trace_warning(WIFI_HARVESTER, "Single client report transaction uuid generated is %s\n", trans_id );

    //source - string
    avro_value_get_by_name(&adr, "header", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "source", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_string(&optional, Report_Source);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    const char *macStr = NULL;
    char CpemacStr[32] = { 0 };

    //cpe_id block
    /* MAC - Get CPE mac address, do it only pointer is NULL */
    if ( macStr == NULL )
    {
        macStr = getDeviceMac();
        strncpy( CpemacStr, macStr, sizeof(CpemacStr));
        wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d:RDK_LOG_DEBUG, Received DeviceMac from Atom side: %s\n",__func__,__LINE__,macStr);
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
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "mac_address", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_fixed(&optional, CpeMacid, 6);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    unsigned char *pMac = (unsigned char*)CpeMacid;
    wifi_util_dbg_print(WIFI_HARVESTER, "RDK_LOG_DEBUG, mac_address = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] );

    // cpe_type - string
    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "cpe_type", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_string(&optional, CPE_TYPE_STR);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    //Data Field block
    wifi_util_dbg_print(WIFI_HARVESTER, "data field\n");
    avro_value_get_by_name(&adr, "data", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    //adrField now contains a reference to the Single Client WiFi ReportsArray
    //Device Report

    //Current Device Report Field
    avro_value_t drField = {0}; /*RDKB-7463, CID-33269, init before use */

    //data block
        /*unsigned int i;
    for (i = 0; i < MAX_VAP; i++)
    {
        if (msmt_type == single_client_msmt_type_all) {
        bssid_data = &monitor->bssid_data[i];
        } else {
        bssid_data = bssid_info;
        if (msmt_type == single_client_msmt_type_one) {
            sta_data = sta_info;
        } else {

        }
        }
    }*/
    wifi_util_dbg_print(WIFI_HARVESTER, "updating and sta_data\n");
    sta_data = sta_info;

    if(sta_data == NULL)
    {
        wifi_util_dbg_print(WIFI_HARVESTER, "sta_data is empty\n");
    }
    else
    {
        //device_mac - fixed 6 bytes
        wifi_util_dbg_print(WIFI_HARVESTER, "adding cli_MACAddress field\n");
        avro_value_get_by_name(&adrField, "device_id", &drField, NULL);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_get_by_name(&drField, "mac_address", &drField, NULL);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_set_branch(&drField, 1, &optional);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_set_fixed(&optional, sta_data->dev_stats.cli_MACAddress, 6);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    //device_status - enum
    avro_value_get_by_name(&adrField, "device_id", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "Avro error: %s\n",  avro_strerror());
    avro_value_get_by_name(&drField, "device_status", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, " Avro error: %s\n",  avro_strerror());

    if((sta_data != NULL) && sta_data->dev_stats.cli_Active)
    {
        wifi_util_dbg_print(WIFI_HARVESTER,"active\n");
        avro_value_set_enum(&drField, avro_schema_enum_get_by_name(avro_value_get_schema(&drField), "Online"));
    }
    else
    {
        avro_value_set_enum(&drField, avro_schema_enum_get_by_name(avro_value_get_schema(&drField), "Offline"));
    }
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, " Avro error: %s\n",  avro_strerror());

    //timestamp - long
    avro_value_get_by_name(&adrField, "timestamp", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_long(&optional, tstamp_av_main);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    memset(CpeMacHoldingBuf, 0, sizeof CpeMacHoldingBuf);
    memset(CpeMacid, 0, sizeof CpeMacid);
    char bssid[MAC_KEY_LEN];
    snprintf(bssid, MIN_MAC_LEN, "%02x%02x%02x%02x%02x%02x", g_harvester_module.inst_msmt.sta_mac[0],
            g_harvester_module.inst_msmt.sta_mac[1],g_harvester_module.inst_msmt.sta_mac[2], g_harvester_module.inst_msmt.sta_mac[3],
            g_harvester_module.inst_msmt.sta_mac[4], g_harvester_module.inst_msmt.sta_mac[5]);

    wifi_util_dbg_print(WIFI_HARVESTER, "BSSID for vap : %s\n",bssid);

    for (k = 0; k < 6; k++ ) {
        /* copy 2 bytes */
        CpeMacHoldingBuf[ k * 2 ] = bssid[ k * 2 ];
        CpeMacHoldingBuf[ k * 2 + 1 ] = bssid[ k * 2 + 1 ];
        CpeMacid[ k ] = (unsigned char)strtol(&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
    }

        // interface_mac
    avro_value_get_by_name(&adrField, "interface_mac", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_fixed(&drField, CpeMacid, 6);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    pMac = (unsigned char*)CpeMacid;
    wifi_util_dbg_print(WIFI_HARVESTER, "RDK_LOG_DEBUG, interface mac_address = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] );

    // vAP_index
    avro_value_get_by_name(&adrField, "vAP_index", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "Avro error: %s\n",  avro_strerror());
    avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "Avro error: %s\n",  avro_strerror());
    avro_value_set_int(&optional, (g_harvester_module.inst_msmt.ap_index)+1);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "Avro error: %s\n",  avro_strerror());

        //interface metrics block
        if (msmt_type == single_client_msmt_type_one) {
            sta_data = sta_info;
        }

    //rx_rate
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "rx_rate", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_int(&optional, (int)sta_data->dev_stats.cli_LastDataDownlinkRate);

        //tx_rate
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "tx_rate", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_int(&optional, (int)sta_data->dev_stats.cli_LastDataUplinkRate);

    //tx_packets
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "tx_packets", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_int(&optional, sta_data->dev_stats.cli_PacketsReceived);

    //rx_packets
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "rx_packets", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_int(&optional, sta_data->dev_stats.cli_PacketsSent);

    //tx_error_packets
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "tx_error_packets", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_int(&optional, sta_data->dev_stats.cli_ErrorsSent);

    //retransmissions
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "retransmissions", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_int(&optional, sta_data->dev_stats.cli_Retransmissions);

    //channel_utilization_percent_5ghz
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "channel_utilization_percent_5ghz", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);

    wifi_util_dbg_print(WIFI_HARVESTER,"avro set g_harvester_module.radio_data[1].channelUtil to int\n");
    avro_value_set_int(&optional, (int)g_harvester_module.radio_data[1]->channelUtil);

    //channel_interference_percent_5ghz
    wifi_util_dbg_print(WIFI_HARVESTER,"channel_interference_percent_5ghz field\n");
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "channel_interference_percent_5ghz", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_int(&optional, (int)g_harvester_module.radio_data[1]->channelInterference);

    //channel_noise_floor_5ghz
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "channel_noise_floor_5ghz", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);

    if((g_harvester_module.inst_msmt.ap_index+1) == 2) //Noise floor for vAP index 2 (5GHz)
    {
        //avro_value_set_int(&optional, (int)(sta_data->dev_stats.cli_SignalStrength - sta_data->dev_stats.cli_SNR));
        avro_value_set_int(&optional, (int)g_harvester_module.radio_data[1]->NoiseFloor);
    }
    else
    {
        avro_value_set_int(&optional, 0);
    }

    //channel_utilization_percent_2_4ghz
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "channel_utilization_percent_2_4ghz", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_int(&optional, (int)g_harvester_module.radio_data[0]->channelUtil);

    //channel_interference_percent_2_4ghz
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "channel_interference_percent_2_4ghz", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_int(&optional, (int)g_harvester_module.radio_data[0]->channelInterference);

    //channel_noise_floor_2_4ghz
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "channel_noise_floor_2_4ghz", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);

    if((g_harvester_module.inst_msmt.ap_index+1) == 1) //Noise floor for vAP index 1 (2.4GHz)
    {
        //avro_value_set_int(&optional, (int)(sta_data->dev_stats.cli_SignalStrength - sta_data->dev_stats.cli_SNR));
        avro_value_set_int(&optional, (int)g_harvester_module.radio_data[0]->NoiseFloor);
    }
    else
    {
        avro_value_set_int(&optional, 0);
    }

        //signal_strength
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_get_by_name(&optional, "signal_strength", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_int(&optional, (int)sta_data->dev_stats.cli_SignalStrength);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    //snr
    avro_value_get_by_name(&adrField, "interface_metrics", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&optional, "snr", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_int(&optional, (int)sta_data->dev_stats.cli_SNR);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

     /* check for writer size, if buffer is almost full, skip trailing linklist */
     avro_value_sizeof(&adr, (size_t*)&size);
     if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

     //Thats the end of that
     avro_value_write(writer, &adr);
     if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

     wifi_util_dbg_print(WIFI_HARVESTER, "Avro packing done\n");
     CcspTraceInfo(("%s-%d AVRO packing done\n", __FUNCTION__, __LINE__));

     char *json;
     if (!avro_value_to_json(&adr, 1, &json))
     {
         wifi_util_dbg_print(WIFI_HARVESTER,"json is %s\n", json);
         free(json);
     }
     //Free up memory
     avro_value_decref(&adr);
     avro_writer_free(writer);

     size += MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH;
     sendWebpaMsg((char *)(serviceName), (char *)(dest), trans_id, NULL, NULL, (char *)(contentType), buff, size);//ONE_WIFI
     wifi_util_dbg_print(WIFI_HARVESTER, "Creating telemetry record successful\n");
     CcspTraceInfo(("%s-%d Creation of Telemetry record is successful\n", __FUNCTION__, __LINE__));
}

void process_instant_msmt_monitor(wifi_provider_response_t *provider_response)
{
    if (g_harvester_module.count >= g_harvester_module.maxCount) {
        wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: instant polling freq reached threshold\n", __func__, __LINE__);
        g_harvester_module.instantDefOverrideTTL = DEFAULT_INSTANT_REPORT_TIME;
        g_harvester_module.instntMsmtenable = false;
        process_instant_msmt_stop();
    } else {
        if (g_harvester_module.count == 0) {
            for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
                g_harvester_module.radio_data[radio_index] = (radio_data_t *) malloc (sizeof(radio_data_t));
                if (g_harvester_module.radio_data[radio_index] == NULL) {
                    wifi_util_error_print(WIFI_HARVESTER, "%s:%d: Unable to allocate memory \n", __func__, __LINE__);
                    return;
                }
                memset(g_harvester_module.radio_data[radio_index], 0, sizeof(radio_data_t));
                if (get_dev_stats_for_radio(radio_index, (radio_data_t *)g_harvester_module.radio_data[radio_index]) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Error getting radio datas\n", __func__, __LINE__);
                    continue;
                }
            }
        }

        g_harvester_module.count += 1;
        wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: client %s on ap %d\n", __func__, __LINE__, g_harvester_module.instantMac, g_harvester_module.inst_msmt.ap_index);
        sta_data_t *assoc_stats = NULL;
        assoc_stats = (sta_data_t *) provider_response->stat_pointer;

        char s_mac[MIN_MAC_LEN+1];

        snprintf(s_mac, MIN_MAC_LEN+1, "%02x%02x%02x%02x%02x%02x", g_harvester_module.inst_msmt.sta_mac[0],
            g_harvester_module.inst_msmt.sta_mac[1],g_harvester_module.inst_msmt.sta_mac[2], g_harvester_module.inst_msmt.sta_mac[3],
            g_harvester_module.inst_msmt.sta_mac[4], g_harvester_module.inst_msmt.sta_mac[5]);

        wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: get single connected client %s stats\n", __func__, __LINE__, s_mac);
        wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: value of stat array size is %u\n", __func__, __LINE__, provider_response->stat_array_size);
        for (unsigned int count = 0; count < provider_response->stat_array_size; count++) {
            if (!memcmp(g_harvester_module.inst_msmt.sta_mac, assoc_stats[count].sta_mac, sizeof(mac_address_t))) {
                wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: Found a match for mac address %s \n", __func__, __LINE__, s_mac);
                upload_single_client_msmt_data(&assoc_stats[count]);
                break;
            }
            else {
                wifi_util_dbg_print(WIFI_HARVESTER, "%s: provider_response->sta_mac is %02x:%02x:%02x:%02x:%02x:%02x\n", __func__, assoc_stats[count].sta_mac[0], 
                        assoc_stats[count].sta_mac[1], assoc_stats[count].sta_mac[2], assoc_stats[count].sta_mac[3],
                        assoc_stats[count].sta_mac[4], assoc_stats[count].sta_mac[5]);
            }
        }
    }
}

void process_instant_msmt_stop()
{
    g_harvester_module.inst_msmt.active = false;
    g_harvester_module.poll_period = DEFAULT_INSTANT_POLL_TIME;
    g_harvester_module.maxCount = 0;
    g_harvester_module.count = 0;
    wifi_util_dbg_print(WIFI_HARVESTER,"%s %d Entering \n",__FUNCTION__, __LINE__);

    if (g_harvester_module.inst_msmt_id != 0) {
        char event_buff[16] = {0};
        wifi_monitor_data_t *data;
        data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));
        if (data == NULL) {
            wifi_util_error_print(WIFI_HARVESTER,"%s:%d data allocation failed\r\n", __func__, __LINE__);
            return;
        }

        memset(data, 0, sizeof(wifi_monitor_data_t));
        push_harvester_config_event_to_monitor_queue(mon_stats_request_state_stop);

        strncpy((char *) data->u.msg.data, "inst_msmt completed", sizeof(MAX_FRAME_SZ)-1);
        strncpy(event_buff, "inst_msmt completed", sizeof(event_buff)-1);

        push_event_to_ctrl_queue(event_buff, (strlen(event_buff) +1), wifi_event_type_command, wifi_event_type_stop_inst_msmt, NULL);
        push_event_to_monitor_queue(data, wifi_event_monitor_stop_inst_msmt, NULL);
        g_harvester_module.inst_msmt_id = 0;

        if (data != NULL) {
            free(data);
            data = NULL;
        }
        for (unsigned int radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
            if (g_harvester_module.radio_data[radio_index] != NULL) {
                free(g_harvester_module.radio_data[radio_index]);
                g_harvester_module.radio_data[radio_index] = NULL;
            }
        }
    }
}

void process_instant_msmt_start()
{
    wifi_monitor_data_t *data;
    data = (wifi_monitor_data_t *) malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_HARVESTER,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        return;
    }

    memset(data, 0, sizeof(wifi_monitor_data_t));
    char event_buff[16] = {0};
    g_harvester_module.poll_period = g_harvester_module.instantPollPeriod;
    g_harvester_module.inst_msmt.active = g_harvester_module.instntMsmtenable;

    if ((g_harvester_module.instantDefOverrideTTL == 0) || (g_harvester_module.instantPollPeriod == 0))
        g_harvester_module.maxCount = 0;
    else
        g_harvester_module.maxCount = g_harvester_module.instantDefOverrideTTL/g_harvester_module.instantPollPeriod;

    g_harvester_module.count = 0;
    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: count:%d, maxCount:%d, TTL:%d, poll:%d\n",__func__, __LINE__,
            g_harvester_module.count, g_harvester_module.maxCount, g_harvester_module.instantDefOverrideTTL, g_harvester_module.instantPollPeriod);
    strncpy((char *)data->u.msg.data, "inst_msmt started", sizeof(MAX_FRAME_SZ)-1);
    strncpy(event_buff, "inst_msmt started", sizeof(event_buff)-1);
    push_event_to_ctrl_queue(event_buff, (strlen(event_buff) +1), wifi_event_type_command, wifi_event_type_start_inst_msmt, NULL);
    push_event_to_monitor_queue(data, wifi_event_monitor_start_inst_msmt, NULL);
    push_harvester_config_event_to_monitor_queue(mon_stats_request_state_start);
    g_harvester_module.inst_msmt_id += 1 ;
    if(data != NULL){
        free(data);
        data = NULL;
    }
}
#endif // CCSP_COMMON

void monitor_enable_instant_msmt(mac_address_t sta_mac, bool enable)
{
    mac_addr_str_t sta;
    unsigned int i;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    to_sta_key(sta_mac, sta);
    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: instant measurements %s for sta:%s\n", __func__, __LINE__, (enable == true)?"start":"stop", sta);

    g_harvester_module.instntMsmtenable = enable;
    pthread_mutex_lock(&g_harvester_module.queue_lock);

    if (g_harvester_module.inst_msmt.active == true) {
        if (enable == false) {
            if (memcmp(g_harvester_module.inst_msmt.sta_mac, sta_mac, sizeof(mac_address_t)) == 0) {
                wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: instant measurements active for sta:%s, should stop\n", __func__, __LINE__, sta);
                g_harvester_module.instantDefOverrideTTL = DEFAULT_INSTANT_REPORT_TIME;
                pthread_mutex_unlock(&g_harvester_module.queue_lock);
                process_instant_msmt_stop();
            }
        } else {
            // must return
            wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: instant measurements active for sta:%s, should just return\n", __func__, __LINE__, sta);
        }
        pthread_mutex_unlock(&g_harvester_module.queue_lock);
        return;
    }

    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: instant measurements not active should look for sta:%s\n", __func__, __LINE__, sta);

    for (i = 0; i < getTotalNumberVAPs(); i++) {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, i);
        UINT radio = RADIO_INDEX(mgr->hal_cap, i);
        if (mgr->hal_cap.wifi_prop.radio_presence[radio] == false) {
            continue;
        }
        if (is_harvester_device_associated(vap_index, sta_mac) == true ) {
            wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: found sta:%s on ap index:%d starting instant measurements\n", __func__, __LINE__, sta, vap_index);
            pthread_mutex_unlock(&g_harvester_module.queue_lock);
            process_instant_msmt_start();
            return;
        }
    }
}

void harvester_str_to_mac_bytes (char *key, mac_addr_t bmac) {
    unsigned int mac[6];

    if (strlen(key) == 0) {
        wifi_util_dbg_print(WIFI_HARVESTER,"%s:%d: Input mac address is empty.\n", __func__, __LINE__);
        return;
    }

    if(strlen(key) > MIN_MAC_LEN)
        sscanf(key, "%02x:%02x:%02x:%02x:%02x:%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    else
        sscanf(key, "%02x%02x%02x%02x%02x%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
               bmac[0] = mac[0]; bmac[1] = mac[1]; bmac[2] = mac[2];
               bmac[3] = mac[3]; bmac[4] = mac[4]; bmac[5] = mac[5];

}

void instant_msmt_macAddr(char *mac_addr)
{
    mac_address_t bmac;
    int i;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: get new client %s stats\n", __func__, __LINE__, mac_addr);
    strncpy(g_harvester_module.instantMac, mac_addr, MIN_MAC_LEN);

    harvester_str_to_mac_bytes(mac_addr, bmac);
    for (i = 0; i < (int)getTotalNumberVAPs(); i++) {
        UINT vap_index = VAP_INDEX(mgr->hal_cap, i);
        UINT radio = RADIO_INDEX(mgr->hal_cap, i);
        if (mgr->hal_cap.wifi_prop.radio_presence[radio] == false) {
            continue;
        }

        if (is_harvester_device_associated(vap_index, bmac)  == true) {
            wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: found client %s on ap %d\n", __func__, __LINE__, mac_addr, vap_index);
            pthread_mutex_lock(&g_harvester_module.queue_lock);
            g_harvester_module.inst_msmt.ap_index = vap_index;
            memcpy(g_harvester_module.inst_msmt.sta_mac, bmac, sizeof(mac_address_t));

            pthread_cond_signal(&g_harvester_module.cond);
            pthread_mutex_unlock(&g_harvester_module.queue_lock);

            break;
        }
    }
}

void instant_msmt_ttl(int overrideTTL)
{
    int curCount = 0;
    int newCount = 0;

    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: TTL changed\n", __func__, __LINE__);
    g_harvester_module.instantDefOverrideTTL = overrideTTL;

    if (g_harvester_module.instantPollPeriod == 0)
        return;

    pthread_mutex_lock(&g_harvester_module.queue_lock);

    if (overrideTTL == 0) {
        g_harvester_module.maxCount = 0;
        g_harvester_module.count = 0;
    }
    else {
        curCount = g_harvester_module.count;
        newCount = g_harvester_module.instantDefOverrideTTL/g_harvester_module.instantPollPeriod;
        if(newCount > curCount){
            g_harvester_module.maxCount = newCount - curCount;
            g_harvester_module.count = 0;
        } else {
            wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d:already created maxCount report, stop polling now\n", __func__, __LINE__);
            g_harvester_module.maxCount = 0;
        }
    }
    if (g_harvester_module.instntMsmtenable == true) {
        pthread_cond_signal(&g_harvester_module.cond);
    }
    pthread_mutex_unlock(&g_harvester_module.queue_lock);
}
void instant_msmt_reporting_period(int pollPeriod)
{
    int timeSpent = 0;
    int timeLeft = 0;

    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: reporting period changed\n", __func__, __LINE__);
    pthread_mutex_lock(&g_harvester_module.queue_lock);

    if (pollPeriod == 0) {
        g_harvester_module.maxCount = 0;
        g_harvester_module.count = 0;
    }
    else {
        timeSpent = g_harvester_module.count * g_harvester_module.instantPollPeriod ;
        timeLeft = g_harvester_module.instantDefOverrideTTL - timeSpent;
        g_harvester_module.maxCount = timeLeft/pollPeriod;
        g_harvester_module.poll_period = pollPeriod;

        if (g_harvester_module.count > g_harvester_module.maxCount)
            g_harvester_module.count = 0;
    }
    g_harvester_module.instantPollPeriod = pollPeriod;
    if (g_harvester_module.instntMsmtenable == true) {
        pthread_cond_signal(&g_harvester_module.cond);
    }
    if (g_harvester_module.inst_msmt_id != 0) {
        push_harvester_config_event_to_monitor_queue(mon_stats_request_state_start);
        g_harvester_module.inst_msmt_id += 1 ;
    }
    pthread_mutex_unlock(&g_harvester_module.queue_lock);
}


void instant_msmt_def_period(int defPeriod)
{
    int curCount = 0;
    int newCount = 0;

    wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d: def period changed\n", __func__, __LINE__);
    g_harvester_module.instantDefReportPeriod = defPeriod;

    if (g_harvester_module.instntMsmtenable == false) {
        pthread_mutex_lock(&g_harvester_module.queue_lock);

        curCount = g_harvester_module.count;
        newCount = g_harvester_module.instantDefReportPeriod / DEFAULT_INSTANT_POLL_TIME;

        if (newCount > curCount) {
            g_harvester_module.maxCount = newCount - curCount;
            g_harvester_module.count = 0;
        }
        else {
            wifi_util_dbg_print(WIFI_HARVESTER, "%s:%d:created max non instant report, stop polling now\n", __func__, __LINE__);
            g_harvester_module.maxCount = 0;
        }
        pthread_cond_signal(&g_harvester_module.cond);
        pthread_mutex_unlock(&g_harvester_module.queue_lock);
    }
}

void webconfig_harvester_apply(wifi_app_t *app, wifi_event_t *event)
{
    webconfig_subdoc_data_t *webconfig_data = NULL;
    webconfig_data = event->u.webconfig_data;
    wifi_util_dbg_print(WIFI_HARVESTER,"%s:%d Entering \n", __func__, __LINE__);

#if DML_SUPPORT
    mac_address_t sta_mac;

    instant_msmt_reporting_period(webconfig_data->u.decoded.harvester.u_inst_client_reporting_period);
    instant_msmt_def_period(webconfig_data->u.decoded.harvester.u_inst_client_def_reporting_period);
    instant_msmt_ttl(webconfig_data->u.decoded.harvester.u_inst_client_def_override_ttl);
    instant_msmt_macAddr(webconfig_data->u.decoded.harvester.mac_address);
    harvester_str_to_mac_bytes(webconfig_data->u.decoded.harvester.mac_address,sta_mac);
    monitor_enable_instant_msmt(sta_mac, webconfig_data->u.decoded.harvester.b_inst_client_enabled);
#endif // DML_SUPPORT
}

void handle_harvester_webconfig_event(wifi_app_t *app, wifi_event_t *event)
{
    wifi_util_dbg_print(WIFI_HARVESTER,"%s:%d Entering \n", __func__, __LINE__);
    switch (event->sub_type) {
        case wifi_event_webconfig_set_data_dml:
            if(event->u.webconfig_data->type == webconfig_subdoc_type_harvester)
            {
                webconfig_harvester_apply(app, event);
            }
            break;
        default:
            wifi_util_dbg_print(WIFI_HARVESTER,"%s:%d Not Processing\n", __func__, __LINE__);
            break;
    }
}

void handle_harvester_provider_response(wifi_app_t *app, wifi_event_t *event)
{
    wifi_util_dbg_print(WIFI_HARVESTER, "Entering %s\n", __func__);
    if (event == NULL) {
        wifi_util_error_print(WIFI_HARVESTER,"%s:%d input event is NULL\r\n", __func__, __LINE__);
        return;
    }
    wifi_provider_response_t    *provider_response;
    provider_response = (wifi_provider_response_t *)event->u.provider_response;

    switch (provider_response->args.app_info) {
        case harvester_app_start_process_instant_msmt_monitor:
            process_instant_msmt_monitor(provider_response);
            break;
        default:
            wifi_util_error_print(WIFI_HARVESTER, "%s:%d Inside default\n", __func__, __LINE__);
            break;
    }
}

void handle_harvester_monitor_event(wifi_app_t *app, wifi_event_t *event)
{
    wifi_util_dbg_print(WIFI_HARVESTER, "Entering %s\n", __func__);
    if (event == NULL) {
        wifi_util_error_print(WIFI_HARVESTER,"%s:%d input event is NULL\r\n", __func__, __LINE__);
        return;
    }

    switch (event->sub_type) {
        case wifi_event_monitor_provider_response:
            wifi_util_dbg_print(WIFI_HARVESTER, "Inside %s\n", __func__);
            handle_harvester_provider_response(app, event);
            break;
        default:
            wifi_util_error_print(WIFI_HARVESTER, "%s:%d Inside default\n", __func__, __LINE__);
            break;
    }
}

void handle_harvester_hal_event(wifi_app_t *app, wifi_event_t *event)
{
    wifi_util_dbg_print(WIFI_HARVESTER, "Entering %s\n", __func__);
    switch(event->sub_type) {
        case wifi_event_hal_disassoc_device:
            process_instant_msmt_stop();
            break;
        default:
            break;
    }
}

#ifdef ONEWIFI_HARVESTER_APP_SUPPORT
int harvester_event(wifi_app_t *app, wifi_event_t *event)
{
    wifi_util_dbg_print(WIFI_HARVESTER, "Entering %s\n", __func__);
    switch (event->event_type) {
        case wifi_event_type_monitor:
            handle_harvester_monitor_event(app, event);
            break;
        case wifi_event_type_webconfig:
            handle_harvester_webconfig_event(app, event);
            break;
        case wifi_event_type_hal_ind:
            handle_harvester_hal_event(app,event);
            break;
        default:
            break;
    }
    return RETURN_OK;
}

int harvester_init(wifi_app_t *app, unsigned int create_flag)
{
    wifi_util_dbg_print(WIFI_HARVESTER, "Entering %s\n", __func__);
    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    g_harvester_module.poll_period = DEFAULT_INSTANT_POLL_TIME;
    return RETURN_OK;
}

int harvester_deinit(wifi_app_t *app)
{
    push_harvester_config_event_to_monitor_queue(mon_stats_request_state_stop);
    return RETURN_OK;
}
#endif
