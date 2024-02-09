 /**************************************************************************
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
                                                                            
 ***************************************************************************/

#include <avro.h>
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
#include "collection.h"
#include "wifi_hal.h"
#include "wifi_monitor.h"
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/un.h>
#include <assert.h>
#include <uuid/uuid.h>
#include "ansc_status.h"
#include <sysevent/sysevent.h>
#include "ccsp_base_api.h"
#include "harvester.h"

#include "wifi_util.h"

// HASH - 7985cdc3a29f21c283fdcc0fcdcce550
// UUID - ec57a5b6-b167-4623-baff-399f063bd56a

uint8_t HASH[16] = {0x79, 0x85, 0xcd, 0xc3, 0xa2, 0x9f, 0x21, 0xc2,
                    0x83, 0xfd, 0xcc, 0x0f, 0xcd, 0xcc, 0xe5, 0x50
                   };

uint8_t UUID[16] = {0xec, 0x57, 0xa5, 0xb6, 0xb1, 0x67, 0x46, 0x23,
                    0xba, 0xff, 0x39, 0x9f, 0x06, 0x3b, 0xd5, 0x6a
                   };

// local data, load it with real data if necessary
char ReportSource[] = "wifi";
char CPE_TYPE_STRING[] = "Gateway";
char PARENT_CPE_TYPE_STRING[] = "Extender";
char DEVICE_TYPE[] = "WiFi";
char ParentCpeMacid[] = { 0x77, 0x88, 0x99, 0x00, 0x11, 0x22 };
int cpe_parent_exists = FALSE;

#define MAX_BUFF_SIZE   20480

#define MAGIC_NUMBER      0x85
#define MAGIC_NUMBER_SIZE 1
#define SCHEMA_ID_LENGTH  32

typedef enum {
    associated_devices_msmt_type_all,
    associated_devices_msmt_type_all_per_bssid,
    associated_devices_msmt_type_one,
} associated_devices_msmt_type_t;

static char *to_sta_key    (mac_addr_t mac, sta_key_t key) {
    snprintf(key, STA_KEY_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (char *)key;
}

void upload_associated_devices_msmt_data(bssid_data_t *bssid_info, sta_data_t *sta_info)
{
    const char * serviceName = "harvester";
    const char * dest = "event:raw.kestrel.reports.InterfaceDevicesWifi";
    const char * contentType = "avro/binary"; // contentType "application/json", "avro/binary"
    uuid_t transaction_id;
    char trans_id[37];
    FILE *fp;
    char *buff;
    int size;
    int radio_idx = 0;
    bssid_data_t *bssid_data;
    hash_map_t *sta_map;
    sta_data_t	*sta_data = NULL;
    wifi_monitor_t *monitor;
    associated_devices_msmt_type_t msmt_type;

    avro_writer_t writer;
    avro_schema_t inst_msmt_schema = NULL;
    avro_schema_error_t	error = NULL;
    avro_value_iface_t  *iface = NULL;
    avro_value_t  adr = {0}; /*RDKB-7463, CID-33353, init before use */
    avro_value_t  adrField = {0}; /*RDKB-7463, CID-33485, init before use */
    avro_value_t optional  = {0}; 

    if (bssid_info == NULL) { 
        if (sta_info != NULL) {
            wifi_util_error_print(WIFI_MON, "%s:%d: Invalid arguments\n", __func__, __LINE__);
            return;
        } else {
            msmt_type = associated_devices_msmt_type_all;
        }

    } else {
        if (sta_info == NULL) {
            msmt_type = associated_devices_msmt_type_all_per_bssid;
        } else {
            msmt_type = associated_devices_msmt_type_one;
        }
    }
    wifi_util_dbg_print(WIFI_MON, "%s:%d: Measurement Type: %d\n", __func__, __LINE__, msmt_type);

    monitor = get_wifi_monitor();
    radio_idx = getRadioIndexFromAp(monitor->inst_msmt.ap_index);

    /* open schema file */
    fp = fopen (INTERFACE_DEVICES_WIFI_AVRO_FILENAME , "rb");
    if (fp == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: Unable to open schema file: %s\n", __func__, __LINE__, INTERFACE_DEVICES_WIFI_AVRO_FILENAME);
        return;
    }

    /* seek through file and get file size*/
    fseek(fp , 0L , SEEK_END);
    size = ftell(fp);
    if(size < 0)
    {
        wifi_util_error_print(WIFI_MON, "%s:%d: ftell error\n", __func__, __LINE__);
        fclose(fp);
        return;
    }

    /*back to the start of the file*/
    rewind(fp);

    /* allocate memory for entire content */
    buff = malloc(size + 1);
    memset(buff, 0, size + 1);

    /* copy the file into the buffer */
    if (1 != fread(buff , size, 1 , fp)) {
        fclose(fp);
        free(buff);
        wifi_util_dbg_print(WIFI_MON, "%s:%d: Unable to read schema file: %s\n", __func__, __LINE__, INTERFACE_DEVICES_WIFI_AVRO_FILENAME);
        return ;
    }
    wifi_util_dbg_print(WIFI_MON, "%s:%d: NULL terminate buff\n",__func__, __LINE__);
    buff[size]='\0';
    fclose(fp);

    if (avro_schema_from_json(buff, strlen(buff), &inst_msmt_schema, &error)) {
        free(buff);
        wifi_util_dbg_print(WIFI_MON, "%s:%d: Unable to parse steering schema, len: %d, error:%s\n", __func__, __LINE__, size, avro_strerror());
        return;
    }
        
    free(buff);

    //generate an avro class from our schema and get a pointer to the value interface
    iface = avro_generic_class_from_schema(inst_msmt_schema);

    avro_schema_decref(inst_msmt_schema);

    buff = malloc(MAX_BUFF_SIZE);
    memset(buff, 0, MAX_BUFF_SIZE);
    buff[0] = MAGIC_NUMBER; /* fill MAGIC number = Empty, i.e. no Schema ID */

    memcpy( &buff[MAGIC_NUMBER_SIZE], UUID, sizeof(UUID));
    memcpy( &buff[MAGIC_NUMBER_SIZE + sizeof(UUID)], HASH, sizeof(HASH));

    writer = avro_writer_memory((char*)&buff[MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH], MAX_BUFF_SIZE - MAGIC_NUMBER_SIZE - SCHEMA_ID_LENGTH);
    avro_writer_reset(writer);

    avro_generic_value_new(iface, &adr);

    // timestamp - long
    avro_value_get_by_name(&adr, "header", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "timestamp", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    struct timeval ts;
    gettimeofday(&ts, NULL);

    int64_t tstamp_av_main = ((int64_t) (ts.tv_sec) * 1000000) + (int64_t) ts.tv_usec;

    tstamp_av_main = tstamp_av_main/1000;

    avro_value_set_long(&optional, tstamp_av_main );

    // uuid - fixed 16 bytes
    uuid_generate_random(transaction_id);
    uuid_unparse(transaction_id, trans_id);

    avro_value_get_by_name(&adr, "header", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "uuid", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_fixed(&optional, transaction_id, 16);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    //source - string
    avro_value_get_by_name(&adr, "header", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "source", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_string(&optional, ReportSource);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    const char *macStr = NULL;
    char CpemacStr[32] = { 0 };

    //cpe_id block
    /* MAC - Get CPE mac address, do it only pointer is NULL */
    if ( macStr == NULL )
    {
        macStr = getDeviceMac();

        strncpy( CpemacStr, macStr, sizeof(CpemacStr));
        wifi_util_dbg_print(WIFI_MON, "%s:%d: RDK_LOG_DEBUG, Received DeviceMac from Atom side: %s\n", __func__, __LINE__, macStr);
    }
    wifi_util_dbg_print(WIFI_MON, "%s:%d\n", __func__, __LINE__);
    unsigned char CpeMacHoldingBuf[ 20 ] = {0};
    unsigned char CpeMacid[ 7 ] = {0};
    unsigned int k;

    for (k = 0; k < 6; k++ )
    {
        /* copy 2 bytes */
        CpeMacHoldingBuf[ k * 2 ] = CpemacStr[ k * 2 ];
        CpeMacHoldingBuf[ k * 2 + 1 ] = CpemacStr[ k * 2 + 1 ];
        CpeMacid[ k ] = (unsigned char)strtol((char *)&CpeMacHoldingBuf[ k * 2 ], NULL, 16);
    }
    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "mac_address", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_fixed(&optional, CpeMacid, 6);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    unsigned char *pMac = (unsigned char*)CpeMacid;
    wifi_util_dbg_print(WIFI_MON, "RDK_LOG_DEBUG, mac_address = 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] );
    wifi_util_dbg_print(WIFI_MON, "%s:%d cpe_type field\n", __func__, __LINE__);
    // cpe_type - string
    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "cpe_type", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_string(&optional, CPE_TYPE_STRING);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    // cpe_parent - Recurrsive CPEIdentifier block
    avro_value_get_by_name(&adr, "cpe_id", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&adrField, "cpe_parent", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&adrField, 0, &optional);
    avro_value_set_null(&optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    //Data Field block

    avro_value_get_by_name(&adr, "data", &adrField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    //adrField now contains a reference to the Interface WiFi ReportsArray
    //Device Report
    avro_value_t dr = {0}; /*RDKB-7463, CID-33085, init before use */

    //Current Device Report Field
    avro_value_t drField = {0}; /*RDKB-7463, CID-33269, init before use */

    //interference sources
    avro_value_t interferenceSource = {0}; /*RDKB-7463, CID-33062, init before use */

    //Append a DeviceReport item to array
    avro_value_append(&adrField, &dr, NULL);

    //data array block

    //device_mac - fixed 6 bytes
    avro_value_get_by_name(&dr, "device_id", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&drField, "mac_address", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_fixed(&optional, CpeMacid, 6);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    //device_type - string
    avro_value_get_by_name(&dr, "device_id", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&drField, "device_type", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_string(&optional, DEVICE_TYPE);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    //timestamp - long
    avro_value_get_by_name(&dr, "timestamp", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_long(&optional, tstamp_av_main);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    // Service_type
    avro_value_get_by_name(&dr, "service_type", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_enum(&drField, avro_schema_enum_get_by_name(avro_value_get_schema(&drField), "PRIVATE"));
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    memset(CpeMacHoldingBuf, 0, sizeof CpeMacHoldingBuf);
    memset(CpeMacid, 0, sizeof CpeMacid);

    unsigned int i;
    for (i = 0; i < MAX_VAP; i++) {
        if (msmt_type == associated_devices_msmt_type_all) {
            bssid_data = &monitor->bssid_data[i];
        } else {
            bssid_data = bssid_info;
            if (msmt_type == associated_devices_msmt_type_one) {
                sta_data = sta_info;
            } else {

            }
        }
    }

    memcpy(CpeMacid, bssid_data->bssid, sizeof(CpeMacid) - 1);

    // interface_mac
    avro_value_get_by_name(&dr, "interface_mac", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_fixed(&drField, CpeMacid, 6);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    pMac = (unsigned char*)CpeMacid;

    //interface parameters block

    // operating standard
    avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_get_by_name(&optional, "operating_standard", &drField, NULL);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    avro_value_set_branch(&drField, 1, &optional);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    
    //Patch HAL values if necessary
    if ( strlen(sta_data->dev_stats.cli_OperatingStandard ) == 0 )
    {
        avro_value_set_null(&optional);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }
    else
    {
        avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), sta_data->dev_stats.cli_OperatingStandard));
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
    }

    // operating channel bandwidth
    avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "operating_channel_bandwidth", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    //Patch HAL values if necessary
    if ( strstr("_20MHz", monitor->radio_data[radio_idx].channel_bandwidth) )
    {
        avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_20MHz"));
    }
    else if ( strstr("_40MHz", monitor->radio_data[radio_idx].channel_bandwidth) )
    {
        avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_40MHz"));
    }
    else if ( strstr("_80MHz", monitor->radio_data[radio_idx].channel_bandwidth) )
    {
        avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_80MHz"));
    }
    else if ( strstr("_160MHz", monitor->radio_data[radio_idx].channel_bandwidth) )
    {
        avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_160MHz"));
    }
    else
    {
        avro_value_set_null(&optional);
    }

    // frequency band
    avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "frequency_band", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    //Patch HAL values if necessary
    if ( strcmp( monitor->radio_data[radio_idx].frequency_band, "2.4GHz" ) == 0 )
    {
        avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_2_4GHz" ));
    }
    else if ( strcmp( monitor->radio_data[radio_idx].frequency_band, "5GHz" ) == 0 )
    {
        avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), "_5GHz" ));
    }
    else
    {
        avro_value_set_enum(&optional, avro_schema_enum_get_by_name(avro_value_get_schema(&optional), monitor->radio_data[radio_idx].frequency_band));
    }

    // channel #
    avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "channel", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_int(&optional, monitor->radio_data[radio_idx].primary_radio_channel);

    // ssid
    avro_value_get_by_name(&dr, "interface_parameters", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_get_by_name(&optional, "ssid", &drField, NULL);
    avro_value_set_branch(&drField, 1, &optional);
    avro_value_set_string(&optional, bssid_data->ssid);

    //interface metrics block
    if (msmt_type == associated_devices_msmt_type_one) {
        sta_data = sta_info;
    } else {
        sta_map = bssid_data->sta_map;
        sta_data = hash_map_get_first(sta_map); 
    }

    while (sta_data != NULL) {

        //WIFI - authenticated
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "authenticated", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        if ( sta_data->dev_stats.cli_AuthenticationState )
        {
            avro_value_set_boolean(&optional, TRUE);
        }
        else
        {
            avro_value_set_boolean(&optional, FALSE);
        }

        //authentication failures
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "authentication_failures", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_set_int(&optional, sta_data->dev_stats.cli_AuthenticationFailures);

        //data_frames_sent_ack
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "data_frames_sent_ack", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_set_long(&optional, sta_data->dev_stats.cli_DataFramesSentAck);

        //data_frames_sent_no_ack
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "data_frames_sent_no_ack", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_set_long(&optional, sta_data->dev_stats.cli_DataFramesSentNoAck);


        //disassociations
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "disassociations", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_set_int(&optional, sta_data->dev_stats.cli_Disassociations);

        //interference_sources
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "interference_sources", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        if (strstr( sta_data->dev_stats.cli_InterferenceSources, "MicrowaveOven") != NULL )
        {
            avro_value_append(&drField, &interferenceSource, NULL);
            avro_value_set_string(&interferenceSource,"MicrowaveOven");
        }
        if (strstr( sta_data->dev_stats.cli_InterferenceSources, "CordlessPhone") != NULL )
        {
            avro_value_append(&drField, &interferenceSource, NULL);
            avro_value_set_string(&interferenceSource,"CordlessPhone");
        }
        if (strstr( sta_data->dev_stats.cli_InterferenceSources, "BluetoothDevices") != NULL )
        {
            avro_value_append(&drField, &interferenceSource, NULL);
            avro_value_set_string(&interferenceSource,"BluetoothDevices");
        }
        if (strstr( sta_data->dev_stats.cli_InterferenceSources, "FluorescentLights") != NULL )
        {
            avro_value_append(&drField, &interferenceSource, NULL);
            avro_value_set_string(&interferenceSource,"FluorescentLights");
        }
        if (strstr( sta_data->dev_stats.cli_InterferenceSources, "ContinuousWaves") != NULL )
        {
            avro_value_append(&drField, &interferenceSource, NULL);
            avro_value_set_string(&interferenceSource,"ContinuousWaves");
        }
        avro_value_append(&drField, &interferenceSource, NULL);
        avro_value_set_string(&interferenceSource,"Others");

        //rx_rate
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "rx_rate", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_set_float(&optional, (float)sta_data->dev_stats.cli_LastDataDownlinkRate);

        //tx_rate
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "tx_rate", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_set_float(&optional, (float)sta_data->dev_stats.cli_LastDataUplinkRate);

        //retransmissions
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_get_by_name(&optional, "retransmissions", &drField, NULL);
        avro_value_set_branch(&drField, 1, &optional);
        avro_value_set_int(&optional, sta_data->dev_stats.cli_Retransmissions);

        //signal_strength
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_set_branch(&drField, 1, &optional);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_get_by_name(&optional, "signal_strength", &drField, NULL);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_set_branch(&drField, 1, &optional);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_set_float(&optional, (float)sta_data->dev_stats.cli_SignalStrength);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

        //snr
        avro_value_get_by_name(&dr, "interface_metrics", &drField, NULL);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_set_branch(&drField, 1, &optional);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_get_by_name(&optional, "snr", &drField, NULL);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_set_branch(&drField, 1, &optional);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
        avro_value_set_float(&optional, (float)sta_data->dev_stats.cli_SNR);
        if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

        if (msmt_type != associated_devices_msmt_type_all) break;   
    }

    /* check for writer size, if buffer is almost full, skip trailing linklist */
    avro_value_sizeof(&adr, (size_t*)&size);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());
  
    //Thats the end of that
    avro_value_write(writer, &adr);
    if (CHK_AVRO_ERR) wifi_util_dbg_print(WIFI_MON, "%s:%d: Avro error: %s\n", __func__, __LINE__, avro_strerror());

    //Free up memory
    avro_value_decref(&adr);
    avro_writer_free(writer);

    size += MAGIC_NUMBER_SIZE + SCHEMA_ID_LENGTH;
    sendWebpaMsg((char *)serviceName,(char *) dest, trans_id, NULL, NULL, (char *)contentType, buff, size);//ONE_WIFI
    wifi_util_dbg_print(WIFI_MON, "Creating telemetry record successful\n");
}

void stream_device_msmt_data()
{
    wifi_monitor_t *monitor;
    hash_map_t  *sta_map;
    sta_data_t *data;
    mac_addr_str_t key;
    unsigned int vap_array_index;

    monitor = get_wifi_monitor();
    getVAPArrayIndexFromVAPIndex((unsigned int)monitor->inst_msmt.ap_index, &vap_array_index);
    sta_map = monitor->bssid_data[vap_array_index].sta_map;
    to_sta_key(monitor->inst_msmt.sta_mac, key);
    wifi_util_dbg_print(WIFI_MON, "%s:%d\n", __func__, __LINE__);
    str_tolower(key);
    data = (sta_data_t *)hash_map_get(sta_map, key);    
    if (data != NULL) {
        wifi_util_dbg_print(WIFI_MON, "%s:%d\n", __func__, __LINE__);
        upload_associated_devices_msmt_data(&monitor->bssid_data[vap_array_index], data);
    }
    
}
