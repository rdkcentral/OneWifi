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

#include <rbus.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "ansc_platform.h"
#include "ccsp_WifiLog_wrapper.h"
#include "wifi_events.h"
#include "wifi_mgr.h"
#include "wifi_util.h"

#define MAX_EVENT_NAME_SIZE     200
#define CLIENTDIAG_JSON_BUFFER_SIZE 665

typedef struct {
    char name[MAX_EVENT_NAME_SIZE];
    int idx;
    wifi_monitor_event_type_t type;
    BOOL subscribed;
    unsigned int num_subscribers;
} event_element_t;


rbusError_t events_subHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, 
                                    rbusFilter_t filter, int32_t interval, bool* autoPublish);
rbusError_t events_APtable_addrowhandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum);
rbusError_t events_CSItable_addrowhandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum);
rbusError_t events_APtable_removerowhandler(rbusHandle_t handle, char const* rowName);
rbusError_t events_CSItable_removerowhandler(rbusHandle_t handle, char const* rowName);
rbusError_t events_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t events_CSIGetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t events_CSISetHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);

static rbusHandle_t         g_rbus_handle;
static queue_t              *g_rbus_events_queue;
static pthread_mutex_t      g_events_lock;
static BOOL                 g_isRbusAvailable = false;
static char                 *gdiag_events_json_buffer[MAX_VAP];
static queue_t              *g_csi_data_queue;
static webconfig_t          g_wifievents_webconfig;
static const char *wifi_log = "/rdklogs/logs/WiFilog.txt.0";

static queue_t** get_csi_entry_queue()
{
    return &g_csi_data_queue;
}

webconfig_error_t webconfig_wifi_events_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data)
{
    wifi_util_dbg_print(WIFI_MON,"%s:%d webconfig wifievents apply\n", __func__, __LINE__);
    return webconfig_error_none;
}

void update_csi_data_queue(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    int len = 0;
    const char * pTmp = NULL;
    webconfig_subdoc_data_t data;
    rbusValue_t value;

    const char* eventName = event->name;

    wifi_util_dbg_print(WIFI_MON,"rbus event callback Event is %s \n",eventName);
    value = rbusObject_GetValue(event->data, NULL );
    if(!value)
    {
        wifi_util_error_print(WIFI_MON,"%s FAIL: value is NULL\n",__FUNCTION__);
        return;
    }
    pTmp = rbusValue_GetString(value, &len);
    if (pTmp == NULL) {
        wifi_util_error_print(WIFI_MON,"%s Null pointer,Rbus set string len=%d\n",__FUNCTION__,len);
        return;
    }

    // setup the raw data
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    data.signature = WEBCONFIG_MAGIC_SIGNATUTRE;
    data.type = webconfig_subdoc_type_dml;
    data.descriptor = 0;
    data.descriptor = webconfig_data_descriptor_encoded;
    strncpy(data.u.encoded.raw, pTmp, sizeof(data.u.encoded.raw) - 1);

    // tell webconfig to decode
    if (webconfig_set(&g_wifievents_webconfig, &data)== webconfig_error_none) {
        wifi_util_info_print(WIFI_MON,"%s %d webconfig_set success \n",__FUNCTION__,__LINE__ );
    } else {
        wifi_util_error_print(WIFI_MON,"%s %d webconfig_set fail \n",__FUNCTION__,__LINE__ );
        return;
    }
    
    queue_t** csi_queue = (queue_t **)get_csi_entry_queue();
    if ((csi_queue != NULL) && (*csi_queue != NULL)) {
        queue_destroy(*csi_queue);
    }
    *csi_queue = data.u.decoded.csi_data_queue;
    if (*csi_queue == NULL) { //empty table
        *csi_queue = queue_create();
    }
}

static int push_csi_data_dml_cache_to_one_wifidb() {
    webconfig_subdoc_data_t data;
    queue_t** csi_queue = (queue_t **)get_csi_entry_queue();
    char *str = NULL;

    if ((csi_queue == NULL) && (*csi_queue == NULL)) {
        wifi_util_error_print(WIFI_MON, "%s:%d: Error, queue is NULL\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    wifi_util_dbg_print(WIFI_MON, "%s: queue count is %lu\n", __func__, queue_count(*csi_queue));
    data.u.decoded.csi_data_queue = *csi_queue;

    if (webconfig_encode(&g_wifievents_webconfig, &data, webconfig_subdoc_type_csi) == webconfig_error_none) {
        str = data.u.encoded.raw;
        wifi_util_info_print(WIFI_MON, "%s: CSI cache encoded successfully  \n", __FUNCTION__);
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_dml);
    } else {
        wifi_util_error_print(WIFI_MON, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    wifi_util_info_print(WIFI_MON, "%s:  CSI cache pushed to queue encoded data is %s\n", __FUNCTION__, str);
    return RBUS_ERROR_SUCCESS;
}

int events_init(void)
{
    char componentName[] = "WifiEventProvider";
    int rc, i, ap_cnt;
    rbusDataElement_t dataElement[10] = {
        {"Device.WiFi.AccessPoint.{i}.",                           RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, events_APtable_addrowhandler, events_APtable_removerowhandler, NULL, NULL}},
        {"Device.WiFi.AccessPoint.{i}.X_RDK_deviceConnected",      RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, events_subHandler, NULL}},
        {"Device.WiFi.AccessPoint.{i}.X_RDK_deviceDisconnected",   RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, events_subHandler, NULL}},
        {"Device.WiFi.AccessPoint.{i}.X_RDK_deviceDeauthenticated",RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, events_subHandler, NULL}},
        {"Device.WiFi.AccessPoint.{i}.X_RDK_DiagData",             RBUS_ELEMENT_TYPE_EVENT, {events_GetHandler, NULL, NULL, NULL, events_subHandler, NULL}},
        {"Device.WiFi.X_RDK_CSI.{i}.",                             RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, events_CSItable_addrowhandler, events_CSItable_removerowhandler, NULL, NULL}},
        {"Device.WiFi.X_RDK_CSI.{i}.data",                         RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, events_subHandler, NULL}},
        {"Device.WiFi.X_RDK_CSI.{i}.ClientMaclist",                RBUS_ELEMENT_TYPE_PROPERTY, {events_CSIGetHandler, events_CSISetHandler, NULL, NULL, NULL, NULL}},
        {"Device.WiFi.X_RDK_CSI.{i}.Enable",                       RBUS_ELEMENT_TYPE_PROPERTY, {events_CSIGetHandler, events_CSISetHandler, NULL, NULL, NULL, NULL}},
        {"Device.WiFi.X_RDK_CSINumberOfEntries",                   RBUS_ELEMENT_TYPE_PROPERTY, {events_CSIGetHandler, NULL, NULL, NULL, NULL, NULL}}
    };
    rbusEventSubscription_t rbusEvents[] = {
        { WIFI_WEBCONFIG_GET_CSI, NULL, 0, 0, update_csi_data_queue, NULL, NULL, NULL, false}, // CSI subdoc
    };

    wifi_util_dbg_print(WIFI_MON, "%s():\n", __FUNCTION__);

    if(RBUS_ENABLED == rbus_checkStatus())
    {
        g_isRbusAvailable = TRUE;
    }
    else
    {
        wifi_util_error_print(WIFI_MON, "%s(): RBUS not available. WifiEvents is not supported\n", __FUNCTION__);
        return 0;
    }

    pthread_mutex_init(&g_events_lock, NULL);

    rc = rbus_open(&g_rbus_handle, componentName);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        wifi_util_error_print(WIFI_MON, "%s():fail to open rbus_open\n", __FUNCTION__);
        return -1;
    }

    g_rbus_events_queue = queue_create();
    if(g_rbus_events_queue == NULL)
    {
        rbus_close(g_rbus_handle);
        wifi_util_error_print(WIFI_MON, "%s(): fail to create rbus events queue\n", __FUNCTION__);
        return -1;
    }
   
    memset(gdiag_events_json_buffer, 0, MAX_VAP*sizeof(char *));

    rc = rbus_regDataElements(g_rbus_handle, 10, dataElement);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        wifi_util_error_print(WIFI_MON, "%s() rbus_regDataElements failed %d\n", __FUNCTION__, rc);
    }
    else
    {
        wifi_util_dbg_print(WIFI_MON, "%s() rbus_regDataElements success\n", __FUNCTION__);
    }

    ap_cnt = getTotalNumberVAPs(NULL); 
    for(i=1;i<=ap_cnt;i++)
    {
        rc = rbusTable_addRow(g_rbus_handle, "Device.WiFi.AccessPoint.", NULL, NULL);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            wifi_util_dbg_print(WIFI_MON, "%s() rbusTable_addRow failed %d\n", __FUNCTION__, rc);
        }
    }

    queue_t **csi_queue = (queue_t**)get_csi_entry_queue();
    *csi_queue = queue_create();

    rc = rbusEvent_SubscribeEx(g_rbus_handle, rbusEvents, ((unsigned int)(sizeof(rbusEvents) / sizeof(rbusEvents[0]))), 0);
    if(rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_MON,"Unable to subscribe to event  with rbus error code : %d\n", rc);
    }

    //Initialize Webconfig Framework
    g_wifievents_webconfig.initializer = webconfig_initializer_wifievents;
    g_wifievents_webconfig.apply_data = (webconfig_apply_data_t)webconfig_wifi_events_apply;

    if (webconfig_init(&g_wifievents_webconfig) != webconfig_error_none) {
        wifi_util_error_print(WIFI_MON,"[%s]:%d Init WiFi Web Config  fail\n",__FUNCTION__,__LINE__);
        // unregister and deinit everything
        return -1;
    }
    return 0;
}

static BOOL events_getSubscribed(char *eventName)
{
    int i;
    event_element_t *event;
    int count = queue_count(g_rbus_events_queue);

    if (count == 0) {
        return FALSE;
    }
    
    for (i = 0; i < count; i++) {
        event = queue_peek(g_rbus_events_queue, i);
        if ((event != NULL) && (strncmp(event->name, eventName, MAX_EVENT_NAME_SIZE) == 0)) {
            return event->subscribed;
        }
    }
    return FALSE;
}

static event_element_t *events_getEventElement(char *eventName)
{
    int i;
    event_element_t *event;
    int count = queue_count(g_rbus_events_queue);

    if (count == 0) {
        return NULL;
    }
    
    for (i = 0; i < count; i++) {
        event = queue_peek(g_rbus_events_queue, i);
        if ((event != NULL) && (strncmp(event->name, eventName, MAX_EVENT_NAME_SIZE) == 0)) {
            return event;
        }
    }
    return NULL;
}

void events_update_clientdiagdata(unsigned int num_devs, int vap_idx, wifi_associated_dev3_t *dev_array)
{

    unsigned int i =0;
    unsigned int pos = 0;
    unsigned int t_pos = 0;
    unsigned int vap_array_index;

    getVAPArrayIndexFromVAPIndex((unsigned int) vap_idx, &vap_array_index);
    if(g_isRbusAvailable == FALSE)
    {
        return;
    }

    pthread_mutex_lock(&g_events_lock);
    if(gdiag_events_json_buffer[vap_array_index] != NULL)
    {

        pos = snprintf(gdiag_events_json_buffer[vap_array_index],
                CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS,
                "{"
                "\"Version\":\"1.0\","
                "\"AssociatedClientsDiagnostics\":["
                "{"
                "\"VapIndex\":\"%d\","
                "\"AssociatedClientDiagnostics\":[", 
                vap_idx + 1);
        t_pos = pos + 1;
        if(dev_array != NULL) {
            for(i=0; i<num_devs; i++) {
                pos += snprintf(&gdiag_events_json_buffer[vap_array_index][pos],
                        (CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS)-pos, "{"
                        "\"MAC\":\"%02x%02x%02x%02x%02x%02x\","
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
                        "\"AuthenticationFailures\":\"%d\""
                        "},",     
                        dev_array->cli_MACAddress[0],
                        dev_array->cli_MACAddress[1],
                        dev_array->cli_MACAddress[2],
                        dev_array->cli_MACAddress[3],
                        dev_array->cli_MACAddress[4],
                        dev_array->cli_MACAddress[5],
                        dev_array->cli_MaxDownlinkRate,
                        dev_array->cli_MaxUplinkRate,
                        dev_array->cli_BytesSent,
                        dev_array->cli_BytesReceived,
                        dev_array->cli_PacketsSent,
                        dev_array->cli_PacketsReceived,
                        dev_array->cli_ErrorsSent,
                        dev_array->cli_RetransCount,
                        dev_array->cli_DataFramesSentAck,
                        dev_array->cli_SignalStrength,
                        dev_array->cli_SNR,
                        dev_array->cli_OperatingStandard,
                        dev_array->cli_OperatingChannelBandwidth,
                        dev_array->cli_AuthenticationFailures);
                dev_array++;
            }
            t_pos = pos;
        }
        snprintf(&gdiag_events_json_buffer[vap_array_index][t_pos-1], (
                CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS)-t_pos-1,"]"
                "}"
                "]"
                "}");
    }
    pthread_mutex_unlock(&g_events_lock);
}

int events_publish(wifi_monitor_data_t data)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    bool should_publish = FALSE;
    char eventName[MAX_EVENT_NAME_SIZE];
    int rc;
    unsigned int vap_array_index;

    if(g_isRbusAvailable == FALSE)
    {
        return 0;
    }

    pthread_mutex_lock(&g_events_lock);
    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    wifi_util_info_print(WIFI_MON, "%s(): rbusEvent_Publish Event %d\n", __FUNCTION__, data.event_type);
    switch(data.event_type)
    {
        case monitor_event_type_diagnostics:
            sprintf(eventName, "Device.WiFi.AccessPoint.%d.X_RDK_DiagData", data.ap_index + 1);
            getVAPArrayIndexFromVAPIndex((unsigned int) data.ap_index, &vap_array_index);
            if(gdiag_events_json_buffer[vap_array_index] != NULL)
            {
                rbusValue_SetString(value, gdiag_events_json_buffer[vap_array_index]);
                wifi_util_dbg_print(WIFI_MON, "%s(): device_diagnostics Event %d %s \n", __FUNCTION__, data.event_type, eventName);
                should_publish = TRUE;
            }
            break;
        case monitor_event_type_connect:
        case monitor_event_type_disconnect:
        case monitor_event_type_deauthenticate:
            if(data.event_type == monitor_event_type_connect) {
                sprintf(eventName, "Device.WiFi.AccessPoint.%d.X_RDK_deviceConnected", data.ap_index + 1);
            }
            else if(data.event_type == monitor_event_type_disconnect) {
                sprintf(eventName, "Device.WiFi.AccessPoint.%d.X_RDK_deviceDisconnected", data.ap_index + 1);
            }
            else {
                sprintf(eventName, "Device.WiFi.AccessPoint.%d.X_RDK_deviceDeauthenticated", data.ap_index + 1);
            }
            if(events_getSubscribed(eventName) == TRUE)
            {
                rbusValue_SetBytes(value, (uint8_t *)&data.u.dev.sta_mac[0], sizeof(data.u.dev.sta_mac));
                wifi_util_dbg_print(WIFI_MON, "%s(): Event - %d %s \n", __FUNCTION__, data.event_type, eventName);
                should_publish = TRUE;
            }
            break;
        case monitor_event_type_csi:
            {
                char buffer[(strlen("CSI") + 1) + sizeof(unsigned int) + sizeof(time_t) + (sizeof(unsigned int)) + (1 *(sizeof(mac_addr_t) + sizeof(unsigned int) + sizeof(wifi_csi_dev_t)))];
                unsigned int total_length, num_csi_clients, csi_data_lenght;
                time_t datetime;
                char *pbuffer = (char *)buffer;

                sprintf(eventName, "Device.WiFi.X_RDK_CSI.%d.data", data.csi_session);

                //ASCII characters "CSI"
                memcpy(pbuffer,"CSI", (strlen("CSI") + 1));
                pbuffer = pbuffer + (strlen("CSI") + 1);

                //Total length:  <length of this entire data field as an unsigned int>
                total_length = sizeof(time_t) + (sizeof(unsigned int)) + (1 *(sizeof(mac_addr_t) + sizeof(unsigned int) + sizeof(wifi_csi_data_t)));
                memcpy(pbuffer, &total_length, sizeof(unsigned int));
                pbuffer = pbuffer + sizeof(unsigned int);

                //DataTimeStamp:  <date-time, number of seconds since the Epoch>
                datetime = time(NULL);
                memcpy(pbuffer, &datetime, sizeof(time_t));
                pbuffer = pbuffer + sizeof(time_t);

                //NumberOfClients:  <unsigned int number of client devices>
                num_csi_clients = 1;
                memcpy(pbuffer, &num_csi_clients, sizeof(unsigned int));
                pbuffer = pbuffer + sizeof(unsigned int);

                //clientMacAddress:  <client mac address>
                memcpy(pbuffer, &data.u.csi.sta_mac, sizeof(mac_addr_t));
                pbuffer = pbuffer + sizeof(mac_addr_t);

                //length of client CSI data:  <size of the next field in bytes>
                csi_data_lenght = sizeof(wifi_csi_data_t);
                memcpy(pbuffer, &csi_data_lenght, sizeof(unsigned int));
                pbuffer = pbuffer + sizeof(unsigned int);

                //<client device CSI data>
                memcpy(pbuffer, &data.u.csi.csi, sizeof(wifi_csi_data_t));

                rbusValue_SetBytes(value, (uint8_t*)buffer, sizeof(buffer));
                should_publish = TRUE;

            }
            break;
        default:
            wifi_util_dbg_print(WIFI_MON, "%s(): Invalid event type\n", __FUNCTION__);
            break;
    }
    if(should_publish == TRUE) {
        rbusObject_SetValue(rdata, eventName, value);
        event.name = eventName;
        event.data = rdata;
        event.type = RBUS_EVENT_GENERAL;
        
        rc = rbusEvent_Publish(g_rbus_handle, &event);

        if(rc != RBUS_ERROR_SUCCESS)
        {
            wifi_util_error_print(WIFI_MON, "%s(): rbusEvent_Publish Event failed: %d\n", __FUNCTION__, rc);
        }
    }
    rbusValue_Release(value);
    rbusObject_Release(rdata);
    pthread_mutex_unlock(&g_events_lock);

    return 0;
}

rbusError_t events_subHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(autoPublish);
    int csi_session = 0;
    unsigned int idx = 0;
    event_element_t *event;
    char *telemetry_start = NULL;
    char *telemetry_cancel = NULL;
    char tmp[128] = {0};
    unsigned int vap_array_index;

    wifi_util_dbg_print(WIFI_MON, "Entering %s: Event %s\n", __FUNCTION__, eventName);

    pthread_mutex_lock(&g_events_lock);
    event = events_getEventElement((char *)eventName);
    if(event != NULL)
    {
        switch(event->type)
        {
            case monitor_event_type_diagnostics:
                idx = event->idx;
                getVAPArrayIndexFromVAPIndex((unsigned int) idx-1, &vap_array_index);
                if(action == RBUS_EVENT_ACTION_SUBSCRIBE)
                {
                    if(interval < MIN_DIAG_INTERVAL)
                    {
                        get_formatted_time(tmp);
                        wifi_util_dbg_print(WIFI_MON, "WiFi_DiagData_SubscriptionFailed %d\n", idx );
                        write_to_file(wifi_log, "%s WiFi_DiagData_SubscriptionFailed %d\n",tmp, idx);

                        pthread_mutex_unlock(&g_events_lock);
                        wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                        return RBUS_ERROR_BUS_ERROR;
                    }
                    if(gdiag_events_json_buffer[vap_array_index] == NULL)
                    {
                        memset(tmp, 0, sizeof(tmp));
                        get_formatted_time(tmp);
                        gdiag_events_json_buffer[vap_array_index] = (char *) malloc(CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS);
                        if(gdiag_events_json_buffer[vap_array_index] == NULL)
                        {
                            wifi_util_dbg_print(WIFI_MON, "WiFi_DiagData_SubscriptionFailed %d\n", idx );
                            write_to_file(wifi_log, "%s WiFi_DiagData_SubscriptionFailed %d\n",tmp, idx);
                            pthread_mutex_unlock(&g_events_lock);
                            wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                            return RBUS_ERROR_BUS_ERROR;
                        }
                        memset(gdiag_events_json_buffer[vap_array_index], 0, (CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS));
                        snprintf(gdiag_events_json_buffer[vap_array_index], 
                                    CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS,
                                    "{"
                                    "\"Version\":\"1.0\","
                                    "\"AssociatedClientsDiagnostics\":["
                                    "{"
                                    "\"VapIndex\":\"%d\","
                                    "\"AssociatedClientDiagnostics\":[]"
                                    "}"
                                    "]"
                                    "}",
                                    idx);
                    }
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    wifi_util_dbg_print(WIFI_MON, "WiFi_DiagData_SubscriptionStarted %d\n",idx);
                    write_to_file(wifi_log, "%s WiFi_DiagData_SubscriptionStarted %d\n", tmp,idx);

                    event->num_subscribers++;
                    event->subscribed = TRUE;

                    //unlock event mutex before updating monitor data to avoid deadlock
                    pthread_mutex_unlock(&g_events_lock);
                    diagdata_set_interval(interval, idx - 1);
                    
                    wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                    return RBUS_ERROR_SUCCESS;
                }
                else
                {
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    wifi_util_dbg_print(WIFI_MON, "WiFi_DiagData_SubscriptionCancelled %d\n", idx);
                    write_to_file(wifi_log, "%s WiFi_DiagData_SubscriptionCancelled %d\n",tmp, idx);

                    event->num_subscribers--;
                    if(event->num_subscribers == 0) {
                        event->subscribed = FALSE;
                        if(gdiag_events_json_buffer[vap_array_index] != NULL)
                        {
                            free(gdiag_events_json_buffer[vap_array_index]);
                            gdiag_events_json_buffer[vap_array_index] = NULL;
                        }
                        //unlock event mutex before updating monitor data to avoid deadlock
                        pthread_mutex_unlock(&g_events_lock);
                        diagdata_set_interval(0, idx - 1);
                        wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                        return RBUS_ERROR_SUCCESS;
                    }
                }
                break;

            case monitor_event_type_connect:
            case monitor_event_type_disconnect:
            case monitor_event_type_deauthenticate:
                idx = event->idx;
                if(event->type == monitor_event_type_connect) {
                    telemetry_start = "WiFi_deviceConnected_SubscriptionStarted";
                    telemetry_cancel = "WiFi_deviceConnected_SubscriptionCancelled"; 
                }
                else if( event->type == monitor_event_type_disconnect) {
                    telemetry_start = "WiFi_deviceDisconnected_SubscriptionStarted";
                    telemetry_cancel = "WiFi_deviceDisconnected_SubscriptionCancelled";
                }
                else {
                    telemetry_start = "WiFi_deviceDeauthenticated_SubscriptionStarted";
                    telemetry_cancel = "WiFi_deviceDeauthenticated_SubscriptionCancelled";
                }
                if(action == RBUS_EVENT_ACTION_SUBSCRIBE)
                {
                    event->num_subscribers++;
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    write_to_file(wifi_log, "%s %s %d\n",tmp, telemetry_start, idx);
                    wifi_util_dbg_print(WIFI_MON, "%s %d\n", telemetry_start, idx);
                    event->subscribed = TRUE;
                }
                else{
                    wifi_util_dbg_print(WIFI_MON, "%s  %d\n",telemetry_cancel, idx);
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    write_to_file(wifi_log,  "%s %s %d\n",tmp, telemetry_cancel, idx);
                    event->num_subscribers--;
                    if(event->num_subscribers == 0) {
                        event->subscribed = FALSE;
                    }
                }
                break;
            
            case monitor_event_type_csi:
                csi_session = event->idx;
                if(action == RBUS_EVENT_ACTION_SUBSCRIBE)
                {
                    /* TODO: interval needs to be multiple of WifiMonitor basic interval */
                    if(interval > MAX_CSI_INTERVAL || interval < MIN_CSI_INTERVAL
                            ||  event->subscribed == TRUE)
                    {
                        //telemetry
                        printf("WiFi_Motion_SubscriptionFailed %d\n", csi_session);
                        memset(tmp, 0, sizeof(tmp));
                        get_formatted_time(tmp);
                        wifi_util_dbg_print(WIFI_MON, "WiFi_Motion_SubscriptionFailed %d\n", csi_session);
                        write_to_file(wifi_log,  "%s WiFi_CSI_SubscriptionFailed %d\n", tmp,csi_session);
                        pthread_mutex_unlock(&g_events_lock);
                        wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                        return RBUS_ERROR_BUS_ERROR;
                    }
                    event->subscribed = TRUE;
                    wifi_util_dbg_print(WIFI_MON, "WiFi_Motion_SubscriptionStarted %d\n", csi_session);
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    write_to_file(wifi_log,  "%s WiFi_CSI_SubscriptionStarted %d\n", tmp,csi_session);

                    //unlock event mutex before updating monitor data to avoid deadlock
                    pthread_mutex_unlock(&g_events_lock);
                    csi_set_interval(interval, csi_session);
                    csi_enable_subscription(TRUE, csi_session);
                    wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                    return RBUS_ERROR_SUCCESS;
                }
                else
                {
                    event->subscribed = FALSE;
                    wifi_util_dbg_print(WIFI_MON, "WiFi_Motion_SubscriptionStopped %d\n", csi_session);
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    write_to_file(wifi_log,  "%s WiFi_CSI_SubscriptionCancelled %d\n", tmp,csi_session);
                    //unlock event mutex before updating monitor data to avoid deadlock
                    pthread_mutex_unlock(&g_events_lock);
                    csi_enable_subscription(FALSE, csi_session);
                    wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                    return RBUS_ERROR_SUCCESS;
                }
                break;
            default:
                wifi_util_dbg_print(WIFI_MON, "%s(): Invalid event type\n", __FUNCTION__);
                break;
        }
    }
    pthread_mutex_unlock(&g_events_lock);
    wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t events_APtable_addrowhandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum)
{
    static int instanceCounter = 1;
    event_element_t *event;
    unsigned int vap_index;

    *instNum = instanceCounter++;
    vap_index = *instNum;

    wifi_util_dbg_print(WIFI_MON, "%s(): %s %d\n", __FUNCTION__, tableName, *instNum);

    pthread_mutex_lock(&g_events_lock);

    //Device.WiFi.AccessPoint.{i}.X_RDK_deviceConnected
    event = (event_element_t *) malloc(sizeof(event_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.AccessPoint.%d.X_RDK_deviceConnected", *instNum);
        event->idx = vap_index;
        event->type = monitor_event_type_connect;
        event->subscribed = FALSE;
        event->num_subscribers = 0;
        queue_push(g_rbus_events_queue, event);
    }

    //Device.WiFi.AccessPoint.{i}.X_RDK_deviceDisconnected
    event = (event_element_t *) malloc(sizeof(event_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.AccessPoint.%d.X_RDK_deviceDisconnected", *instNum);
        event->idx = vap_index;
        event->type = monitor_event_type_disconnect;
        event->subscribed = FALSE;
        event->num_subscribers = 0;
        queue_push(g_rbus_events_queue, event);
    }

    //Device.WiFi.AccessPoint.{i}.X_RDK_deviceDeauthenticated
    event = (event_element_t *) malloc(sizeof(event_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.AccessPoint.%d.X_RDK_deviceDeauthenticated", *instNum);
        event->idx = vap_index;
        event->type = monitor_event_type_deauthenticate;
        event->subscribed = FALSE;
        event->num_subscribers = 0;
        queue_push(g_rbus_events_queue, event);
    }

    //Device.WiFi.AccessPoint.{i}.X_RDK_DiagData
    event = (event_element_t *) malloc(sizeof(event_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.AccessPoint.%d.X_RDK_DiagData", *instNum);
        event->idx = vap_index;
        event->type = monitor_event_type_diagnostics;
        event->subscribed = FALSE;
        event->num_subscribers = 0;
        queue_push(g_rbus_events_queue, event);
    }

    pthread_mutex_unlock(&g_events_lock);
    wifi_util_dbg_print(WIFI_MON, "%s(): exit\n", __FUNCTION__);

    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(aliasName);
    return RBUS_ERROR_SUCCESS;
}


rbusError_t events_CSItable_addrowhandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum)
{
    static int instanceCounter = 1;
    event_element_t *event;
    queue_t** csi_queue = (queue_t**)get_csi_entry_queue();
    csi_data_t *csi_data;
    *instNum = instanceCounter++;

    wifi_util_dbg_print(WIFI_MON, "%s(): %s %d\n", __FUNCTION__, tableName, *instNum);

    pthread_mutex_lock(&g_events_lock);

    event = (event_element_t *) malloc(sizeof(event_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.X_RDK_CSI.%d.data", *instNum);
        event->idx = *instNum;
        event->type = monitor_event_type_csi;
        event->subscribed = FALSE;
    }

    if (*csi_queue == NULL) {
        *csi_queue = queue_create();
        if (*csi_queue == NULL) {
            wifi_util_error_print(WIFI_MON,"%s:%d fail to create csi queue\n", __func__, __LINE__);
            pthread_mutex_unlock(&g_events_lock);
            return RBUS_ERROR_BUS_ERROR;
        }
    }

    csi_data = (csi_data_t *)malloc(sizeof(csi_data_t));
    if (csi_data == NULL) {
        wifi_util_error_print(WIFI_MON,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&g_events_lock);
        return RBUS_ERROR_BUS_ERROR;
    }
    memset(csi_data, 0, sizeof(csi_data_t));
    csi_data->csi_session_num = *instNum;
    
    queue_push(*csi_queue, csi_data);
    queue_push(g_rbus_events_queue, event);

    push_csi_data_dml_cache_to_one_wifidb();

    pthread_mutex_unlock(&g_events_lock);
    wifi_util_dbg_print(WIFI_MON, "%s(): exit\n", __FUNCTION__);

    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(aliasName);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t events_APtable_removerowhandler(rbusHandle_t handle, char const* rowName)
{
    int i = 0;
    event_element_t *event;
    int count = queue_count(g_rbus_events_queue);

    wifi_util_dbg_print(WIFI_MON, "%s(): %s\n", __FUNCTION__, rowName);

    pthread_mutex_lock(&g_events_lock);

    while(i < count)
    {
        event = queue_peek(g_rbus_events_queue, i);
        if ((event != NULL) && (strstr(event->name, rowName) != NULL))
        {
            wifi_util_dbg_print(WIFI_MON, "%s():event remove from queue %s\n", __FUNCTION__, event->name);
            event = queue_remove(g_rbus_events_queue, i);
            if(event) {
                free(event);
            }
            count--;
        }
        else {
            i++;
        }
    }

    pthread_mutex_unlock(&g_events_lock);

    UNREFERENCED_PARAMETER(handle);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t events_CSItable_removerowhandler(rbusHandle_t handle, char const *rowName)
{
    unsigned int i = 0;
    event_element_t *event = NULL;
    csi_data_t *tmp_csi_data =  NULL;
    unsigned int itr, qcount;
    queue_t** csi_queue = (queue_t**)get_csi_entry_queue();
    
    wifi_util_dbg_print(WIFI_MON, "%s(): %s\n", __FUNCTION__, rowName);

    pthread_mutex_lock(&g_events_lock);

    if ((*csi_queue == NULL)){
        wifi_util_error_print(WIFI_MON,"%s:%d NULL Pointer\n", __func__, __LINE__);
        pthread_mutex_unlock(&g_events_lock);
        return RBUS_ERROR_BUS_ERROR;
    }

    qcount = queue_count(g_rbus_events_queue);
    while(i < qcount)
    {
        event = queue_peek(g_rbus_events_queue, i);
        if ((event != NULL) && (strstr(event->name, rowName) != NULL))
        {
            event = queue_remove(g_rbus_events_queue, i);
            break;
        }
        else {
            i++;
        }
    }

    if (event == NULL) {
        wifi_util_error_print(WIFI_MON,"%s:%d Could not find entry\n", __func__, __LINE__);
        pthread_mutex_unlock(&g_events_lock);
        return RBUS_ERROR_BUS_ERROR;
    }

    qcount = queue_count(*csi_queue);
    for (itr=0; itr<qcount; itr++) {
        tmp_csi_data = queue_peek(*csi_queue, itr);
        if (tmp_csi_data->csi_session_num == (unsigned long) event->idx) {
            tmp_csi_data = queue_remove(*csi_queue, itr);
            if (tmp_csi_data) {
                free(tmp_csi_data);
            }
            break;
        }
    }
    free(event);

    push_csi_data_dml_cache_to_one_wifidb();

    pthread_mutex_unlock(&g_events_lock);

    UNREFERENCED_PARAMETER(handle);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t events_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(opts);
    char const* name;
    rbusValue_t value;
    unsigned int idx = 0;
    int ret;
    unsigned int vap_array_index;

    pthread_mutex_lock(&g_events_lock);
    name = rbusProperty_GetName(property);
    if (!name)
    {
        pthread_mutex_unlock(&g_events_lock);
        return RBUS_ERROR_INVALID_INPUT;
    }

    wifi_util_dbg_print(WIFI_MON, "%s(): %s\n", __FUNCTION__, name);

    ret = sscanf(name, "Device.WiFi.AccessPoint.%d.X_RDK_DiagData", &idx);
    if(ret==1 && idx > 0 && idx <= MAX_VAP)
    {
        rbusValue_Init(&value);

        getVAPArrayIndexFromVAPIndex((unsigned int) idx-1, &vap_array_index);
        if(gdiag_events_json_buffer[vap_array_index] != NULL)
        {
            rbusValue_SetString(value, gdiag_events_json_buffer[vap_array_index]);
        }
        else
        {
            char buffer[500];
            snprintf(buffer,sizeof(buffer),
                                    "{"
                                    "\"Version\":\"1.0\","
                                    "\"AssociatedClientsDiagnostics\":["
                                    "{"
                                    "\"VapIndex\":\"%d\","
                                    "\"AssociatedClientDiagnostics\":[]"
                                    "}"
                                    "]"
                                    "}",
                                    idx);
            rbusValue_SetString(value, buffer);
        }
        rbusProperty_SetValue(property, value);
        rbusValue_Release(value);

        pthread_mutex_unlock(&g_events_lock);
        return RBUS_ERROR_SUCCESS;
    }

    pthread_mutex_unlock(&g_events_lock);
    return RBUS_ERROR_INVALID_INPUT;
}

rbusError_t events_CSIGetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(opts);
    char const* name;
    rbusValue_t value;
    unsigned int idx = 0;
    int ret;
    char parameter[MAX_EVENT_NAME_SIZE];
    unsigned int itr, count, qcount;
    csi_data_t *csi_data =  NULL;
    queue_t** csi_queue = (queue_t**)get_csi_entry_queue();

    pthread_mutex_lock(&g_events_lock);
    name = rbusProperty_GetName(property);
    if (!name)
    {
        pthread_mutex_unlock(&g_events_lock);
        return RBUS_ERROR_INVALID_INPUT;
    }

    wifi_util_dbg_print(WIFI_MON, "%s(): %s\n", __FUNCTION__, name);
    if (strcmp(name, "Device.WiFi.X_RDK_CSINumberOfEntries") == 0) {
        queue_t** csi_queue = (queue_t**)get_csi_entry_queue();
        if ((csi_queue == NULL) || (*csi_queue == NULL)) {
            wifi_util_error_print(WIFI_MON,"%s:%d invalid queue pointer\n", __func__, __LINE__);
            pthread_mutex_unlock(&g_events_lock);
            return RBUS_ERROR_BUS_ERROR;
        }

        count = queue_count(*csi_queue);
        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, count);
        rbusProperty_SetValue(property, value);
        rbusValue_Release(value);

        pthread_mutex_unlock(&g_events_lock);
        return RBUS_ERROR_SUCCESS;
    }

    ret = sscanf(name, "Device.WiFi.X_RDK_CSI.%d.%s", &idx, parameter);
    if(ret==2 && idx > 0 && idx <= MAX_VAP)
    {
        qcount = queue_count(*csi_queue);
        for (itr=0; itr<qcount; itr++) {
            csi_data = queue_peek(*csi_queue, itr);
            if (csi_data->csi_session_num == idx) {
                break;
            }
        }

        if (csi_data == NULL) {
            wifi_util_error_print(WIFI_MON,"%s:%d Could not find entry\n", __func__, __LINE__);
            pthread_mutex_unlock(&g_events_lock);
            return RBUS_ERROR_BUS_ERROR;
        }

        rbusValue_Init(&value);
        if (strcmp(parameter, "ClientMaclist") == 0) {
            char tmp_cli_list[128];
            mac_addr_str_t mac_str;
            memset(tmp_cli_list, 0, sizeof(tmp_cli_list));
            if (csi_data->csi_client_count > 0) {
                for (itr=0; itr<csi_data->csi_client_count; itr++) {
                    snprintf(mac_str, sizeof(mac_str), "%02x%02x%02x%02x%02x%02x",
                            csi_data->csi_client_list[itr][0], csi_data->csi_client_list[itr][1], 
                            csi_data->csi_client_list[itr][2], csi_data->csi_client_list[itr][3],
                            csi_data->csi_client_list[itr][4], csi_data->csi_client_list[itr][5]);
                    strcat(tmp_cli_list, mac_str);
                    strcat(tmp_cli_list, ",");
                }
                int len  = strlen(tmp_cli_list);
                tmp_cli_list[len-1] = '\0';
            }
            rbusValue_SetString(value, tmp_cli_list);
        } else if(strcmp(parameter, "Enable") == 0) {
            rbusValue_SetBoolean(value, csi_data->enabled);
        }
        rbusProperty_SetValue(property, value);
        rbusValue_Release(value);

        pthread_mutex_unlock(&g_events_lock);
        return RBUS_ERROR_SUCCESS;
    }

    pthread_mutex_unlock(&g_events_lock);
    return RBUS_ERROR_INVALID_INPUT;
}

rbusError_t events_CSISetHandler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    char const* name;
    rbusValue_t value;
    rbusValueType_t type;
    unsigned int idx = 0;
    int ret, apply = false;
    char parameter[MAX_EVENT_NAME_SIZE];
    unsigned int itr, i, j, k, qcount, num_unique_mac=0;
    csi_data_t *csi_data =  NULL, *tmp_csi_data;
    mac_address_t unique_mac_list[MAX_NUM_CSI_CLIENTS];
    bool found = false;
    unsigned int csi_client_count;
    mac_address_t csi_client_list[MAX_NUM_CSI_CLIENTS];
    queue_t** csi_queue = (queue_t**)get_csi_entry_queue();
    
    name = rbusProperty_GetName(property);
    value = rbusProperty_GetValue(property);
    type = rbusValue_GetType(value);

    if (!name)
    {
        return RBUS_ERROR_INVALID_INPUT;
    }
    pthread_mutex_lock(&g_events_lock);

    wifi_util_dbg_print(WIFI_MON, "%s(): %s\n", __FUNCTION__, name);

    ret = sscanf(name, "Device.WiFi.X_RDK_CSI.%d.%s", &idx, parameter);
    if(ret==2 && idx > 0 && idx <= MAX_VAP)
    {
        qcount = queue_count(*csi_queue);
        for (itr=0; itr<qcount; itr++) {
            csi_data = queue_peek(*csi_queue, itr);
            if (csi_data->csi_session_num == idx) {
                break;
            }
        }

        if (csi_data == NULL) {
            wifi_util_error_print(WIFI_MON,"%s:%d Could not find entry\n", __func__, __LINE__);
            pthread_mutex_unlock(&g_events_lock);
            return RBUS_ERROR_BUS_ERROR;
        }
        if (strcmp(parameter, "ClientMaclist") == 0) {

            if (type != RBUS_STRING)
            {
                wifi_util_error_print(WIFI_MON,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
                pthread_mutex_unlock(&g_events_lock);
                return RBUS_ERROR_INVALID_INPUT;
            } else {
                char *str, *cptr, *str_dup; 
                mac_address_t l_client_list[MAX_NUM_CSI_CLIENTS];
                char const* pTmp = NULL;
                int len = 0;
                memset(l_client_list, 0, MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));
 
                pTmp = rbusValue_GetString(value, &len);
                str_dup = strdup(pTmp);
                if (str_dup == NULL) {
                    wifi_util_error_print(WIFI_MON,"%s:%d strdup failed\n", __func__, __LINE__);
                    pthread_mutex_unlock(&g_events_lock);
                    return RBUS_ERROR_BUS_ERROR;
                }
                itr = 0;
                str = strtok_r(str_dup, ",", &cptr);
                while (str != NULL) {
                    str_to_mac_bytes(str, l_client_list[itr]);
                    str = strtok_r(NULL, ",", &cptr);
                    itr++;
                    if (itr > MAX_NUM_CSI_CLIENTS) {
                        wifi_util_error_print(WIFI_MON,"%s:%d client list is big %d\n", __func__, __LINE__, itr);
                        if (str_dup) {
                            free(str_dup);
                        }
                        pthread_mutex_unlock(&g_events_lock);
                        return RBUS_ERROR_BUS_ERROR;
                    }
                }
                if (memcmp(csi_data->csi_client_list, l_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t)) != 0) {
                    //check new configuration did not exceed the max number of csi clients 
                    num_unique_mac = 0;
                    for (i=0; i<qcount; i++) {
                        tmp_csi_data = (csi_data_t *)queue_peek(*csi_queue, i);
                        if ((tmp_csi_data != NULL) && (tmp_csi_data->enabled)) {
                            if (tmp_csi_data->csi_session_num == csi_data->csi_session_num) {
                                csi_client_count = itr;
                                memcpy(csi_client_list, l_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));
                            } else {
                                csi_client_count = tmp_csi_data->csi_client_count;
                                memcpy(csi_client_list, tmp_csi_data->csi_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));
                            }
                            for (j=0; j < csi_client_count; j++) {
                                found  = false;
                                for (k=0; k < num_unique_mac; k++) {
                                    if (memcmp(csi_client_list[j], unique_mac_list[k], sizeof(mac_address_t)) == 0) {
                                        found  = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    num_unique_mac++;
                                    if (num_unique_mac > MAX_NUM_CSI_CLIENTS) {
                                        wifi_util_error_print(WIFI_MON, "%s %d MAX_NUM_CSI_CLIENTS reached\n", __func__, __LINE__);
                                        if (str_dup) {
                                            free(str_dup);
                                        }
                                        pthread_mutex_unlock(&g_events_lock);
                                        return RBUS_ERROR_BUS_ERROR;
                                    } else {
                                        memcpy(unique_mac_list[num_unique_mac-1], csi_client_list[j], sizeof(mac_address_t));
                                    }
                                }
                            }
                        }
                    }

                    memcpy(csi_data->csi_client_list, l_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));
                    csi_data->csi_client_count = itr;
                    apply = true;
                } else {
                    wifi_util_error_print(WIFI_MON,"%s:%d config not change\n", __func__, __LINE__);
                }
                if (str_dup) {
                    free(str_dup);
                }
            }

        } else if(strcmp(parameter, "Enable") == 0) {
            if (type != RBUS_BOOLEAN)
            {
                wifi_util_error_print(WIFI_MON,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
                pthread_mutex_unlock(&g_events_lock);
                return RBUS_ERROR_INVALID_INPUT;
            } else {
                bool enabled = rbusValue_GetBoolean(value);
                if (enabled != csi_data->enabled) {
                    //check new configuration did not exceed the max number of csi clients
                    num_unique_mac = 0;
                    if (enabled == true) {
                        for (i=0; i<qcount; i++) {
                            tmp_csi_data = (csi_data_t *)queue_peek(*csi_queue, i);
                            if (tmp_csi_data != NULL) {
                                if (tmp_csi_data->csi_session_num != csi_data->csi_session_num) {
                                    if (tmp_csi_data->enabled == false) {
                                        continue;
                                    }
                                }
                                for (j=0; j < tmp_csi_data->csi_client_count; j++) {
                                    found  = false;
                                    for (k=0; k < num_unique_mac; k++) {
                                        if (memcmp(tmp_csi_data->csi_client_list[j], unique_mac_list[k], sizeof(mac_address_t)) == 0) {
                                            found  = true;
                                            break;
                                        }
                                    }
                                    if (!found) {
                                        num_unique_mac++;
                                        if (num_unique_mac > MAX_NUM_CSI_CLIENTS) {
                                            wifi_util_error_print(WIFI_MON,"%s %d MAX_NUM_CSI_CLIENTS reached\n", __func__, __LINE__);
                                            pthread_mutex_unlock(&g_events_lock);
                                            return RBUS_ERROR_BUS_ERROR;
                                        } else {
                                            memcpy(unique_mac_list[num_unique_mac-1], tmp_csi_data->csi_client_list[j], sizeof(mac_address_t));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    csi_data->enabled = enabled;
                    apply = true;
                }
            }
        }

        if (apply) {
            push_csi_data_dml_cache_to_one_wifidb();
        }
        pthread_mutex_unlock(&g_events_lock);
        return RBUS_ERROR_SUCCESS;
    }

    pthread_mutex_unlock(&g_events_lock);
    return RBUS_ERROR_INVALID_INPUT;
}


int events_deinit(void)
{
    event_element_t *event;

    if(g_isRbusAvailable == FALSE)
    {
        return 0;
    }

    wifi_util_dbg_print(WIFI_MON, "%s():\n", __FUNCTION__);
    pthread_mutex_lock(&g_events_lock);

    do
    {
        event = queue_pop(g_rbus_events_queue);
        free(event);
    } while (event != NULL);

    queue_t** csi_queue = (queue_t **)get_csi_entry_queue();
    if ((csi_queue != NULL) && (*csi_queue != NULL)) {
        queue_destroy(*csi_queue);
    }

    rbus_close(g_rbus_handle);
    pthread_mutex_unlock(&g_events_lock);

    pthread_mutex_destroy(&g_events_lock);

    return 0;
}
