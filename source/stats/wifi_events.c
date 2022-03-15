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

static rbusHandle_t         g_rbus_handle;
static queue_t              *g_rbus_events_queue;
static pthread_mutex_t      g_events_lock;
static BOOL                 g_isRbusAvailable = false;
static char                 *gdiag_events_json_buffer[MAX_VAP];



int events_init(void)
{
    char componentName[] = "WifiEventProvider";
    int rc, i, ap_cnt;
    rbusDataElement_t dataElement[7] = {
        {"Device.WiFi.AccessPoint.{i}.",                            RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, events_APtable_addrowhandler, events_APtable_removerowhandler, NULL, NULL}},
        {"Device.WiFi.AccessPoint.{i}.X_RDK_deviceConnected",      RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, events_subHandler, NULL}},
        {"Device.WiFi.AccessPoint.{i}.X_RDK_deviceDisconnected",   RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, events_subHandler, NULL}},
        {"Device.WiFi.AccessPoint.{i}.X_RDK_deviceDeauthenticated",RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, events_subHandler, NULL}},
        {"Device.WiFi.AccessPoint.{i}.X_RDK_DiagData",             RBUS_ELEMENT_TYPE_EVENT, {events_GetHandler, NULL, NULL, NULL, events_subHandler, NULL}},
        {"Device.WiFi.X_RDK_CSI.{i}.",                              RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, events_CSItable_addrowhandler, events_CSItable_removerowhandler, NULL, NULL}},
        {"Device.WiFi.X_RDK_CSI.{i}.data",                         RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, events_subHandler, NULL}}
    };

    wifi_util_dbg_print(WIFI_MON, "%s():\n", __FUNCTION__);

    if(RBUS_ENABLED == rbus_checkStatus())
    {
        g_isRbusAvailable = TRUE;
    }
    else
    {
        wifi_util_dbg_print(WIFI_MON, "%s(): RBUS not available. WifiEvents is not supported\n", __FUNCTION__);
        return 0;
    }

    pthread_mutex_init(&g_events_lock, NULL);

    rc = rbus_open(&g_rbus_handle, componentName);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        wifi_util_dbg_print(WIFI_MON, "%s():fail to open rbus_open\n", __FUNCTION__);
        return -1;
    }

    g_rbus_events_queue = queue_create();
    if(g_rbus_events_queue == NULL)
    {
        rbus_close(g_rbus_handle);
        wifi_util_dbg_print(WIFI_MON, "%s(): fail to create rbus events queue\n", __FUNCTION__);
        return -1;
    }
   
    memset(gdiag_events_json_buffer, 0, MAX_VAP*sizeof(char *));

    rc = rbus_regDataElements(g_rbus_handle, 7, dataElement);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        wifi_util_dbg_print(WIFI_MON, "%s() rbus_regDataElements failed %d\n", __FUNCTION__, rc);
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

    if(g_isRbusAvailable == FALSE)
    {
        return;
    }

    pthread_mutex_lock(&g_events_lock);
    if(gdiag_events_json_buffer[vap_idx] != NULL)
    {

        pos = snprintf(gdiag_events_json_buffer[vap_idx], 
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
                pos += snprintf(&gdiag_events_json_buffer[vap_idx][pos], 
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
        snprintf(&gdiag_events_json_buffer[vap_idx][t_pos-1], (
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

    if(g_isRbusAvailable == FALSE)
    {
        return 0;
    }

    pthread_mutex_lock(&g_events_lock);
    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    wifi_util_dbg_print(WIFI_MON, "%s(): rbusEvent_Publish Event %d\n", __FUNCTION__, data.event_type);
    switch(data.event_type)
    {
        case monitor_event_type_diagnostics:
            sprintf(eventName, "Device.WiFi.AccessPoint.%d.X_RDK_DiagData", data.ap_index + 1);
            if(events_getSubscribed(eventName) == TRUE && (gdiag_events_json_buffer[data.ap_index] != NULL))
            {
                rbusValue_SetString(value, gdiag_events_json_buffer[data.ap_index]);
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
            sprintf(eventName, "Device.WiFi.X_RDK_CSI.%d.data", data.csi_session);
            if(events_getSubscribed(eventName) == TRUE)
            {
                char buffer[(strlen("CSI") + 1) + sizeof(unsigned int) + sizeof(time_t) + (sizeof(unsigned int)) + (1 *(sizeof(mac_addr_t) + sizeof(unsigned int) + sizeof(wifi_csi_dev_t)))];
                unsigned int total_length, num_csi_clients, csi_data_lenght;
                time_t datetime;
                char *pbuffer = (char *)buffer;

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
            wifi_util_dbg_print(WIFI_MON, "%s(): rbusEvent_Publish Event failed: %d\n", __FUNCTION__, rc);
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

    wifi_util_dbg_print(WIFI_MON, "Entering %s: Event %s\n", __FUNCTION__, eventName);

    pthread_mutex_lock(&g_events_lock);
    event = events_getEventElement((char *)eventName);
    if(event != NULL)
    {
        switch(event->type)
        {
            case monitor_event_type_diagnostics:
                idx = event->idx;
                if(action == RBUS_EVENT_ACTION_SUBSCRIBE)
                {
                    if(interval < MIN_DIAG_INTERVAL)
                    {
                        wifi_util_dbg_print(WIFI_MON, "WiFi_DiagData_SubscriptionFailed %d\n", idx );
                        pthread_mutex_unlock(&g_events_lock);
                        wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                        return RBUS_ERROR_BUS_ERROR;
                    }
                    if(gdiag_events_json_buffer[idx-1] == NULL)
                    {
                        gdiag_events_json_buffer[idx-1] = (char *) malloc(CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS);
                        if(gdiag_events_json_buffer[idx-1] == NULL)
                        {
                            wifi_util_dbg_print(WIFI_MON, "WiFi_DiagData_SubscriptionFailed %d\n", idx );
                            pthread_mutex_unlock(&g_events_lock);
                            wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                            return RBUS_ERROR_BUS_ERROR;
                        }
                        memset(gdiag_events_json_buffer[idx-1], 0, (CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS));
                        snprintf(gdiag_events_json_buffer[idx-1], 
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
                    wifi_util_dbg_print(WIFI_MON, "WiFi_DiagData_SubscriptionStarted %d\n", idx);

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
                    wifi_util_dbg_print(WIFI_MON, "WiFi_DiagData_SubscriptionCancelled %d\n", idx);
                    event->num_subscribers--;
                    if(event->num_subscribers == 0) {
                        event->subscribed = FALSE;
                        if(gdiag_events_json_buffer[idx-1] != NULL)
                        {
                            free(gdiag_events_json_buffer[idx-1]);
                            gdiag_events_json_buffer[idx-1] = NULL;
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
                    wifi_util_dbg_print(WIFI_MON, "%s %d\n", telemetry_start, idx);
                    event->subscribed = TRUE;
                }
                else{
                    wifi_util_dbg_print(WIFI_MON, "%s  %d\n",telemetry_cancel, idx);
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
                        wifi_util_dbg_print(WIFI_MON, "WiFi_Motion_SubscriptionFailed %d\n", csi_session);
                        pthread_mutex_unlock(&g_events_lock);
                        wifi_util_dbg_print(WIFI_MON, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                        return RBUS_ERROR_BUS_ERROR;
                    }
                    event->subscribed = TRUE;
                    wifi_util_dbg_print(WIFI_MON, "WiFi_Motion_SubscriptionStarted %d\n", csi_session);

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

    *instNum = instanceCounter++;

    wifi_util_dbg_print(WIFI_MON, "%s(): %s %d\n", __FUNCTION__, tableName, *instNum);

    pthread_mutex_lock(&g_events_lock);

    //Device.WiFi.AccessPoint.{i}.X_RDK_deviceConnected
    event = (event_element_t *) malloc(sizeof(event_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.AccessPoint.%d.X_RDK_deviceConnected", *instNum);
        event->idx = *instNum;
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
        event->idx = *instNum;
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
        event->idx = *instNum;
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
        event->idx = *instNum;
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
        queue_push(g_rbus_events_queue, event);
    }

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
            free(event);
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

rbusError_t events_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(opts);
    char const* name;
    rbusValue_t value;
    unsigned int idx = 0;
    int ret;

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

        if(gdiag_events_json_buffer[idx-1] != NULL)
        {
            rbusValue_SetString(value, gdiag_events_json_buffer[idx-1]);
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

    rbus_close(g_rbus_handle);
    pthread_mutex_unlock(&g_events_lock);

    pthread_mutex_destroy(&g_events_lock);

    return 0;
}
