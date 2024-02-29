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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <rbus.h>
#include <signal.h>
#include <wifi_hal.h>
#include <collection.h>
#include <wifi_monitor.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <wifi_base.h>
#include <errno.h>

#define MAX_EVENTS 11
#define DEFAULT_CSI_INTERVAL 500
#define DEFAULT_CLIENTDIAG_INTERVAL 5000
#define MAX_CSI_INTERVAL 30000
#define MIN_CSI_INTERVAL 100
#define DEFAULT_DBG_FILE "/tmp/wifiEventConsumer"
#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(_p_) (void)(_p_)
#endif

#define WIFI_EVENT_CONSUMER_DGB(msg, ...) \
    wifievents_consumer_dbg_print("%s:%d  " msg "\n", __func__, __LINE__, ##__VA_ARGS__);

FILE *g_fpg = NULL;

char g_component_name[RBUS_MAX_NAME_LENGTH];
char g_debug_file_name[RBUS_MAX_NAME_LENGTH];
int g_pid;
bool g_motion_sub = false;
bool g_csi_levl_sub = false;

int pipe_read_fd = -1;
int lvel_pipe_read_fd = -1;

rbusHandle_t g_handle;
rbusEventSubscription_t *g_all_subs = NULL;
rbusEventSubscription_t *g_csi_sub = NULL;
int g_sub_total = 0;
int g_csi_sub_total = 0;

int g_events_list[MAX_EVENTS];
int g_events_cnt = 0;
int g_vaps_list[MAX_VAP];
int g_device_vaps_list[MAX_VAP];
int g_vaps_cnt = 0;
int g_csi_interval = 0;
bool g_csi_session_set = false;
uint32_t g_csi_index = 0;
int g_clientdiag_interval = 0;
int g_disable_csi_log = 0;
int g_rbus_direct_enabled = 0;

static void wifievents_get_device_vaps()
{
    char cmd[200];
    int i;
    rbusValue_t value;
    int rc = RBUS_ERROR_SUCCESS;

    for (i = 0; i < MAX_VAP; i++) {
        snprintf(cmd, sizeof(cmd), "Device.WiFi.SSID.%d.Enable", i + 1);
        rc = rbus_get(g_handle, cmd, &value);
        if (rc != RBUS_ERROR_SUCCESS) {
            g_device_vaps_list[i] = -1;
        } else {
            g_device_vaps_list[i] = i + 1;
        }
    }
}

static void wifievents_update_vap_list(void)
{
    int i, j;
    if (g_vaps_cnt == 0) {
        for (i = 0, j = 0; i < MAX_VAP; i++) {
            if (g_device_vaps_list[i] != -1) {
                g_vaps_list[j] = g_device_vaps_list[i];
                j++;
                g_vaps_cnt++;
            }
        }
    }
}

static void wifievents_consumer_dbg_print(char *format, ...)
{
    char buff[256] = { 0 };
    va_list list;

    if ((access("/nvram/wifiEventConsumerDbg", R_OK)) != 0) {
        return;
    }
    snprintf(buff, 12, " pid:%d ", g_pid);

#ifdef LINUX_VM_PORT
    printf("%s ", buff);
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
#else
    if (g_fpg == NULL) {
        g_fpg = fopen(g_debug_file_name, "a+");
        if (g_fpg == NULL) {
            printf("Failed to open file\n");
            return;
        }
    }

    fprintf(g_fpg, "%s ", buff);
    va_start(list, format);
    vfprintf(g_fpg, format, list);
    va_end(list);
    fflush(g_fpg);
#endif
    return;
}

static void diagHandler(rbusHandle_t handle, rbusEvent_t const *event,
    rbusEventSubscription_t *subscription)
{
    rbusValue_t value;
    int vap;

    if (!event ||
        (sscanf(subscription->eventName, "Device.WiFi.AccessPoint.%d.X_RDK_DiagData", &vap) != 1)) {
        WIFI_EVENT_CONSUMER_DGB("Invalid Event Received %s", subscription->eventName);
        return;
    }
    value = rbusObject_GetValue(event->data, subscription->eventName);
    if (value) {
        WIFI_EVENT_CONSUMER_DGB("VAP %d Device Diag Data '%s'\n", vap,
            rbusValue_GetString(value, NULL));
    }
    UNREFERENCED_PARAMETER(handle);
}

static void deviceConnectHandler(rbusHandle_t handle, rbusEvent_t const *event,
    rbusEventSubscription_t *subscription)
{
    rbusValue_t value;
    int vap, len;
    uint8_t const *data_ptr;
    mac_address_t sta_mac;

    if (!event ||
        (sscanf(subscription->eventName, "Device.WiFi.AccessPoint.%d.X_RDK_deviceConnected",
             &vap) != 1)) {
        WIFI_EVENT_CONSUMER_DGB("Invalid Event Received %s %d %p", subscription->eventName, vap,
            event);
        return;
    }

    value = rbusObject_GetValue(event->data, subscription->eventName);
    if (value) {
        data_ptr = rbusValue_GetBytes(value, &len);
        if (data_ptr != NULL && len == sizeof(mac_address_t)) {
            memcpy(&sta_mac, data_ptr, sizeof(mac_address_t));
            WIFI_EVENT_CONSUMER_DGB("Device %02x:%02x:%02x:%02x:%02x:%02x connected to VAP %d\n",
                sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5], vap);
        } else {
            WIFI_EVENT_CONSUMER_DGB("Invalid Event Data Received %s", subscription->eventName);
            return;
        }
    }
    UNREFERENCED_PARAMETER(handle);
}

static void deviceDisonnectHandler(rbusHandle_t handle, rbusEvent_t const *event,
    rbusEventSubscription_t *subscription)
{
    rbusValue_t value;
    int vap, len;
    uint8_t const *data_ptr;
    mac_address_t sta_mac;

    if (!event ||
        (sscanf(subscription->eventName, "Device.WiFi.AccessPoint.%d.X_RDK_deviceDisconnected",
             &vap) != 1)) {
        WIFI_EVENT_CONSUMER_DGB("Invalid Event Received %s %d %p", subscription->eventName, vap,
            event);
        return;
    }
    value = rbusObject_GetValue(event->data, subscription->eventName);
    if (value) {
        data_ptr = rbusValue_GetBytes(value, &len);
        if (data_ptr != NULL && len == sizeof(mac_address_t)) {
            memcpy(&sta_mac, data_ptr, sizeof(mac_address_t));
            WIFI_EVENT_CONSUMER_DGB(
                "Device %02x:%02x:%02x:%02x:%02x:%02x disconnected from VAP %d\n", sta_mac[0],
                sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5], vap);
        } else {
            WIFI_EVENT_CONSUMER_DGB("Invalid Event Data Received %s", subscription->eventName);
            return;
        }
    }
    UNREFERENCED_PARAMETER(handle);
}

static void deviceDeauthHandler(rbusHandle_t handle, rbusEvent_t const *event,
    rbusEventSubscription_t *subscription)
{
    rbusValue_t value;
    int vap, len;
    uint8_t const *data_ptr;
    mac_address_t sta_mac;

    if (!event ||
        (sscanf(subscription->eventName, "Device.WiFi.AccessPoint.%d.X_RDK_deviceDeauthenticated",
             &vap) != 1)) {
        WIFI_EVENT_CONSUMER_DGB("Invalid Event Received %s", subscription->eventName);
        return;
    }

    value = rbusObject_GetValue(event->data, subscription->eventName);
    if (value) {
        data_ptr = rbusValue_GetBytes(value, &len);
        if (data_ptr != NULL && len == sizeof(mac_address_t)) {
            memcpy(&sta_mac, data_ptr, sizeof(mac_address_t));
            WIFI_EVENT_CONSUMER_DGB(
                "Device %02x:%02x:%02x:%02x:%02x:%02x deauthenticated from VAP %d\n", sta_mac[0],
                sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5], vap);
        } else {
            WIFI_EVENT_CONSUMER_DGB("Invalid Event Data Received %s", subscription->eventName);
            return;
        }
    }

    UNREFERENCED_PARAMETER(handle);
}

static void statusHandler(rbusHandle_t handle, rbusEvent_t const *event,
    rbusEventSubscription_t *subscription)
{
    rbusValue_t value;
    int vap;

    if (!event ||
        (sscanf(subscription->eventName, "Device.WiFi.AccessPoint.%d.Status", &vap) != 1)) {
        WIFI_EVENT_CONSUMER_DGB("Invalid Event Received %s", subscription->eventName);
        return;
    }

    value = rbusObject_GetValue(event->data, "value");
    if (value) {
        WIFI_EVENT_CONSUMER_DGB("AP %d status changed to %s", vap,
            rbusValue_GetString(value, NULL));
    }

    UNREFERENCED_PARAMETER(handle);
}

static void levlstatusHandler(rbusHandle_t handle, rbusEvent_t const *event,
    rbusEventSubscription_t *subscription)
{
    rbusValue_t value;
    unsigned int status, mac[6];
    char const *pTmp = NULL;

    if (strcmp(subscription->eventName, "Device.WiFi.X_RDK_CSI_LEVL.soundingStatus") != 0) {
        WIFI_EVENT_CONSUMER_DGB("Invalid Event Received %s", subscription->eventName);
        return;
    }

    value = rbusObject_GetValue(event->data, subscription->eventName);
    if (value) {
        pTmp = rbusValue_GetString(value, NULL);
        sscanf(pTmp, "%02x:%02x:%02x:%02x:%02x:%02x;%d", (unsigned int *)&mac[0],
            (unsigned int *)&mac[1], (unsigned int *)&mac[2], (unsigned int *)&mac[3],
            (unsigned int *)&mac[4], (unsigned int *)&mac[5], (unsigned int *)&status);
        WIFI_EVENT_CONSUMER_DGB("Levl Status for Mac %02x:%02x:%02x:%02x:%02x:%02x is %d", mac[0],
            mac[1], mac[2], mac[3], mac[4], mac[5], status);
    }

    UNREFERENCED_PARAMETER(handle);
}

static void csiMacListHandler(rbusHandle_t handle, rbusEvent_t const *event,
    rbusEventSubscription_t *subscription)
{
    rbusValue_t value;
    int csi_session;

    if (!event ||
        (sscanf(subscription->eventName, "Device.WiFi.X_RDK_CSI.%d.ClientMaclist", &csi_session) !=
            1)) {
        WIFI_EVENT_CONSUMER_DGB("Invalid Event Received %s", subscription->eventName);
        return;
    }

    value = rbusObject_GetValue(event->data, "value");
    if (value) {
        WIFI_EVENT_CONSUMER_DGB("CSI session %d MAC list changed to %s", csi_session,
            rbusValue_GetString(value, NULL));
    }

    UNREFERENCED_PARAMETER(handle);
}

void rotate_and_write_CSIData(mac_address_t sta_mac, wifi_csi_data_t *csi)
{
#define MB(x) ((long int)(x) << 20)
#define CSI_FILE "/tmp/CSI.bin"
#define CSI_TMP_FILE "/tmp/CSI_tmp.bin"
    WIFI_EVENT_CONSUMER_DGB("Enter %s: %d\n", __FUNCTION__, __LINE__);
    char filename[] = CSI_FILE;
    char filename_tmp[] = CSI_TMP_FILE;
    FILE *csifptr;
    FILE *csifptr_tmp;
    struct stat st;
    mac_address_t tmp_mac;
    wifi_csi_matrix_t tmp_csi_matrix;
    wifi_frame_info_t tmp_frame_info;

    if (csi == NULL)
        return;
    csifptr = fopen(filename, "r");
    csifptr_tmp = fopen(filename_tmp, "w");
    if (csifptr != NULL) {
        // get the size of the file
        stat(filename, &st);
        if (st.st_size > MB(1)) // if file size is greate than 1 mb
        {
            mac_address_t tmp_mac;
            wifi_frame_info_t tmp_frame_info;
            wifi_csi_matrix_t tmp_csi_matrix;

            fread(&tmp_mac, sizeof(mac_address_t), 1, csifptr);
            fread(&tmp_frame_info, sizeof(wifi_frame_info_t), 1, csifptr);
            fread(&tmp_csi_matrix, sizeof(wifi_csi_matrix_t), 1, csifptr);
        }
        // copy rest of the content in to the temp file
        while (csifptr != NULL && fread(&tmp_mac, sizeof(mac_address_t), 1, csifptr)) {
            fread(&tmp_frame_info, sizeof(wifi_frame_info_t), 1, csifptr);
            fread(&tmp_csi_matrix, sizeof(wifi_csi_matrix_t), 1, csifptr);
            fwrite(&tmp_mac, sizeof(mac_address_t), 1, csifptr_tmp);
            fwrite(&tmp_frame_info, sizeof(wifi_frame_info_t), 1, csifptr_tmp);
            fwrite(&tmp_csi_matrix, sizeof(wifi_csi_matrix_t), 1, csifptr_tmp);
        }
    }

    if (csifptr_tmp != NULL) {
        fwrite(sta_mac, sizeof(mac_address_t), 1, csifptr_tmp);
        fwrite(&(csi->frame_info), sizeof(wifi_frame_info_t), 1, csifptr_tmp);
        fwrite(&(csi->csi_matrix), sizeof(wifi_csi_matrix_t), 1, csifptr_tmp);
    }

    if (csifptr != NULL) {
        fclose(csifptr);
        unlink(filename);
    }
    if (csifptr_tmp != NULL) {
        fclose(csifptr_tmp);
        rename(filename_tmp, filename);
    }

    WIFI_EVENT_CONSUMER_DGB("Exit %s: %d\n", __FUNCTION__, __LINE__);
}

static void print_csi_data(char *buffer)
{
    char csilabel[4];
    unsigned int total_length, num_csi_clients, csi_data_length;
    time_t datetime;
    wifi_csi_data_t csi;
    mac_address_t sta_mac;
    char buf[128] = { 0 };
    char *data_ptr = NULL;
    int itr;

    if (g_disable_csi_log) {
        return;
    }

    if (buffer != NULL) {
        data_ptr = buffer;
    } else {
        WIFI_EVENT_CONSUMER_DGB("NULL Pointer\n");
        return;
    }

    // ASCII characters "CSI"
    memcpy(csilabel, data_ptr, 4);
    data_ptr = data_ptr + 4;
    WIFI_EVENT_CONSUMER_DGB("%s\n", csilabel);

    // Total length:  <length of this entire data field as an unsigned int>
    memcpy(&total_length, data_ptr, sizeof(unsigned int));
    data_ptr = data_ptr + sizeof(unsigned int);
    WIFI_EVENT_CONSUMER_DGB("total_length %u\n", total_length);

    // DataTimeStamp:  <date-time, number of seconds since the Epoch>
    memcpy(&datetime, data_ptr, sizeof(time_t));
    data_ptr = data_ptr + sizeof(time_t);
    memset(buf, 0, sizeof(buf));
    ctime_r(&datetime, buf);
    WIFI_EVENT_CONSUMER_DGB("datetime %s\n", buf);

    // NumberOfClients:  <unsigned int number of client devices>
    memcpy(&num_csi_clients, data_ptr, sizeof(unsigned int));
    data_ptr = data_ptr + sizeof(unsigned int);
    WIFI_EVENT_CONSUMER_DGB("num_csi_clients %u\n", num_csi_clients);

    // clientMacAddress:  <client mac address>
    memcpy(&sta_mac, data_ptr, sizeof(mac_address_t));
    data_ptr = data_ptr + sizeof(mac_address_t);
    WIFI_EVENT_CONSUMER_DGB("==========================================================");
    WIFI_EVENT_CONSUMER_DGB("MAC %02x%02x%02x%02x%02x%02x\n", sta_mac[0], sta_mac[1], sta_mac[2],
        sta_mac[3], sta_mac[4], sta_mac[5]);

    // length of client CSI data:  <size of the next field in bytes>
    memcpy(&csi_data_length, data_ptr, sizeof(unsigned int));
    data_ptr = data_ptr + sizeof(unsigned int);
    WIFI_EVENT_CONSUMER_DGB("csi_data_length %u\n", csi_data_length);

    //<client device CSI data>
    memcpy(&csi, data_ptr, sizeof(wifi_csi_data_t));

    // Writing the CSI data to /tmp/CSI.bin
    rotate_and_write_CSIData(sta_mac, &csi);

    // Printing _wifi_frame_info
    WIFI_EVENT_CONSUMER_DGB("bw_mode %d, mcs %d, Nr %d, Nc %d, valid_mask %hu, phy_bw %hu, cap_bw "
                            "%hu, num_sc %hu, decimation %d, channel %d, cfo %d, time_stamp %llu",
        csi.frame_info.bw_mode, csi.frame_info.mcs, csi.frame_info.Nr, csi.frame_info.Nc,
        csi.frame_info.valid_mask, csi.frame_info.phy_bw, csi.frame_info.cap_bw,
        csi.frame_info.num_sc, csi.frame_info.decimation, csi.frame_info.channel,
        csi.frame_info.cfo, csi.frame_info.time_stamp);

    // Printing rssii
    WIFI_EVENT_CONSUMER_DGB("rssi values on each Nr are");
    for (itr = 0; itr <= csi.frame_info.Nr; itr++) {
        WIFI_EVENT_CONSUMER_DGB("%d...", csi.frame_info.nr_rssi[itr]);
    }
    WIFI_EVENT_CONSUMER_DGB("==========================================================");
    return;
}

static void csiDataHandler(rbusHandle_t handle, rbusEventRawData_t const *event,
    rbusEventSubscription_t *subscription)
{
    int itr;
    char *data_ptr = NULL;
    char csilabel[4];
    unsigned int total_length, num_csi_clients, csi_data_length;
    time_t datetime;
    wifi_csi_data_t csi;
    mac_address_t sta_mac;
    char buf[128] = { 0 };

    if (g_disable_csi_log) {
        UNREFERENCED_PARAMETER(handle);
        return;
    }

    if (!event) {
        WIFI_EVENT_CONSUMER_DGB("Invalid Event Received %s", subscription->eventName);
        return;
    }

    data_ptr = (char *)event->rawData;

    // ASCII characters "CSI"
    memcpy(csilabel, data_ptr, 4);
    data_ptr = data_ptr + 4;
    WIFI_EVENT_CONSUMER_DGB("%s\n", csilabel);

    // Total length:  <length of this entire data field as an unsigned int>
    memcpy(&total_length, data_ptr, sizeof(unsigned int));
    data_ptr = data_ptr + sizeof(unsigned int);
    WIFI_EVENT_CONSUMER_DGB("total_length %u\n", total_length);

    // DataTimeStamp:  <date-time, number of seconds since the Epoch>
    memcpy(&datetime, data_ptr, sizeof(time_t));
    data_ptr = data_ptr + sizeof(time_t);
    memset(buf, 0, sizeof(buf));
    ctime_r(&datetime, buf);
    WIFI_EVENT_CONSUMER_DGB("datetime %s\n", buf);

    // NumberOfClients:  <unsigned int number of client devices>
    memcpy(&num_csi_clients, data_ptr, sizeof(unsigned int));
    data_ptr = data_ptr + sizeof(unsigned int);
    WIFI_EVENT_CONSUMER_DGB("num_csi_clients %u\n", num_csi_clients);

    // clientMacAddress:  <client mac address>
    memcpy(&sta_mac, data_ptr, sizeof(mac_address_t));
    data_ptr = data_ptr + sizeof(mac_address_t);
    WIFI_EVENT_CONSUMER_DGB("==========================================================");
    WIFI_EVENT_CONSUMER_DGB("MAC %02x%02x%02x%02x%02x%02x\n", sta_mac[0], sta_mac[1], sta_mac[2],
        sta_mac[3], sta_mac[4], sta_mac[5]);

    // length of client CSI data:  <size of the next field in bytes>
    memcpy(&csi_data_length, data_ptr, sizeof(unsigned int));
    data_ptr = data_ptr + sizeof(unsigned int);
    WIFI_EVENT_CONSUMER_DGB("csi_data_length %u\n", csi_data_length);

    //<client device CSI data>
    memcpy(&csi, data_ptr, sizeof(wifi_csi_data_t));

    // Writing the CSI data to /tmp/CSI.bin
    rotate_and_write_CSIData(sta_mac, &csi);

    // Printing _wifi_frame_info
    WIFI_EVENT_CONSUMER_DGB("bw_mode %d, mcs %d, Nr %d, Nc %d, valid_mask %hu, phy_bw %hu, cap_bw "
                            "%hu, num_sc %hu, decimation %d, channel %d, cfo %d, time_stamp %llu",
        csi.frame_info.bw_mode, csi.frame_info.mcs, csi.frame_info.Nr, csi.frame_info.Nc,
        csi.frame_info.valid_mask, csi.frame_info.phy_bw, csi.frame_info.cap_bw,
        csi.frame_info.num_sc, csi.frame_info.decimation, csi.frame_info.channel,
        csi.frame_info.cfo, csi.frame_info.time_stamp);

    // Printing rssii
    WIFI_EVENT_CONSUMER_DGB("rssi values on each Nr are");
    for (itr = 0; itr <= csi.frame_info.Nr; itr++) {
        WIFI_EVENT_CONSUMER_DGB("%d...", csi.frame_info.nr_rssi[itr]);
    }
    WIFI_EVENT_CONSUMER_DGB("==========================================================");
    UNREFERENCED_PARAMETER(handle);
}

static void doNothingHandler(rbusHandle_t handle, rbusEventRawData_t const *event,
    rbusEventSubscription_t *subscription)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(event);
    UNREFERENCED_PARAMETER(subscription);
}

static void csiEnableHandler(rbusHandle_t handle, rbusEvent_t const *event,
    rbusEventSubscription_t *subscription)
{
    rbusValue_t value;
    int csi_session;

    if (!event ||
        (sscanf(subscription->eventName, "Device.WiFi.X_RDK_CSI.%d.Enable", &csi_session) != 1)) {
        WIFI_EVENT_CONSUMER_DGB("Invalid Event Received %s", subscription->eventName);
        return;
    }

    value = rbusObject_GetValue(event->data, "value");
    if (value) {
        WIFI_EVENT_CONSUMER_DGB("CSI session %d enable changed to %d", csi_session,
            rbusValue_GetBoolean(value));
    }

    UNREFERENCED_PARAMETER(handle);
}

rbusEventSubscription_t g_subscriptions[11] = {
    /* Event Name,                                             filter, interval,   duration,
       handler,                user data, handle */
    { "Device.WiFi.AccessPoint.%d.X_RDK_DiagData",              NULL, 0,   0, diagHandler,            NULL, NULL, NULL,
     false                                                                                                                    },
    { "Device.WiFi.AccessPoint.%d.X_RDK_deviceConnected",       NULL, 0,   0, deviceConnectHandler,   NULL,
     NULL,                                                                                                        NULL, false },
    { "Device.WiFi.AccessPoint.%d.X_RDK_deviceDisconnected",    NULL, 0,   0, deviceDisonnectHandler,
     NULL,                                                                                                  NULL, NULL, false },
    { "Device.WiFi.AccessPoint.%d.X_RDK_deviceDeauthenticated", NULL, 0,   0, deviceDeauthHandler,
     NULL,                                                                                                  NULL, NULL, false },
    { "Device.WiFi.AccessPoint.%d.Status",                      NULL, 0,   0, statusHandler,          NULL, NULL, NULL, false },
    { "Device.WiFi.X_RDK_CSI.%d.ClientMaclist",                 NULL, 0,   0, csiMacListHandler,      NULL, NULL, NULL,
     false                                                                                                                    },
    { "Device.WiFi.X_RDK_CSI.%d.data",                          NULL, 100, 0, doNothingHandler,       NULL, NULL, NULL, false },
    { "Device.WiFi.X_RDK_CSI.%d.Enable",                        NULL, 0,   0, csiEnableHandler,       NULL, NULL, NULL, false },
    { "Device.WiFi.X_RDK_CSI_LEVL.data",                        NULL, 0,   0, csiDataHandler,         NULL, NULL, NULL, false },
    { "Device.WiFi.X_RDK_CSI_LEVL.soundingStatus",              NULL, 0,   0, levlstatusHandler,      NULL, NULL, NULL,
     false                                                                                                                    },
    { "Device.WiFi.X_RDK_CSI_LEVL.datafifo",                    NULL, 0,   0, doNothingHandler,       NULL, NULL, NULL, false }
};

static int isCsiEventSet(void)
{
    return (g_events_list[5] || g_events_list[6] || g_events_list[7]);
}

static bool parseEvents(char *ev_list)
{
    int i, event;
    char *token;

    if (!ev_list) {
        return false;
    }

    for (i = 0; i < MAX_EVENTS; i++) {
        g_events_list[i] = 0;
    }

    token = strtok(ev_list, ",");
    while (token != NULL) {
        event = atoi(token);
        if (event < 1 || event > MAX_EVENTS) {
            return false;
        }
        g_events_list[event - 1] = 1;
        token = strtok(NULL, ",");
        g_events_cnt++;
    }

    return true;
}

static bool parseVaps(char *vap_list)
{
    char *token;
    int i, found;

    if (!vap_list) {
        return false;
    }

    token = strtok(vap_list, ",");
    while (token != NULL) {
        g_vaps_list[g_vaps_cnt] = atoi(token);
        if (g_vaps_list[g_vaps_cnt] < 1 || g_vaps_list[g_vaps_cnt] > MAX_VAP) {
            return false;
        }
        found = 0;
        for (i = 0; i < MAX_VAP; i++) {
            if (g_vaps_list[g_vaps_cnt] == g_device_vaps_list[i]) {
                found = 1;
                break;
            }
        }
        if (found == 0) {
            return false;
        }
        token = strtok(NULL, ",");
        g_vaps_cnt++;
    }

    return true;
}

static int fillSubscribtion(int index, char *name, int event_index)
{
    if (name == NULL) {
        return -1;
    }
    g_all_subs[index].eventName = malloc(strlen(name) + 1);
    memcpy((char *)g_all_subs[index].eventName, name, strlen(name) + 1);
    g_all_subs[index].handler = g_subscriptions[event_index].handler;
    g_all_subs[index].userData = NULL;
    g_all_subs[index].filter = NULL;
    g_all_subs[index].handle = NULL;
    g_all_subs[index].asyncHandler = NULL;
    return 0;
}

static int fillCsiSubscribtion(int index, char *name, int event_index)
{
    if (name == NULL) {
        return -1;
    }
    g_csi_sub[index].eventName = malloc(strlen(name) + 1);
    memcpy((char *)g_csi_sub[index].eventName, name, strlen(name) + 1);
    g_csi_sub[index].handler = g_subscriptions[event_index].handler;
    g_csi_sub[index].userData = NULL;
    g_csi_sub[index].filter = NULL;
    g_csi_sub[index].handle = NULL;
    g_csi_sub[index].asyncHandler = NULL;
    return 0;
}

static void freeSubscription(rbusEventSubscription_t *sub)
{
    if (sub && sub->eventName) {
        free((void *)sub->eventName);
    }
}

static bool parseArguments(int argc, char **argv)
{
    int c;
    bool ret = true;
    char *p;

    while ((c = getopt(argc, argv, "he:s:v:i:c:f:")) != -1) {
        switch (c) {
        case 'h':
            printf("HELP :  wifi_events_consumer -e [numbers] - default all events\n"
                   "\t1 - subscribe to client diagnostic event\n"
                   "\t2 - subscribe to device connected event\n"
                   "\t3 - subscribe to device disconnected\n"
                   "\t4 - subscribe to device deauthenticated\n"
                   "\t5 - subscribe to VAP status\n"
                   "\t6 - subscribe to csi ClientMacList\n"
                   "\t7 - subscribe to csi data\n"
                   "\t8 - subscribe to csi Enable\n"
                   "\t9 - subscribe to levl data (rbus) \n"
                   "\t10- subscribe to levl sounding status \n"
                   "\t11 - subscribe to levl data (fifo) \n"
                   "-s [csi session] - default create session\n"
                   "-v [vap index list] - default all VAPs\n"
                   "-i [csi data interval] - default %dms min %d max %d\n"
                   "-c [client diag interval] - default %dms\n"
                   "-f [debug file name] - default /tmp/wifiEventConsumer\n"
                   "Example: wifi_events_consumer -e 1,2,3,7 -s 1 -v 1,2,13,14\n"
                   "touch /nvram/wifiEventsAppCSILogDisable to disable CSI detail log\n"
                   "touch /nvram/wifiEventsAppCSIRBUSDirect to enable RBUS Direct for CSI data\n",
                DEFAULT_CSI_INTERVAL, MIN_CSI_INTERVAL, MAX_CSI_INTERVAL,
                DEFAULT_CLIENTDIAG_INTERVAL);
            exit(0);
            break;
        case 'e':
            if (!parseEvents(optarg)) {
                printf(" Failed to parse events list\n");
                ret = false;
            }
            break;
        case 's':
            if (!optarg || atoi(optarg) < 0) {
                printf(" Failed to parse csi session\n");
                ret = false;
            }
            g_csi_index = strtoul(optarg, &p, 10);
            g_csi_session_set = true;
            break;
        case 'v':
            if (!parseVaps(optarg)) {
                printf(" Failed to parse VAPs list\n");
                ret = false;
            }
            break;
        case 'i':
            if (!optarg || atoi(optarg) <= 0) {
                printf(" Failed to parse csi interval: %s\n", optarg);
                ret = false;
            }
            g_csi_interval = atoi(optarg);
            break;
        case 'c':
            if (!optarg || atoi(optarg) < 0) {
                printf(" Failed to parse client diag interval: %s\n", optarg);
                ret = false;
            }
            g_clientdiag_interval = atoi(optarg);
            break;
        case 'f':
            if (!optarg) {
                printf(" Failed to parse debug file name\n");
                ret = false;
            }
            snprintf(g_debug_file_name, RBUS_MAX_NAME_LENGTH, "/tmp/%s", optarg);
            break;
        case '?':
            printf("Supposed to get an argument for this option or invalid option\n");
            exit(0);
        default:
            printf("Starting with default values\n");
            break;
        }
    }

    return ret;
}

static void termSignalHandler(int sig)
{
    char name[RBUS_MAX_NAME_LENGTH];
    int i;

    WIFI_EVENT_CONSUMER_DGB("Caught signal %d", sig);

    if (g_all_subs) {
        rbusEvent_UnsubscribeEx(g_handle, g_all_subs, g_sub_total);
        for (i = 0; i < g_sub_total; i++)
            freeSubscription(&g_all_subs[i]);

        free(g_all_subs);
    }
    if (g_csi_sub_total) {
        rbusEvent_UnsubscribeExRawData(g_handle, g_csi_sub, g_csi_sub_total);
        for (i = 0; i < g_csi_sub_total; i++)
            freeSubscription(&g_csi_sub[i]);

        free(g_csi_sub);
    }

    if (!g_events_cnt || (!g_csi_session_set && isCsiEventSet())) {
        snprintf(name, RBUS_MAX_NAME_LENGTH, "Device.WiFi.X_RDK_CSI.%d.", g_csi_index);
        WIFI_EVENT_CONSUMER_DGB("Remove %s", name);
        rbusTable_removeRow(g_handle, name);
        if (pipe_read_fd > 0) {
            close(pipe_read_fd);
        }
        if (lvel_pipe_read_fd >= 0) {
            close(lvel_pipe_read_fd);
        }
    }

    rbus_close(g_handle);

    if (g_fpg) {
        fclose(g_fpg);
    }

    exit(0);
}

int main(int argc, char *argv[])
{
    struct sigaction new_action;
    char name[RBUS_MAX_NAME_LENGTH];
    int i, j;
    int rc = RBUS_ERROR_SUCCESS;
    int sub_index = 0, csi_sub_index = 0;
    rbusHandle_t directHandle = NULL;
    char fifo_path[64] = { 0 };

    /* Add pid to rbus component name */
    g_pid = getpid();
    snprintf(g_component_name, RBUS_MAX_NAME_LENGTH, "%s%d", "WifiEventConsumer", g_pid);

    rc = rbus_open(&g_handle, g_component_name);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf("consumer: rbus_open failed: %d\n", rc);
        if (g_fpg) {
            fclose(g_fpg);
        }
        return rc;
    }

    wifievents_get_device_vaps();

    if (!parseArguments(argc, argv)) {
        return -1;
    }
    wifievents_update_vap_list();

    /* Set default debug file */
    if (g_debug_file_name[0] == '\0') {
        snprintf(g_debug_file_name, RBUS_MAX_NAME_LENGTH, "%s", DEFAULT_DBG_FILE);
    }

    /* Register signal handler */
    new_action.sa_handler = termSignalHandler;
    sigaction(SIGTERM, &new_action, NULL);
    sigaction(SIGINT, &new_action, NULL);

    if (access("/nvram/wifiEventsAppCSILogDisable", R_OK) == 0) {
        printf("consumer: CSI log disabled\n");
        g_disable_csi_log = 1;
    }
    if (access("/nvram/wifiEventsAppCSIRBUSDirect", R_OK) == 0) {
        printf("consumer: RBUS Direct enabled for CSI data\n");
        g_rbus_direct_enabled = 1;
    }

    for (i = 0; i < MAX_EVENTS; i++) {
        if (g_events_cnt && !g_events_list[i]) {
            continue;
        }
        switch (i) {
        case 0: /* Device.WiFi.AccessPoint.{i}.X_RDK_DiagData */
        case 1: /* Device.WiFi.AccessPoint.{i}.X_RDK_deviceConnected" */
        case 2: /* Device.WiFi.AccessPoint.{i}.X_RDK_deviceDisconnected */
        case 3: /* Device.WiFi.AccessPoint.{i}.X_RDK_deviceDeauthenticated*/
        case 4: /* Device.WiFi.AccessPoint.{i}.Status */
            g_sub_total += g_vaps_cnt;
            break;
        case 5: /* Device.WiFi.X_RDK_CSI.{i}.ClientMaclist */
        case 7: /* Device.WiFi.X_RDK_CSI.{i}.Enable */
        case 9: /* Device.WiFi.X_RDK_CSI_LEVL.Status */
            g_sub_total++;
            break;
        case 6: /* Device.WiFi.X_RDK_CSI.{i}.data */
        case 8: /* Device.WiFi.X_RDK_CSI_LEVL.data */
        case 10: /* Device.WiFi.X_RDK_CSI_LEVL.datafifo */
            g_csi_sub_total++;
            break;
        }
    }

    /* Create new CSI session if index was not set by command line */
    if (!g_events_cnt || (!g_csi_session_set && isCsiEventSet())) {
        rc = rbusTable_addRow(g_handle, "Device.WiFi.X_RDK_CSI.", NULL, &g_csi_index);
        if (rc != RBUS_ERROR_SUCCESS) {
            printf("Failed to add CSI\n");
            goto exit;
        }
    }

    if (g_sub_total > 0) {
        g_all_subs = malloc(sizeof(rbusEventSubscription_t) * g_sub_total);
        if (!g_all_subs) {
            printf("Failed to alloc memory\n");
            goto exit1;
        }

        memset(g_all_subs, 0, (sizeof(rbusEventSubscription_t) * g_sub_total));
    }

    if (g_csi_sub_total > 0) {
        g_csi_sub = (rbusEventSubscription_t *)malloc(
            sizeof(rbusEventSubscription_t) * g_csi_sub_total);
        if (!g_csi_sub) {
            printf("Failed to alloc memory\n");
            goto exit1;
        }
        memset(g_csi_sub, 0, sizeof(rbusEventSubscription_t) * g_csi_sub_total);
    }

    for (i = 0; i < MAX_EVENTS; i++) {
        if (g_events_cnt && !g_events_list[i])
            continue;

        switch (i) {
        case 0: /* Device.WiFi.AccessPoint.{i}.X_RDK_DiagData */
            for (j = 0; j < g_vaps_cnt; j++) {
                if (g_clientdiag_interval) {
                    g_all_subs[sub_index].interval = g_clientdiag_interval;
                } else {
                    g_all_subs[sub_index].interval = DEFAULT_CLIENTDIAG_INTERVAL;
                }
                snprintf(name, RBUS_MAX_NAME_LENGTH, g_subscriptions[i].eventName, g_vaps_list[j]);
                WIFI_EVENT_CONSUMER_DGB("Add subscription %s", name);
                fillSubscribtion(sub_index, name, i);
                sub_index++;
            }
            break;
        case 1: /* Device.WiFi.AccessPoint.{i}.X_RDK_deviceConnected*/
        case 2: /* Device.WiFi.AccessPoint.{i}.X_RDK_deviceDisconnected */
        case 3: /* Device.WiFi.AccessPoint.{i}.X_RDK_deviceDeauthenticated*/
        case 4: /* Device.WiFi.AccessPoint.{i}.Status */
            for (j = 0; j < g_vaps_cnt; j++) {
                snprintf(name, RBUS_MAX_NAME_LENGTH, g_subscriptions[i].eventName, g_vaps_list[j]);
                WIFI_EVENT_CONSUMER_DGB("Add subscription %s", name);
                fillSubscribtion(sub_index, name, i);
                sub_index++;
            }
            break;
        case 6: /* Device.WiFi.X_RDK_CSI.{i}.data */
            if (g_csi_interval) {
                g_csi_sub[csi_sub_index].interval = g_csi_interval;
            } else {
                g_csi_sub[csi_sub_index].interval = DEFAULT_CSI_INTERVAL;
            }

            snprintf(name, RBUS_MAX_NAME_LENGTH, g_subscriptions[i].eventName, g_csi_index);
            WIFI_EVENT_CONSUMER_DGB("Add subscription %s", name);
            fillCsiSubscribtion(csi_sub_index, name, i);
            csi_sub_index++;
            g_motion_sub = true;
            break;
        case 5: /* Device.WiFi.X_RDK_CSI.{i}.ClientMaclist */
        case 7: /* Device.WiFi.X_RDK_CSI.{i}.Enable */
            snprintf(name, RBUS_MAX_NAME_LENGTH, g_subscriptions[i].eventName, g_csi_index);
            WIFI_EVENT_CONSUMER_DGB("Add subscription %s", name);
            fillSubscribtion(sub_index, name, i);
            sub_index++;
            break;
        case 9: /* Device.WiFi.X_RDK_CSI_LEVL.soundingStatus */
            snprintf(name, RBUS_MAX_NAME_LENGTH, g_subscriptions[i].eventName);
            WIFI_EVENT_CONSUMER_DGB("Add subscription for Levl CSI Sounding Status %s", name);
            fillSubscribtion(sub_index, name, i);
            sub_index++;
            break;
        case 8: /* Device.WiFi.X_RDK_CSI_LEVL.data */
            snprintf(name, RBUS_MAX_NAME_LENGTH, g_subscriptions[i].eventName);
            WIFI_EVENT_CONSUMER_DGB("Add subscription for Levl CSI Data %s", name);
            fillCsiSubscribtion(csi_sub_index, name, i);
            csi_sub_index++;
            break;
        case 10: /* Device.WiFi.X_RDK_CSI_LEVL.datafifo */
            snprintf(name, RBUS_MAX_NAME_LENGTH, g_subscriptions[i].eventName);
            WIFI_EVENT_CONSUMER_DGB("Add subscription for Levl CSI Data %s", name);
            fillCsiSubscribtion(csi_sub_index, name, i);
            csi_sub_index++;
            g_csi_levl_sub = true;
            break;
        default:
            break;
        }
    }

    if (g_sub_total) {
        rc = rbusEvent_SubscribeEx(g_handle, g_all_subs, g_sub_total, 0);
        if (rc != RBUS_ERROR_SUCCESS) {
            printf("consumer: rbusEvent_Subscribe failed: %d\n", rc);
            goto exit2;
        }
    }

    if (g_csi_sub_total) {
        rc = rbusEvent_SubscribeExRawData(g_handle, g_csi_sub, g_csi_sub_total, 0);
        if (rc != RBUS_ERROR_SUCCESS) {
            printf("consumer: rbusEvent_SubscribeExNoCopy failed: %d\n", rc);
            goto exit3;
        }
    }

    if (g_motion_sub || g_csi_levl_sub) {
        fd_set readfds;
        size_t numRead;
        int max_fd = 0;
        FD_ZERO(&readfds);

        if (g_motion_sub) {
            snprintf(fifo_path, sizeof(fifo_path), "/tmp/csi_motion_pipe%d", g_csi_index);
            pipe_read_fd = open(fifo_path, O_RDONLY | O_NONBLOCK);
            if (pipe_read_fd < 0) {
                WIFI_EVENT_CONSUMER_DGB("Error openning fifo for session number %d %s\n",
                    g_csi_index, strerror(errno));
                return -1;
            }
            max_fd = pipe_read_fd;
            FD_SET(pipe_read_fd, &readfds);
        }
        if (g_csi_levl_sub) {
            WIFI_EVENT_CONSUMER_DGB("open fifo for csi levl\n");
            lvel_pipe_read_fd = open("/tmp/csi_levl_pipe", O_RDONLY | O_NONBLOCK);
            if (lvel_pipe_read_fd < 0) {
                WIFI_EVENT_CONSUMER_DGB("Error openning fifo for csi levl %s\n", strerror(errno));
                return -1;
            }
            if (max_fd < lvel_pipe_read_fd) {
                max_fd = lvel_pipe_read_fd;
            }
            FD_SET(lvel_pipe_read_fd, &readfds);
        }

        while (1) {
            int buffer_size = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t);
            char buffer[buffer_size];
            memset(buffer, 0, sizeof(buffer));

            int ready = select(max_fd + 1, &readfds, NULL, NULL, NULL);
            if (ready == -1) {
                WIFI_EVENT_CONSUMER_DGB("Something went Wrong");
                goto exit;
            } else if (ready == 0) {
                WIFI_EVENT_CONSUMER_DGB("TIMEOUT");
            } else {
                if (FD_ISSET(pipe_read_fd, &readfds)) {
                    numRead = read(pipe_read_fd, buffer, sizeof(buffer));
                    if (numRead > 0) {
                        WIFI_EVENT_CONSUMER_DGB("CSI\n");
                        print_csi_data(buffer);
                    }
                }
                if (FD_ISSET(lvel_pipe_read_fd, &readfds)) {
                    numRead = read(lvel_pipe_read_fd, buffer, sizeof(buffer));
                    if (numRead > 0) {
                        WIFI_EVENT_CONSUMER_DGB("Levl CSI\n");
                        print_csi_data(buffer);
                    }
                }
            }
            FD_ZERO(&readfds);
            if (g_motion_sub) {
                FD_SET(pipe_read_fd, &readfds);
            }
            if (g_csi_levl_sub) {
                FD_SET(lvel_pipe_read_fd, &readfds);
            }
        }
    }

    if (g_rbus_direct_enabled) {
        for (i = 0; i < g_csi_sub_total; i++) {
            if (strstr(g_csi_sub[i].eventName, "X_RDK_CSI") != NULL &&
                strstr(g_csi_sub[i].eventName, "data") != NULL) {
                rc = rbus_openDirect(g_handle, &directHandle, g_csi_sub[i].eventName);
                if (rc != RBUS_ERROR_SUCCESS) {
                    printf("consumer: rbus_openDirect failed: %d, eventName '%s'\n", rc,
                        g_csi_sub[i].eventName);
                    goto exit3;
                }
            }
        }
    }
    while (1) {
        sleep(1024);
    }

exit3:
    if (g_csi_sub_total) {
        rbusEvent_UnsubscribeExRawData(g_handle, g_csi_sub, g_csi_sub_total);
        for (i = 0; i < g_csi_sub_total; i++) {
            freeSubscription(&g_csi_sub[i]);
        }
        free(g_csi_sub);
    }

exit2:
    if (g_all_subs) {
        rbusEvent_UnsubscribeEx(g_handle, g_all_subs, g_sub_total);
        for (i = 0; i < g_sub_total; i++) {
            freeSubscription(&g_all_subs[i]);
        }
        free(g_all_subs);
    }

exit1:
    if (!g_csi_session_set && isCsiEventSet()) {
        snprintf(name, RBUS_MAX_NAME_LENGTH, "Device.WiFi.X_RDK_CSI.%d.", g_csi_index);
        WIFI_EVENT_CONSUMER_DGB("Remove %s", name);
        rbusTable_removeRow(g_handle, name);
    }

exit:
    printf("consumer: exit\n");

    rbus_close(g_handle);
    if (g_fpg) {
        fclose(g_fpg);
    }
    return rc;
}
