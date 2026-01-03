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
#include <rbus/rbus.h>
#include <signal.h>
#include <wifi_hal.h>
#include <collection.h>
#include <wifi_monitor.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <wifi_base.h>
#include <errno.h>
#include <cjson/cJSON.h>

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

typedef struct csi_data_json_obj {
    cJSON *main_json_obj;
    cJSON *json_csi_obj;
    cJSON *json_sounding_devices;
    hash_map_t *stalist_array_map;
    FILE *json_dump_fptr;
} csi_data_json_obj_t;

typedef struct stalist_map_info {
    cJSON *sta_json_arr_obj;
} stalist_map_info_t;

csi_data_json_obj_t json_obj;

csi_data_json_obj_t *get_csi_json_obj(void)
{
    return &json_obj;
}

#define VERIFY_NULL_CHECK(T)                                                                     \
    if (NULL == (T)) {                                                                           \
        WIFI_EVENT_CONSUMER_DGB("[%s:%d] input parameter:%s is NULL\n", __func__, __LINE__, #T); \
        return;                                                                                  \
    }

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
int g_num_of_samples = -1;
int g_sample_counter = 0;
char g_csi_cfg_clients_mac[256];
char g_gw_str_mac[32];

long long int get_cur_time_in_sec(void)
{
    struct timeval tv_now = { 0 };
    gettimeofday(&tv_now, NULL);

    return (long long int)tv_now.tv_sec;
}

void remove_colons(char *str)
{
    char *src = str, *dst = str;

    while (*src) {
        if (*src != ':') {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

int get_cm_mac_addr(char *mac, unsigned int mac_size)
{
    FILE *f;
    char ptr[32];
    char *cmd = "deviceinfo.sh -cmac";

    if (mac == NULL || mac_size == 0) {
        return -1;
    }

    memset(ptr, 0, sizeof(ptr));

    f = popen(cmd, "r");
    if (f == NULL) {
        return -1;
    }

    if (fgets(ptr, sizeof(ptr), f) == NULL) {
        pclose(f);
        return -1;
    }

    pclose(f);

    ptr[strcspn(ptr, "\n")] = '\0';

    remove_colons(ptr);

    snprintf(mac, mac_size, "%s", ptr);

    printf("device cm mac: %s\r\n", mac);

    return 0;
}

int execute_system_command_with_status(const char *cmd,
                                       char *cmd_output,
                                       size_t output_size,
                                       int *exit_status)
{
    FILE *fp;
    char buffer[256];
    size_t len = 0;

    if (!cmd || !cmd_output || output_size == 0) {
        errno = EINVAL;
        return -1;
    }

    fp = popen(cmd, "r");
    if (!fp) {
        perror("popen failed");
        return -1;
    } else {
        printf("cmd:%s send success\r\n", cmd);
    }

    cmd_output[0] = '\0';

    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t buf_len = strlen(buffer);
        if (len + buf_len < output_size - 1) {
            memcpy(cmd_output + len, buffer, buf_len);
            len += buf_len;
            cmd_output[len] = '\0';
        } else {
            break;
        }
    }

    int status = pclose(fp);
    if (exit_status) {
        if (WIFEXITED(status))
            *exit_status = WEXITSTATUS(status);
        else
            *exit_status = -1;
    }

    return 0;
}

int get_server_password(char *output_key, size_t output_len)
{
    if (!output_key || output_len == 0) {
        errno = EINVAL;
        return -1;
    }

#if defined (_XB7_PRODUCT_REQ_)
    if (execute_system_command_with_status(
            "/usr/bin/rdkssacli \"{STOR=GET,SRC=kquhqtoczcbx,DST=/dev/stdout}\"",
            output_key,
            output_len,
            NULL) != 0)
    {
        return -1;
    }
#else
    if (system("GetConfigFile /tmp/.cfgDynamicSExpki") != 0) {
        perror("Failed to generate certificate password");
        return -1;
    } else {
        printf("command:\"GetConfigFile /tmp/.cfgDynamicSExpki\" execute success\r\n");
    }

    if (execute_system_command_with_status(
            "cat /tmp/.cfgDynamicSExpki",
            output_key,
            output_len,
            NULL) != 0)
    {
        return -1;
    }
#endif

    output_key[strcspn(output_key, "\r\n")] = '\0';
    printf("Key value:%s\r\n", output_key);

    return 0;
}

int upload_file_to_cloud(const char *file_name)
{
    static char password[256] = { 0 };
    char curl_cmd[1024];
    char curl_output[1024];
    int curl_exit_code;

#if defined (_XB7_PRODUCT_REQ_)
    const char *cert_file_name = "/nvram/certs/devicecert_1.pk12";
#else
    const char *cert_file_name = "/nvram/certs/devicecert_2.pk12";
#endif

    if (!file_name) {
        fprintf(stderr, "Invalid file name\n");
        return -1;
    }

    if (strlen(password) == 0) {
        if (get_server_password(password, sizeof(password)) != 0) {
            fprintf(stderr, "Failed to get server password\n");
            return -1;
        }
    }

    for (int attempt = 0; attempt < 2; attempt++) {
        snprintf(curl_cmd, sizeof(curl_cmd),
            "curl -s "
            "--cert-type P12 "
            "--cert %s:%s "
            "-F \"data=@%s\" "
            "https://devprimary.vbautobot.comcast.com:6002/post_csi_file",
            cert_file_name,
            password,
            file_name);

        if (execute_system_command_with_status(
                curl_cmd,
                curl_output,
                sizeof(curl_output),
                &curl_exit_code) != 0)
        {
            fprintf(stderr, "Failed to execute curl\n");
            return -1;
        }

        printf("Curl Output:\n%s\n", curl_output);

        if (curl_exit_code == 0) {
            printf("Upload successful\n");
            return 0;
        }

        if (curl_exit_code == 58 && attempt == 0) {
            printf("PKCS12 password invalid, regenerating and retrying once...\n");

            memset(password, 0, sizeof(password));
            if (get_server_password(password, sizeof(password)) != 0) {
                fprintf(stderr, "Failed to regenerate password\n");
                return -1;
            }
            continue;
        }

        fprintf(stderr, "Upload failed (curl exit code %d)\n", curl_exit_code);
    }

    return -1;
}

static void wifievents_get_device_vaps()
{
    char cmd[200];
    int i;
    int rc = RBUS_ERROR_SUCCESS;

    for (i = 0; i < MAX_VAP; i++) {
        rbusValue_t value;
        snprintf(cmd, sizeof(cmd), "Device.WiFi.SSID.%d.Enable", i + 1);
        rc = rbus_get(g_handle, cmd, &value);
        if (rc != RBUS_ERROR_SUCCESS) {
            g_device_vaps_list[i] = -1;
        } else {
            g_device_vaps_list[i] = i + 1;
            rbusValue_Release(value);
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
    int vap = 0, len = 0;
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
    int vap = 0, len = 0;
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

void json_add_wifi_csi_frame_info(cJSON *sta_obj, wifi_frame_info_t *frame_info)
{
    cJSON *obj_array, *number_item;

    cJSON_AddNumberToObject(sta_obj, "bw_mode", frame_info->bw_mode);
    cJSON_AddNumberToObject(sta_obj, "mcs", frame_info->mcs);
    cJSON_AddNumberToObject(sta_obj, "Nr", frame_info->Nr);
    cJSON_AddNumberToObject(sta_obj, "Nc", frame_info->Nc);

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(sta_obj, "nr_rssi", obj_array);
    for (int index = 0; index < frame_info->Nr; index++) {
        number_item = cJSON_CreateNumber(frame_info->nr_rssi[index]);
        if (number_item == NULL) {
            return;
        }

        cJSON_AddItemToArray(obj_array, number_item);
    }

    cJSON_AddNumberToObject(sta_obj, "valid_mask", frame_info->valid_mask);
    cJSON_AddNumberToObject(sta_obj, "phy_bw", frame_info->phy_bw);
    cJSON_AddNumberToObject(sta_obj, "cap_bw", frame_info->cap_bw);
    cJSON_AddNumberToObject(sta_obj, "num_sc", frame_info->num_sc);
    cJSON_AddNumberToObject(sta_obj, "decimation", frame_info->decimation);
    cJSON_AddNumberToObject(sta_obj, "channel", frame_info->channel);
    cJSON_AddNumberToObject(sta_obj, "cfo", frame_info->cfo);
    cJSON_AddNumberToObject(sta_obj, "time_stamp", frame_info->time_stamp);
}

void json_add_wifi_csi_matrix_info(cJSON *csi_matrix_obj_wrapper, wifi_csi_data_t *csi)
{
    cJSON *subcarrier_array = cJSON_CreateArray();
    VERIFY_NULL_CHECK(subcarrier_array);
    cJSON_AddItemToObject(csi_matrix_obj_wrapper, "sub_carrier", subcarrier_array);

    for (uint32_t sc_idx = 0; sc_idx < csi->frame_info.num_sc; sc_idx++) {
        cJSON *subcarrier_data_obj = cJSON_CreateObject();
        VERIFY_NULL_CHECK(subcarrier_data_obj);

        cJSON *stream_array_for_subcarrier = cJSON_CreateArray();
        VERIFY_NULL_CHECK(stream_array_for_subcarrier);

        cJSON_AddItemToObject(subcarrier_data_obj, "stream", stream_array_for_subcarrier);

        cJSON_AddItemToArray(subcarrier_array, subcarrier_data_obj);

        for (uint32_t stream_idx = 0; stream_idx < csi->frame_info.Nc; stream_idx++) {
            cJSON *stream_data_obj = cJSON_CreateObject();
            VERIFY_NULL_CHECK(stream_data_obj);

            cJSON *antenna_data_array = cJSON_CreateArray();
            VERIFY_NULL_CHECK(antenna_data_array);

            cJSON_AddItemToObject(stream_data_obj, "antenna", antenna_data_array);

            cJSON_AddItemToArray(stream_array_for_subcarrier, stream_data_obj);

            for (uint32_t ant_idx = 0; ant_idx < csi->frame_info.Nr; ant_idx++) {
                cJSON *real_imag_object = cJSON_CreateObject();
                VERIFY_NULL_CHECK(real_imag_object);

                int16_t real_data = (int16_t)((csi->csi_matrix[sc_idx][ant_idx][stream_idx] >> 16) &
                    0xFFFF);
                int16_t imag_data = (int16_t)(csi->csi_matrix[sc_idx][ant_idx][stream_idx] &
                    0xFFFF);

                cJSON_AddNumberToObject(real_imag_object, "real", real_data);
                cJSON_AddNumberToObject(real_imag_object, "img", imag_data);

                cJSON_AddItemToArray(antenna_data_array, real_imag_object);
            }
        }
    }
}

void client_csi_data_json_elem_add(cJSON *sta_obj, wifi_csi_data_t *csi,
    char *str_sta_mac)
{
    cJSON *obj;

    cJSON_AddStringToObject(sta_obj, "sta_mac", str_sta_mac);

    obj = cJSON_CreateObject();
    VERIFY_NULL_CHECK(obj);
    cJSON_AddItemToObject(sta_obj, "frame_info", obj);
    json_add_wifi_csi_frame_info(obj, &csi->frame_info);

    obj = cJSON_CreateObject();
    VERIFY_NULL_CHECK(obj);
    cJSON_AddItemToObject(sta_obj, "csi_matrix", obj);
    json_add_wifi_csi_matrix_info(obj, csi);
}

void csi_data_in_json_format(mac_address_t sta_mac, wifi_csi_data_t *csi)
{
    if (g_num_of_samples == -1) {
        return;
    }
    mac_addr_str_t str_sta_mac = { 0 };
    cJSON *obj;

    csi_data_json_obj_t *p_csi_json_obj = get_csi_json_obj();
    if (p_csi_json_obj->main_json_obj == NULL) {
        p_csi_json_obj->main_json_obj = cJSON_CreateObject();
        VERIFY_NULL_CHECK(p_csi_json_obj->main_json_obj);
    }

    if (p_csi_json_obj->json_csi_obj == NULL) {
        p_csi_json_obj->json_csi_obj = cJSON_CreateObject();
        VERIFY_NULL_CHECK(p_csi_json_obj->json_csi_obj);
        cJSON_AddItemToObject(p_csi_json_obj->main_json_obj, "CSI", p_csi_json_obj->json_csi_obj);
    }

    if (p_csi_json_obj->json_sounding_devices == NULL) {
        p_csi_json_obj->json_sounding_devices = cJSON_CreateArray();
        VERIFY_NULL_CHECK(p_csi_json_obj->json_sounding_devices);
        cJSON_AddItemToObject(p_csi_json_obj->json_csi_obj, "SoundingDevices",
            p_csi_json_obj->json_sounding_devices);
    }

    if (p_csi_json_obj->stalist_array_map == NULL) {
        p_csi_json_obj->stalist_array_map = hash_map_create();
        VERIFY_NULL_CHECK(p_csi_json_obj->stalist_array_map);
    }

    to_mac_str(sta_mac, str_sta_mac);
    stalist_map_info_t *ptr = hash_map_get(p_csi_json_obj->stalist_array_map,
        str_sta_mac);
    if (ptr == NULL) {
        ptr = calloc(1, sizeof(stalist_map_info_t));
        VERIFY_NULL_CHECK(ptr);
        hash_map_put(p_csi_json_obj->stalist_array_map,
            strdup(str_sta_mac), ptr);
    }

    if (ptr->sta_json_arr_obj == NULL) {
        ptr->sta_json_arr_obj = cJSON_CreateArray();
        VERIFY_NULL_CHECK(ptr->sta_json_arr_obj);
        cJSON_AddItemToArray(p_csi_json_obj->json_sounding_devices,
            ptr->sta_json_arr_obj);
    }

    obj = cJSON_CreateObject();
    cJSON_AddItemToArray(ptr->sta_json_arr_obj, obj);
    client_csi_data_json_elem_add(obj, csi, str_sta_mac);
}

void save_json_data_to_file(void)
{
    csi_data_json_obj_t *p_csi_json_obj = get_csi_json_obj();
    if (p_csi_json_obj->main_json_obj != NULL) {
        hash_map_destroy(p_csi_json_obj->stalist_array_map);
        p_csi_json_obj->stalist_array_map = NULL;
        char *json_string = cJSON_Print(p_csi_json_obj->main_json_obj);
        if (json_string == NULL) {
            cJSON_Delete(p_csi_json_obj->main_json_obj);
            p_csi_json_obj->main_json_obj = NULL;
            return;
        }

        char file_name[64] = { 0 };
        long long int timestamp = get_cur_time_in_sec();

        snprintf(file_name, sizeof(file_name), "/tmp/csi_samples_%s_%llu.json",
            g_gw_str_mac, timestamp);

        p_csi_json_obj->json_dump_fptr = fopen(file_name, "a+");
        if (p_csi_json_obj->json_dump_fptr == NULL) {
            printf("%s Failed to open file:%s\n", __func__, file_name);
            goto file_error;
        }

        if (fputs(json_string, p_csi_json_obj->json_dump_fptr) == EOF) {
            perror("Failed to write to csi json file");
            goto file_error;
        }
        fputc('\n', p_csi_json_obj->json_dump_fptr);

        if (upload_file_to_cloud(file_name) == 0) {
            remove(file_name);
        }
    file_error:
        if (p_csi_json_obj->json_dump_fptr != NULL) {
            fclose(p_csi_json_obj->json_dump_fptr);
        }
        cJSON_Delete(p_csi_json_obj->main_json_obj);
        p_csi_json_obj->main_json_obj = NULL;
        free(json_string);
    }
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

    csi_data_in_json_format(sta_mac, csi);

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
    for (itr = 0; itr < csi.frame_info.Nr; itr++) {
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

bool is_valid_mac(const char *mac)
{
    int i;

    if (strlen(mac) != 17)
        return false;

    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (mac[i] != ':') {
                return false;
            }
        }
    }
    return true;
}

bool validate_mac_list(const char *input)
{
    char buffer[256];
    char *token;

    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    token = strtok(buffer, ",");

    while (token != NULL) {
        // Trim leading spaces
        while (*token == ' ')
            token++;

        if (!is_valid_mac(token)) {
            printf("Invalid MAC address found: %s\n", token);
            return false;
        }

        token = strtok(NULL, ",");
    }

    return true;
}

static bool parseArguments(int argc, char **argv)
{
    int c;
    bool ret = true;
    char *p;

    while ((c = getopt(argc, argv, "he:s:v:i:c:f:n:m:")) != -1) {
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
                   "-n [number of samples]"
                   "-m [All client MAC addresses separated by commas]"
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
        case 'n':
            if (!optarg || atoi(optarg) <= 0) {
                printf(" Failed to parse number of samples: %s\n", optarg);
                ret = false;
            }
            g_num_of_samples = atoi(optarg);
            printf(" number of samples to be collected : %d\n", g_num_of_samples);
            break;
        case 'm':
            if (!optarg || (validate_mac_list(optarg) == false)) {
                printf("%s:%d Failed to parse csi mac list:%s\n", __func__, __LINE__, optarg);
                ret = false;
            }
            snprintf(g_csi_cfg_clients_mac, sizeof(g_csi_cfg_clients_mac), "%s", optarg);
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

int set_rbus_csi_sta_maclist(rbusHandle_t bus_handle, int csi_session_index, char *sta_mac)
{
    char name[64] = { 0 };
    int rc = RBUS_ERROR_SUCCESS;

    snprintf(name, sizeof(name), "Device.WiFi.X_RDK_CSI.%d.ClientMaclist", csi_session_index);

    rc = rbus_setStr(bus_handle, name, sta_mac);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf("%s:%d: bus:%s bus set string:%s Failed %d\n", __func__,
            __LINE__, name, sta_mac, rc);
        return RETURN_ERR;
    } else {
        printf("%s:%d: bus:%s bus set string:%s success\n", __func__,
            __LINE__, name, sta_mac);
    }

    return rc;
}

rbusError_t rbus_set_bool_value(rbusHandle_t p_rbus_handle, int csi_session_index, bool bool_value)
{
    char name[64] = { 0 };
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    rbusValue_t value;

    rbusValue_Init(&value);

    rbusValue_SetBoolean(value, bool_value);

    snprintf(name, sizeof(name), "Device.WiFi.X_RDK_CSI.%d.Enable", csi_session_index);

    rc = rbus_set(p_rbus_handle, name, value, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf("%s:%d bus: rbus_set() failed:%d for name:%s\n",
          __func__, __LINE__, rc, name);
    }
    rbusValue_Release(value);

    return rc;
}

int main(int argc, char *argv[])
{
    struct sigaction new_action = { 0 };
    char name[RBUS_MAX_NAME_LENGTH];
    int i, j;
    int rc = RBUS_ERROR_SUCCESS;
    int sub_index = 0, csi_sub_index = 0;
    rbusHandle_t directHandle = NULL;
    char fifo_path[64] = { 0 };

    /* Add pid to rbus component name */
    g_pid = getpid();
    snprintf(g_component_name, RBUS_MAX_NAME_LENGTH, "%s%d", "WifiEventConsumer", g_pid);

    get_cm_mac_addr(g_gw_str_mac, sizeof(g_gw_str_mac));

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
        if (strlen(g_csi_cfg_clients_mac) != 0) {
            usleep(500 * 1000);
            set_rbus_csi_sta_maclist(g_handle, g_csi_index, g_csi_cfg_clients_mac);
            usleep(500 * 1000);
            rbus_set_bool_value(g_handle, g_csi_index, true);
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
                        if (g_num_of_samples != -1) {
                            g_sample_counter++;

                            if (g_sample_counter >= g_num_of_samples) {
                                printf("collected samples : %d, exiting program\n",
                                    g_sample_counter);
                                save_json_data_to_file();
                                goto exit2;
                            }
                        }
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
