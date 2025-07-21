#include "wifi_csi_analytics.h"
#include "scheduler.h"
#include "stdlib.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_analytics.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#ifdef ONEWIFI_CSI_APP_SUPPORT
#define UNREFERENCED_PARAMETER(_p_) (void)(_p_)
#define ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))

#define MUTEX_ERROR_CHECK(CMD)                                                         \
    {                                                                                  \
        int err;                                                                       \
        if ((err = CMD) != 0) {                                                        \
            wifi_util_error_print(WIFI_APPS, "Error %d:%s running command " #CMD, err, \
                strerror(err));                                                        \
        }                                                                              \
    }

#define INIT_MUTEX_PARAM(handle_mutex)                                                   \
    {                                                                                    \
        pthread_mutexattr_t attrib;                                                      \
        MUTEX_ERROR_CHECK(pthread_mutexattr_init(&attrib));                              \
        MUTEX_ERROR_CHECK(pthread_mutexattr_settype(&attrib, PTHREAD_MUTEX_ERRORCHECK)); \
        MUTEX_ERROR_CHECK(pthread_mutex_init(&handle_mutex, &attrib));                   \
    }

#define DEINIT_MUTEX_PARAM(handle_mutex)                         \
    {                                                            \
        MUTEX_ERROR_CHECK(pthread_mutex_destroy(&handle_mutex)); \
    }

#define MUTEX_LOCK(handle_mutex)                             \
    {                                                        \
        MUTEX_ERROR_CHECK(pthread_mutex_lock(&handle_mutex)) \
    }

#define MUTEX_UNLOCK(handle_mutex)                             \
    {                                                          \
        MUTEX_ERROR_CHECK(pthread_mutex_unlock(&handle_mutex)) \
    }

void *get_wifi_app_obj(wifi_app_inst_t inst)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr = NULL;
    wifi_app_t *p_app = NULL;
    if (ctrl != NULL) {
        apps_mgr = &ctrl->apps_mgr;
        p_app = (wifi_app_t *)get_app_by_inst(apps_mgr, inst);
        return p_app;
    }
    return NULL;
}

csi_analytics_data_t *add_new_hash_map_entry(hash_map_t *csi_analytics_map, char *key)
{
    csi_analytics_data_t *csi_info;
    csi_info = calloc(1, sizeof(csi_analytics_data_t));
    if (csi_info == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d csi analytics calloc failed\n", __func__, __LINE__);
        return NULL;
    }
    hash_map_put(csi_analytics_map, strdup(key), csi_info);
    return csi_info;
}

int set_bus_csi_sta_maclist(bus_handle_t *bus_handle, csi_analytics_info_t *csi_info)
{
    char name[BUS_MAX_NAME_LENGTH] = { 0 };
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    bus_error_t rc = bus_error_success;

    snprintf(name, BUS_MAX_NAME_LENGTH, CSI_CLIENT_MACLIST, csi_info->csi_session_index);

    rc = bus_desc->bus_set_string_fn(bus_handle, name, csi_info->sta_mac);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: bus:%s bus set string:%s Failed %d\n", __func__,
            __LINE__, name, csi_info->sta_mac, rc);
        return RETURN_ERR;
    } else {
        wifi_util_info_print(WIFI_APPS, "%s:%d: bus:%s bus set string:%s success\n", __func__,
            __LINE__, name, csi_info->sta_mac);
    }

    return rc;
}

static char *mac_exists_in_list(const char *total_mac, const char *mac_to_check)
{
    return (strstr(total_mac, mac_to_check));
}

static int add_str_mac_addr(char *total_mac, const char *str_mac)
{
    if (mac_exists_in_list((const char *)total_mac, str_mac) == NULL) {
        uint32_t str_len = strlen(total_mac);
        if (str_len + MAX_MAC_STR_SIZE > MAX_MACLIST_SIZE) {
            wifi_util_error_print(WIFI_APPS, "%s:%d: max stored mac addr reached:%s\n", __func__,
                __LINE__, total_mac);
            return RETURN_ERR;
        } else if (str_len != 0) {
            strcat(total_mac, ",");
            strcat(total_mac, str_mac);
        } else {
            snprintf(total_mac, MAX_MACLIST_SIZE, "%s", str_mac);
        }
    }
    return RETURN_OK;
}

void process_csi_analytics_data(wifi_app_t *p_app, wifi_csi_dev_t *csi_dev_data)
{
    csi_analytics_info_t *p_info = &p_app->data.u.csi_analytics;
    if (p_info->csi_analytics_map == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d csi analytics map is NULL\n", __func__, __LINE__);
        return;
    }

    uint8_t *p_mac = csi_dev_data->sta_mac;
    mac_addr_str_t mac_str = { 0 };
    csi_analytics_data_t *csi_info;
    long long int current_time_sec = get_current_time_in_sec();
    bool print_log_msg = false;
    bool is_csi_data_mismatch;

    to_mac_str(p_mac, mac_str);
    csi_info = hash_map_get(p_info->csi_analytics_map, mac_str);
    if (csi_info == NULL) {
        csi_info = add_new_hash_map_entry(p_info->csi_analytics_map, mac_str);
        if (csi_info == NULL) {
            wifi_util_error_print(WIFI_APPS,
                "%s:%d csi analytics pointer"
                " is NULL\n",
                __func__, __LINE__);
            return;
        }
        csi_info->csi_data_capture_time_sec = current_time_sec;
        csi_info->num_sc = csi_dev_data->csi.frame_info.num_sc;
        csi_info->decimation = csi_dev_data->csi.frame_info.decimation;
        csi_info->skip_mismatch_data_num = 0;
        MUTEX_LOCK(p_info->maclist_lock);
        if (add_str_mac_addr(p_info->sta_mac, mac_str) == RETURN_OK) {
            set_bus_csi_sta_maclist(&p_app->handle, p_info);
        }
        MUTEX_UNLOCK(p_info->maclist_lock);
        return;
    }

    is_csi_data_mismatch = ((csi_info->num_sc != csi_dev_data->csi.frame_info.num_sc) ||
        (csi_info->decimation != csi_dev_data->csi.frame_info.decimation));

    if (csi_info->skip_mismatch_data_num || is_csi_data_mismatch) {
        if (current_time_sec - csi_info->csi_data_capture_time_sec >= MAX_LOG_MSG_PRINT_TIME_SEC) {
            print_log_msg = true;
        }
        if (print_log_msg) {
            if (csi_info->num_sc != csi_dev_data->csi.frame_info.num_sc) {
                wifi_util_info_print(WIFI_APPS,
                    "%s:%d STA:%s number of subcarriers old:%d -> new:%d\n", __func__, __LINE__,
                    mac_str, csi_info->num_sc, csi_dev_data->csi.frame_info.num_sc);
            }

            if (csi_info->decimation != csi_dev_data->csi.frame_info.decimation) {
                wifi_util_info_print(WIFI_APPS,
                    "%s:%d STA:%s number of decimation old:%d -> new:%d\n", __func__, __LINE__,
                    mac_str, csi_info->decimation, csi_dev_data->csi.frame_info.decimation);
            }

            if (csi_info->skip_mismatch_data_num) {
                wifi_util_info_print(WIFI_APPS, "STA:%s previous csi data mismatch skip cnt:%d\n",
                    mac_str, csi_info->skip_mismatch_data_num);
            }

            csi_info->skip_mismatch_data_num = 0;
            csi_info->csi_data_capture_time_sec = current_time_sec;
        } else if (is_csi_data_mismatch) {
            csi_info->skip_mismatch_data_num++;
        }
    }

    csi_info->num_sc = csi_dev_data->csi.frame_info.num_sc;
    csi_info->decimation = csi_dev_data->csi.frame_info.decimation;
}

static int run_bus_csi_sta_maclist(void *arg)
{
    wifi_app_t *p_app = (wifi_app_t *)arg;
    csi_analytics_info_t *csi_info = &p_app->data.u.csi_analytics;

    MUTEX_LOCK(csi_info->maclist_lock);
    set_bus_csi_sta_maclist(&p_app->handle, csi_info);
    MUTEX_UNLOCK(csi_info->maclist_lock);
    csi_info->sta_maclist_sched_id = 0;
    return TIMER_TASK_COMPLETE;
}

void update_mac_list(wifi_app_t *apps, char *new_str_maclist)
{
    csi_analytics_info_t *csi_info = &apps->data.u.csi_analytics;

    MUTEX_LOCK(csi_info->maclist_lock);
    snprintf(csi_info->sta_mac, MAX_MACLIST_SIZE, "%s", new_str_maclist);
    MUTEX_UNLOCK(csi_info->maclist_lock);
    if (csi_info->sta_maclist_sched_id == 0) {
        scheduler_add_timer_task(apps->ctrl->sched, FALSE, &csi_info->sta_maclist_sched_id,
            run_bus_csi_sta_maclist, apps, (CSI_STA_MACLIST_SET_SEC * 1000), 1, FALSE);
        wifi_util_info_print(WIFI_APPS, "[%s] set sta maclist:%s timer started\r\n", __func__,
            csi_info->sta_mac);
    }
}

static int webconfig_hal_csi_data_apply(wifi_app_t *apps, webconfig_subdoc_decoded_data_t *data)
{
    queue_t *new_config;
    new_config = data->csi_data_queue;
    uint32_t index = 0, s_index = 0, total_session;
    csi_data_t *new_csi_data;
    csi_analytics_info_t *csi_info = &apps->data.u.csi_analytics;
    mac_addr_str_t mac_str;
    char total_str_mac[MAX_MACLIST_SIZE] = { 0 };

    // check new configuration of csi clients
    wifi_util_dbg_print(WIFI_APPS, "%s webconfig csi config:%p\r\n", __func__, new_config);
    if (new_config == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s webconfig csi config is NULL\r\n", __func__);
        return RETURN_ERR;
    }

    total_session = queue_count(new_config);
    for (index = 0; index < total_session; index++) {
        new_csi_data = (csi_data_t *)queue_peek(new_config, index);
        if (new_csi_data != NULL) {
            if (new_csi_data->csi_session_num == csi_info->csi_session_index) {
                wifi_util_dbg_print(WIFI_APPS,
                    "%s:%d csi own session index:%d"
                    " index:%d\n",
                    __func__, __LINE__, csi_info->csi_session_index, index);
            } else if (new_csi_data->enabled == false) {
                wifi_util_dbg_print(WIFI_APPS,
                    "%s:%d csi not enabled for"
                    " session index:%d\n",
                    __func__, __LINE__, new_csi_data->csi_session_num);
            } else {
                for (s_index = 0; s_index < new_csi_data->csi_client_count; s_index++) {
                    memset(mac_str, 0, MAX_MAC_STR_SIZE);
                    to_mac_str(new_csi_data->csi_client_list[s_index], mac_str);
                    if (add_str_mac_addr(total_str_mac, mac_str) != RETURN_OK) {
                        break;
                    }
                }
            }
        }
    }

    update_mac_list(apps, total_str_mac);

    return RETURN_OK;
}

static int webconfig_set_data_event(wifi_app_t *apps, void *arg, wifi_event_subtype_t sub_type)
{
    webconfig_subdoc_data_t *doc = (webconfig_subdoc_data_t *)arg;
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;

    decoded_params = &doc->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d csi Analytics Decoded data"
            " is NULL\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    switch (doc->type) {
    case webconfig_subdoc_type_csi:
        webconfig_hal_csi_data_apply(apps, decoded_params);
        break;
    default:
        break;
    }

    return RETURN_OK;
}

int csi_analytics_webconfig_events(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *data)
{
    switch (sub_type) {
    case wifi_event_webconfig_set_data:
    case wifi_event_webconfig_set_data_dml:
        webconfig_set_data_event(apps, data, sub_type);
        break;
    default:
        break;
    }
    return RETURN_OK;
}

int csi_analytics_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
    case wifi_event_type_webconfig:
        csi_analytics_webconfig_events(app, event->sub_type, event->u.webconfig_data);
    default:
        break;
    }
    return RETURN_OK;
}

bus_error_t set_bus_csi_sub_enable_status(bus_handle_t *bus_handle, uint32_t csi_session_index,
    bool status)
{
    raw_data_t data;
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    bus_error_t rc = bus_error_success;
    char name[BUS_MAX_NAME_LENGTH] = { 0 };

    memset(&data, 0, sizeof(raw_data_t));
    data.data_type = bus_data_type_boolean;
    data.raw_data.b = status;
    data.raw_data_len = sizeof(status);

    snprintf(name, BUS_MAX_NAME_LENGTH, CSI_ENABLE_NAME, csi_session_index);

    rc = bus_desc->bus_set_fn(bus_handle, name, &data);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "bus: bus_set_fn error:%d name:%s value:%d\n", rc, name,
            status);
    } else {
        wifi_util_info_print(WIFI_APPS, "bus: set csi enable for %s state:%d\n", name, status);
    }
    return rc;
}

static int run_bus_csi_enable_status(void *arg)
{
    wifi_app_t *p_app = (wifi_app_t *)arg;
    csi_analytics_info_t *csi_info = &p_app->data.u.csi_analytics;

    wifi_util_info_print(WIFI_APPS, "%s:%d csi analytics enable status:%d\r\n", __func__, __LINE__,
        csi_info->is_csi_capture_enabled);
    set_bus_csi_sub_enable_status(&p_app->handle, csi_info->csi_session_index,
        csi_info->is_csi_capture_enabled);
    csi_info->csi_analytics_enable_sched_id = 0;

    return TIMER_TASK_COMPLETE;
}

void run_csi_enable_timer(wifi_app_t *p_app, bool status)
{
    csi_analytics_info_t *csi_info = &p_app->data.u.csi_analytics;

    csi_info->is_csi_capture_enabled = status;
    if (csi_info->csi_analytics_enable_sched_id == 0) {
        scheduler_add_timer_task(p_app->ctrl->sched, FALSE,
            &csi_info->csi_analytics_enable_sched_id, run_bus_csi_enable_status, p_app,
            (CSI_ENABLE_TRIGGER_SEC * 1000), 1, FALSE);
        wifi_util_info_print(WIFI_APPS,
            "%s:%d csi analytics enable"
            " bus timer started\n",
            __func__, __LINE__);
    }
}

static void do_nothing_handler(char *event_name, raw_data_t *p_data, void *userData)
{
    UNREFERENCED_PARAMETER(event_name);
    UNREFERENCED_PARAMETER(p_data);
    UNREFERENCED_PARAMETER(userData);
}

static void clean_all_csi_analytics_data(wifi_app_t *p_app)
{
    csi_analytics_info_t *p_info = &p_app->data.u.csi_analytics;
    bus_error_t rc = bus_error_success;
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();

    set_bus_csi_sub_enable_status(&p_app->handle, p_info->csi_session_index, false);
    wifi_util_info_print(WIFI_APPS, "deinit all analytics parameters\r\n");

    if (p_info->csi_session_index > 0) {
        bus_name_string_t name = { 0 };

        snprintf(name, BUS_MAX_NAME_LENGTH, CSI_SUB_DATA, p_info->csi_session_index);
        bus_desc->bus_event_unsubs_fn(&p_app->handle, name);

        snprintf(name, BUS_MAX_NAME_LENGTH, "Device.WiFi.X_RDK_CSI.%d.", p_info->csi_session_index);
        wifi_util_info_print(WIFI_APPS, "Remove %s\r\n", name);
        bus_desc->bus_remove_table_row_fn(&p_app->handle, name);
        if (p_info->pipe_read_fd > 0) {
            close(p_info->pipe_read_fd);
        }
    }

    rc = bus_desc->bus_close_fn(&p_app->handle);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Unable to close bus handle:%d\n", __func__,
            __LINE__, rc);
    }

    MUTEX_LOCK(p_info->maclist_lock);
    memset(p_info->sta_mac, 0, MAX_MACLIST_SIZE);
    MUTEX_UNLOCK(p_info->maclist_lock);

    DEINIT_MUTEX_PARAM(p_info->maclist_lock);
    p_info->csi_session_index = 0;
    p_info->is_read_oper_thread_enabled = false;
}

int csi_analytics_deinit(wifi_app_t *app)
{
    if (app == NULL) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d: app obj is NULL"
            " for Csi Analytics\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }
    app_deinit(app, app->desc.create_flag);

    hash_map_destroy(app->data.u.csi_analytics.csi_analytics_map);
    app->data.u.csi_analytics.csi_analytics_map = NULL;
    clean_all_csi_analytics_data(app);
    wifi_util_info_print(WIFI_APPS, "%s:%d:Deinit Csi Analytics App\n", __func__, __LINE__);
    return RETURN_OK;
}

int decode_csi_pipe_msg(uint8_t *data_ptr, wifi_csi_dev_t *p_csi_dev)
{
    // ASCII characters "CSI"
    data_ptr = data_ptr + 4;

    // Total length:  <length of this entire data field as an unsigned int>
    data_ptr = data_ptr + sizeof(unsigned int);

    // DataTimeStamp:  <date-time, number of seconds since the Epoch>
    data_ptr = data_ptr + sizeof(time_t);

    // NumberOfClients:  <unsigned int number of client devices>
    data_ptr = data_ptr + sizeof(unsigned int);

    // clientMacAddress:  <client mac address>
    memcpy(&p_csi_dev->sta_mac, data_ptr, sizeof(mac_address_t));
    data_ptr = data_ptr + sizeof(mac_address_t);

    // length of client CSI data:  <size of the next field in bytes>
    data_ptr = data_ptr + sizeof(unsigned int);

    //<client device CSI data>
    memcpy(&p_csi_dev->csi, data_ptr, sizeof(wifi_csi_data_t));

    return RETURN_OK;
}

void *pipe_read_oper_thread_func(void *arg)
{
    wifi_app_t *p_app = (wifi_app_t *)arg;
    csi_analytics_info_t *p_info = &p_app->data.u.csi_analytics;
    int buffer_len = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t);
    char buffer[buffer_len];
    char fifo_path[64] = { 0 };

    snprintf(fifo_path, sizeof(fifo_path), "/tmp/csi_motion_pipe%d", p_info->csi_session_index);
    wifi_util_info_print(WIFI_APPS, "csi analytics file open path:%s\n", fifo_path);
    int pipe_read_fd = open(fifo_path, O_RDONLY);
    if (pipe_read_fd < 0) {
        wifi_util_error_print(WIFI_APPS, "Error openning fifo for session number %d %s\n",
            p_info->csi_session_index, strerror(errno));
        return NULL;
    }
    p_info->is_read_oper_thread_enabled = true;
    p_info->pipe_read_fd = pipe_read_fd;

    while (p_info->is_read_oper_thread_enabled) {
        memset(buffer, 0, sizeof(buffer));
        buffer_len = read(pipe_read_fd, buffer, sizeof(buffer));
        if (buffer_len == -1) {
            wifi_util_error_print(WIFI_APPS, "%s:%d Error:%s reading from pipe\n", __func__,
                __LINE__, strerror(errno));
            break;
        } else if (buffer_len == 0) {
            wifi_util_error_print(WIFI_APPS,
                "%s:%d Writer closed pipe. Exiting"
                " blocking reader.\n",
                __func__, __LINE__);
            break;
        } else {
            wifi_csi_dev_t csi_dev_data = { 0 };
            decode_csi_pipe_msg((uint8_t *)buffer, &csi_dev_data);
            process_csi_analytics_data(p_app, &csi_dev_data);
        }
    }

    if (p_info->is_read_oper_thread_enabled) {
        clean_all_csi_analytics_data(p_app);
    }
    return NULL;
}

bus_error_t csi_analytics_bus_subscription(bus_handle_t *bus_handle, bus_event_sub_t *bus_event,
    uint32_t size)
{
    bus_error_t rc;
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();

    rc = bus_desc->bus_event_subs_ex_fn(bus_handle, bus_event, size, 0);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d busEvent:%s Subscribe failed:%d\n", __func__,
            __LINE__, bus_event->event_name, rc);
        bus_desc->bus_event_unsubs_fn(bus_handle, bus_event->event_name);
        rc = bus_desc->bus_close_fn(bus_handle);
        if (rc != bus_error_success) {
            wifi_util_error_print(WIFI_APPS, "%s:%d: Unable to close bus handle\n", __func__,
                __LINE__);
            return rc;
        }
    } else {
        wifi_util_info_print(WIFI_APPS, "%s:%d bus: bus event:%s subscribe success\n", __func__,
            __LINE__, bus_event->event_name);
    }

    return rc;
}

bus_error_t init_bus_subscription(bus_handle_t *bus_handle, wifi_app_t *p_app)
{
    char *component_name = "CsiAnanlytics";
    bus_error_t rc;
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    csi_analytics_info_t *p_info = &p_app->data.u.csi_analytics;

    rc = bus_desc->bus_open_fn(bus_handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d bus_open failed: %d\n", __func__, __LINE__, rc);
        return rc;
    }

    if (p_info->csi_session_index == 0) {
        uint32_t csi_index = 0;
        bus_name_string_t name = { 0 };

        rc = bus_desc->bus_add_table_row_fn(bus_handle, "Device.WiFi.X_RDK_CSI.", NULL, &csi_index);
        if (rc != bus_error_success) {
            wifi_util_error_print(WIFI_APPS, "%s:%d Failed to add CSI\n", __func__, __LINE__);
            rc = bus_desc->bus_close_fn(bus_handle);
            if (rc != bus_error_success) {
                wifi_util_error_print(WIFI_APPS,
                    "%s:%d: Unable to close"
                    " bus handle\n",
                    __func__, __LINE__);
            }
            return rc;
        }
        wifi_util_info_print(WIFI_APPS, "%s:%d CSI session:%d added\n", __func__, __LINE__,
            csi_index);

        bus_event_sub_t bus_events[] = {
            /* Event Name, filter, interval, duration, handler, user data, handle */
            { CSI_SUB_DATA, NULL, CSI_ANALYTICS_INTERVAL, 0, do_nothing_handler, NULL, NULL, NULL,
             false }
        };

        snprintf(name, BUS_MAX_NAME_LENGTH, bus_events[0].event_name, csi_index);
        bus_events[0].event_name = (char const *)name;
        rc = csi_analytics_bus_subscription(bus_handle, &bus_events[0], 1);
        if (rc != bus_error_success) {
            return rc;
        }

        p_info->csi_session_index = csi_index;
        run_csi_enable_timer(p_app, true);
    }

    return rc;
}

int open_csi_data_connection(wifi_app_t *p_app)
{
    ssize_t stack_size = 0x800000; /* 8MB */
    pthread_attr_t attr;
    pthread_attr_t *attrp = NULL;
    pthread_t pid;
    int ret = 0;

    attrp = &attr;
    pthread_attr_init(&attr);
    ret = pthread_attr_setstacksize(&attr, stack_size);
    if (ret != 0) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d pthread_attr_setstacksize failed for size:%ld ret:%d\n", __func__, __LINE__,
            stack_size, ret);
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&pid, attrp, pipe_read_oper_thread_func, p_app) != 0) {
        wifi_util_error_print(WIFI_APPS, ":%s async method invoke thread create error\n", __func__);
        if (attrp != NULL) {
            pthread_attr_destroy(attrp);
        }
        return RETURN_ERR;
    }

    if (attrp != NULL) {
        pthread_attr_destroy(attrp);
    }

    return RETURN_OK;
}

int csi_analytics_init(wifi_app_t *app, unsigned int create_flag)
{
    if (app == NULL) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d: app obj is NULL"
            " for Csi Analytics\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }

    INIT_MUTEX_PARAM(app->data.u.csi_analytics.maclist_lock);
    if (init_bus_subscription(&app->handle, app) != RETURN_OK) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d: init bus subscription falied"
            " for Csi Analytics\n",
            __func__, __LINE__);
        goto init_error;
    }

    if (open_csi_data_connection(app) != RETURN_OK) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d: init bus subscription falied"
            " for Csi Analytics\n",
            __func__, __LINE__);
        goto init_error;
    }

    app->data.u.csi_analytics.csi_analytics_map = hash_map_create();
    if (app->data.u.csi_analytics.csi_analytics_map == NULL) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d: hash_map Init failure"
            " for Csi Analytics\n",
            __func__, __LINE__);
        goto init_error;
    }

    if (app_init(app, create_flag) != 0) {
        goto init_error;
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d: Init Csi Analytics App\n", __func__, __LINE__);
    return RETURN_OK;
init_error:
    DEINIT_MUTEX_PARAM(app->data.u.csi_analytics.maclist_lock);
    return RETURN_ERR;
}

int csi_analytics_update(wifi_app_t *app)
{
    if (app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    // Only handling RFC as of NOW
    if (app->desc.inst != wifi_app_inst_csi_analytics) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Unknown app:%x instance\n", __func__, __LINE__,
            app->desc.inst);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: RFC state:%d enable:%d\n", __func__, __LINE__,
        app->desc.rfc, app->desc.enable);
    if (app->desc.enable != app->desc.rfc) {
        app->desc.enable = app->desc.rfc;
        if (app->desc.enable) {
            csi_analytics_init(app, app->desc.create_flag);
        } else {
            csi_analytics_deinit(app);
        }
    }
    return 0;
}
#endif
