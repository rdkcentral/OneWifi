#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include "wifi_base.h"
#include "motion_core.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"
#include <rbus/rbus.h>

motion_core_param_t g_motion_core_cfg;

motion_core_param_t *get_motion_core_param(void)
{
    return &g_motion_core_cfg;
}

void remove_mac_colon(char *mac_str)
{   
    unsigned int mac[6] = { 0 };
    
    sscanf(mac_str, "%2x:%2x:%2x:%2x:%2x:%2x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    
    snprintf(mac_str, MAX_MAC_STR_SIZE, "%02X%02X%02X%02X%02X%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void get_gw_str_mac(char *str_gw_mac)
{
    get_cm_mac_address(str_gw_mac);
    remove_mac_colon(str_gw_mac);
}

void set_cal_duration_for_each_clients(uint32_t duration_sec)
{   
    motion_core_param_t *p_cfg = (motion_core_param_t *)get_motion_core_param();
    uint32_t cal_packets = ((duration_sec * 1000) / CSI_MOTION_CORE_INTERVAL);
    motion_whitelist_info_t *p_sta_info;
    
    p_sta_info = (motion_whitelist_info_t *)hash_map_get_first(p_cfg->motion_sta_map);
    while (p_sta_info != NULL) {
        //we need to add lock for this variable protection
        p_sta_info->cal_packets_cnt = cal_packets;
        wifi_util_info_print(WIFI_MGR,"%s:%d number of packet:%d calibration"
            "configure for sta:%s\r\n", __func__, __LINE__,
            cal_packets, p_sta_info->sta_mac);
        p_sta_info = hash_map_get_next(p_cfg->motion_sta_map, p_sta_info);
    }
}

static void do_nothing_handler(char *event_name, raw_data_t *p_data, void *userData)
{
    UNREFERENCED_PARAMETER(event_name);
    UNREFERENCED_PARAMETER(p_data);
    UNREFERENCED_PARAMETER(userData);
}

motion_whitelist_info_t *create_new_motion_sta_info(hash_map_t *motion_sta_map,
    bool enable_status, char *key)
{
    motion_whitelist_info_t *motion_sta_info;
    motion_sta_info = calloc(1, sizeof(motion_whitelist_info_t));
    if (motion_sta_info == NULL) {
        return NULL;
    }
    motion_sta_info->sta_mac = strdup(key);
    motion_sta_info->enable_status = enable_status;

    motion_sta_info->cal_packets_cnt = 1200;

    hash_map_put(motion_sta_map, motion_sta_info->sta_mac, motion_sta_info);
    wifi_util_info_print(WIFI_MGR, "%s:%d: new sta:%s added to motion table\n", __func__, __LINE__, motion_sta_info->sta_mac);

    return motion_sta_info;
}

void process_csi_raw_data(motion_core_param_t *p_cfg, wifi_csi_dev_t *csi_dev_data)
{
    uint8_t *p_mac = csi_dev_data->sta_mac;
    mac_addr_str_t mac_str = { 0 };
    motion_whitelist_info_t *p_sta_info;

    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
            p_mac[0], p_mac[1], p_mac[2], p_mac[3], p_mac[4], p_mac[5]);

    p_sta_info = hash_map_get(p_cfg->motion_sta_map, mac_str);
    if (p_sta_info == NULL) {
        wifi_util_dbg_print(WIFI_MGR, "%s:%d sta:%s info not found\r\n", __func__,
            __LINE__, mac_str);
        p_sta_info = (motion_whitelist_info_t *)create_new_motion_sta_info(p_cfg->motion_sta_map,
                    true, mac_str);
        if (p_sta_info == NULL) {
            wifi_util_error_print(WIFI_MGR, "%s:%d sta:%s info not created\r\n", __func__,
                __LINE__, mac_str);
            return;
        }
        p_sta_info->sounder_obj = create_sounder(p_mac);
    }

    process_csi_motion_data(p_sta_info->sounder_obj, &csi_dev_data->csi, 0);
}

int decode_csi_pipe_msg_info(uint8_t *data_ptr, wifi_csi_dev_t *p_csi_dev)
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

static void clean_all_motion_core_data(motion_core_param_t *p_cfg)
{
    bus_error_t rc = bus_error_success;
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();

    set_bus_csi_sub_enable_status(&p_cfg->handle, p_cfg->csi_session_index, false);
    wifi_util_info_print(WIFI_MGR, "deinit all motion core parameters\r\n");

    if (p_cfg->csi_session_index > 0) {
        bus_name_string_t name = { 0 };

        snprintf(name, BUS_MAX_NAME_LENGTH, CSI_SUB_DATA, p_cfg->csi_session_index);
        bus_desc->bus_event_unsubs_fn(&p_cfg->handle, name);

        snprintf(name, BUS_MAX_NAME_LENGTH, "Device.WiFi.X_RDK_CSI.%d.", p_cfg->csi_session_index);
        wifi_util_info_print(WIFI_MGR, "Remove %s\r\n", name);
        bus_desc->bus_remove_table_row_fn(&p_cfg->handle, name);
        if (p_cfg->s_conn_info.pipe_read_fd > 0) {
            close(p_cfg->s_conn_info.pipe_read_fd);
        }
    }

    rc = bus_desc->bus_close_fn(&p_cfg->handle);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR, "%s:%d: Unable to close bus handle:%d\n", __func__,
            __LINE__, rc);
    }

    p_cfg->csi_session_index = 0;
    p_cfg->s_conn_info.is_read_oper_thread_enabled = false;

    //deinit_tensor_and_inference_param();
}

void *pipe_read_thread_func(void *arg)
{
    motion_core_param_t *p_motion_core_cfg = (motion_core_param_t *)arg;
    session_conn_info_t *p_conn_info = &p_motion_core_cfg->s_conn_info;

    int buffer_len = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t);
    char buffer[buffer_len];
    char fifo_path[64] = { 0 };

    snprintf(fifo_path, sizeof(fifo_path), "/tmp/csi_motion_pipe%d", p_motion_core_cfg->csi_session_index);
    wifi_util_info_print(WIFI_MGR, "motion core file open path:%s\n", fifo_path);
    int pipe_read_fd = open(fifo_path, O_RDONLY);
    if (pipe_read_fd < 0) {
        wifi_util_error_print(WIFI_MGR, "Error openning fifo for session number %d %s\n",
            p_motion_core_cfg->csi_session_index, strerror(errno));
        return NULL;
    }
    p_conn_info->is_read_oper_thread_enabled = true;
    p_conn_info->pipe_read_fd = pipe_read_fd;

    while (p_conn_info->is_read_oper_thread_enabled) {
        memset(buffer, 0, sizeof(buffer));
        buffer_len = read(pipe_read_fd, buffer, sizeof(buffer));
        if (buffer_len == -1) {
            wifi_util_error_print(WIFI_MGR, "%s:%d Error:%s reading from pipe\n", __func__,
                __LINE__, strerror(errno));
            break;
        } else if (buffer_len == 0) {
            wifi_util_error_print(WIFI_MGR,
                "%s:%d Writer closed pipe. Exiting"
                " blocking reader.\n",
                __func__, __LINE__);
            break;
        } else {
            wifi_csi_dev_t csi_dev_data = { 0 };
            decode_csi_pipe_msg_info((uint8_t *)buffer, &csi_dev_data);
            process_csi_raw_data(p_motion_core_cfg, &csi_dev_data);
        }
    }

    if (p_conn_info->is_read_oper_thread_enabled) {
        clean_all_motion_core_data(p_motion_core_cfg);
    }
    return NULL;
}

bus_error_t bus_sub_event_trigger(bus_handle_t *bus_handle, bus_event_sub_t *bus_event,
    uint32_t size)
{
    bus_error_t rc;
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();

    rc = bus_desc->bus_event_subs_ex_fn(bus_handle, bus_event, size, 0);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR, "%s:%d busEvent:%s Subscribe failed:%d\n", __func__,
            __LINE__, bus_event->event_name, rc);
        bus_desc->bus_event_unsubs_fn(bus_handle, bus_event->event_name);
        rc = bus_desc->bus_close_fn(bus_handle);
        if (rc != bus_error_success) {
            wifi_util_error_print(WIFI_MGR, "%s:%d: Unable to close bus handle\n", __func__,
                __LINE__);
            return rc;
        }
    } else {
        wifi_util_info_print(WIFI_MGR, "%s:%d bus: bus event:%s subscribe success\n", __func__,
            __LINE__, bus_event->event_name);
    }

    return rc;
}

int set_motion_core_sta_maclist(bus_handle_t *bus_handle, uint32_t csi_session_index, char *mac_list)
{
    char name[BUS_MAX_NAME_LENGTH] = { 0 };
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    bus_error_t rc = bus_error_success;

    snprintf(name, BUS_MAX_NAME_LENGTH, CSI_CLIENT_MACLIST, csi_session_index);

    rc = bus_desc->bus_set_string_fn(bus_handle, name, mac_list);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR, "%s:%d: bus:%s bus set string:%s Failed %d\n", __func__,
            __LINE__, name, mac_list, rc);
        return RETURN_ERR;
    } else {
        wifi_util_info_print(WIFI_MGR, "%s:%d: bus:%s bus set string:%s success\n", __func__,
            __LINE__, name, mac_list);
    }

    return rc;
}

bus_error_t bus_set_bool_value(bus_handle_t *bus_handle, char *event_name, bool status)
{
    raw_data_t data;
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    bus_error_t rc = bus_error_success;

    memset(&data, 0, sizeof(raw_data_t));
    data.data_type = bus_data_type_boolean;
    data.raw_data.b = status;
    data.raw_data_len = sizeof(status);

    rc = bus_desc->bus_set_fn(bus_handle, event_name, &data);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR, "%s:%d bus: bus_set_fn error:%d event_name:%s value:%d\n",
            __func__, __LINE__, rc, event_name, status);
    } else {
        wifi_util_info_print(WIFI_MGR, "%s:%d bus: set for:%s state:%d\n", __func__,
            __LINE__, event_name, status);
    }

    return rc;
}

bus_error_t set_motion_core_enable_status(bus_handle_t *bus_handle, uint32_t csi_session_index,
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
        wifi_util_error_print(WIFI_MGR, "bus: bus_set_fn error:%d name:%s value:%d\n", rc, name,
            status);
    } else {
        wifi_util_info_print(WIFI_MGR, "bus: set csi enable for %s state:%d\n", name, status);
    }

    return rc;
}

bus_error_t subscribe_csi_motion_data(motion_core_param_t *p_cfg, uint32_t csi_index, uint32_t csi_interval)
{
    bus_name_string_t name = { 0 };
    bus_error_t rc;
    bus_event_sub_t bus_events[] = {
        /* Event Name, filter, interval, duration, handler, user data, handle */
        { CSI_SUB_DATA, NULL, csi_interval, 0, do_nothing_handler, NULL, NULL, NULL,
         false }
    };

    snprintf(name, BUS_MAX_NAME_LENGTH, bus_events[0].event_name, csi_index);
    bus_events[0].event_name = (char const *)name;
    rc = bus_sub_event_trigger(&p_cfg->handle, &bus_events[0], 1);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR, "%s:%d bus_sub_event_trigger failed:%d\n", __func__, __LINE__, rc);
        return rc;
    }

    p_cfg->motion_interval_in_ms = csi_interval;

    return rc;
}

bus_error_t init_bus_for_motion_core(motion_core_param_t *p_cfg)
{
    char *component_name = "MotionCore";
    bus_error_t rc;
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();

    rc = bus_desc->bus_open_fn(&p_cfg->handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR, "%s:%d bus_open failed: %d\n", __func__, __LINE__, rc);
        return rc;
    }

    if (p_cfg->csi_session_index == 0) {
        uint32_t csi_index = 0;

        rc = bus_desc->bus_add_table_row_fn(&p_cfg->handle, "Device.WiFi.X_RDK_CSI.", NULL, &csi_index);
        if (rc != bus_error_success) {
            wifi_util_error_print(WIFI_MGR, "%s:%d Failed to add CSI\n", __func__, __LINE__);
            rc = bus_desc->bus_close_fn(&p_cfg->handle);
            if (rc != bus_error_success) {
                wifi_util_error_print(WIFI_MGR,
                    "%s:%d: Unable to close"
                    " bus handle\n",
                    __func__, __LINE__);
            }
            return rc;
        }
        wifi_util_info_print(WIFI_MGR, "%s:%d CSI session:%d added\n", __func__, __LINE__,
            csi_index);

        subscribe_csi_motion_data(p_cfg, csi_index, CSI_MOTION_CORE_INTERVAL);

	p_cfg->csi_session_index = csi_index;
    }

    return rc;
}

int open_csi_raw_data_conn(motion_core_param_t *p_motion_core_cfg)
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
        wifi_util_error_print(WIFI_MGR,
            "%s:%d pthread_attr_setstacksize failed for size:%ld ret:%d\n", __func__, __LINE__,
            stack_size, ret);
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&pid, attrp, pipe_read_thread_func, p_motion_core_cfg) != 0) {
        wifi_util_error_print(WIFI_MGR, ":%s async method invoke thread create error\n", __func__);
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

int motion_core_init(wifi_ctrl_t *ctrl)
{
    motion_core_param_t *p_cfg = get_motion_core_param();
    int ret;

    p_cfg->ctrl = ctrl;

    wifi_util_info_print(WIFI_MGR, "%s:%d wifi tflite motion app will start\n", __func__, __LINE__);
    get_gw_str_mac(p_cfg->gw_mac_str);

    ret = init_bus_for_motion_core(p_cfg);
    if (ret != bus_error_success) {
        return ret;
    }

    ret = open_csi_raw_data_conn(p_cfg);
    p_cfg->motion_sta_map = hash_map_create();
    wifi_util_info_print(WIFI_MGR, "%s:%d wifi tflite motion app started\n", __func__, __LINE__);

    return ret;
}
