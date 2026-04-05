/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

#include "csimgr.h"
#include "wifi_base.h"
#include "wifi_util.h"
#include "common_web_gui.h"
#include "bus.h"
#include "wifi_csi_analytics.h"

// ============================================================
// Static helpers / callbacks
// ============================================================

/*static*/
void csimgr_t::remove_mac_colon(char *mac_str)
{
    unsigned int mac[6] = {};
    sscanf(mac_str, "%2x:%2x:%2x:%2x:%2x:%2x",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    snprintf(mac_str, MAX_STA_MAC_STR_SIZE, "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*static*/
void csimgr_t::do_nothing_handler(char *event_name, raw_data_t *p_data, void *userData)
{
    // intentionally empty — suppresses CSI data delivery to this component
}

/*static*/
void *csimgr_t::pipe_thread_entry(void *arg)
{
    return static_cast<csimgr_t *>(arg)->pipe_read_loop();
}

// ============================================================
// Motion core — public methods
// ============================================================

int csimgr_t::motion_init()
{
    wifi_util_info_print(WIFI_MGR, "%s:%d wifi motion app starting\n",
                         __func__, __LINE__);

    get_cm_mac_address(m_gw_mac_str);
    remove_mac_colon(m_gw_mac_str);

    bus_error_t rc = init_bus();
    if (rc != bus_error_success) {
        return static_cast<int>(rc);
    }

    open_csi_conn();

    wifi_util_info_print(WIFI_MGR, "%s:%d wifi motion app started\n",
                         __func__, __LINE__);
    return RETURN_OK;
}

void csimgr_t::set_cal_duration(uint32_t duration_sec)
{
    const uint32_t cal_packets =
        (duration_sec * 1000u) / CSI_MOTION_CORE_INTERVAL;

    sounder_t *sd =
        static_cast<sounder_t *>(hash_map_get_first(m_sounders_map));
    while (sd != nullptr) {
        sd->set_cal_packets_cnt(cal_packets);
        wifi_util_info_print(WIFI_MGR,
            "%s:%d cal_packets:%u configured for sta:%s\r\n",
            __func__, __LINE__, cal_packets, sd->get_mac_str());
        sd = static_cast<sounder_t *>(
                 hash_map_get_next(m_sounders_map, sd));
    }
}

// ============================================================
// Motion core — private methods
// ============================================================

void csimgr_t::process_csi_raw_data(wifi_csi_dev_t *csi_dev_data)
{
    const uint8_t *p_mac = csi_dev_data->sta_mac;
    mac_addr_str_t  mac_str = {};

    snprintf(mac_str, sizeof(mac_str),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             p_mac[0], p_mac[1], p_mac[2],
             p_mac[3], p_mac[4], p_mac[5]);

    sounder_t *sd =
        static_cast<sounder_t *>(hash_map_get(m_sounders_map, mac_str));

    if (sd == nullptr) {
        wifi_util_dbg_print(WIFI_MGR,
            "%s:%d sta:%s not found, creating entry\r\n",
            __func__, __LINE__, mac_str);

        sd = get_or_create_sounder_from_map(m_sounders_map, mac_str,
            csi_dev_data->sta_mac);
        if (sd == nullptr) {
            wifi_util_error_print(WIFI_MGR,
                "%s:%d sta:%s entry could not be created\r\n",
                __func__, __LINE__, mac_str);
            return;
        }

        sd->set_enable_status(true);
        sd->set_cal_packets_cnt(1200);
        sd->set_last_motion_detected_time(0.0);
        wifi_util_info_print(WIFI_MGR,
            "%s:%d sta:%s added to sounder table\n",
            __func__, __LINE__, sd->get_mac_str());
    }

    process_csi_motion_data(sd, csi_dev_data, 0);
}

bool csimgr_t::decode_csi_pipe_msg_info(const uint8_t *data,
                                         wifi_csi_dev_t &out_dev)
{
    const uint8_t *p = data;
    p += 4;                          // ASCII tag "CSI\0"
    p += sizeof(unsigned int);       // total packet length
    p += sizeof(time_t);             // date-time timestamp
    p += sizeof(unsigned int);       // number of client devices

    memcpy(&out_dev.sta_mac, p, sizeof(mac_address_t));
    p += sizeof(mac_address_t);
    p += sizeof(unsigned int);       // length of CSI data field

    memcpy(&out_dev.csi, p, sizeof(wifi_csi_data_t));
    return true;
}

void csimgr_t::deinit_motion_core()
{
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();

    set_csi_enable_status(false);
    wifi_util_info_print(WIFI_MGR, "deinit motion core\r\n");

    if (m_csi_session_index > 0) {
        bus_name_string_t name = {};

        snprintf(name, BUS_MAX_NAME_LENGTH,
                 CSI_SUB_DATA, m_csi_session_index);
        bus_desc->bus_event_unsubs_fn(&m_handle, name);

        snprintf(name, BUS_MAX_NAME_LENGTH,
                 "Device.WiFi.X_RDK_CSI.%u.", m_csi_session_index);
        wifi_util_info_print(WIFI_MGR, "Remove %s\r\n", name);
        bus_desc->bus_remove_table_row_fn(&m_handle, name);

        if (m_pipe_read_fd > 0) {
            close(m_pipe_read_fd);
        }
    }

    bus_error_t rc = bus_desc->bus_close_fn(&m_handle);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR,
            "%s:%d Unable to close bus handle: %d\n",
            __func__, __LINE__, rc);
    }

    m_csi_session_index    = 0;
    m_pipe_thread_running  = false;
}

void *csimgr_t::pipe_read_loop()
{
    constexpr size_t BUFFER_SZ = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t);
    char buffer[BUFFER_SZ];
    char fifo_path[64] = {};

    snprintf(fifo_path, sizeof(fifo_path),
             "/tmp/csi_motion_pipe%u", m_csi_session_index);
    wifi_util_info_print(WIFI_MGR, "opening pipe: %s\n", fifo_path);

    int fd = open(fifo_path, O_RDONLY);
    if (fd < 0) {
        wifi_util_error_print(WIFI_MGR,
            "Error opening fifo (session %u): %s\n",
            m_csi_session_index, strerror(errno));
        return nullptr;
    }

    m_pipe_thread_running = true;
    m_pipe_read_fd        = fd;

    while (m_pipe_thread_running) {
        memset(buffer, 0, sizeof(buffer));
        ssize_t n = read(fd, buffer, sizeof(buffer));

        if (n < 0) {
            wifi_util_error_print(WIFI_MGR,
                "%s:%d read error: %s\n",
                __func__, __LINE__, strerror(errno));
            break;
        }
        if (n == 0) {
            wifi_util_error_print(WIFI_MGR,
                "%s:%d writer closed pipe, exiting\n",
                __func__, __LINE__);
            break;
        }

        wifi_csi_dev_t csi_dev = {};
        decode_csi_pipe_msg_info(
            reinterpret_cast<const uint8_t *>(buffer), csi_dev);
        process_csi_raw_data(&csi_dev);
    }

    if (m_pipe_thread_running) {
        deinit_motion_core();
    }
    return nullptr;
}

bus_error_t csimgr_t::trigger_bus_event_sub(bus_event_sub_t *bus_event,
                                             uint32_t size)
{
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    bus_error_t rc =
        bus_desc->bus_event_subs_ex_fn(&m_handle, bus_event, size, 0);

    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR,
            "%s:%d bus event:%s subscribe failed: %d\n",
            __func__, __LINE__, bus_event->event_name, rc);
        bus_desc->bus_event_unsubs_fn(&m_handle, bus_event->event_name);
        bus_error_t close_rc = bus_desc->bus_close_fn(&m_handle);
        if (close_rc != bus_error_success) {
            wifi_util_error_print(WIFI_MGR,
                "%s:%d Unable to close bus handle\n",
                __func__, __LINE__);
        }
        return rc;
    }

    wifi_util_info_print(WIFI_MGR,
        "%s:%d bus event:%s subscribed\n",
        __func__, __LINE__, bus_event->event_name);
    return rc;
}

bus_error_t csimgr_t::set_sta_maclist(const char *mac_list)
{
    char name[BUS_MAX_NAME_LENGTH] = {};
    snprintf(name, sizeof(name), CSI_CLIENT_MACLIST, m_csi_session_index);

    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    bus_error_t rc =
        bus_desc->bus_set_string_fn(&m_handle, name, mac_list);

    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR,
            "%s:%d bus set_string %s=%s failed: %d\n",
            __func__, __LINE__, name, mac_list, rc);
    } else {
        wifi_util_info_print(WIFI_MGR,
            "%s:%d bus set_string %s=%s success\n",
            __func__, __LINE__, name, mac_list);
    }
    return rc;
}

bus_error_t csimgr_t::set_bool_bus_value(const char *event_name, bool status)
{
    raw_data_t data = {};
    data.data_type    = bus_data_type_boolean;
    data.raw_data.b   = status;
    data.raw_data_len = sizeof(status);

    wifi_bus_desc_t *bus_desc = get_bus_descriptor();
    bus_error_t rc =
        bus_desc->bus_set_fn(&m_handle, event_name, &data);

    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR,
            "%s:%d bus_set_fn error:%d name:%s value:%d\n",
            __func__, __LINE__, rc, event_name, status);
    } else {
        wifi_util_info_print(WIFI_MGR,
            "%s:%d bus set %s=%d\n",
            __func__, __LINE__, event_name, status);
    }
    return rc;
}

bus_error_t csimgr_t::set_csi_enable_status(bool status)
{
    char name[BUS_MAX_NAME_LENGTH] = {};
    snprintf(name, sizeof(name), CSI_ENABLE_NAME, m_csi_session_index);
    return set_bool_bus_value(name, status);
}

bus_error_t csimgr_t::subscribe_csi_data(uint32_t csi_index,
                                          uint32_t csi_interval)
{
    bus_name_string_t name = {};
    bus_event_sub_t bus_events[] = {
        { CSI_SUB_DATA, nullptr, csi_interval, 0,
          (void*)do_nothing_handler, nullptr, nullptr, nullptr, false }
    };

    snprintf(name, BUS_MAX_NAME_LENGTH,
             bus_events[0].event_name, csi_index);
    bus_events[0].event_name = static_cast<const char *>(name);

    bus_error_t rc = trigger_bus_event_sub(&bus_events[0], 1);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR,
            "%s:%d trigger_bus_event_sub failed: %d\n",
            __func__, __LINE__, rc);
        return rc;
    }

    m_motion_interval_in_ms = csi_interval;
    return rc;
}

bus_error_t csimgr_t::init_bus()
{
    char COMPONENT_NAME[] = "MotionCore";
    wifi_bus_desc_t *bus_desc = get_bus_descriptor();

    bus_error_t rc =
        bus_desc->bus_open_fn(&m_handle, COMPONENT_NAME);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_MGR,
            "%s:%d bus_open failed: %d\n", __func__, __LINE__, rc);
        return rc;
    }

    if (m_csi_session_index == 0) {
        uint32_t csi_index = 0;
        rc = bus_desc->bus_add_table_row_fn(
                 &m_handle, "Device.WiFi.X_RDK_CSI.", nullptr, &csi_index);
        if (rc != bus_error_success) {
            wifi_util_error_print(WIFI_MGR,
                "%s:%d Failed to add CSI table row\n",
                __func__, __LINE__);
            bus_error_t close_rc = bus_desc->bus_close_fn(&m_handle);
            if (close_rc != bus_error_success) {
                wifi_util_error_print(WIFI_MGR,
                    "%s:%d Unable to close bus handle\n",
                    __func__, __LINE__);
            }
            return rc;
        }

        wifi_util_info_print(WIFI_MGR,
            "%s:%d CSI session %u added\n",
            __func__, __LINE__, csi_index);

        subscribe_csi_data(csi_index, CSI_MOTION_CORE_INTERVAL);
        m_csi_session_index = csi_index;
    }

    return rc;
}

int csimgr_t::open_csi_conn()
{
    constexpr ssize_t STACK_SIZE = 0x800000; // 8 MB

    pthread_attr_t attr;
    pthread_t      tid;

    pthread_attr_init(&attr);
    int ret = pthread_attr_setstacksize(&attr, STACK_SIZE);
    if (ret != 0) {
        wifi_util_error_print(WIFI_MGR,
            "%s:%d pthread_attr_setstacksize failed size:%zd ret:%d\n",
            __func__, __LINE__, STACK_SIZE, ret);
    }
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&tid, &attr, pipe_thread_entry, this) != 0) {
        wifi_util_error_print(WIFI_MGR,
            "%s:%d pthread_create failed\n", __func__, __LINE__);
        pthread_attr_destroy(&attr);
        return RETURN_ERR;
    }

    pthread_attr_destroy(&attr);
    return RETURN_OK;
}

// ============================================================
// extern "C" bridge  –  called from C-compiled motion_cpp_wrapper.c
// ============================================================

extern "C" int motion_core_init(void)
{
    web_gui_obj_t *p_web = get_web_gui_obj();
    if (p_web == nullptr || p_web->gui_csi_mgr == nullptr) {
        wifi_util_error_print(WIFI_MGR,
            "%s:%d csimgr_t instance not initialised\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }
    return p_web->gui_csi_mgr->motion_init();
}

