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

#ifndef CSIMGR_H
#define CSIMGR_H

#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include "cJSON.h"
#include "bus.h"
#include "collection.h"
#include "common_web_gui.h"
#include "common_defs.h"
#include "vector.h"
#include "matrix.h"
#include "wifi_csi.h"
#include "wifi_hal.h"
#include "sounder.h"
#include "web.h"

#define CSI_MOTION_CORE_INTERVAL 100
#define MAX_STA_MACLIST_SIZE 512
#define MAX_STA_MAC_STR_SIZE 18

class csimgr_t {
    bool               m_exit;
    pthread_mutex_t    m_lock;
    pthread_cond_t     m_cond;
    queue_t           *m_queue;
    hash_map_t        *m_sounders_map;

    unsigned int       m_sampling;
    motion_test_params_t m_test_params;

    int                m_remaining;
    unsigned int       m_iters;

    char               m_output_file[PATH_NAME_SZ];
    char               m_storage_dir[PATH_NAME_SZ];
    cJSON             *m_out_obj;

    // ------------------------------------------------------------------
    // Motion core (CSI bus / pipe reader) state  –  private
    // ------------------------------------------------------------------
    bus_handle_t       m_handle;
    uint32_t           m_csi_session_index;
    uint32_t           m_motion_interval_in_ms;
    int32_t            m_pipe_read_fd;
    bool               m_pipe_thread_running;
    bool               m_motion_enabled;
    char               m_sta_mac_list[MAX_STA_MACLIST_SIZE];
    mac_addr_str_t     m_gw_mac_str;

    // ------------------------------------------------------------------
    // Motion core private methods
    // ------------------------------------------------------------------
    static void   remove_mac_colon(char *mac_str);
    void          process_csi_raw_data(wifi_csi_dev_t *csi_dev_data);
    bool          decode_csi_pipe_msg_info(const uint8_t *data,
                                           wifi_csi_dev_t &out_dev);
    void          deinit_motion_core();
    void         *pipe_read_loop();
    bus_error_t   trigger_bus_event_sub(bus_event_sub_t *bus_event,
                                        uint32_t size);
    bus_error_t   set_sta_maclist(const char *mac_list);
    bus_error_t   set_bool_bus_value(const char *event_name, bool status);
    bus_error_t   set_csi_enable_status(bool status);
    bus_error_t   subscribe_csi_data(uint32_t csi_index,
                                     uint32_t csi_interval);
    bus_error_t   init_bus();
    int           open_csi_conn();

    // Static C-style callbacks (pthread / bus)
    static void  *pipe_thread_entry(void *arg);
    static void   do_nothing_handler(char *event_name, raw_data_t *p_data,
                                     void *userData);

public:
    // ------------------------------------------------------------------
    // CSI manager public interface
    // ------------------------------------------------------------------
    int  init();
    void deinit();
    int  run();

    void push(web_event_t *evt) {
        pthread_mutex_lock(&m_lock);
        queue_push(m_queue, evt);
        pthread_cond_signal(&m_cond);
        pthread_mutex_unlock(&m_lock);
    }

    int  read_test_object(cJSON *obj);
    int  read_gesture_object(cJSON *obj);
    int  read_capture_object(cJSON *obj);
    int  handle_result_object(cJSON *obj);
    struct timespec *get_periodicity(struct timespec *time_to_wait);
    void periodicity_handler(struct timespec **t_wait);

    void create_output_template();
    void update_graph(sounder_t *sd);
    void dump_json(cJSON *obj);

    hash_map_t *get_sounders_map() const { return m_sounders_map; }

    // ------------------------------------------------------------------
    // Motion core public interface
    // ------------------------------------------------------------------
    int  motion_init();
    void set_cal_duration(uint32_t duration_sec);

    // ------------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------------
    static char *get_local_time(char *buff, unsigned int len);

    explicit csimgr_t(const char *path);
    csimgr_t();
    ~csimgr_t();
};

#endif // CSIMGR_H
