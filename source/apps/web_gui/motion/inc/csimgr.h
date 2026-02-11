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

#include <pthread.h>
#include "cJSON.h"
#include "collection.h"
#include "common_defs.h"
#include "vector.h"
#include "matrix.h"
#include "wifi_hal.h"
#include "sounder.h"
#include "web.h"

class csimgr_t {
    bool m_exit;
    pthread_mutex_t m_lock;
    pthread_cond_t m_cond;
    queue_t *m_queue;
    hash_map_t *m_sounders_map;
    
    unsigned int m_sampling;
    motion_test_params_t    m_test_params;
    
    int m_remaining;
    unsigned int m_iters;
    
    char m_output_file[PATH_NAME_SZ];
    char m_storage_dir[PATH_NAME_SZ];
    cJSON *m_out_obj;
    
public:
    int init();
    void deinit();
    int run();
    
    void push(web_event_t *evt) { pthread_mutex_lock(&m_lock); queue_push(m_queue, evt); pthread_cond_signal(&m_cond); pthread_mutex_unlock(&m_lock); }
    int read_test_object(cJSON *obj);
    int read_gesture_object(cJSON *obj);
    int read_capture_object(cJSON *obj);
    int handle_result_object(cJSON *obj);
    struct timespec *get_periodicity(struct timespec *time_to_wait);
    void periodicity_handler(struct timespec **t_wait);
    
    
    void create_output_template();
    
    void update_graph(sounder_t *sd);
    static char *get_local_time(char *buff, unsigned int len);
    
    void dump_json(cJSON *obj);
    
public:
    csimgr_t(const char *path);
	~csimgr_t();
};

#endif
