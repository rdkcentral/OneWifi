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

#ifndef QMGR_H
#define QMGR_H

#include <pthread.h>
#include <cjson/cJSON.h>
#include "collection.h"
#include "run_qmgr.h"
#include <vector>
#include <algorithm>
#include <string>
#include <unordered_map>
#include "linkq.h"
#include "caffinity.h"

#define MAX_FILE_NAME_SZ 1024
#define MAX_PATH_SZ MAX_FILE_NAME_SZ
#define MAX_HISTORY 15


class qmgr_t {
    pthread_mutex_t m_lock;
    pthread_cond_t m_cond;
    server_arg_t    m_args;
    pthread_mutex_t m_json_lock;
    stats_arg_t    m_stats;
    linkq_t *lq;
    caffinity_t *caff;
    hash_map_t *m_link_map;
    static qmgr_t *instance;
    qmgr_t();
    qmgr_t(server_arg_t *args,stats_arg_t *stats);
    bool m_exit;
    pthread_t m_thread;
    bool m_run_started;
    bool m_bg_running;
    static uint8_t m_gw_mac[6];
    cJSON *out_obj;
    cJSON *affinity_obj;
    cJSON *caffinity_out_obj;  // Separate JSON for caffinity telemetry
    std::unordered_map<const char*, stats_arg_t> m_affinity_map;
    std::unordered_map<std::string, caffinity_t*> m_caffinity_map;  // Object storage for caffinity
    
    // RMS aggregate tracking
    double m_rms_conn_sum_sq;
    int m_rms_conn_count;
    double m_rms_unconn_sum_sq;
    int m_rms_unconn_count;
    static const int RMS_RESET_COUNT = 24 * 60 * 60 / 5;  // Reset daily (86400/5 = 17280 samples)
    
    // Link Quality RMS tracking
    double m_rms_lq_sum_sq;
    int m_rms_lq_count;
    static const int SCORE_INDEX = 11;  // Index of aggregate "Score" in m_score_params

    cJSON* create_affinity_template(mac_addr_str_t mac_str,unsigned int vap_index);
    cJSON* create_caffinity_template(mac_addr_str_t mac_str);
    void populate_caffinity_client_json(const char *mac_cstr, double score, const char *timestamp,
                                        cJSON *target_arr, cJSON *other_arr, const char *target_name);
public:
    int init(stats_arg_t *arg,bool create_flag);
    int rapid_disconnect(stats_arg_t *arg);
    int reinit(server_arg_t *arg);
    void deinit();
    void trim_cjson_array(cJSON *arr, int max_len);
    void deinit(mac_addr_str_t mac_str);
    int run();
    int push_reporting_subdoc();
    void start_background_run();
    static void* run_helper(void* arg);
    void remove_device_from_out_obj(cJSON *out_obj, const char *mac_str);
    static qmgr_t* get_instance();
    char *get_local_time(char *buff, unsigned int len,bool flag);
    cJSON *create_dev_template(mac_addr_str_t mac_str,unsigned int vap_index);
    static int set_max_snr_radios(radio_max_snr_t *max_snr_val);    
    void update_json(const char *str, vector_t v, cJSON *out_obj, bool &alarm);
    void update_caffinity_json(const char *str, double caffinity_score);
    void update_caffinity_graph();
    void update_rms_aggregate_json(double rms_connected, double rms_unconnected);
    void update_rms_lq_aggregate_json(double rms_lq);
    void register_station_mac(const char* str);
    void unregister_station_mac(const char* str);
    static void destroy_instance();
    static int set_quality_flags(quality_flags_t *flag);
    static int get_quality_flags(quality_flags_t *flag);
    void update_graph( cJSON *out_obj);
    int update_affinity_stats(stats_arg_t *arg,bool flag);
    int caffinity_periodic_stats_update(stats_arg_t *stats);
    bool is_client_connected(const char *mac_str);
    static int store_gw_mac(uint8_t *mac);
    static int get_gw_mac(uint8_t *mac);
    ~qmgr_t();
};

#endif
