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

#ifndef LINKQ_H
#define LINKQ_H

#include "vector.h"
#include "sequence.h"
#include <cjson/cJSON.h>
#include "wifi_hal.h"
#include "run_qmgr.h"
#include <vector>
#include <deque>

#define MAX_LINE_SIZE   1024
#define MAX_LINKQ_PARAMS    6
#define MAX_SCORE_PARAMS    12
#define PER_WINDOW_SIZE   36
#define UPLINK_PHY_WINDOW  5

typedef struct {
    const char *name;
    bool booster;
} linkq_params_t;

typedef float linkq_data_t[MAX_LINKQ_PARAMS];

class linkq_t {
    mac_addr_str_t m_mac;
    static mac_addr_str_t ignite_station_mac;
    unsigned int m_vapindex;    
    sequence_t m_seq[MAX_LINKQ_PARAMS];
    pthread_mutex_t m_vec_lock; 
    pthread_mutex_t m_deque_lock; 
    unsigned int m_recs;
    unsigned int m_current;
    double m_threshold;
    unsigned int m_reporting_mult;
    unsigned int m_threshold_cross_counter;
    unsigned int m_sampled;
    int m_recovery_remaining;
    int m_recovery_total;
    std::deque<window_per_param_t> m_per_window;
    std::deque<double> m_uplink_phy_history;
    bool m_alarm;
    bool m_disconnected;
    int m_disconnect_samples;
    std::vector<stats_arg_t> m_stats_arr; 
    static linkq_params_t m_linkq_params[MAX_LINKQ_PARAMS];
    static linkq_params_t m_score_params[MAX_SCORE_PARAMS];
    sample_t m_data_sample;
    double m_window_downlink_per;
    double m_window_uplink_per;
    std::vector<sample_t> m_window_samples;
    char *get_local_time(char *buff, unsigned int len,bool flag); 
    static quality_flags_t m_quality_flag;
public:
    vector_t run_test(bool &alarm,bool update_alarm,bool &rapid_disconnect);
    vector_t run_algorithm(linkq_data_t data, bool &alarm, bool update_alarm);
    int init(double threshold, unsigned int reporting_mult,stats_arg_t *stats);
    size_t get_window_samples(sample_t **out_samples); 
    int reinit(server_arg_t *arg);
    int rapid_disconnect(stats_arg_t *stats);
    void update_window_per();
    static linkq_params_t *get_score_params();
    static int set_quality_flags(quality_flags_t *flag);
    static int get_quality_flags(quality_flags_t *flag);
    const char * get_mac_addr() const{ return m_mac; }
    unsigned int get_vap_index() const{ return m_vapindex; }
    bool get_alarm() const{ return m_alarm; }
    void clear_window_samples(); 
    static void register_station_mac(const char* str);
    static void unregister_station_mac(const char* str);
    linkq_t(mac_addr_str_t mac,unsigned int vap_index);
    ~linkq_t();
};

#endif
