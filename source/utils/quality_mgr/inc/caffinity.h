
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

#ifndef CAFFINITY_H
#define CAFFINITY_H

#include <pthread.h>
#include <cjson/cJSON.h>
#include "collection.h"
#include "linkq.h"
#include "run_qmgr.h"
#include <algorithm>
#include <string>

using ap_mac_str_t = std::string;

// Result structure returned by run_algorithm_caffinity
typedef struct {
    mac_addr_str_t mac;
    double score;
    bool connected;
} caffinity_result_t;

class caffinity_t
{
    pthread_mutex_t m_lock;
    mac_addr_str_t m_mac;
    std::vector<ap_mac_str_t> m_ap_mac;
    unsigned int m_auth_failures;
    unsigned int m_auth_attempts;
    unsigned int m_assoc_failures;
    unsigned int m_assoc_attempts;
    unsigned int m_discover;
    unsigned int m_offer;
    unsigned int m_request;
    unsigned int m_decline;
    unsigned int m_nak;
    unsigned int m_ack;
    unsigned int m_snr_assoc;
    int m_cli_snr;
    int m_channel_utilization;
    bool m_connected;
    bool m_power_save;
    struct timespec  m_disconnected_time;
    struct timespec  m_connected_time;
    struct timespec  m_sleep_time;
    struct timespec  m_total_time;
public:
    caffinity_t(mac_addr_str_t *mac);
    ~caffinity_t();
    int init(stats_arg_t *stats);  // Returns 0 on success, -1 on error
    int periodic_stats_update(stats_arg_t *stats);  // Updates connected_time, disconnected_time, and SNR
    int score();
    caffinity_result_t run_algorithm_caffinity();
    bool get_connected() const { return m_connected; }
    struct timespec get_disconnected_time() const { 
        return m_disconnected_time; 
    }
    struct timespec get_connected_time() const { 
        return m_connected_time; 
    }

   
};

#endif
