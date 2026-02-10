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

#ifndef SOUNDER_H
#define SOUNDER_H

#include "vector.h"
#include "matrix.h"
#include "sequence.h"
#include "cJSON.h"
#include "wifi_hal.h"
#include "common_defs.h"

class sounder_t {
    mac_address_t m_mac;
    mac_addr_str_t m_mac_str;
    
    // test parameters
    cJSON *m_input_obj;
    unsigned int m_recs;
    unsigned int m_current;
    
    matrix_t m_samples;
    sequence_t m_sequence[MAX_NR];
    matrix_t m_antenna_variance;
    
    motion_test_params_t    m_test_params;
    
    wifi_frame_info_t m_frame_info;
    
public:
    vector_t run_test();
    int update(cJSON *input_obj, wifi_frame_info_t *frame_info, motion_test_params_t *params);
    vector_t run(wifi_csi_data_t &csi);
    
    void reset();
    
    void push(vector_t v) { m_samples.push(v); }
    matrix_t *get_samples() { return &m_samples; }
    void add_sequence(unsigned int rx_index, number_t num);
    number_t get_mean(unsigned int rx_index)  { return m_sequence[rx_index].m_mean; }
    number_t get_variance(unsigned int rx_index) { return m_sequence[rx_index].m_variance; }
    number_t get_kurtosis(unsigned int rx_index) { return m_sequence[rx_index].m_kurtosis; }
    number_t get_mfilter(unsigned int rx_index) { return m_sequence[rx_index].m_mfilter; }
    void reset_samples() { m_samples.reset(); }
    
    unsigned char* get_mac_addr() { return m_mac; }
    char *get_mac_str(){ return m_mac_str; }
    unsigned int get_num_antennas() { return m_frame_info.Nr; }
    
    static char *get_local_time(char *buff, unsigned int len);
    static void parse_frame_object(cJSON *frame_obj, wifi_frame_info_t *frame_info);
    
    sounder_t(mac_address_t mac);
	~sounder_t();
};

#endif
