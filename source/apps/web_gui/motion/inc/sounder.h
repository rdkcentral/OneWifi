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

#include <stdint.h>
#include "vector.h"
#include "matrix.h"
#include "sequence.h"
#include "cJSON.h"
#include "wifi_hal.h"
#include "common_defs.h"


#define gesture_idle   0
#define gesture_finger 1
#define gesture_hand gesture_finger << 1

typedef unsigned int gestures_t;

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
    sequence_t m_uber_variance;
    
    motion_test_params_t    m_test_params;
    
    wifi_frame_info_t m_frame_info;

    bool m_enable_status;
    double m_last_motion_detected_time;
    uint32_t m_cal_packets_cnt;
    
public:
    //vector_t run_test();//@TODO TBD ANIKET
    int update(cJSON *input_obj, wifi_frame_info_t *frame_info, motion_test_params_t *params);
    vector_t process_csi_data(wifi_csi_data_t &csi, gestures_t gestures);

    void reset();
    
    void push(vector_t v) { m_samples.push(v); }
    matrix_t *get_samples() { return &m_samples; }
    float get_uber_variance() { return m_uber_variance.get_mean().m_re; }
    void add_sequence(unsigned int rx_index, number_t num);
    number_t get_mean(unsigned int rx_index)  { return m_sequence[rx_index].m_mean; }
    number_t get_variance(unsigned int rx_index) { return m_sequence[rx_index].m_variance; }
    number_t get_kurtosis(unsigned int rx_index) { return m_sequence[rx_index].m_kurtosis; }
    number_t get_mfilter(unsigned int rx_index) { return m_sequence[rx_index].m_mfilter; }
    void reset_samples() { m_samples.reset(); }
    
    unsigned char* get_mac_addr() { return m_mac; }
    char *get_mac_str(){ return m_mac_str; }
    unsigned int get_num_antennas() { return m_frame_info.Nr; }

    void set_enable_status(bool status) { m_enable_status = status; }
    bool get_enable_status() const { return m_enable_status; }
    void set_last_motion_detected_time(double t) { m_last_motion_detected_time = t; }
    double get_last_motion_detected_time() const { return m_last_motion_detected_time; }
    void set_cal_packets_cnt(uint32_t cnt) { m_cal_packets_cnt = cnt; }
    uint32_t get_cal_packets_cnt() const { return m_cal_packets_cnt; }
    
    static char *get_local_time(char *buff, unsigned int len);
    static void parse_frame_object(cJSON *frame_obj, wifi_frame_info_t *frame_info);
    
    sounder_t(mac_address_t mac);
	~sounder_t();
};

#endif
