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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sounder.h"
#include <sys/time.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include <ctime>

vector_t sounder_t::run(wifi_csi_data_t &csi)
{
    vector_t v = {0};
    unsigned int i, j;
    vector_t variance_cond;
    unsigned int num_antennas_satisfied = 0;
    
    variance_cond.m_num = csi.frame_info.Nr;
    v.m_num = 5*csi.frame_info.Nr + 1;
    
    // calculate the mean magnitude of the signals on each antenna
    for (i = 0; i < csi.frame_info.Nr; i++) {
        for (j = 0; j < csi.frame_info.num_sc; j++) {
            v.m_val[i].m_re += number_t(csi.csi_matrix[j][i][0].re, csi.csi_matrix[j][i][0].im).mod_z();
        }
        
        v.m_val[i].m_re /= csi.frame_info.num_sc;
        
        m_sequence[i] = m_sequence[i] + number_t(v.m_val[i].m_re, 0);
        
        v.m_val[i + csi.frame_info.Nr] = get_mean(i);
        v.m_val[i + 2 * csi.frame_info.Nr] = get_variance(i);
        v.m_val[i + 3 * csi.frame_info.Nr] = get_kurtosis(i);
        v.m_val[i + 4 * csi.frame_info.Nr] = get_mfilter(i);
    }
    
    for (j = 1; j < m_antenna_variance.m_cols; j++) {
        for (i = 0; i < m_antenna_variance.m_rows; i++) {
            m_antenna_variance.m_val[i][j - 1] = m_antenna_variance.m_val[i][j];
        }
    }
    
    for (i = 0; i < m_antenna_variance.m_rows; i++) {
        m_antenna_variance.m_val[i][m_antenna_variance.m_cols - 1] = v.m_val[i + 2 * csi.frame_info.Nr];
    }
    
    //m_antenna_variance.print();
    //printf("\n");
    
    for (i = 0; i < m_antenna_variance.m_rows; i++) {
        variance_cond.m_val[i] = number_t(1, 0);
        for (j = 0; j < m_antenna_variance.m_cols; j++) {
            variance_cond.m_val[i] = variance_cond.m_val[i]*(m_antenna_variance.m_val[i][j].m_re > m_test_params.algo_params.variance_threshold);
            //printf("%f\t%d\t%f\n", m_antenna_variance.m_val[i][j].m_re, m_test_params.algo_params.variance_threshold, variance_cond.m_val[i].m_re);
        }
        
        if (variance_cond.m_val[i] == number_t(1, 0)) {
            num_antennas_satisfied++;
        }
        
    }
    
    //printf("Number of antennas for which condition is satisfied: %d\n", num_antennas_satisfied);
    
    v.m_val[5 * csi.frame_info.Nr].m_re = (num_antennas_satisfied >= m_test_params.algo_params.antenna_considerations) ? 1:0;
    
    return v;
}

void sounder_t::add_sequence(unsigned int rx_index, number_t num)
{
    m_sequence[rx_index] = m_sequence[rx_index] + num;
}
 
void sounder_t::parse_frame_object(cJSON *frame_obj, wifi_frame_info_t *frame_info)
{
    cJSON *rssi_arr_obj;
    unsigned int i;
    
    frame_info->Nc = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "Nc"));
    frame_info->Nr = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "Nr"));
    frame_info->bw_mode = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "bw_mode"));
    frame_info->mcs = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "mcs"));
    
    if ((rssi_arr_obj = cJSON_GetObjectItem(frame_obj, "nr_rssi")) == NULL) {
        return;
    }
    
    for (i = 0; i < frame_info->Nr; i++) {
        
        frame_info->nr_rssi[i] = cJSON_GetNumberValue(cJSON_GetArrayItem(rssi_arr_obj, i)) - 0xff;
    }
    
    frame_info->valid_mask = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "valid_mask"));
    frame_info->phy_bw = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "phy_bw"));
    frame_info->cap_bw = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "cap_bw"));
    frame_info->num_sc = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "num_sc"));
    
    frame_info->decimation = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "decimation"));
    frame_info->channel = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "channel"));
    frame_info->cfo = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "cfo"));
    frame_info->time_stamp = cJSON_GetNumberValue(cJSON_GetObjectItem(frame_obj, "time_stamp"));
}

vector_t sounder_t::run_test()
{
    cJSON *obj, *frame_obj, *csi_matrix_obj, *sc_arr_obj, *sc_obj, *stream_arr_obj, *stream_obj, *antenna_arr_obj, *antenna_obj;
    mac_address_t sta_mac;
    wifi_csi_data_t csi = {0};
    unsigned int i, j, k;
    
    if (0) {
        char now[MAX_LINE_SIZE] = {0};
        mac_addr_str_t mac_str;
        printf("%s:%d: Sounder: %s\tTime:%s\tStart Frame Index: %d\n", __func__, __LINE__, mac_str, get_local_time(now, sizeof(now)), m_current);
    }
    
    if ((obj = cJSON_GetArrayItem(m_input_obj, m_current)) == NULL) {
        //printf("%s:%d: Sounder: %s\tnull item in array index: %d\n", __func__, __LINE__, m_mac_str, m_irecs[index].current);
        return vector_t(0);
    }
    
    m_current++;
    if (m_current == m_test_params.end_frame) {
        return vector_t(0);
    }
    
    sscanf(cJSON_GetStringValue(cJSON_GetObjectItem(obj, "sta_mac")), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
           &sta_mac[0], &sta_mac[1], &sta_mac[2], &sta_mac[3], &sta_mac[4], &sta_mac[5]);
    assert(memcmp(sta_mac, m_mac, sizeof(mac_address_t)) == 0);
    
    if ((frame_obj = cJSON_GetObjectItem(obj, "frame_info")) == NULL) {
        printf("%s:%d: Sounder: %s\tnull frame info array index: %d\n", __func__, __LINE__, m_mac_str, m_current);
        return vector_t(0);
    }
    
    parse_frame_object(frame_obj, &csi.frame_info);
    
    if ((csi_matrix_obj = cJSON_GetObjectItem(obj, "csi_matrix")) == NULL) {
        printf("%s:%d: Sounder: %s\tnull csi matrix array index: %d\n", __func__, __LINE__, m_mac_str, m_current);
        return vector_t(0);
    }
    
    if ((sc_arr_obj = cJSON_GetObjectItem(csi_matrix_obj, "sub_carrier")) == NULL) {
        printf("%s:%d: Sounder: %s\tnull sub carrier array object in array index: %d\n", __func__, __LINE__, m_mac_str, m_current);
        return vector_t(0);
    }
    
    assert(csi.frame_info.num_sc == cJSON_GetArraySize(sc_arr_obj));
    
    for (i = 0; i < csi.frame_info.num_sc; i++) {
        sc_obj = cJSON_GetArrayItem(sc_arr_obj, i);
        
        stream_arr_obj = cJSON_GetObjectItem(sc_obj, "stream");
        assert(csi.frame_info.Nc == cJSON_GetArraySize(stream_arr_obj));
        
        for (k = 0; k < csi.frame_info.Nc; k++) {
            stream_obj = cJSON_GetArrayItem(stream_arr_obj, k);
            antenna_arr_obj = cJSON_GetObjectItem(stream_obj, "antenna");
            
            for (j = 0; j < csi.frame_info.Nr; j++) {
                antenna_obj = cJSON_GetArrayItem(antenna_arr_obj, j);
                //printf("%f\t%f\n", cJSON_GetNumberValue(cJSON_GetObjectItem(antenna_obj, "real")), cJSON_GetNumberValue(cJSON_GetObjectItem(antenna_obj, "img")));
                csi.csi_matrix[i][j][k].re = cJSON_GetNumberValue(cJSON_GetObjectItem(antenna_obj, "real"));
                csi.csi_matrix[i][j][k].im = cJSON_GetNumberValue(cJSON_GetObjectItem(antenna_obj, "img"));
            }
        }
        
        
    }
    
    return run(csi);
}



char *sounder_t::get_local_time(char *str, unsigned int len)
{
    struct timeval tv;
    struct tm *local_time;
    
    gettimeofday(&tv, NULL); // Get current time into tv
    local_time = localtime(&tv.tv_sec);
    strftime(str, len, "%Y-%m-%d %H:%M:%S", local_time);

    return str;
}

void sounder_t::reset()
{
    unsigned int i;
    
    m_current = m_test_params.start_frame;
    m_samples = {0, 0};
    
    for (i = 0; i < MAX_NR; i++) {
        m_sequence[i].reset();
    }
}

int sounder_t::update(cJSON *input_obj, wifi_frame_info_t *frame_info, motion_test_params_t *params)
{
    unsigned int i;
    
    m_input_obj = input_obj;
    m_recs = cJSON_GetArraySize(input_obj);
    
    memcpy(&m_frame_info, frame_info, sizeof(wifi_frame_info_t));
    memcpy(&m_test_params, params, sizeof(motion_test_params_t));
    
    m_current = params->start_frame;
    m_samples = {0, 0};
    
    for (i = 0; i < MAX_NR; i++) {
        m_sequence[i] = sequence_t(params->algo_params.algorithm_window);
    }
    
    m_antenna_variance.m_cols = params->algo_params.consecutive_samples;
    m_antenna_variance.m_rows = frame_info->Nr;
    
    return 0;
}

sounder_t::sounder_t(mac_address_t mac)
{
    memcpy(m_mac, mac, sizeof(mac_address_t));
    snprintf(m_mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m_mac[0], m_mac[1], m_mac[2], m_mac[3], m_mac[4], m_mac[5]);
}

sounder_t::~sounder_t()
{

}

