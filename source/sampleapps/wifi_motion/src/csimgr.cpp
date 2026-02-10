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
#include <dirent.h>
#include "csimgr.h"
#include <sys/time.h>
#include <errno.h>
#include <math.h>
#include "cJSON.h"
#include "sounder.h"
#include <assert.h>
#include "utils.h"

void csimgr_t::dump_json(cJSON *obj)
{
    char *buff;
    unsigned int size = MAX_BUFF_SIZE;
    
    buff = (char *)malloc(size);
    cJSON_PrintPreallocated(obj, buff, size, 1);
    printf("%s\n", buff);
    free(buff);
}

void csimgr_t::update_graph(sounder_t *sd)
{
    char *buff;
    FILE *fp;
    unsigned int size = MAX_BUFF_SIZE;
    cJSON *sounder_arr_obj, *sounder_obj = NULL;
    cJSON *sample_arr_obj, *sample_obj, *kurtosis_arr_obj, *kurtosis_obj;
    cJSON *mean_arr_obj, *mean_obj, *variance_arr_obj, *variance_obj;
    cJSON *mfilter_arr_obj, *mfilter_obj;
    cJSON *algores_arr_obj;
    
    unsigned int i, j;
    bool found = false;
    char *str = sd->get_mac_str();
    matrix_t *m;
    vector_t vc;
    char scratch[MAX_LINE_SIZE];
    
    //printf("%s:%s:%d: Updating graph for device: %s, test duration: %d\n", get_local_time(scratch, sizeof(scratch)), __func__, __LINE__, str, m_args.remaining/1000);
    
    
    if ((sounder_arr_obj = cJSON_GetObjectItem(m_out_obj, "Devices")) == NULL) {
        printf("%s:%d: Failed to get sounders array\n", __func__, __LINE__);
        return;
    }
    
    for (i = 0; i < cJSON_GetArraySize(sounder_arr_obj); i++) {
        sounder_obj = cJSON_GetArrayItem(sounder_arr_obj, i);
        if (strncmp(cJSON_GetStringValue(cJSON_GetObjectItem(sounder_obj, "MAC")), str, strlen(str)) == 0) {
            found = true;
            break;
        }
    }
    
    if (found == false) {
        printf("%s:%d: Failed to get sounder: %s\n", __func__, __LINE__, str);
        return;
    }
    
    sample_arr_obj = cJSON_GetObjectItem(sounder_obj, "Magnitude");
    mean_arr_obj = cJSON_GetObjectItem(sounder_obj, "Mean");
    variance_arr_obj = cJSON_GetObjectItem(sounder_obj, "Variance");
    kurtosis_arr_obj = cJSON_GetObjectItem(sounder_obj, "Kurtosis");
    mfilter_arr_obj = cJSON_GetObjectItem(sounder_obj, "Mfilter");
    algores_arr_obj = cJSON_GetObjectItem(sounder_obj, "AlgorithmResult");
    
    m = sd->get_samples();
    //m->print();
    //printf("\n");
    
    for (i = 0; i < m->m_rows; i++) {
        sample_obj = cJSON_CreateArray();
        cJSON_AddItemToArray(sample_arr_obj, sample_obj);
        
        mean_obj = cJSON_CreateArray();
        cJSON_AddItemToArray(mean_arr_obj, mean_obj);
        
        variance_obj = cJSON_CreateArray();
        cJSON_AddItemToArray(variance_arr_obj, variance_obj);
        
        kurtosis_obj = cJSON_CreateArray();
        cJSON_AddItemToArray(kurtosis_arr_obj, kurtosis_obj);
        
        mfilter_obj = cJSON_CreateArray();
        cJSON_AddItemToArray(mfilter_arr_obj, mfilter_obj);
        
        
        for (j = 0; j < sd->get_num_antennas(); j++) {
            cJSON_AddItemToArray(sample_obj, cJSON_CreateNumber(m->m_val[i][j].m_re));
        }
        
        for (j = sd->get_num_antennas(); j < 2 * sd->get_num_antennas(); j++) {
            cJSON_AddItemToArray(mean_obj, cJSON_CreateNumber(m->m_val[i][j].m_re));
        }
        
        for (j = 2 * sd->get_num_antennas(); j < 3 * sd->get_num_antennas(); j++) {
            cJSON_AddItemToArray(variance_obj, cJSON_CreateNumber(m->m_val[i][j].m_re));
        }
        
        for (j = 3 * sd->get_num_antennas(); j < 4 * sd->get_num_antennas(); j++) {
            cJSON_AddItemToArray(kurtosis_obj, cJSON_CreateNumber(m->m_val[i][j].m_re));
        }
        
        for (j = 4 * sd->get_num_antennas(); j < 5 * sd->get_num_antennas(); j++) {
            cJSON_AddItemToArray(mfilter_obj, cJSON_CreateNumber(m->m_val[i][j].m_re));
        }
        
        // add the algorithm result
        cJSON_AddItemToArray(algores_arr_obj, cJSON_CreateNumber(m->m_val[i][j].m_re));
        
    }
    
    sd->reset_samples();
        
    buff = (char *)malloc(size);
    cJSON_PrintPreallocated(m_out_obj, buff, size, 1);
    //printf("%s\n", buff);
    
    if ((fp = fopen(m_output_file, "w")) == NULL) {
        free(buff);
        return;
    }
    
    fputs(buff, fp);
    fclose(fp);
    free(buff);
 
}

int csimgr_t::handle_result_object(cJSON *obj)
{
    cJSON *data_arr_obj;
    unsigned int i;
    unsigned char *out = NULL;
    FILE *fp;
    char file_name[MAX_LINE_SIZE];
    png_file_info_t png_info[5];
    size_t size, ret;
    
    if (obj == NULL) {
        return -1;
    }
    //dump_json(obj);
    
    if ((data_arr_obj = cJSON_GetObjectItem(obj, "data")) == NULL) {
        printf("%s:%d: Could not find data array in result object\n", __func__, __LINE__);
        return -1;
    }
    snprintf(file_name, sizeof(file_name), "%s%s.png", m_storage_dir, cJSON_GetStringValue(cJSON_GetObjectItem(obj, "file")));
    
    if ((fp = fopen(file_name, "w")) == NULL) {
        printf("%s:%d: Could not open file: %s for saving\n", __func__, __LINE__, file_name);
        return -1;
    }
    
    for (i = 0; i < cJSON_GetArraySize(data_arr_obj); i++) {
        png_info[i].enc_info.ptr = (unsigned char *)(cJSON_GetStringValue(cJSON_GetArrayItem(data_arr_obj, i)) + strlen("data:image/png;base64,"));
        png_info[i].enc_info.len = strlen((char *)png_info[i].enc_info.ptr);
    }
    
    size = utils_t::png_concatenate(png_info, cJSON_GetArraySize(data_arr_obj), &out);
    
    if (size > 0) {
        ret = fwrite(out, 1, size, fp);
        free(out);
    }
    
    fclose(fp);
    
    return 0;
}

int csimgr_t::read_gesture_object(cJSON *obj)
{
    cJSON *arr_obj;
    unsigned int i;
    
    if (obj == NULL) {
        printf("%s:%d: Invalid gesture object\n", __func__, __LINE__);
        return -1;
    }
    
    arr_obj = obj;
    
    for (i = 0; i < cJSON_GetArraySize(arr_obj); i++) {
        printf("%s:%d: Motion Descriptor: %s\n", __func__, __LINE__, cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetArrayItem(arr_obj, i), "Descriptor")));
    }
    
    return 0;
}

int csimgr_t::read_capture_object(cJSON *obj)
{
    cJSON *arr_obj;
    unsigned int i;
    
    if (obj == NULL) {
        printf("%s:%d: Invalid test object\n", __func__, __LINE__);
        return -1;
    }
    
    if ((arr_obj = cJSON_GetObjectItem(obj, "SoundingDevices")) == NULL) {
        printf("%s:%d: Failed to get array object\n", __func__, __LINE__);
        return -1;
    }
    
    for (i = 0; i < cJSON_GetArraySize(arr_obj); i++) {
        ;//printf("%s:%d: Sounding device: %s\n", __func__, __LINE__, cJSON_GetStringValue(cJSON_GetArrayItem(arr_obj, i)));
    }
    
    return 0;
}

int csimgr_t::read_test_object(cJSON *obj)
{
    cJSON *test_obj, *algorithm_param_obj, *arr_obj, *sounder_arr_obj;
    unsigned int i;
    mac_address_t sta_mac;
    mac_addr_str_t mac_str;
    sounder_t *sd;
    wifi_frame_info_t frame_info;
    
    if (obj == NULL) {
        printf("%s:%d: Invalid test object\n", __func__, __LINE__);
        return -1;
    }
    
    if ((test_obj = cJSON_GetObjectItem(obj, "Reporting")) == NULL) {
        printf("%s:%d: Failed to get Reporting object\n", __func__, __LINE__);
        return -1;
    }
    
    m_test_params.reporting = atoi(cJSON_GetStringValue(test_obj));
    
    if ((algorithm_param_obj = cJSON_GetObjectItem(obj, "AlgorithmParameters")) == NULL) {
        printf("%s:%d: Failed to get algorithm parameters object\n", __func__, __LINE__);
        return -1;
    }
    
    if ((test_obj = cJSON_GetObjectItem(algorithm_param_obj, "AlgorithmSamples")) == NULL) {
        printf("%s:%d: Failed to get AlgorithmSamples object\n", __func__, __LINE__);
        return -1;
    }
    
    m_test_params.algo_params.algorithm_window = atoi(cJSON_GetStringValue(test_obj));
    
    if ((test_obj = cJSON_GetObjectItem(algorithm_param_obj, "VarianceThreshold")) == NULL) {
        printf("%s:%d: Failed to get VarianceThreshold object\n", __func__, __LINE__);
        return -1;
    }
    
    m_test_params.algo_params.variance_threshold = atoi(cJSON_GetStringValue(test_obj));
    
    if ((test_obj = cJSON_GetObjectItem(algorithm_param_obj, "AntennaConsiderations")) == NULL) {
        printf("%s:%d: Failed to get AntennaConsiderations object\n", __func__, __LINE__);
        return -1;
    }
    
    m_test_params.algo_params.antenna_considerations = atoi(cJSON_GetStringValue(test_obj));
    
    if ((test_obj = cJSON_GetObjectItem(algorithm_param_obj, "ConsecutiveSamples")) == NULL) {
        printf("%s:%d: Failed to get ConsecutiveSamples object\n", __func__, __LINE__);
        return -1;
    }
    
    m_test_params.algo_params.consecutive_samples = atoi(cJSON_GetStringValue(test_obj));
    
    if ((test_obj = cJSON_GetObjectItem(obj, "Start")) == NULL) {
        printf("%s:%d: Failed to get Start object\n", __func__, __LINE__);
        return -1;
    }
    
    m_test_params.start_frame = atoi(cJSON_GetStringValue(test_obj));
    
    if ((test_obj = cJSON_GetObjectItem(obj, "End")) == NULL) {
        printf("%s:%d: Failed to get End object\n", __func__, __LINE__);
        return -1;
    }
    
    m_test_params.end_frame = atoi(cJSON_GetStringValue(test_obj));
    
    if ((test_obj = cJSON_GetObjectItem(obj, "CSI")) == NULL) {
        printf("%s:%d: Failed to get CSI object\n", __func__, __LINE__);
        return -1;
    }
    
    m_remaining = (m_test_params.end_frame - m_test_params.start_frame) * m_sampling;
    
    if ((test_obj = cJSON_Parse(cJSON_GetStringValue(test_obj))) == NULL) {
        printf("%s:%d: Failed to create CSI object\n", __func__, __LINE__);
        return -1;
    }
    
    if ((arr_obj = cJSON_GetObjectItem(test_obj, "SoundingDevices")) == NULL) {
        printf("%s:%d: Failed to get array object\n", __func__, __LINE__);
        return -1;
    }
    
    for (i = 0; i < cJSON_GetArraySize(arr_obj); i++) {
        sounder_arr_obj = cJSON_GetArrayItem(arr_obj, i);
        assert(cJSON_GetArraySize(sounder_arr_obj) != 0);
        
        sscanf(cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetArrayItem(sounder_arr_obj, 0), "sta_mac")), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
               &sta_mac[0], &sta_mac[1], &sta_mac[2], &sta_mac[3], &sta_mac[4], &sta_mac[5]);
        
        sounder_t::parse_frame_object(cJSON_GetObjectItem(cJSON_GetArrayItem(sounder_arr_obj, 0), "frame_info"), &frame_info);
        
        snprintf(mac_str, 18, "%02x:%02x:%02x:%02x:%02x:%02x", sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);
        if ((sd = (sounder_t *)hash_map_get(m_sounders_map, mac_str)) == NULL) {
            sd = new sounder_t(sta_mac);
            hash_map_put(m_sounders_map, strdup(mac_str), sd);
            
        } else {
            sd->reset();
        }
        
        sd->update(sounder_arr_obj, &frame_info, &m_test_params);
    }
    
    return 0;

}

struct timespec *csimgr_t::get_periodicity(struct timespec *time_to_wait)
{
    struct timeval tm;
    
    gettimeofday(&tm, NULL);
    
    // Calculate the absolute future time for the timeout
    time_to_wait->tv_sec = tm.tv_sec + (m_sampling / 1000);
    long remaining_us = tm.tv_usec + (m_sampling % 1000) * 1000;

    time_to_wait->tv_sec += remaining_us / 1000000;
    time_to_wait->tv_nsec = (remaining_us % 1000000) * 1000;
    
    return time_to_wait;
}

void csimgr_t::periodicity_handler(struct timespec **t_wait)
{
    sounder_t *sd;
    char scratch[MAX_LINE_SIZE];
    struct timespec time_to_wait;
    
    m_remaining -= m_sampling;
    m_iters++;
    
    if (m_remaining <= 0) {
        printf("%s:%s:%d: Test Stopping, resetting periodcity to infinite\n", get_local_time(scratch, sizeof(scratch)), __func__, __LINE__);
        *t_wait = NULL;
        return;
    }
    
    sd = (sounder_t *)hash_map_get_first(m_sounders_map);
    while (sd != NULL) {
        sd->push(sd->run_test());
        if ((m_iters != 0) && ((m_iters % (m_test_params.reporting/m_sampling)) == 0)) {
            
            update_graph(sd);
        }
        sd = (sounder_t *)hash_map_get_next(m_sounders_map, sd);
    }
    
    *t_wait = get_periodicity(&time_to_wait);
    //printf("%s:%s:%d: Test Running\n", get_local_time(scratch, sizeof(scratch)), __func__, __LINE__);
}

int csimgr_t::run()
{
    int rc;
    struct timespec time_to_wait, *t_wait = NULL;
    web_event_t *event;
    char scratch[MAX_LINE_SIZE];
    struct timespec now;

    if (init() != 0) {
        printf("%s:%d: Failed to initialize\n", __func__, __LINE__);
        return -1;
    }
    
    pthread_mutex_lock(&m_lock);
    while (m_exit == false) {
        
        clock_gettime(CLOCK_MONOTONIC, &now);
        time_to_wait.tv_sec = now.tv_sec + 5;
        time_to_wait.tv_nsec = now.tv_nsec;

        rc = pthread_cond_timedwait(&m_cond, &m_lock, &time_to_wait);
        //rc = pthread_cond_timedwait(&m_cond, &m_lock, t_wait);
        if (rc == 0) {
            //assert(queue_count(m_queue) == 1);
            if ((event = (web_event_t *)queue_pop(m_queue)) == NULL) {
                continue;
            }
            
            pthread_mutex_unlock(&m_lock);
            
            switch (event->type) {
                case web_event_type_csi_analyze:
                    if (read_test_object(cJSON_Parse(event->buff)) < 0) {
                        printf("%s:%d: Failed to read test object\n", __func__, __LINE__);
                        continue;
                    }
                    
                    printf("%s:%s:%d:Test Started, Reporting Period: %d\tStart Frame: %d\tEnd Frame: %d\tTest Duration: %d\nAlgorithm Samples: %d\tVariance Threshold: %d\tConsecutive Samples: %d\tAntenna Considerations: %d\n",
                           get_local_time(scratch, sizeof(scratch)), __func__, __LINE__,
                           m_test_params.reporting, m_test_params.start_frame, m_test_params.end_frame, m_remaining,
                           m_test_params.algo_params.algorithm_window, m_test_params.algo_params.variance_threshold, m_test_params.algo_params.consecutive_samples, m_test_params.algo_params.antenna_considerations);
                    
                    t_wait = get_periodicity(&time_to_wait);
                    m_iters = 0;
                    m_remaining -= m_sampling;
                    
                    fopen(m_output_file, "w");
                    create_output_template();
                    break;
                    
                case web_event_type_csi_save:
                    if (handle_result_object(cJSON_Parse(event->buff)) < 0) {
                        printf("%s:%d: Failed to parse result object\n", __func__, __LINE__);
                    }
                    break;
                    
                case web_event_type_csi_abort:
                    m_remaining = m_sampling;
                    break;
                    
                case web_event_type_csi_capture:
                    if (read_capture_object(cJSON_Parse(event->buff)) < 0) {
                        printf("%s:%d: Failed to read test object\n", __func__, __LINE__);
                        continue;
                    }
                    break;
                    
                case web_event_type_csi_motion_info:
                    if (read_gesture_object(cJSON_Parse(event->buff)) < 0) {
                        printf("%s:%d: Failed to read gesture object\n", __func__, __LINE__);
                        continue;
                    }
                    break;
                    
                default:
                    break;
            }
            if (event->buff != NULL) {
                free(event->buff);
            }
            free(event);
            pthread_mutex_lock(&m_lock);

        } else if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&m_lock);
            periodicity_handler(&t_wait);
            pthread_mutex_lock(&m_lock);
        } else {
            printf("%s:%d Thead exited with rc - %d\n",__func__,__LINE__,rc);
            pthread_mutex_unlock(&m_lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&m_lock);

    return 0;
}

void csimgr_t::create_output_template()
{
    cJSON *sounder_arr_obj, *sounder_obj;
    sounder_t *sd = NULL;
    
    if (m_out_obj != NULL) {
        cJSON_Delete(m_out_obj);
    }
    
    m_out_obj = cJSON_CreateObject();
    
    sounder_arr_obj = cJSON_CreateArray();
    cJSON_AddItemToObject(m_out_obj, "Devices", sounder_arr_obj);
    
    sd = (sounder_t *)hash_map_get_first(m_sounders_map);
    while (sd != NULL) {
        sounder_obj = cJSON_CreateObject();
        cJSON_AddItemToArray(sounder_arr_obj, sounder_obj);
        
        cJSON_AddItemToObject(sounder_obj, "MAC", cJSON_CreateString(sd->get_mac_str()));
        cJSON_AddItemToObject(sounder_obj, "Magnitude", cJSON_CreateArray());
        cJSON_AddItemToObject(sounder_obj, "Mean", cJSON_CreateArray());
        cJSON_AddItemToObject(sounder_obj, "Variance", cJSON_CreateArray());
        cJSON_AddItemToObject(sounder_obj, "Kurtosis", cJSON_CreateArray());
        cJSON_AddItemToObject(sounder_obj, "Mfilter", cJSON_CreateArray());
        cJSON_AddItemToObject(sounder_obj, "AlgorithmResult", cJSON_CreateArray());
        
        sd = (sounder_t *)hash_map_get_next(m_sounders_map, sd);
    }
}

void csimgr_t::deinit()
{
    queue_destroy(m_queue);
    hash_map_destroy(m_sounders_map);
    pthread_mutex_destroy(&m_lock);
    pthread_cond_destroy(&m_cond);
}

int csimgr_t::init()
{
    pthread_mutex_init(&m_lock, NULL);
    //pthread_cond_init(&m_cond, NULL);
    pthread_condattr_t cond_attr;
    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&m_cond, &cond_attr);

    m_sounders_map = hash_map_create();
    m_queue = queue_create();
    
    m_exit = false;
    
    return 0;
}

char *csimgr_t::get_local_time(char *str, unsigned int len)
{
    struct timeval tv;
    struct tm *local_time;
    
    gettimeofday(&tv, NULL); // Get current time into tv
    local_time = localtime(&tv.tv_sec);
    strftime(str, len, "%Y-%m-%d %H:%M:%S", local_time);

    return str;
}

csimgr_t::csimgr_t(const char *path)
{
    m_sampling = 500;
    m_iters = 0;
    
    m_out_obj = NULL;
    snprintf(m_output_file, sizeof(m_output_file), "%s/motion.json", path);
    snprintf(m_storage_dir, sizeof(m_storage_dir), "%s/saved/", path);
}

csimgr_t::~csimgr_t()
{

}

