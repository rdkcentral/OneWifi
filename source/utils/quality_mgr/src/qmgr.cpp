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
#include "qmgr.h"
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <vector>
#include <map>
#include <cjson/cJSON.h>
#include "wifi_util.h"

qmgr_t* qmgr_t::instance = NULL;
uint8_t qmgr_t::m_gw_mac[6] = {0};
extern "C" void qmgr_invoke_batch(const report_batch_t *batch);
qmgr_t* qmgr_t::get_instance()
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&lock);

    if (instance == NULL) {
        instance = new qmgr_t();
    }

    pthread_mutex_unlock(&lock);

    return instance;
}

void  qmgr_t::trim_cjson_array(cJSON *arr, int max_len)
{
    int size;

    if (!arr || !cJSON_IsArray(arr))
        return;

    size = cJSON_GetArraySize(arr);
    while (size > max_len) {
        cJSON_DeleteItemFromArray(arr, 0); // remove oldest
        size--;
    }
}

void qmgr_t::update_json(const char *str, vector_t v, cJSON *out_obj, bool &alarm)
{
    pthread_mutex_lock(&m_json_lock);
    char  tmp[MAX_LINE_SIZE];
    unsigned int i;
    cJSON *arr;
    cJSON *obj, *dev_obj;
    bool found = false;
    linkq_params_t *params;
 
    if ((arr = cJSON_GetObjectItem(out_obj, "Devices")) == NULL) {
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
    
    for (i = 0; i < cJSON_GetArraySize(arr); i++) {
        dev_obj = cJSON_GetArrayItem(arr, i);
        if (strncmp(cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "MAC")), str, strlen(str)) == 0) {
            found = true;
            break;
        }
    }
    
    if (found == false) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Device %s not found in Devices array (array size=%d)\n",
            __func__,__LINE__, str, cJSON_GetArraySize(arr));
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
    
    wifi_util_dbg_print(WIFI_APPS,"%s:%d Found device %s in Devices array, updating scores\n",
        __func__,__LINE__, str);
    
    obj = cJSON_GetObjectItem(dev_obj, "LinkQuality");
    if (!obj) {
        wifi_util_error_print(WIFI_APPS,"%s:%d LinkQuality object not found for MAC %s\n",__func__,__LINE__, str);
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
 
    params = linkq_t::get_score_params();
    for (i = 0; i < MAX_SCORE_PARAMS; i++) {
        snprintf(tmp, sizeof(tmp), "%s", params->name);
        arr = cJSON_GetObjectItem(obj, tmp);
        
        if (arr) {
            cJSON_AddItemToArray(arr, cJSON_CreateNumber(v.m_val[i].m_re));
            trim_cjson_array(arr, MAX_HISTORY);
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Appended %s=%.4f for MAC %s (array size now %d)\n",
                __func__,__LINE__, params->name, v.m_val[i].m_re, str, cJSON_GetArraySize(arr));
        }
        params++;
    }

    if (v.m_num > MAX_LEN) {
        //wifi_util_error_print(WIFI_APPS,"ERROR: Invalid m_num=%d (MAX_LEN=%d) for MAC %s\n", v.m_num, MAX_LEN, str);
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
 
    arr = cJSON_GetObjectItem(obj, "Alarms");
    cJSON_AddItemToArray(arr, cJSON_CreateString((alarm == true)?get_local_time(tmp, sizeof(tmp),false):""));
    trim_cjson_array(arr, MAX_HISTORY);
    arr = cJSON_GetObjectItem(dev_obj, "Time");
    cJSON_AddItemToArray(arr,cJSON_CreateString(get_local_time(tmp, sizeof(tmp),true)));
    trim_cjson_array(arr, MAX_HISTORY);
    pthread_mutex_unlock(&m_json_lock);
    return;
}

void qmgr_t::update_caffinity_json(const char *str, double caffinity_score)
{
    pthread_mutex_lock(&m_json_lock);
    char tmp[MAX_LINE_SIZE];
    unsigned int i;
    cJSON *arr;
    cJSON *caff_obj, *dev_obj;
    bool found = false;
    const char *target_array_name = NULL;
    
    // Check if client is connected using m_caffinity_map
    std::string mac_key(str);
    std::unordered_map<std::string, caffinity_t*>::iterator it = m_caffinity_map.find(mac_key);
    bool is_connected = false;
    if (it != m_caffinity_map.end() && it->second) {
        is_connected = it->second->get_connected();
    }
    
    target_array_name = is_connected ? "ConnectedClients" : "UnconnectedClients";
    
    wifi_util_info_print(WIFI_CTRL, "CAFF %s:%d Updating caffinity JSON for MAC %s in %s\n",
        __func__, __LINE__, str, target_array_name);
 
    if ((arr = cJSON_GetObjectItem(caffinity_out_obj, target_array_name)) == NULL) {
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
    
    // Find device by MAC
    for (i = 0; i < (unsigned int)cJSON_GetArraySize(arr); i++) {
        dev_obj = cJSON_GetArrayItem(arr, i);
        if (strncmp(cJSON_GetStringValue(cJSON_GetObjectItem(dev_obj, "MAC")), str, strlen(str)) == 0) {
            found = true;
            break;
        }
    }
    
    if (!found) {
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
    
    caff_obj = cJSON_GetObjectItem(dev_obj, "CAffinityScore");
    if (caff_obj == NULL) {
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
    
    // Append score
    arr = cJSON_GetObjectItem(caff_obj, "Score");
    if (arr) {
        cJSON_AddItemToArray(arr, cJSON_CreateNumber(caffinity_score));
        trim_cjson_array(arr, MAX_HISTORY);
    }
    
    // Append timestamp
    arr = cJSON_GetObjectItem(caff_obj, "Time");
    if (arr) {
        cJSON_AddItemToArray(arr, cJSON_CreateString(get_local_time(tmp, sizeof(tmp), true)));
        trim_cjson_array(arr, MAX_HISTORY);
    }
    
    pthread_mutex_unlock(&m_json_lock);
    return;
}

void qmgr_t::update_caffinity_graph()
{
    pthread_mutex_lock(&m_json_lock);
    char *json = cJSON_PrintUnformatted(caffinity_out_obj);
    wifi_util_dbg_print(WIFI_APPS,"%s:%d Caffinity JSON: %s\n",__func__,__LINE__,json); 
    FILE *fp = fopen("/www/data/caffinity_telemetry.json", "w");
    if (fp) {
        fputs(json, fp);
        fclose(fp);
    }
    free(json);
    pthread_mutex_unlock(&m_json_lock);
    return;
}

void qmgr_t::update_rms_aggregate_json(double rms_connected, double rms_unconnected)
{
    char tmp[MAX_LINE_SIZE];
    cJSON *rms_obj = cJSON_GetObjectItem(caffinity_out_obj, "RMS_score");
    
    if (!rms_obj) {
        // Create RMS_score structure if it doesn't exist
        rms_obj = cJSON_CreateObject();
        cJSON_AddItemToObject(rms_obj, "connected", cJSON_CreateArray());
        cJSON_AddItemToObject(rms_obj, "unconnected", cJSON_CreateArray());
        cJSON_AddItemToObject(rms_obj, "Time", cJSON_CreateArray());
        cJSON_AddItemToObject(caffinity_out_obj, "RMS_score", rms_obj);
    }
    
    // Append connected RMS score
    cJSON *conn_arr = cJSON_GetObjectItem(rms_obj, "connected");
    if (conn_arr) {
        cJSON_AddItemToArray(conn_arr, cJSON_CreateNumber(rms_connected));
        trim_cjson_array(conn_arr, MAX_HISTORY);
    }
    
    // Append unconnected RMS score
    cJSON *unconn_arr = cJSON_GetObjectItem(rms_obj, "unconnected");
    if (unconn_arr) {
        cJSON_AddItemToArray(unconn_arr, cJSON_CreateNumber(rms_unconnected));
        trim_cjson_array(unconn_arr, MAX_HISTORY);
    }
    
    // Append timestamp
    cJSON *time_arr = cJSON_GetObjectItem(rms_obj, "Time");
    if (time_arr) {
        cJSON_AddItemToArray(time_arr, cJSON_CreateString(get_local_time(tmp, sizeof(tmp), true)));
        trim_cjson_array(time_arr, MAX_HISTORY);
    }
    
    wifi_util_dbg_print(WIFI_APPS, "%s:%d RMS scores updated - connected: %.4f, unconnected: %.4f\n",
        __func__, __LINE__, rms_connected, rms_unconnected);
}

void qmgr_t::update_rms_lq_aggregate_json(double rms_lq)
{
    char tmp[MAX_LINE_SIZE];
    cJSON *rms_obj = cJSON_GetObjectItem(out_obj, "RMS_lq_score");
    
    if (!rms_obj) {
        // Create RMS_lq_score structure if it doesn't exist
        rms_obj = cJSON_CreateObject();
        cJSON_AddItemToObject(rms_obj, "Score", cJSON_CreateArray());
        cJSON_AddItemToObject(rms_obj, "Time", cJSON_CreateArray());
        cJSON_AddItemToObject(out_obj, "RMS_lq_score", rms_obj);
    }
    
    // Append RMS score
    cJSON *score_arr = cJSON_GetObjectItem(rms_obj, "Score");
    if (score_arr) {
        cJSON_AddItemToArray(score_arr, cJSON_CreateNumber(rms_lq));
        trim_cjson_array(score_arr, MAX_HISTORY);
    }
    
    // Append timestamp
    cJSON *time_arr = cJSON_GetObjectItem(rms_obj, "Time");
    if (time_arr) {
        cJSON_AddItemToArray(time_arr, cJSON_CreateString(get_local_time(tmp, sizeof(tmp), true)));
        trim_cjson_array(time_arr, MAX_HISTORY);
    }
    
    wifi_util_dbg_print(WIFI_APPS, "%s:%d RMS LQ score updated: %.4f\n",
        __func__, __LINE__, rms_lq);
}

// Finds or creates a caffinity client entry in target JSON array, moves from other array if needed, and appends score/time data
void qmgr_t::populate_caffinity_client_json(const char *mac_cstr, double score, const char *timestamp,
                                            cJSON *target_arr, cJSON *other_arr, const char *target_name)
{
    int i, arr_size;
    cJSON *dev_obj = NULL;
    cJSON *dev, *caff_obj, *score_arr;
    const char *existing_mac;
    bool found = false;

    // Find in target JSON array
    if (target_arr) {
        arr_size = cJSON_GetArraySize(target_arr);
        for (i = 0; i < arr_size; i++) {
            dev = cJSON_GetArrayItem(target_arr, i);
            existing_mac = cJSON_GetStringValue(cJSON_GetObjectItem(dev, "MAC"));
            if (existing_mac && strcmp(existing_mac, mac_cstr) == 0) {
                dev_obj = dev;
                found = true;
                break;
            }
        }
    }

    // If not found in target, check other array and move
    if (!found && other_arr) {
        arr_size = cJSON_GetArraySize(other_arr);
        for (i = 0; i < arr_size; i++) {
            dev = cJSON_GetArrayItem(other_arr, i);
            existing_mac = cJSON_GetStringValue(cJSON_GetObjectItem(dev, "MAC"));
            if (existing_mac && strcmp(existing_mac, mac_cstr) == 0) {
                dev_obj = cJSON_DetachItemFromArray(other_arr, i);
                cJSON_AddItemToArray(target_arr, dev_obj);
                wifi_util_info_print(WIFI_CTRL, "CAFF %s:%d Moved %s to %s\n", __func__, __LINE__, mac_cstr, target_name);
                break;
            }
        }
    }

    // Create new if not found
    if (!dev_obj && target_arr) {
        mac_addr_str_t mac_copy;
        strncpy(mac_copy, mac_cstr, sizeof(mac_copy) - 1);
        mac_copy[sizeof(mac_copy) - 1] = '\0';
        dev_obj = create_caffinity_template(mac_copy);
        cJSON_AddItemToArray(target_arr, dev_obj);
    }

    // Append score and timestamp
    if (dev_obj) {
        caff_obj = cJSON_GetObjectItem(dev_obj, "CAffinityScore");
        if (caff_obj) {
            score_arr = cJSON_GetObjectItem(caff_obj, "Score");
            if (score_arr) {
                cJSON_AddItemToArray(score_arr, cJSON_CreateNumber(score));
                trim_cjson_array(score_arr, MAX_HISTORY);
            }
            score_arr = cJSON_GetObjectItem(caff_obj, "Time");
            if (score_arr) {
                cJSON_AddItemToArray(score_arr, cJSON_CreateString(timestamp));
                trim_cjson_array(score_arr, MAX_HISTORY);
            }
        }
    }
}


int qmgr_t::push_reporting_subdoc()
{
    linkq_t *lq;
    lq = (linkq_t *)hash_map_get_first(m_link_map);
    size_t total_links = hash_map_count(m_link_map);  // or precompute
    report_batch_t *report = (report_batch_t *)calloc(1, sizeof(report_batch_t));
    if (!report) return -1;
    report->links = (link_report_t *)calloc(total_links, sizeof(link_report_t));
    if (!report->links) {
        free(report);
        return -1;
    }

    size_t link_index = 0;
    sample_t *samples = NULL;
    size_t sample_count = 0;

    while (lq != NULL) {
        sample_count = lq->get_window_samples(&samples);
        if (sample_count > 0) {
            link_report_t *lr = &report->links[link_index];
            memset(lr, 0, sizeof(link_report_t));

            strncpy(lr->mac, lq->get_mac_addr(), sizeof(lr->mac) - 1);
            lr->mac[sizeof(lr->mac) - 1] = '\0';
            lr->vap_index = lq->get_vap_index();
            lr->threshold = m_args.threshold;
            lr->alarm = lq->get_alarm();
            get_local_time(lr->reporting_time,sizeof(lr->reporting_time),false);
            lr->sample_count = sample_count;
            lr->samples = (sample_t *)calloc(sample_count, sizeof(sample_t));
            for (size_t i = 0; i < sample_count; i++) {
                lr->samples[i] = samples[i];   // only safe if no pointers
            }

            free(samples);
            samples = NULL;

            link_index++;
        }
        lq->clear_window_samples();
        lq = (linkq_t *)hash_map_get_next(m_link_map, lq);
    }
    report->link_count = link_index;
    // Call the callback
    qmgr_invoke_batch(report);
    wifi_util_dbg_print(WIFI_APPS,"%s:%d Executed callback\n",__func__,__LINE__);

    // Free everything after callback
    for (size_t i = 0; i < report->link_count; i++) {
        free(report->links[i].samples);
    }
    free(report->links);
    free(report);
    return 0;
}
void qmgr_t::update_graph( cJSON *out_obj)
{
    pthread_mutex_lock(&m_json_lock);
    
    // Log device count and array sizes before writing
    cJSON *dev_arr = cJSON_GetObjectItem(out_obj, "Devices");
    if (dev_arr) {
        int dev_count = cJSON_GetArraySize(dev_arr);
        wifi_util_info_print(WIFI_APPS,"%s:%d Writing telemetry.json with %d devices\n",__func__,__LINE__, dev_count);
        
        // Log first device's score count for debugging
        if (dev_count > 0) {
            cJSON *first_dev = cJSON_GetArrayItem(dev_arr, 0);
            if (first_dev) {
                const char *mac = cJSON_GetStringValue(cJSON_GetObjectItem(first_dev, "MAC"));
                cJSON *lq = cJSON_GetObjectItem(first_dev, "LinkQuality");
                if (lq) {
                    cJSON *score = cJSON_GetObjectItem(lq, "SCORE");
                    int score_count = score ? cJSON_GetArraySize(score) : 0;
                    wifi_util_info_print(WIFI_APPS,"%s:%d First device MAC=%s has %d score entries\n",
                        __func__,__LINE__, mac ? mac : "unknown", score_count);
                }
            }
        }
    }
    
    char *json = cJSON_PrintUnformatted(out_obj);
    wifi_util_dbg_print(WIFI_APPS,"%s:%d %s\n",__func__,__LINE__,json); 
    FILE *fp = fopen(m_args.output_file, "w");
    if (fp) {
        fputs(json, fp);
        fclose(fp);
    }
    free(json);
    pthread_mutex_unlock(&m_json_lock);
    return ;
}
int qmgr_t::run()
{
    int rc,count = 0;
    struct timespec time_to_wait;
    struct timeval tm;
    struct timeval start_time;
    linkq_t *lq;
    vector_t v;
    mac_addr_str_t mac_str;
    unsigned char *sta_mac;
    bool alarm = false;
    bool rapid_disconnect = false;
    long elapsed_sec  = 0;
    bool update_alarm = false;
    gettimeofday(&start_time, NULL);
    pthread_mutex_lock(&m_lock);
    while (m_exit == false) {
        rc = 0;

        gettimeofday(&tm, NULL);
        time_to_wait.tv_sec = tm.tv_sec + m_args.sampling;
        time_to_wait.tv_nsec = tm.tv_usec * 1000;
        
        rc = pthread_cond_timedwait(&m_cond, &m_lock, &time_to_wait);
        gettimeofday(&tm, NULL);
        if (rc == 0) {
            ;
        } else if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&m_lock);
            elapsed_sec = tm.tv_sec - start_time.tv_sec;
            if (elapsed_sec >= m_args.reporting) {
                update_alarm = true;  
            } else {
                update_alarm = false;  
            }
            lq = (linkq_t *)hash_map_get_first(m_link_map);
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Processing %d devices in m_link_map\n",
                __func__,__LINE__, hash_map_count(m_link_map));
            double lq_sum_sq_iter = 0.0;
            int lq_count_iter = 0;
            while (lq != NULL) {
                v = lq->run_test(alarm,update_alarm, rapid_disconnect);
                // Skip if run_test returned invalid/no data
                if (v.m_num == 0 && !rapid_disconnect) {
                    wifi_util_dbg_print(WIFI_APPS,
                        "%s:%d: Skipping device %s as no valid data available (v.m_num=%d)\n",
                        __func__, __LINE__, lq->get_mac_addr(), v.m_num);
                    lq = (linkq_t *)hash_map_get_next(m_link_map, lq);
                    continue;
                }
                wifi_util_dbg_print(WIFI_APPS,"%s:%d Device %s has valid data (v.m_num=%d), updating JSON\n",
                    __func__,__LINE__, lq->get_mac_addr(), v.m_num);
                strncpy(mac_str, lq->get_mac_addr(), sizeof(mac_str) - 1);
                mac_str[sizeof(mac_str) - 1] = '\0';
                update_json(mac_str, v, out_obj, alarm);
                
                // Accumulate RMS for Link Quality Score (per-iteration)
                double lq_score = v.m_val[SCORE_INDEX].m_re;
                lq_sum_sq_iter += lq_score * lq_score;
                lq_count_iter++;

                lq = (linkq_t *)hash_map_get_next(m_link_map, lq);
            }
            
            // Calculate and update Link Quality RMS (per-iteration snapshot)
            if (lq_count_iter > 0) {
                double rms_lq = sqrt(lq_sum_sq_iter / lq_count_iter);
                update_rms_lq_aggregate_json(rms_lq);
            }
            
            // --- Process caffinity in single pass: classify and populate JSON ---
            if (!m_caffinity_map.empty()) {
                pthread_mutex_lock(&m_json_lock);
                cJSON *conn_arr = cJSON_GetObjectItem(caffinity_out_obj, "ConnectedClients");
                cJSON *unconn_arr = cJSON_GetObjectItem(caffinity_out_obj, "UnconnectedClients");
                char tmp[MAX_LINE_SIZE];
                
                // Reset counts for this iteration
                int connected_count = 0;
                int unconnected_count = 0;
                double conn_sum_sq_iter = 0.0;
                double unconn_sum_sq_iter = 0.0;
                
                // Process each client: compute score, classify, populate JSON, accumulate RMS
                std::unordered_map<std::string, caffinity_t*>::iterator caff_it;
                for (caff_it = m_caffinity_map.begin(); caff_it != m_caffinity_map.end(); ++caff_it) {
                    caffinity_t *caff = caff_it->second;
                    if (!caff) continue;
                    
                    // Compute score and get connection status
                    caffinity_result_t result = caff->run_algorithm_caffinity();
                    const char *mac_cstr = result.mac;
                    double score = result.score;
                    
                    if (result.connected) {
                        // Process connected client
                        populate_caffinity_client_json(mac_cstr, score, get_local_time(tmp, sizeof(tmp), true),
                                                      conn_arr, unconn_arr, "ConnectedClients");
                        conn_sum_sq_iter += score * score;
                        connected_count++;
                    } else {
                        // Process unconnected client
                        populate_caffinity_client_json(mac_cstr, score, get_local_time(tmp, sizeof(tmp), true),
                                                      unconn_arr, conn_arr, "UnconnectedClients");
                        unconn_sum_sq_iter += score * score;
                        unconnected_count++;
                    }
                }
                
                // Calculate per-iteration RMS values (snapshot, no historical accumulation)
                double rms_connected = (connected_count > 0) ? sqrt(conn_sum_sq_iter / connected_count) : 0.0;
                double rms_unconnected = (unconnected_count > 0) ? sqrt(unconn_sum_sq_iter / unconnected_count) : 0.0;
                wifi_util_info_print(WIFI_CTRL, "%s:%d RMS connected %lf samples, RMS unconnected %lf samples\n",
                        __func__, __LINE__, rms_connected, rms_unconnected);
                // Update RMS aggregate JSON
                update_rms_aggregate_json(rms_connected, rms_unconnected);

                pthread_mutex_unlock(&m_json_lock);
            }
            update_caffinity_graph();
            count = hash_map_count(m_link_map);
            if (count == 0 ) {
                remove(m_args.output_file);
            }
            if (update_alarm) {
                start_time = tm;
                update_alarm = false;
                update_graph(out_obj);
                if (qmgr_is_batch_registered()) {
                    push_reporting_subdoc();   // batch mode
                }
            }
            pthread_mutex_lock(&m_lock);
        } else {
            wifi_util_error_print(WIFI_APPS,"%s:%d em exited with rc - %d",__func__,__LINE__,rc);
            pthread_mutex_unlock(&m_lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&m_lock);
    return 0;
}

cJSON *qmgr_t::create_dev_template(mac_addr_str_t mac_str,unsigned int vap_index)
{
    cJSON *obj, *lq_obj;
    char tmp[MAX_LINE_SIZE];
    unsigned int i;
    linkq_params_t *params;
    
    obj = cJSON_CreateObject();
    
    snprintf(tmp, sizeof(tmp), "MAC");
    cJSON_AddItemToObject(obj, tmp, cJSON_CreateString(mac_str));
    
    snprintf(tmp, sizeof(tmp), "VapIndex");
    cJSON_AddItemToObject(obj, tmp, cJSON_CreateNumber(vap_index));

    
    lq_obj = cJSON_CreateObject();
    snprintf(tmp, sizeof(tmp), "LinkQuality");
    cJSON_AddItemToObject(obj, tmp, lq_obj);
    
    params = linkq_t::get_score_params();
    for (i = 0; i < MAX_SCORE_PARAMS; i++) {
        snprintf(tmp, sizeof(tmp), "%s", params->name);
        cJSON_AddItemToObject(lq_obj, tmp, cJSON_CreateArray());
        
        params++;
    }
    
    snprintf(tmp, sizeof(tmp), "Alarms");
    cJSON_AddItemToObject(lq_obj, tmp, cJSON_CreateArray());
    
    snprintf(tmp, sizeof(tmp), "Time");
    cJSON_AddItemToObject(obj, tmp, cJSON_CreateArray());
    
    return obj;
}

cJSON *qmgr_t::create_caffinity_template(mac_addr_str_t mac_str)
{
    cJSON *obj, *caff_obj;
    
    obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "MAC", mac_str);
    
    caff_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(obj, "CAffinityScore", caff_obj);
    cJSON_AddItemToObject(caff_obj, "Score", cJSON_CreateArray());
    cJSON_AddItemToObject(caff_obj, "Time", cJSON_CreateArray());
    
    return obj;
}

void qmgr_t::deinit()
{
    m_exit = true;
    pthread_cond_signal(&m_cond);

    // Wait for thread to finish
    pthread_join(m_thread, NULL);
    pthread_cond_destroy(&m_cond);
    
    // Clean up caffinity map
    std::unordered_map<std::string, caffinity_t*>::iterator caff_it;
    for (caff_it = m_caffinity_map.begin(); caff_it != m_caffinity_map.end(); ++caff_it) {
        delete caff_it->second;
    }
    m_caffinity_map.clear();
    
    hash_map_destroy(m_link_map);
    wifi_util_info_print(WIFI_APPS," %s:%d\n",__func__,__LINE__);
    return;
}

void qmgr_t::deinit(mac_addr_str_t mac_str)
{
    wifi_util_info_print(WIFI_APPS," %s:%d\n",__func__,__LINE__);
    return;
}
 void qmgr_t::remove_device_from_out_obj(cJSON *out_obj, const char *mac_str)
{
    if (!out_obj || !mac_str) return;

    cJSON *dev_arr = cJSON_GetObjectItem(out_obj, "Devices");
    if (!dev_arr) return;

    int size = cJSON_GetArraySize(dev_arr);
    for (int i = 0; i < size; i++) {
        cJSON *dev = cJSON_GetArrayItem(dev_arr, i);
        const char *existing_mac = cJSON_GetStringValue(cJSON_GetObjectItem(dev, "MAC"));

        if (existing_mac && strcmp(existing_mac, mac_str) == 0) {
            cJSON_DeleteItemFromArray(dev_arr, i);
            wifi_util_info_print(WIFI_APPS,"Removed device %s from out_obj\n", mac_str);
            return;
        }
    }
}

int qmgr_t::reinit(server_arg_t *args)
{
    linkq_t *lq = NULL;
    if (args){
        wifi_util_info_print(WIFI_APPS," %s:%d sampling=%d args->reporting =%d args->threshold=%f\n"
	, __func__,__LINE__,args->sampling,args->reporting,args->threshold); 
    } else {
        wifi_util_info_print(WIFI_APPS," %s:%d err\n", __func__,__LINE__); 
        return -1;
    }
   
    memcpy(&m_args, args, sizeof(server_arg_t));
    int count = hash_map_count(m_link_map);
    wifi_util_info_print(WIFI_APPS," count=%d\n",count);
    lq = (linkq_t *)hash_map_get_first(m_link_map);
    while ((lq != NULL)) {
        if (count > 0){
            lq->reinit(args);
            lq = (linkq_t *)hash_map_get_next(m_link_map, lq);
            count--;
        }
    }
    return 0;
}
int qmgr_t::update_affinity_stats(stats_arg_t *arg, bool create_flag)
{
    wifi_util_info_print(WIFI_APPS,"CAFF qmgr_t %s:%d event=%d create_flag=%d\n",__func__,__LINE__, arg->event, create_flag);
    mac_addr_str_t mac_str;
    strncpy(mac_str, arg->mac_str, sizeof(mac_str) - 1);
    mac_str[sizeof(mac_str) - 1] = '\0';
    
    wifi_util_info_print(WIFI_CTRL, "CAFF qmgr_t %s:%d Processing MAC %s\n", __func__, __LINE__, mac_str);

    pthread_mutex_lock(&m_json_lock);

    /* ---------- CHECK MAP FOR EXISTING MAC ---------- */
    std::unordered_map<const char*, stats_arg_t>::iterator it;
    bool map_exists = false;

    for (it = m_affinity_map.begin(); it != m_affinity_map.end(); ++it) {
        if (strcmp(it->first, mac_str) == 0) {
            map_exists = true;
            break;
        }
    }

    /* ---------- GET / CREATE JSON ROOT ---------- */
    cJSON *affinity_root = cJSON_GetObjectItem(affinity_obj, "AffinityScore");

    if (!affinity_root) {
        affinity_root = cJSON_CreateObject();
        cJSON_AddItemToObject(affinity_obj, "AffinityScore", affinity_root);

        cJSON_AddItemToObject(affinity_root, "Connected_client", cJSON_CreateArray());
        cJSON_AddItemToObject(affinity_root, "UnConnected_client", cJSON_CreateArray());
    }

    cJSON *connected_arr =
        cJSON_GetObjectItem(affinity_root, "Connected_client");

    cJSON *unconnected_arr =
        cJSON_GetObjectItem(affinity_root, "UnConnected_client");

    /* ---------- DELETE CLIENT ---------- */
    if (!create_flag) {


        /* remove from JSON arrays */

        if (connected_arr) {
            for (int i = 0; i < cJSON_GetArraySize(connected_arr); i++) {
                cJSON *dev = cJSON_GetArrayItem(connected_arr, i);
                const char *existing_mac =
                    cJSON_GetStringValue(cJSON_GetObjectItem(dev, "MAC"));

                if (existing_mac && strcmp(existing_mac, mac_str) == 0) {
                    cJSON_DeleteItemFromArray(connected_arr, i);
                    break;
                }
            }
        }

        if (unconnected_arr) {
            for (int i = 0; i < cJSON_GetArraySize(unconnected_arr); i++) {
                cJSON *dev = cJSON_GetArrayItem(unconnected_arr, i);
                const char *existing_mac =
                    cJSON_GetStringValue(cJSON_GetObjectItem(dev, "MAC"));

                if (existing_mac && strcmp(existing_mac, mac_str) == 0) {
                    cJSON_DeleteItemFromArray(unconnected_arr, i);
                    break;
                }
            }
        }

        wifi_util_info_print(WIFI_APPS,
            "Removed client %s from affinity stats\n", mac_str);

        pthread_mutex_unlock(&m_json_lock);
        return 0;
    }

    /* ---------- ADD CLIENT ---------- */

    if (!map_exists) {

        /* create JSON entry using helper */
        cJSON *client = create_affinity_template(mac_str,arg->vap_index);

        cJSON_AddItemToArray(connected_arr, client);


        wifi_util_info_print(WIFI_APPS,
            "Added client %s to Connected_client\n", mac_str);
    }


    pthread_mutex_unlock(&m_json_lock);
    return 0;
}

bool qmgr_t::is_client_connected(const char *mac_str)
{
    if (!mac_str) {
        return false;
    }
    
    std::string mac_key(mac_str);
    pthread_mutex_lock(&m_json_lock);
    
    std::unordered_map<std::string, caffinity_t*>::iterator it = m_caffinity_map.find(mac_key);
    bool is_connected = false;
    
    if (it != m_caffinity_map.end() && it->second) {
        is_connected = it->second->get_connected();
    }
    
    pthread_mutex_unlock(&m_json_lock);
    
    wifi_util_dbg_print(WIFI_CTRL, "CAFF %s:%d MAC %s is_connected=%d\n",
        __func__, __LINE__, mac_str, is_connected);
    
    return is_connected;
}



int qmgr_t::init(stats_arg_t *stats, bool create_flag)
{
    char tmp[MAX_FILE_NAME_SZ];
    cJSON *dev_arr;
    mac_addr_str_t mac_str;

    strncpy(mac_str, stats->mac_str, sizeof(mac_str) - 1);
    mac_str[sizeof(mac_str) - 1] = '\0';

    snprintf(tmp, sizeof(tmp), "Devices");
    pthread_mutex_lock(&m_json_lock);
    dev_arr = cJSON_GetObjectItem(out_obj, tmp);
    if (!dev_arr) {
        dev_arr = cJSON_CreateArray();
        cJSON_AddItemToObject(out_obj, tmp, dev_arr);
    }

    // ---------- FIND EXISTING DEVICE ----------
    bool device_exists = false;
    for (int i = 0; i < cJSON_GetArraySize(dev_arr); i++) {
        cJSON *dev = cJSON_GetArrayItem(dev_arr, i);
        const char *existing_mac =
            cJSON_GetStringValue(cJSON_GetObjectItem(dev, "MAC"));
        if (existing_mac && strcmp(existing_mac, mac_str) == 0) {
            device_exists = true;
            break;
        }
    }

    // ---------- DELETE PATH ----------
    if (!create_flag) {
        if (device_exists) {
            wifi_util_info_print(WIFI_APPS,"Removing device %s\n", mac_str);

            // remove from Devices JSON
            remove_device_from_out_obj(out_obj, mac_str);
            // remove from hashmap
            linkq_t *lq = (linkq_t *)hash_map_get(m_link_map, mac_str);
            if (lq) {
                hash_map_remove(m_link_map, mac_str);
                delete lq;
            }
        } else {
            wifi_util_info_print(WIFI_APPS,"Device %s not found, nothing to delete\n", mac_str);
        }
        pthread_mutex_unlock(&m_json_lock);
        return 0;
    }

    // ---------- CREATE PATH ----------
    if (!device_exists) {
        wifi_util_info_print(WIFI_APPS,"Creating device %s vap_index=%d\n", mac_str, stats->vap_index);

        // Create linkq_t object and add to hashmap
        linkq_t *lq = new linkq_t(mac_str, stats->vap_index);
        if (lq) {
            lq->init(m_args.threshold, m_args.reporting, stats);
            hash_map_put(m_link_map, strdup(mac_str), lq);
            wifi_util_info_print(WIFI_APPS,"Added linkq_t for %s to m_link_map\n", mac_str);
        }

        // Create device JSON template and add to Devices array
        cJSON *dev_template = create_dev_template(mac_str, stats->vap_index);
        cJSON_AddItemToArray(dev_arr, dev_template);
        wifi_util_info_print(WIFI_APPS,"Added device %s to Devices JSON array (total devices now: %d)\n", 
            mac_str, cJSON_GetArraySize(dev_arr));
    } else {
        // Device exists, update stats
        linkq_t *lq = (linkq_t *)hash_map_get(m_link_map, mac_str);
        if (lq) {
            lq->init(m_args.threshold, m_args.reporting, stats);
            wifi_util_dbg_print(WIFI_APPS,"Updated stats for existing device %s\n", mac_str);
        }
    }

    pthread_mutex_unlock(&m_json_lock);
    return 0;
}
int qmgr_t::rapid_disconnect(stats_arg_t *stats)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
    if (!stats || stats->mac_str[0] == '\0') {
        wifi_util_error_print(WIFI_APPS, "%s:%d invalid stats or empty MAC\n", __func__, __LINE__);
        return -1;
    }
    mac_addr_str_t mac_str;

    strncpy(mac_str, stats->mac_str, sizeof(mac_str) - 1);
    mac_str[sizeof(mac_str) - 1] = '\0';
    wifi_util_info_print(WIFI_APPS,"%s:%d mac_str=%s\n",__func__,__LINE__,mac_str);

    pthread_mutex_lock(&m_json_lock);
    linkq_t *lq = (linkq_t *)hash_map_get(m_link_map, mac_str);
    if (lq) {
        lq->rapid_disconnect(stats);   
        wifi_util_dbg_print(WIFI_APPS,"%s:%d rapid_disconnect called for mac_str=%s\n",__func__,__LINE__,mac_str);
    }
    pthread_mutex_unlock(&m_json_lock);
    return 0;
}

int qmgr_t::caffinity_periodic_stats_update(stats_arg_t *stats)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
    if (!stats || stats->mac_str[0] == '\0') {
        wifi_util_error_print(WIFI_APPS, "%s:%d invalid stats or empty MAC\n", __func__, __LINE__);
        return -1;
    }
    update_affinity_stats(stats,true);

    mac_addr_str_t mac_str;
    strncpy(mac_str, stats->mac_str, sizeof(mac_str) - 1);
    mac_str[sizeof(mac_str) - 1] = '\0';

    wifi_util_info_print(WIFI_APPS,"%s:%d mac_str=%s connected_time=%ld.%09ld disconnected_time=%ld.%09ld cli_SNR=%d\n",
        __func__, __LINE__, mac_str,
        (long)stats->total_connected_time.tv_sec, stats->total_connected_time.tv_nsec,
        (long)stats->total_disconnected_time.tv_sec, stats->total_disconnected_time.tv_nsec,
        stats->dev.cli_SNR);

    pthread_mutex_lock(&m_json_lock);

    // Find or create caffinity_t object for this MAC
    std::string mac_key(mac_str);
    std::unordered_map<std::string, caffinity_t*>::iterator it = m_caffinity_map.find(mac_key);
    caffinity_t *caff = NULL;

    if (it == m_caffinity_map.end()) {
        // Create new caffinity object for this MAC
        wifi_util_info_print(WIFI_CTRL, "CAFF qmgr_t %s:%d Creating new caffinity_t for MAC %s\n",
            __func__, __LINE__, mac_str);
        mac_addr_str_t mac_str_array;
        strncpy(mac_str_array, mac_str, sizeof(mac_str_array) - 1);
        mac_str_array[sizeof(mac_str_array) - 1] = '\0';
        caff = new caffinity_t(&mac_str_array);
        if (caff) {
            m_caffinity_map[mac_key] = caff;
            wifi_util_info_print(WIFI_CTRL, "CAFF qmgr_t %s:%d Successfully created caffinity_t for MAC %s\n",
                __func__, __LINE__, mac_str);
        }
    } else {
        caff = it->second;
        wifi_util_info_print(WIFI_CTRL, "CAFF qmgr_t %s:%d Found existing caffinity_t for MAC %s\n",
            __func__, __LINE__, mac_str);
    }

    if (caff) {
        wifi_util_info_print(WIFI_CTRL, "CAFF qmgr_t %s:%d Calling caffinity_t::periodic_stats_update() for MAC %s\n",
            __func__, __LINE__, mac_str);
        caff->periodic_stats_update(stats);
    }

    pthread_mutex_unlock(&m_json_lock);
    return 0;
}


// static helper function for pthread
void* qmgr_t::run_helper(void* arg)
{
    wifi_util_info_print(WIFI_APPS," %s:%d\n",__func__,__LINE__);
    qmgr_t* mgr = static_cast<qmgr_t*>(arg);
    if (mgr) {
        wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
        mgr->run();
    }
    return NULL;
}

void qmgr_t::start_background_run()
{
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
    if (m_bg_running) {
        return;   // already running
    }
    m_bg_running = true;
    int ret = pthread_create(&m_thread, NULL, run_helper, this);
    if (ret != 0) {
        wifi_util_info_print(WIFI_APPS,"Failed to create background run thread\n");
    } else {
        wifi_util_info_print(WIFI_APPS,"created background run thread\n");
    }
    return;
}

char *qmgr_t::get_local_time(char *str, unsigned int len, bool hourformat)
{
    struct timeval tv;
    struct tm *local_time;
    
    gettimeofday(&tv, NULL); // Get current time into tv
    local_time = localtime(&tv.tv_sec);
    if(hourformat)
        strftime(str, len, "%M:%S", local_time);
    else
        strftime(str, len, "%Y-%m-%d %H:%M:%S", local_time);

    return str;
}

void qmgr_t::register_station_mac(const char* str)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
    linkq_t::register_station_mac(str);
    return;
}

void qmgr_t::unregister_station_mac(const char* str)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
    linkq_t::unregister_station_mac(str);
    reset_qmgr_score_cb();
    return;
}

int qmgr_t::set_max_snr_radios(radio_max_snr_t *max_snr_val)
{
    linkq_t::set_max_snr_radios(max_snr_val);
    return 0;   
}

qmgr_t::qmgr_t()
{
    memset(&m_args, 0, sizeof(server_arg_t));
    m_args.threshold = THRESHOLD;
    m_args.sampling = SAMPLING_INTERVAL;
    m_args.reporting = REPORTING_INTERVAL;
    snprintf(m_args.output_file, sizeof(m_args.output_file), "%s", "/www/data/telemetry.json");
    snprintf(m_args.path, sizeof(m_args.path), "%s", "/www/data");
    m_link_map = hash_map_create();
    out_obj = cJSON_CreateObject();
    affinity_obj = cJSON_CreateObject();
    
    // Initialize caffinity telemetry JSON with future-proof structure
    caffinity_out_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(caffinity_out_obj, "ConnectedClients", cJSON_CreateArray());
    cJSON_AddItemToObject(caffinity_out_obj, "UnconnectedClients", cJSON_CreateArray());
    
    // Initialize RMS_score structure
    cJSON *rms_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(rms_obj, "connected", cJSON_CreateArray());
    cJSON_AddItemToObject(rms_obj, "unconnected", cJSON_CreateArray());
    cJSON_AddItemToObject(rms_obj, "Time", cJSON_CreateArray());
    cJSON_AddItemToObject(caffinity_out_obj, "RMS_score", rms_obj);
    
    // Initialize RMS tracking variables
    m_rms_conn_sum_sq = 0.0;
    m_rms_conn_count = 0;
    m_rms_unconn_sum_sq = 0.0;
    m_rms_unconn_count = 0;
    m_rms_lq_sum_sq = 0.0;
    m_rms_lq_count = 0;
    
    m_bg_running = false;
    m_exit = false;
    pthread_mutex_init(&m_json_lock, NULL);
    pthread_mutex_init(&m_lock, NULL);
    pthread_cond_init(&m_cond, NULL);
}

qmgr_t::qmgr_t(server_arg_t *args,stats_arg_t *stats)
{
    memcpy(&m_args, args, sizeof(server_arg_t));
    memcpy(&m_stats, stats, sizeof(stats_arg_t));
    
    // Initialize caffinity telemetry JSON with future-proof structure
    caffinity_out_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(caffinity_out_obj, "ConnectedClients", cJSON_CreateArray());
    cJSON_AddItemToObject(caffinity_out_obj, "UnconnectedClients", cJSON_CreateArray());
    
    // Initialize RMS_score structure
    cJSON *rms_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(rms_obj, "connected", cJSON_CreateArray());
    cJSON_AddItemToObject(rms_obj, "unconnected", cJSON_CreateArray());
    cJSON_AddItemToObject(rms_obj, "Time", cJSON_CreateArray());
    cJSON_AddItemToObject(caffinity_out_obj, "RMS_score", rms_obj);
    
    // Initialize RMS tracking variables
    m_rms_conn_sum_sq = 0.0;
    m_rms_conn_count = 0;
    m_rms_unconn_sum_sq = 0.0;
    m_rms_unconn_count = 0;
    m_rms_lq_sum_sq = 0.0;
    m_rms_lq_count = 0;
    
    m_exit = false;
    m_bg_running = false;
    m_link_map = hash_map_create();
    out_obj = cJSON_CreateObject();
    affinity_obj = cJSON_CreateObject();
    pthread_mutex_init(&m_json_lock, NULL);
    pthread_mutex_init(&m_lock, NULL);
    pthread_cond_init(&m_cond, NULL);
}
void qmgr_t::destroy_instance()
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&lock);
    wifi_util_info_print(WIFI_APPS," %s:%d\n",__func__,__LINE__);

    if (instance) {
        instance->deinit();    // cleanup internal resources
        delete instance;       // call destructor
        instance = NULL;
    }

    pthread_mutex_unlock(&lock);
    return;
}

int qmgr_t::set_quality_flags(quality_flags_t *flag)
{
    linkq_t::set_quality_flags(flag);
    return 0;
}

int qmgr_t::get_quality_flags(quality_flags_t *flag)
{
    linkq_t::get_quality_flags(flag);
    return 0;
}
qmgr_t::~qmgr_t()
{
}

cJSON* qmgr_t::create_affinity_template(mac_addr_str_t mac_str,
                                unsigned int vap_index)
{
    char tmp[MAX_LINE_SIZE];
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddItemToObject(obj, "MAC", cJSON_CreateString(mac_str));
    cJSON_AddItemToObject(obj, "vapIndex", cJSON_CreateNumber(vap_index));
    
    snprintf(tmp, sizeof(tmp), "Score");
    cJSON_AddItemToObject(obj, tmp, cJSON_CreateArray());
    
    snprintf(tmp, sizeof(tmp), "Time");
    cJSON_AddItemToObject(obj, tmp, cJSON_CreateArray());
    return obj;
}

int qmgr_t::store_gw_mac(uint8_t *mac) 
{
    wifi_util_info_print(WIFI_APPS," %s:%d\n",__func__,__LINE__);
    memcpy(m_gw_mac,mac,sizeof(m_gw_mac));
   return 0;
}
int qmgr_t::get_gw_mac(uint8_t *mac)
{
    wifi_util_info_print(WIFI_APPS," %s:%d\n",__func__,__LINE__);
    if (!mac) {
        return -1;
    }

    memcpy(mac, m_gw_mac, sizeof(m_gw_mac));
    return 0;
}
