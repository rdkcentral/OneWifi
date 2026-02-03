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
#include <errno.h>
#include <math.h>
#include <cjson/cJSON.h>
#include "wifi_util.h"

qmgr_t* qmgr_t::instance = nullptr;
extern "C" void qmgr_invoke_batch(const report_batch_t *batch);

qmgr_t* qmgr_t::get_instance()
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&lock);

    if (instance == nullptr) {
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
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
    
    obj = cJSON_GetObjectItem(dev_obj, "LinkQuality");
 
    params = linkq_t::get_score_params();
    for (i = 0; i < MAX_SCORE_PARAMS; i++) {
        snprintf(tmp, sizeof(tmp), "%s", params->name);
        arr = cJSON_GetObjectItem(obj, tmp);
        
        cJSON_AddItemToArray(arr, cJSON_CreateNumber(v.m_val[i].m_re));
        trim_cjson_array(arr, MAX_HISTORY);
        params++;
    }
   #if 0 
    if (v.m_num == 0) {
        wifi_util_error_print(WIFI_APPS,"ERROR: vector_t has m_num=0 for MAC %s\n", str);
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
    #endif

    if (v.m_num > MAX_LEN) {
        wifi_util_error_print(WIFI_APPS,"ERROR: Invalid m_num=%d (MAX_LEN=%d) for MAC %s\n", v.m_num, MAX_LEN, str);
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
    cJSON *ca_obj = cJSON_GetObjectItem(dev_obj, "ConnectionAffinity");
    if (ca_obj) {
        cJSON *score_arr = cJSON_GetObjectItem(ca_obj, "Score");
        if (score_arr) {
        double last_val = 0.5; // default if array is empty

        int size = cJSON_GetArraySize(score_arr);
        if (size > 0) {
            cJSON *last_item = cJSON_GetArrayItem(score_arr, size - 1);
            last_val = last_item->valuedouble;
        }

        // Smooth: add small random delta between -0.02 and +0.02
        double delta = ((rand() % 5) - 2) * 0.01; // -0.02, -0.01, 0, 0.01, 0.02
        double val = last_val + delta;

        // Clamp between 0 and 1
        if (val < 0.0) val = 0.0;
        if (val > 1.0) val = 1.0;

        cJSON_AddItemToArray(score_arr, cJSON_CreateNumber(val));
        trim_cjson_array(score_arr, MAX_HISTORY);
    }

    cJSON *time_arr = cJSON_GetObjectItem(ca_obj, "Time");
    cJSON_AddItemToArray(time_arr, cJSON_CreateString(get_local_time(tmp, sizeof(tmp), true)));
    trim_cjson_array(time_arr, MAX_HISTORY);
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

char* qmgr_t::update_graph()
{
    pthread_mutex_lock(&m_json_lock);
    char *json = cJSON_PrintUnformatted(out_obj);
    wifi_util_dbg_print(WIFI_APPS,"%s:%d ijson=%s\n",__func__,__LINE__,json); 

    pthread_mutex_unlock(&m_json_lock);
    return json;
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
    wifi_util_dbg_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return 0;
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
            while (lq != NULL) {
                v = lq->run_test(alarm,update_alarm, rapid_disconnect);
                // Skip if run_test returned invalid/no data
                if (v.m_num == 0 && !rapid_disconnect) {
                    wifi_util_dbg_print(WIFI_APPS,
                        "%s:%d: Skipping device %s as no valid data available\n",
                        __func__, __LINE__, lq->get_mac_addr());
                    lq = (linkq_t *)hash_map_get_next(m_link_map, lq);
                    continue;
                }
                strncpy(mac_str, lq->get_mac_addr(), sizeof(mac_str) - 1);
                mac_str[sizeof(mac_str) - 1] = '\0';
                update_json(mac_str, v, out_obj, alarm);
                lq = (linkq_t *)hash_map_get_next(m_link_map, lq);
            }
            count = hash_map_count(m_link_map);
            if (update_alarm) {
                start_time = tm;
                update_alarm = false;
                if (qmgr_is_batch_registered) {
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
    cJSON *obj, *lq_obj, *ca_obj;
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
    
    ca_obj = cJSON_CreateObject();
    snprintf(tmp, sizeof(tmp), "ConnectionAffinity");
    cJSON_AddItemToObject(obj, tmp, ca_obj);
       
    cJSON *score_arr = cJSON_CreateArray();
    snprintf(tmp, sizeof(tmp), "Time");

    cJSON_AddItemToObject(ca_obj, "Score", score_arr);
    cJSON_AddItemToObject(ca_obj, tmp, cJSON_CreateArray());

    snprintf(tmp, sizeof(tmp), "Alarms");
    cJSON_AddItemToObject(ca_obj, tmp, cJSON_CreateArray());
    
    snprintf(tmp, sizeof(tmp), "Time");
    cJSON_AddItemToObject(obj, tmp, cJSON_CreateArray());
    
    return obj;
}

void qmgr_t::deinit()
{
    wifi_util_info_print(WIFI_APPS,"Pramod %s:%d\n",__func__,__LINE__);
    m_exit = true;
    pthread_cond_signal(&m_cond);

    // Wait for thread to finish
    if (m_run_started) {
        pthread_join(m_thread, nullptr);
        m_run_started = false;
    }
    pthread_cond_destroy(&m_cond);
    hash_map_destroy(m_link_map);
    wifi_util_info_print(WIFI_APPS,"Pramod %s:%d\n",__func__,__LINE__);
    return;
}

void qmgr_t::deinit(mac_addr_str_t mac_str)
{
    wifi_util_info_print(WIFI_APPS,"Pramod %s:%d\n",__func__,__LINE__);
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
    wifi_util_info_print(WIFI_APPS," %s:%d\n", __func__,__LINE__);
    if (args){
        wifi_util_info_print(WIFI_APPS," %s:%d args->reporting =%d args->threshold=%f\n", __func__,__LINE__,args->reporting,args->threshold); 
    } else {
        wifi_util_info_print(WIFI_APPS," %s:%d err\n", __func__,__LINE__); 
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
        wifi_util_info_print(WIFI_APPS,"Adding new device %s\n", mac_str);
        cJSON_AddItemToArray(dev_arr, create_dev_template(mac_str, stats->vap_index));
    }

    linkq_t *lq = (linkq_t *)hash_map_get(m_link_map, mac_str);
    if (!lq) {
        lq = new linkq_t(mac_str, stats->vap_index);
        hash_map_put(m_link_map, strdup(mac_str), lq);
    }

    wifi_util_dbg_print(WIFI_APPS,"Initializing linkq for %s\n", mac_str);
    lq->init(m_args.threshold,
             m_args.reporting ,
             stats);
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
        wifi_util_info_print(WIFI_APPS,"%s:%d rapid_disconnect called for mac_str=%s\n",__func__,__LINE__,mac_str);
    }
    pthread_mutex_unlock(&m_json_lock);
    return 0;
}

// static helper function for pthread
void* qmgr_t::run_helper(void* arg)
{
    wifi_util_info_print(WIFI_APPS,"Pramod %s:%d\n",__func__,__LINE__);
    qmgr_t* mgr = static_cast<qmgr_t*>(arg);
    if (mgr) {
        wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
        mgr->run();
    }
    return nullptr;
}

void qmgr_t::start_background_run()
{
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
    if (m_bg_running) {
        return;   // already running
    }
    m_bg_running = true;
    int ret = pthread_create(&m_thread, nullptr, run_helper, this);
    if (ret != 0) {
        wifi_util_info_print(WIFI_APPS,"Failed to create background run thread\n");
    } else {
        wifi_util_info_print(WIFI_APPS,"created background run thread\n");
    }
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
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

qmgr_t::qmgr_t()
{
    memset(&m_args, 0, sizeof(server_arg_t));
    m_args.threshold = THRESHOLD;
    m_args.sampling = SAMPLING_INTERVAL;
    m_args.reporting = REPORTING_INTERVAL;
    m_link_map = hash_map_create();
    out_obj = cJSON_CreateObject();
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
    m_exit = false;
    m_bg_running = false;
    m_link_map = hash_map_create();
    out_obj = cJSON_CreateObject();
    pthread_mutex_init(&m_json_lock, NULL);
    pthread_mutex_init(&m_lock, NULL);
    pthread_cond_init(&m_cond, NULL);
}
void qmgr_t::destroy_instance()
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&lock);
    wifi_util_info_print(WIFI_APPS,"Pramod %s:%d\n",__func__,__LINE__);

    if (instance) {
        instance->deinit();    // cleanup internal resources
        delete instance;       // call destructor
        instance = nullptr;
    }

    pthread_mutex_unlock(&lock);
    return;
}

qmgr_t::~qmgr_t()
{
}

