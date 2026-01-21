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
extern "C" void qmgr_invoke_callback(const report_batch_t *batch);


qmgr_t* qmgr_t::get_instance(server_arg_t *args)
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
    pthread_mutex_lock(&lock);

    if (instance == nullptr) {
        instance = new qmgr_t(args);
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
 
    params = linkq_t::get_linkq_params();
    for (i = 0; i < MAX_LINKQ_PARAMS; i++) {
        snprintf(tmp, sizeof(tmp), "%s", params->name);
        arr = cJSON_GetObjectItem(obj, tmp);
        
        cJSON_AddItemToArray(arr, cJSON_CreateNumber(v.m_val[i].m_re));
        trim_cjson_array(arr, MAX_HISTORY);
        params++;
    }
    
    if (v.m_num == 0) {
        wifi_util_error_print(WIFI_APPS,"ERROR: vector_t has m_num=0 for MAC %s\n", str);
        pthread_mutex_unlock(&m_json_lock);
        return;
    }

    if (v.m_num > MAX_LEN) {
        wifi_util_error_print(WIFI_APPS,"ERROR: Invalid m_num=%d (MAX_LEN=%d) for MAC %s\n", v.m_num, MAX_LEN, str);
        pthread_mutex_unlock(&m_json_lock);
        return;
    }
    arr = cJSON_GetObjectItem(obj, "Score");
    if (!arr) {
        wifi_util_error_print(WIFI_APPS,"ERROR: Missing Score array for MAC %s\n", str);
        pthread_mutex_unlock(&m_json_lock);
        return;
    }


    cJSON_AddItemToArray(arr, cJSON_CreateNumber(v.m_val[v.m_num - 1].m_re));
    trim_cjson_array(arr, MAX_HISTORY);
    arr = cJSON_GetObjectItem(obj, "Alarms");
    cJSON_AddItemToArray(arr, cJSON_CreateString((alarm == true)?get_local_time(tmp, sizeof(tmp),false):""));
    trim_cjson_array(arr, MAX_HISTORY);
    arr = cJSON_GetObjectItem(dev_obj, "Time");
    cJSON_AddItemToArray(arr,cJSON_CreateString(get_local_time(tmp, sizeof(tmp),true)));
    trim_cjson_array(arr, MAX_HISTORY);
    pthread_mutex_unlock(&m_json_lock);
    return;
}

void qmgr_t::update_graph( cJSON *out_obj)
{
    pthread_mutex_lock(&m_json_lock);
    wifi_util_dbg_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    char *json = cJSON_PrintUnformatted(out_obj);
    FILE *fp = fopen(m_args.output_file, "w");
    if (fp) {
        fputs(json, fp);
        fclose(fp);
    }
    free(json);
    pthread_mutex_unlock(&m_json_lock);
    return ;
}
int qmgr_t::push_reporting_subdoc()
{
    linkq_t *lq;
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d \n",__func__,__LINE__); 
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
    wifi_util_error_print(WIFI_CTRL,"%s:%d Executing callback\n",__func__,__LINE__);
    qmgr_invoke_callback(report);
    wifi_util_error_print(WIFI_CTRL,"%s:%d Executed callback\n",__func__,__LINE__);

    // Free everything after callback
    for (size_t i = 0; i < report->link_count; i++) {
        free(report->links[i].samples);
    }
    free(report->links);
    free(report);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d \n",__func__,__LINE__); 
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
    long elapsed_sec  = 0;
    bool update_alarm = false;
    gettimeofday(&start_time, NULL);
    wifi_util_info_print(WIFI_CTRL,"%s:%d:%d:%f:%d\n",m_args.output_file, m_args.sampling, m_args.reporting,m_args.threshold,__LINE__);
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
	    wifi_util_info_print(WIFI_APPS,"%s:%d reporting=%d thrshold=%f\n" ,__func__,__LINE__,m_args.reporting,m_args.threshold);
            lq = (linkq_t *)hash_map_get_first(m_link_map);
            while (lq != NULL) {
                v = lq->run_test(alarm,update_alarm);
                // Skip if run_test returned invalid/no data
                if (v.m_num == 0) {
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
            if (count == 0 ) {
                remove(m_args.output_file);
                //wifi_util_info_print(WIFI_CTRL,"output_file = %s\n",m_args.output_file);
            }
            if (update_alarm && count != 0) {

                start_time = tm;
                update_alarm = false;
                update_graph(out_obj);
                push_reporting_subdoc(); 
             }
             pthread_mutex_lock(&m_lock);
        } else {
            wifi_util_error_print(WIFI_CTRL,"%s:%d em exited with rc - %d",__func__,__LINE__,rc);
            pthread_mutex_unlock(&m_lock);
            return -1;
        }
    }
    pthread_mutex_unlock(&m_lock);

    return 0;
}

cJSON *qmgr_t::create_dev_template(mac_addr_str_t mac_str)
{
    cJSON *obj, *lq_obj, *ca_obj;
    char tmp[MAX_LINE_SIZE];
    unsigned int i;
    linkq_params_t *params;
    
    obj = cJSON_CreateObject();
    
    snprintf(tmp, sizeof(tmp), "MAC");
    cJSON_AddItemToObject(obj, tmp, cJSON_CreateString(mac_str));
    
    lq_obj = cJSON_CreateObject();
    snprintf(tmp, sizeof(tmp), "LinkQuality");
    cJSON_AddItemToObject(obj, tmp, lq_obj);
    
    params = linkq_t::get_linkq_params();
    for (i = 0; i < MAX_LINKQ_PARAMS; i++) {
        snprintf(tmp, sizeof(tmp), "%s", params->name);
        cJSON_AddItemToObject(lq_obj, tmp, cJSON_CreateArray());
        
        params++;
    }
    
    snprintf(tmp, sizeof(tmp), "Score");
    cJSON_AddItemToObject(lq_obj, tmp, cJSON_CreateArray());
    
    snprintf(tmp, sizeof(tmp), "Alarms");
    cJSON_AddItemToObject(lq_obj, tmp, cJSON_CreateArray());
    
    ca_obj = cJSON_CreateObject();
    snprintf(tmp, sizeof(tmp), "ConnectionAffinity");
    cJSON_AddItemToObject(obj, tmp, ca_obj);
    
    snprintf(tmp, sizeof(tmp), "Alarms");
    cJSON_AddItemToObject(ca_obj, tmp, cJSON_CreateArray());
    
    snprintf(tmp, sizeof(tmp), "Time");
    cJSON_AddItemToObject(obj, tmp, cJSON_CreateArray());
    
    return obj;
}

void qmgr_t::deinit()
{
    hash_map_destroy(m_link_map);
    pthread_mutex_destroy(&m_lock);
    pthread_cond_destroy(&m_cond);
}
void qmgr_t::deinit(mac_addr_str_t mac_str)
{
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
   linkq_t *lq;
   wifi_util_info_print(WIFI_APPS," %s:%d\n", __func__,__LINE__);
   memcpy(&m_args, args, sizeof(server_arg_t));
   lq = (linkq_t *)hash_map_get_first(m_link_map);
   while (lq != NULL) {
       lq->reinit(args);
       lq = (linkq_t *)hash_map_get_next(m_link_map, lq);
  }
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
        cJSON_AddItemToArray(dev_arr, create_dev_template(mac_str));
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

// static helper function for pthread
void* qmgr_t::run_helper(void* arg)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__);
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
    m_run_started = true;

    pthread_t tid;
    int ret = pthread_create(&tid, nullptr, run_helper, this);
    if (ret != 0) {
        wifi_util_info_print(WIFI_APPS,"Failed to create background run thread\n");
    } else {
        pthread_detach(tid);  // detach to run independently
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

qmgr_t::qmgr_t(server_arg_t *args)
{
    memcpy(&m_args, args, sizeof(server_arg_t));
    m_link_map = hash_map_create();
    out_obj = cJSON_CreateObject();
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
    m_link_map = hash_map_create();
    out_obj = cJSON_CreateObject();
    pthread_mutex_init(&m_json_lock, NULL);
    pthread_mutex_init(&m_lock, NULL);
    pthread_cond_init(&m_cond, NULL);
}

qmgr_t::~qmgr_t()
{
}

