/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2018 RDK Management
  
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
  http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include "const.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "scheduler.h"
#include <unistd.h>
#include <pthread.h>
#include <rbus.h>
#include <libgen.h>
#include <pcap.h>
#include "wifi_hal_rdk.h"
#include "errno.h"
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "webconfig_external_proto_ovsdb.h"
#include "wifi_webconfig_consumer.h"
#include "ieee80211.h"
#include "webconfig_consumer_cli.h"

#define WPA3_SECURITY_SCHEMA

#define MAX_NUM_CLIENTS 64
#define MAX_NUM_CONFIG  16//Used for steering_Config

webconfig_consumer_t    webconfig_consumer;
webconfig_external_ovsdb_t    ext_proto;
BOOL is_ovs_init = false;
BOOL dml_init_sync = false;
BOOL enable_ovsdb = false;
BOOL debug_enable = false;
void free_ovs_schema_structs();
void dump_subdoc(const char *str, webconfig_subdoc_type_t type);
wifi_vap_info_t *get_wifi_radio_vap_info(rdk_wifi_radio_t *wifi_radio, const char *vap_name_prefix);
rdk_wifi_vap_info_t *get_wifi_radio_rdkvap_info(rdk_wifi_radio_t *wifi_radio, const char *vap_name_prefix);
char *read_subdoc_input_param_from_file(char *file_path);

static unsigned long long int cmd_start_time = 0;
static unsigned int cmd_delta_time = 0;
unsigned long long int get_current_time_ms(void)
{
    struct timeval tv_now = { 0 };
    unsigned long long int milliseconds = 0;
    gettimeofday(&tv_now, NULL);
    milliseconds = (tv_now.tv_sec*1000LL + tv_now.tv_usec/1000);
    return milliseconds;
}

webconfig_consumer_t *get_consumer_object()
{
    return &webconfig_consumer;
}

webconfig_error_t   app_free_macfilter_entries(webconfig_subdoc_data_t *data)
{
    unsigned int i, j;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    rdk_wifi_vap_info_t *rdk_vap;
    acl_entry_t *temp_acl_entry, *acl_entry;
    mac_addr_str_t mac_str;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        printf("%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];

        for (j = 0; j < radio->vaps.num_vaps; j++) {
            rdk_vap = &decoded_params->radios[i].vaps.rdk_vap_array[j];
            if (rdk_vap == NULL){
                continue;
            }
            if(rdk_vap->acl_map != NULL) {
                acl_entry = hash_map_get_first(rdk_vap->acl_map);
                while(acl_entry != NULL) {
                    to_mac_str(acl_entry->mac,mac_str);
                    acl_entry = hash_map_get_next(rdk_vap->acl_map,acl_entry);
                    temp_acl_entry = hash_map_remove(rdk_vap->acl_map, mac_str);
                    if (temp_acl_entry != NULL) {
                        free(temp_acl_entry);
                    }
                }
                hash_map_destroy(rdk_vap->acl_map);
                rdk_vap->acl_map = NULL;
            }
        }
    }
    return webconfig_error_none;
}

int push_data_to_consumer_queue(const void *msg, unsigned int len, wifi_event_type_t type, wifi_event_subtype_t sub_type)
{
    consumer_event_t *data;
    webconfig_consumer_t *consumer = &webconfig_consumer;

    printf("%s:%d start send data to consumer queue[%d] type:%d sub_type:%d\r\n",__func__, __LINE__, len, type, sub_type);
    data = (consumer_event_t *)malloc(sizeof(consumer_event_t));
    if(data == NULL) {
        printf("RDK_LOG_WARN, WIFI %s: data malloc null\n",__FUNCTION__);
        return RETURN_ERR;
    }

    data->event_type = type;
    data->sub_type = sub_type;

    data->msg = malloc(len + 1);
    if(data->msg == NULL) {
        printf("RDK_LOG_WARN,,,WIFI %s: data message malloc null\n",__FUNCTION__);
        free(data);
        return RETURN_ERR;
    }
    /* copy msg to data */
    memcpy(data->msg, msg, len);
    data->len = len;

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    pthread_mutex_lock(&consumer->lock);
    queue_push(consumer->queue, data);
    pthread_cond_signal(&consumer->cond);
    pthread_mutex_unlock(&consumer->lock);
    return RETURN_OK;
}

webconfig_error_t webconfig_consumer_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

int init_queue(webconfig_consumer_t *consumer)
{
    pthread_condattr_t cond_attr;

    clock_gettime(CLOCK_MONOTONIC, &consumer->last_signalled_time);
    clock_gettime(CLOCK_MONOTONIC, &consumer->last_polled_time);
    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&consumer->cond, &cond_attr);
    pthread_condattr_destroy(&cond_attr);
    pthread_mutex_init(&consumer->lock, NULL);
    consumer->poll_period = QUEUE_WIFI_CTRL_TASK_TIMEOUT;

    /*Intialize the scheduler*/
    consumer->sched = scheduler_init();
    if (consumer->sched == NULL) {
        printf( "RDK_LOG_WARN, WIFI %s: control monitor scheduler init failed\n", __FUNCTION__);
        return -1;
    }

    consumer->queue = queue_create();
    if (consumer->queue == NULL) {
        printf("RDK_LOG_WARN, WIFI %s: control monitor queue create failed\n",__FUNCTION__);
        return -1;
    }

    return 0;
}

int init_tests(webconfig_consumer_t *consumer)
{
    init_queue(consumer);

    //Initialize Webconfig Framework
    consumer->webconfig.initializer = webconfig_initializer_ovsdb;
    consumer->webconfig.apply_data = (webconfig_apply_data_t)webconfig_consumer_apply;

    if (webconfig_init(&consumer->webconfig) != webconfig_error_none) {
        printf("[%s]:%d Init WiFi Web Config  fail\n",__FUNCTION__,__LINE__);
        return -1;
    }

    consumer->rbus_events_subscribed = false;

#ifndef WEBCONFIG_TESTS_OVER_QUEUE
    if (webconfig_consumer_register(consumer) != webconfig_error_none) {
        printf("[%s]:%d Init WiFi Web Config  fail\n",__FUNCTION__,__LINE__);
        // unregister and deinit everything
        return RETURN_ERR;
    }

#endif

    return 0;
}

hash_map_t** get_sample_app_acl_hash_map(unsigned int radio_index, unsigned int vap_index)
{
    webconfig_consumer_t *consumer = get_consumer_object();
    if (consumer == NULL) {
        printf("%s %d NULL Pointer\n", __func__, __LINE__);
        return NULL;
    }

    return &(consumer->radios[radio_index].vaps.rdk_vap_array[vap_index].acl_map);
}

void mac_filter_sample_app_vap_cache_update(int radio_index, int vap_array_index)
{
    //webconfig decode allocate mem for the hash map which is getting cleared and destroyed here
    hash_map_t** acl_dev_map = get_sample_app_acl_hash_map(radio_index, vap_array_index);
    if(*acl_dev_map) {
        acl_entry_t *temp_acl_entry, *acl_entry;
        mac_addr_str_t mac_str;
        acl_entry = hash_map_get_first(*acl_dev_map);
        while (acl_entry != NULL) {
            to_mac_str(acl_entry->mac,mac_str);
            acl_entry = hash_map_get_next(*acl_dev_map,acl_entry);
            temp_acl_entry = hash_map_remove(*acl_dev_map, mac_str);
            if (temp_acl_entry != NULL) {
                free(temp_acl_entry);
            }
        }
        hash_map_destroy(*acl_dev_map);
    }
}

void update_sample_app_subdoc_vap_data(webconfig_consumer_t *consumer, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *params;
    unsigned int i, j;
    wifi_vap_info_map_t *recv_maps;
    wifi_vap_info_t *recv_vaps;
    wifi_vap_info_map_t *local_vap_maps;
    wifi_vap_info_t *local_vaps;

    params = &data->u.decoded;
    printf("%s:%d subdoc parse and update sample app global cache:%d\n",__func__, __LINE__, data->type);
    for (i = 0; i < params->num_radios; i++) {
        recv_maps = &params->radios[i].vaps.vap_map;
        local_vap_maps = &consumer->radios[i].vaps.vap_map;
        for (j = 0; j < recv_maps->num_vaps; j++) {
            recv_vaps = &recv_maps->vap_array[j];
            local_vaps = &local_vap_maps->vap_array[j];

            switch (data->type) {
                case webconfig_subdoc_type_private:
                    if (is_vap_private(&params->hal_cap.wifi_prop, recv_vaps->vap_index) && (strlen(recv_vaps->vap_name))) {
                        memcpy(local_vaps, recv_vaps, sizeof(wifi_vap_info_t));
                    }
                    break;
                case webconfig_subdoc_type_home:
                    if (is_vap_xhs(&params->hal_cap.wifi_prop, recv_vaps->vap_index)) {
                        memcpy(local_vaps, recv_vaps, sizeof(wifi_vap_info_t));
                    }
                    break;
                case webconfig_subdoc_type_xfinity:
                    if (is_vap_hotspot(&params->hal_cap.wifi_prop, recv_vaps->vap_index)) {
                        memcpy(local_vaps, recv_vaps, sizeof(wifi_vap_info_t));
                    }
                    break;
                case webconfig_subdoc_type_mesh:
                    if (is_vap_mesh(&params->hal_cap.wifi_prop, recv_vaps->vap_index)) {
                        mac_filter_sample_app_vap_cache_update(i, j);
                        memcpy(local_vaps, recv_vaps, sizeof(wifi_vap_info_t));
                        consumer->radios[i].vaps.rdk_vap_array[j].acl_map = params->radios[i].vaps.rdk_vap_array[j].acl_map;
                        consumer->radios[i].vaps.rdk_vap_array[j].vap_index = params->radios[i].vaps.rdk_vap_array[j].vap_index;
                    }
                    break;
                case webconfig_subdoc_type_mesh_backhaul:
                    if (is_vap_mesh_backhaul(&params->hal_cap.wifi_prop, recv_vaps->vap_index)) {
                        mac_filter_sample_app_vap_cache_update(i, j);
                        memcpy(local_vaps, recv_vaps, sizeof(wifi_vap_info_t));
                        consumer->radios[i].vaps.rdk_vap_array[j].acl_map = params->radios[i].vaps.rdk_vap_array[j].acl_map;
                        consumer->radios[i].vaps.rdk_vap_array[j].vap_index = params->radios[i].vaps.rdk_vap_array[j].vap_index;
                    }
                    break;
                case webconfig_subdoc_type_mesh_sta:
                    if (is_vap_mesh_sta(&params->hal_cap.wifi_prop, recv_vaps->vap_index)) {
                        memcpy(local_vaps, recv_vaps, sizeof(wifi_vap_info_t));
                    }
                    break;
                default:
                    printf("%s %d Invalid subdoc parse:%d\n",__func__, __LINE__, data->type);
                    break;
            }
        }
    }
}

void mac_filter_sample_app_cache_update(webconfig_subdoc_data_t *data)
{
    int itr, itrj;

    //webconfig decode allocate mem for the hash map which is getting cleared and destroyed here
    for (itr=0; itr<(int)data->u.decoded.num_radios; itr++) {
        for(itrj = 0; itrj < MAX_NUM_VAP_PER_RADIO; itrj++) {
            hash_map_t** acl_dev_map = get_sample_app_acl_hash_map(itr,itrj);
            if(*acl_dev_map) {
                acl_entry_t *temp_acl_entry, *acl_entry;
                mac_addr_str_t mac_str;
                acl_entry = hash_map_get_first(*acl_dev_map);
                while (acl_entry != NULL) {
                    to_mac_str(acl_entry->mac,mac_str);
                    acl_entry = hash_map_get_next(*acl_dev_map,acl_entry);
                    temp_acl_entry = hash_map_remove(*acl_dev_map, mac_str);
                    if (temp_acl_entry != NULL) {
                        free(temp_acl_entry);
                    }
                }
                hash_map_destroy(*acl_dev_map);
            }
        }
    }
}

void sample_app_cache_update(webconfig_consumer_t *consumer, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *params;
    unsigned int i;

    switch(data->type) {
        case webconfig_subdoc_type_radio:
            params = &data->u.decoded;
            for (i = 0; i < params->num_radios; i++) {
                printf("%s %d sample app radio[%d] cache update\r\n", __func__, __LINE__, i);
                memcpy(&consumer->radios[i].oper, &params->radios[i].oper, sizeof(params->radios[i].oper));
            }
            break;
        case webconfig_subdoc_type_dml:
            printf("%s:%d subdoc parse and update sample app global cache:%d\n",__func__, __LINE__, data->type);
            mac_filter_sample_app_cache_update(data);
            memcpy((unsigned char *)&consumer->radios, (unsigned char *)&data->u.decoded.radios, data->u.decoded.num_radios*sizeof(rdk_wifi_radio_t));
            memcpy((unsigned char *)&consumer->config, (unsigned char *)&data->u.decoded.config, sizeof(wifi_global_config_t));
            memcpy((unsigned char *)&consumer->hal_cap,(unsigned char *)&data->u.decoded.hal_cap, sizeof(wifi_hal_capability_t));
            consumer->hal_cap.wifi_prop.numRadios = data->u.decoded.num_radios;
            break;
        default:
            update_sample_app_subdoc_vap_data(consumer, data);
            break;
    }
}

void handle_webconfig_subdoc_test_result(webconfig_subdoc_type_t subdoc_type, webconfig_consumer_t *consumer)
{
    switch (subdoc_type) {
        case webconfig_subdoc_type_dml:
            if (consumer->test_state == consumer_test_state_radio_subdoc_test_pending) {
                consumer->radio_test_pending_count = 0;
                consumer->test_state = consumer_test_state_radio_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: Radio set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            } else if (consumer->test_state == consumer_test_state_private_subdoc_test_pending) {
                consumer->private_test_pending_count = 0;
                consumer->test_state = consumer_test_state_private_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: consumer vap private set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            } else if (consumer->test_state == consumer_test_state_mesh_subdoc_test_pending) {
                consumer->mesh_test_pending_count = 0;
                consumer->test_state = consumer_test_state_mesh_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: consumer vap mesh set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            } else if (consumer->test_state == consumer_test_state_xfinity_subdoc_test_pending) {
                consumer->xfinity_test_pending_count = 0;
                consumer->test_state = consumer_test_state_xfinity_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: consumer vap xfinity set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            } else if (consumer->test_state == consumer_test_state_home_subdoc_test_pending) {
                consumer->home_test_pending_count = 0;
                consumer->test_state = consumer_test_state_home_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: consumer Vap home set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            } else if (consumer->test_state == consumer_test_state_macfilter_subdoc_test_pending) {
                consumer->macfilter_test_pending_count = 0;
                consumer->test_state = consumer_test_state_macfilter_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: macfilter set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            } else if (consumer->test_state == consumer_test_state_band_steer_config_test_pending) {
                consumer->steer_config_test_pending_count = 0;
                consumer->test_state = consumer_test_state_band_steer_config_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: steer config set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            } else {
                consumer->test_state = consumer_test_state_cache_init_complete;
                printf("%s:%d: Cache init successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            }
        break;

        case webconfig_subdoc_type_radio:
            if (consumer->test_state == consumer_test_state_radio_subdoc_test_pending) {
                consumer->radio_test_pending_count = 0;
                consumer->test_state = consumer_test_state_radio_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: Radio set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            }
        break;

        case webconfig_subdoc_type_private:
            if (consumer->test_state == consumer_test_state_private_subdoc_test_pending) {
                consumer->private_test_pending_count = 0;
                consumer->test_state = consumer_test_state_private_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: consumer vap private set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            }
        break;

        case webconfig_subdoc_type_home:
            if (consumer->test_state == consumer_test_state_home_subdoc_test_pending) {
                consumer->home_test_pending_count = 0;
                consumer->test_state = consumer_test_state_home_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: consumer Vap home set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            }
        break;

        case webconfig_subdoc_type_xfinity:
            if (consumer->test_state == consumer_test_state_xfinity_subdoc_test_pending) {
                consumer->xfinity_test_pending_count = 0;
                consumer->test_state = consumer_test_state_xfinity_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: consumer vap xfinity set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            }
        break;

        case webconfig_subdoc_type_mesh_backhaul:
        case webconfig_subdoc_type_mesh:
            if (consumer->test_state == consumer_test_state_mesh_subdoc_test_pending) {
                consumer->mesh_test_pending_count = 0;
                consumer->test_state = consumer_test_state_mesh_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: consumer vap mesh set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            }
        break;

        case webconfig_subdoc_type_mac_filter:
            if (consumer->test_state == consumer_test_state_macfilter_subdoc_test_pending) {
                consumer->macfilter_test_pending_count = 0;
                consumer->test_state = consumer_test_state_macfilter_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: macfilter set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            }
        break;

        case webconfig_subdoc_type_steering_config:
            if (consumer->test_state == consumer_test_state_band_steer_config_test_pending) {
                consumer->steer_config_test_pending_count = 0;
                consumer->test_state = consumer_test_state_band_steer_config_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: steer config set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            }
        break;

        case webconfig_subdoc_type_lnf:
            if (consumer->test_state == consumer_test_state_lnf_subdoc_test_pending) {
                consumer->lnf_test_pending_count = 0;
                consumer->test_state = consumer_test_state_lnf_subdoc_test_complete;
                cmd_delta_time = get_current_time_ms() - cmd_start_time;
                printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                printf("%s:%d: consumer Vap lnf set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
            }
        break;

        case webconfig_subdoc_type_mesh_sta:
            printf("%s:%d: Cache init successful, mesh_sta subdoc Test State:%d\n", __func__, __LINE__,
                                consumer->test_state);
        break;

        default:
            printf("%s:%d: Unknown webconfig subdoc type:%d\n", __func__, __LINE__, subdoc_type);
        break;
    }
}

void handle_webconfig_consumer_event(webconfig_consumer_t *consumer, const char *str, unsigned int len, consumer_event_subtype_t subtype)
{
    webconfig_t *config = NULL;
    webconfig_subdoc_data_t data;
    webconfig_subdoc_type_t subdoc_type;
    webconfig_error_t ret = webconfig_error_none;
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memset(&subdoc_type, 0, sizeof(webconfig_subdoc_type_t));
    config = &consumer->webconfig;

    printf( "%s:%d:webconfig initializ:%d\n", __func__, __LINE__, config->initializer);
    switch (subtype) {
        case consumer_event_webconfig_set_data:

            //            printf("%s:%d: Received webconfig subdoc:\n%s\n ... decoding and translating\n", __func__, __LINE__, str);
            // tell webconfig to decode
            if (enable_ovsdb == true) {
            } else {
                printf( "%s:%d:webconfig_decode\n", __func__, __LINE__);

                memset(&data, 0, sizeof(webconfig_subdoc_data_t));
                memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

                ret = webconfig_decode(&consumer->webconfig, &data, str);
                if (ret == webconfig_error_none)
                    subdoc_type = data.type;
            }

            if (ret == webconfig_error_none ) {
                printf( "%s:%d:webconfig initializ:%d subdoc_type : %d\n", __func__, __LINE__, config->initializer, subdoc_type);

                dump_subdoc(str, subdoc_type);
                sample_app_cache_update(consumer, &data);
                handle_webconfig_subdoc_test_result(subdoc_type, consumer);

                if (enable_ovsdb == true) {
                }
            } else {
                printf("%s:%d: webconfig error\n", __func__, __LINE__);
            }

            webconfig_data_free(&data);
        break;
        case consumer_event_webconfig_get_data:
            //printf("%s:%d: Received webconfig subdoc:\n%s\n ... decoding and translating\n", __func__, __LINE__, str);
            // tell webconfig to decode
            if (enable_ovsdb == true) {
            } else {
                printf( "%s:%d:webconfig_decode\n", __func__, __LINE__);

                memset(&data, 0, sizeof(webconfig_subdoc_data_t));
                memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

                ret = webconfig_decode(&consumer->webconfig, &data, str);
                if (ret == webconfig_error_none)
                    subdoc_type = data.type;
            }

            if (ret == webconfig_error_none ) {
                printf( "%s:%d:webconfig initializ:%d subdoc_type : %d\n", __func__, __LINE__, config->initializer, subdoc_type);
                switch (subdoc_type) {
                    case webconfig_subdoc_type_associated_clients:
                        printf("%s:%d: Received Associated client status, Use -d 1 option to see the log file\n", __func__, __LINE__);
                        dump_subdoc(str, webconfig_subdoc_type_associated_clients);
                    break;
                    case webconfig_subdoc_type_null:
                        printf("%s:%d: webconfig_subdoc_type_null subdoc\n", __func__, __LINE__);
                        if (consumer->test_state == consumer_test_state_null_subdoc_test_pending) {
                            consumer->null_test_pending_count = 0;
                            consumer->test_state = consumer_test_state_null_subdoc_test_complete;
                            cmd_delta_time = get_current_time_ms() - cmd_start_time;
                            printf("%s:%d: current time:%llu subdoc execution delta time:%u milliSeconds\n", __func__, __LINE__, get_current_time_ms(), cmd_delta_time);
                            printf("%s:%d: null set successful, Radios: %s, %s, Test State:%d\n", __func__, __LINE__,
                                    consumer->radios[0].name, consumer->radios[1].name,
                                    consumer->test_state);
                            if (enable_ovsdb == true) {
                            }
                            dump_subdoc(str, webconfig_subdoc_type_null);
                        }
                    break;

                    default:
                        printf("%s:%d: Unknown webconfig subdoc type:%d\n", __func__, __LINE__, data.type);
                    break;
                }
            } else {
                printf("%s:%d: webconfig error\n", __func__, __LINE__);
            }

            webconfig_data_free(&data);
        break;
    }
}

webconfig_error_t webconfig_parse_json_to_struct(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    webconfig_error_t err = RETURN_OK;

    if (validate_subdoc_data(config, data) == false) {
        printf("%s:%d: Invalid data .. not parsable\r\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    printf("%s %d subdoc data type:%d\n", __func__, __LINE__, data->type);
    doc = &config->subdocs[data->type];
    if (doc->access_check_subdoc(config, data) != webconfig_error_none) {
        printf("%s:%d: invalid access for subdocument type:%d in entity:%d\n",
                __func__, __LINE__, doc->type, config->initializer);
        return webconfig_error_not_permitted;
    }

    if ((err = doc->decode_subdoc(config, data)) != webconfig_error_none) {
        printf("%s:%d: Subdocument translation failed\n", __func__, __LINE__);
    }

    return err;

}

int parse_subdoc_input_param(webconfig_consumer_t *consumer, webconfig_subdoc_data_t *data)
{
    int ret = RETURN_OK;

    data->u.encoded.raw = (webconfig_subdoc_encoded_raw_t)read_subdoc_input_param_from_file(consumer->user_input_file_name);
    if (data->u.encoded.raw != NULL) {
        // parse JSON blob
        data->signature = WEBCONFIG_MAGIC_SIGNATUTRE;
        data->type = webconfig_subdoc_type_unknown;
        data->descriptor = webconfig_data_descriptor_encoded;
        ret = webconfig_parse_json_to_struct(&consumer->webconfig, data);
    } else {
        printf("%s:%d: Using default config\r\n", __func__, __LINE__);
    }

    return ret;
}

void test_radio_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    char *str;
    webconfig_error_t ret=webconfig_error_none;

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    } else {
        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            data.u.decoded.radios[0].oper.channel = 3;
        }
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        //clearing the descriptor
        data.descriptor =  0;

        printf("%s:%d: start webconfig_encode\n", __func__, __LINE__);
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_radio);
        if (ret == webconfig_error_none)
            str = data.u.encoded.raw;
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer radio start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_radio);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}

void test_null_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret=webconfig_error_none;
    char *str;
    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    //The below information is not required for the null subdoc, Filled the structures for testing purpose.
    if (enable_ovsdb == true) {
    } else {
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_null);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer null vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_null);
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}

void test_mesh_sta_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret=webconfig_error_none;
    time_t t;

    char *str;
    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    srand((unsigned) time(&t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            wifi_vap_info_t *vap_info;

            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "mesh_sta");
            if (vap_info == NULL) {
                printf("%s:%d: vap_info is NULL \n", __func__, __LINE__);
                return;
            }
            vap_info->u.sta_info.scan_params.period = rand() % 10;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "mesh_sta");
            if (vap_info == NULL) {
                printf("%s:%d: vap_info is NULL \n", __func__, __LINE__);
                return;
            }
            vap_info->u.sta_info.scan_params.period = rand() % 10;
        }

        // clearing the descriptor and raw json data
        data.descriptor =  0;
        if (data.u.encoded.raw != NULL) {
            free(data.u.encoded.raw);
            data.u.encoded.raw = NULL;
        }
        printf("%s:%d: start webconfig_encode\n", __func__, __LINE__);
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_mesh_sta);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer mesh sta vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_mesh_sta);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}

void test_mesh_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret=webconfig_error_none;
    char test_mac[18];
    time_t t;
    rdk_wifi_vap_info_t *rdk_vap;
    mac_address_t mac;
    acl_entry_t *acl_entry;

    char *str;
    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    srand((unsigned) time(&t));
    snprintf(test_mac, sizeof(test_mac), "%02x:%02x:%02x:%02x:%02x:%02x", 0xaa, 0xbb,0xcc,0xaa, rand() % 25, rand() % 50);

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            int radio_0_bssMaxSta;
            wifi_vap_info_t *vap_info;

            data.u.decoded.radios[0].oper.channel = 4;
            data.u.decoded.radios[1].oper.channel = 36;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "mesh_backhaul");
            /* set to different value from current to force a change */
            if (vap_info->u.bss_info.bssMaxSta == 5) {
                vap_info->u.bss_info.bssMaxSta = radio_0_bssMaxSta = 6;
            } else {
                vap_info->u.bss_info.bssMaxSta = radio_0_bssMaxSta = 5;
            }
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "mesh_backhaul");
            vap_info->u.bss_info.bssMaxSta = (radio_0_bssMaxSta == 6) ? 5 : 6;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "mesh_sta");
            vap_info->u.sta_info.scan_params.period = 2;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "mesh_sta");
            vap_info->u.sta_info.scan_params.period = 2;

            rdk_vap = get_wifi_radio_rdkvap_info(&data.u.decoded.radios[0], "mesh_backhaul");
            if ((rdk_vap == NULL)) {
                printf("%s:%d: rdk_vap is null\n", __func__, __LINE__);
                return;
            }

            rdk_vap->acl_map = hash_map_create();
            str_tolower(test_mac);
            str_to_mac_bytes(test_mac, mac);
            acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
            if (acl_entry == NULL) {
                printf("%s:%d NULL Pointer \n", __func__, __LINE__);
                return;
            }
            memset(acl_entry, 0, (sizeof(acl_entry_t)));

            memcpy(&acl_entry->mac, mac, sizeof(mac_address_t));
            hash_map_put(rdk_vap->acl_map, strdup(test_mac), acl_entry);
        }

        // clearing the descriptor and raw json data
        data.descriptor =  0;
        if (data.u.encoded.raw != NULL) {
            free(data.u.encoded.raw);
            data.u.encoded.raw = NULL;
        }
        printf("%s:%d: start webconfig_encode\n", __func__, __LINE__);
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_mesh);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer mesh vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_mesh);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}


void test_macfilter_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    uint8_t vap_array_index = 0;
    webconfig_error_t ret=webconfig_error_none;
    char test_mac[18];
    rdk_wifi_vap_info_t *rdk_vap;
    mac_address_t mac;
    acl_entry_t *acl_entry;
    time_t t;

    char *str;
    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    srand((unsigned) time(&t));

    snprintf(test_mac, sizeof(test_mac), "%02x:%02x:%02x:%02x:%02x:%02x", 0xaa, 0xbb,0xcc,0xdd, rand() % 25, rand() % 50);

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            rdk_vap = NULL;
            for (vap_array_index = 0; vap_array_index < data.u.decoded.radios[0].vaps.num_vaps; ++vap_array_index) {
                if (!strncmp(data.u.decoded.radios[0].vaps.rdk_vap_array[vap_array_index].vap_name, "mesh_backhaul", strlen("mesh_backhaul"))) {
                    rdk_vap = &data.u.decoded.radios[0].vaps.rdk_vap_array[vap_array_index];
                    break;
                }
            }

            if ((rdk_vap == NULL)) {
                printf("%s:%d: rdk_vap is null\n", __func__, __LINE__);
                return;
            }

            rdk_vap->acl_map = hash_map_create();
            str_tolower(test_mac);
            str_to_mac_bytes(test_mac, mac);
            acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
            if (acl_entry == NULL) {
                printf("%s:%d NULL Pointer \n", __func__, __LINE__);
                return;
            }
            memset(acl_entry, 0, (sizeof(acl_entry_t)));

            memcpy(&acl_entry->mac, mac, sizeof(mac_address_t));
            hash_map_put(rdk_vap->acl_map, strdup(test_mac), acl_entry);
        }

        // clearing the descriptor and raw json data
        data.descriptor =  0;
        if (data.u.encoded.raw != NULL) {
            free(data.u.encoded.raw);
            data.u.encoded.raw = NULL;
        }
        printf("%s:%d: start webconfig_encode\n", __func__, __LINE__);
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_mac_filter);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer macfilter start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_mac_filter);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}

void test_vif_neighbors_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret = webconfig_error_none;

    char *str;

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer vif neighbour start test\n", __func__, __LINE__);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}


void test_steeringclient_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret = webconfig_error_none;

    char *str;

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer steer client start test\n", __func__, __LINE__);
//        dump_subdoc(str, webconfig_subdoc_type_steering_config);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}

void test_steerconfig_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret = webconfig_error_none;

    char *str;

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer steer config start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_steering_config);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}


void test_statsconfig_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret = webconfig_error_none;

    char *str;

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer steer config start test\n", __func__, __LINE__);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}

void test_private_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret = webconfig_error_none;

    char *str;

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            int bssMaxSta;
            wifi_vap_info_t *vap_info;

            data.u.decoded.radios[0].oper.channel = 5;
            data.u.decoded.radios[1].oper.channel = 36;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "private_ssid");
            if (vap_info->u.bss_info.bssMaxSta == 5) {
                vap_info->u.bss_info.bssMaxSta = bssMaxSta = 6;
            } else {
                vap_info->u.bss_info.bssMaxSta = bssMaxSta = 5;
            }
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "private_ssid");
            vap_info->u.bss_info.bssMaxSta = bssMaxSta;
        }
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        // clearing the descriptor and raw json data
        data.descriptor =  0;
        if (data.u.encoded.raw != NULL) {
            free(data.u.encoded.raw);
            data.u.encoded.raw = NULL;
        }
        printf("%s:%d: start webconfig_encode num_of_radio:%d\n", __func__, __LINE__, data.u.decoded.num_radios);
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_private);
        if (ret == webconfig_error_none)
            str = data.u.encoded.raw;
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer private vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_private);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}

void test_home_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    char *str;
    webconfig_error_t ret = webconfig_error_none;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    int num_vaps;

    str = NULL;
    num_vaps = get_list_of_vap_names(&consumer->hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
                                     1, VAP_PREFIX_IOT);
    if (num_vaps == 0) {
        printf("%s:%d: Home VAP is not supported\n", __func__, __LINE__);
        consumer->home_test_pending_count = 0;
        consumer->test_state = consumer_test_state_home_subdoc_test_complete;
        return;
    }

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            int bssMaxSta;
            wifi_vap_info_t *vap_info;

            data.u.decoded.radios[0].oper.channel = 5;
            data.u.decoded.radios[1].oper.channel = 36;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "iot_ssid");
            if (vap_info->u.bss_info.bssMaxSta == 5) {
                vap_info->u.bss_info.bssMaxSta = bssMaxSta = 6;
            } else {
                vap_info->u.bss_info.bssMaxSta = bssMaxSta = 5;
            }
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "iot_ssid");
            vap_info->u.bss_info.bssMaxSta = bssMaxSta;
        }
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        // clearing the descriptor and raw json data
        data.descriptor =  0;
        if (data.u.encoded.raw != NULL) {
            free(data.u.encoded.raw);
            data.u.encoded.raw = NULL;
        }
        printf("%s:%d: start webconfig_encode\n", __func__, __LINE__);
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_home);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer home vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_home);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}


void test_getsubdoctype(webconfig_consumer_t *consumer)
{
    int num_vaps;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    wifi_interface_name_t *ifname;
    int vapindex = 0;
    webconfig_subdoc_type_t type = webconfig_subdoc_type_unknown;

    num_vaps = get_list_of_vap_names(&consumer->hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
            8, VAP_PREFIX_PRIVATE, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE, \
            VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS, VAP_PREFIX_MESH_BACKHAUL, \
            VAP_PREFIX_MESH_STA, VAP_PREFIX_IOT);

    for (vapindex = 0; vapindex < num_vaps; vapindex++) {
        ifname = get_interface_name_for_vap_index(vapindex, &consumer->hal_cap.wifi_prop);
        if (ifname == NULL) {
            printf("%s:%d: ifname get failed\n", __func__, __LINE__);
            return;
        }
        printf("%s:%d: ifname %s type : %d\n", __func__, __LINE__, ifname[0], type);

    }
    return;
}

void test_lnf_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret = webconfig_error_none;
    char *str;
    int num_vaps;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    int i = 0;
    unsigned int array_index = 0;
    unsigned int radio_index = 0;

    num_vaps = get_list_of_vap_names(&consumer->hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
                                     2, VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS);
    if (num_vaps == 0) {
        printf("%s:%d: lnf VAP is not supported\n", __func__, __LINE__);
        consumer->lnf_test_pending_count = 0;
        consumer->test_state = consumer_test_state_lnf_subdoc_test_complete;
        return;
    }

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            wifi_vap_info_t *vap_info;

            for ( i = 0; i < num_vaps; i++) {
                array_index = convert_vap_name_to_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
                radio_index = convert_vap_name_to_radio_array_index(&consumer->hal_cap.wifi_prop, vap_names[i]);
                if (((int)array_index < 0) || ((int)radio_index < 0)) {
                    printf("%s:%d: Invalid index\n", __func__, __LINE__);
                    continue;
                }
                vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[radio_index], vap_names[i]);
                snprintf((char *)vap_info->u.bss_info.ssid, sizeof(vap_info->u.bss_info.ssid), "app_lnf_test_%d", array_index);
                printf("%s:%d: radio_index : %d vap_names[i] : %s\n", __func__, __LINE__, radio_index, vap_names[i]);
            }
        }
        // clearing the descriptor and raw json data
        data.descriptor =  0;
        if (data.u.encoded.raw != NULL) {
            free(data.u.encoded.raw);
            data.u.encoded.raw = NULL;
        }
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        printf("%s:%d: start webconfig_encode \n", __func__, __LINE__);
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_lnf);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer lnf vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_lnf);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}


void test_xfinity_subdoc_change(webconfig_consumer_t *consumer)
{
    webconfig_subdoc_data_t data;
    webconfig_error_t ret = webconfig_error_none;
    char *str;
    int num_vaps;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];

    num_vaps = get_list_of_vap_names(&consumer->hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
            2, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE);
    if (num_vaps == 0) {
        printf("%s:%d: Xfinity VAP is not supported\n", __func__, __LINE__);
        consumer->xfinity_test_pending_count = 0;
        consumer->test_state = consumer_test_state_xfinity_subdoc_test_complete;
        return;
    }

    str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    printf("%s:%d: current time:%llu\n", __func__, __LINE__, get_current_time_ms());
    if (enable_ovsdb == true) {
    } else {

        memcpy((unsigned char *)data.u.decoded.radios, (unsigned char *)consumer->radios, consumer->hal_cap.wifi_prop.numRadios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

        if (parse_subdoc_input_param(consumer, &data) != RETURN_OK) {
            int radio_1_open_bssMaxSta, radio_2_open_bssMaxSta;
            wifi_vap_info_t *vap_info;

            data.u.decoded.radios[0].oper.channel = 6;
            data.u.decoded.radios[1].oper.channel = 36;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "hotspot_open");
            if (vap_info->u.bss_info.bssMaxSta == 5) {
                vap_info->u.bss_info.bssMaxSta = radio_1_open_bssMaxSta = 6;
                radio_2_open_bssMaxSta = 5;
            } else {
                vap_info->u.bss_info.bssMaxSta = radio_1_open_bssMaxSta = 5;
                radio_2_open_bssMaxSta = 6;
            }
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "hotspot_open");
            vap_info->u.bss_info.bssMaxSta = radio_2_open_bssMaxSta;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[0], "hotspot_secure");
            vap_info->u.bss_info.bssMaxSta = radio_2_open_bssMaxSta;
            vap_info = get_wifi_radio_vap_info(&data.u.decoded.radios[1], "hotspot_secure");
            vap_info->u.bss_info.bssMaxSta = radio_1_open_bssMaxSta;
        }
        // clearing the descriptor and raw json data
        data.descriptor =  0;
        if (data.u.encoded.raw != NULL) {
            free(data.u.encoded.raw);
            data.u.encoded.raw = NULL;
        }
        data.u.decoded.num_radios = consumer->hal_cap.wifi_prop.numRadios;

        printf("%s:%d: start webconfig_encode \n", __func__, __LINE__);
        ret = webconfig_encode(&consumer->webconfig, &data,
                webconfig_subdoc_type_xfinity);
        if (ret == webconfig_error_none) {
            str = data.u.encoded.raw;
        }
    }

    if (ret == webconfig_error_none) {
        printf("%s:%d: webconfig consumer xfinity vap start test\n", __func__, __LINE__);
        dump_subdoc(str, webconfig_subdoc_type_xfinity);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data, NULL);
#else
        cmd_start_time = get_current_time_ms();
        printf("%s:%d: command start current time:%llu\n", __func__, __LINE__, cmd_start_time);
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_DOC_DATA_SOUTH, str);
#endif
    } else {
        printf("%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    if (str != NULL) {
        free(str);
    }
}

void test_initial_sync()
{
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
    bool dummy_msg = FALSE;
    push_event_to_ctrl_queue((void *)&dummy_msg, 0, wifi_event_type_webconfig, wifi_event_webconfig_get_data, NULL);
#else
    initial_sync(&webconfig_consumer);
#endif
}

void exit_consumer_queue_loop(void)
{
    webconfig_consumer_t *consumer = get_consumer_object();
    printf("%s:%d: Exit consumer queue loop\n", __func__, __LINE__);
    consumer->exit_consumer = true;
}

void consumer_app_all_test_sequence(webconfig_consumer_t *consumer)
{
    switch (consumer->test_state) {
        case consumer_test_state_none:
            consumer->test_state = consumer_test_state_cache_init_pending;
            test_initial_sync();
            break;

        case consumer_test_state_cache_init_complete:
            consumer->test_state = consumer_test_state_radio_subdoc_test_pending;
            // do radio subdoc change test
            test_radio_subdoc_change(consumer);
            break;

        case consumer_test_state_radio_subdoc_test_pending:
            consumer->radio_test_pending_count++;
            if (consumer->radio_test_pending_count > MAX_WAIT) {
                printf("%s:%d: Radio test failed, timed out, proceeding with private subdoc test\n", __func__, __LINE__);
                consumer->radio_test_pending_count = 0;
                consumer->test_state = consumer_test_state_radio_subdoc_test_complete;
            }
            break;

        case consumer_test_state_radio_subdoc_test_complete:
            consumer->test_state = consumer_test_state_private_subdoc_test_pending;
            test_private_subdoc_change(consumer);
            break;

        case consumer_test_state_private_subdoc_test_pending:
            consumer->private_test_pending_count++;
            if (consumer->private_test_pending_count > MAX_WAIT) {
                printf("%s:%d: Private test failed, timed out, proceeding with mesh subdoc test\n", __func__, __LINE__);
                consumer->private_test_pending_count = 0;
                consumer->test_state = consumer_test_state_private_subdoc_test_complete;
            }
            break;

        case consumer_test_state_private_subdoc_test_complete:
            consumer->test_state = consumer_test_state_mesh_subdoc_test_pending;
            test_mesh_subdoc_change(consumer);
            break;

        case consumer_test_state_mesh_subdoc_test_pending:
            consumer->mesh_test_pending_count++;
            if (consumer->mesh_test_pending_count > MAX_WAIT) {
                printf("%s:%d: vap mesh test failed, timed out, proceeding with xfinity test\n", __func__, __LINE__);
                consumer->mesh_test_pending_count = 0;
                consumer->test_state = consumer_test_state_mesh_subdoc_test_complete;
            }
            break;

        case consumer_test_state_mesh_subdoc_test_complete:
            consumer->test_state = consumer_test_state_xfinity_subdoc_test_pending;
            test_xfinity_subdoc_change(consumer);
            break;

        case consumer_test_state_xfinity_subdoc_test_pending:
            consumer->xfinity_test_pending_count++;
            if (consumer->xfinity_test_pending_count > MAX_WAIT) {
                printf("%s:%d: vap xfinity test failed, timed out, proceeding with home test\n", __func__, __LINE__);
                consumer->mesh_test_pending_count = 0;
                consumer->test_state = consumer_test_state_xfinity_subdoc_test_complete;
            }
            break;

        case consumer_test_state_xfinity_subdoc_test_complete:
            consumer->test_state = consumer_test_state_home_subdoc_test_pending;
            test_home_subdoc_change(consumer);
            break;

        case consumer_test_state_home_subdoc_test_pending:
            consumer->home_test_pending_count++;
            if (consumer->home_test_pending_count > MAX_WAIT) {
                printf("%s:%d: vap home test failed, timed out, all test completed\n", __func__, __LINE__);
                consumer->home_test_pending_count = 0;
                consumer->test_state = consumer_test_state_home_subdoc_test_complete;
            }
            break;

        default:
            //printf("%s:%d: Noop test state:%d\n", __func__, __LINE__, consumer->test_state);
        break;
    }
}

void reset_all_test_pending_count(void)
{
    webconfig_consumer_t *consumer = get_consumer_object();

    consumer->radio_test_pending_count = 0;
    consumer->private_test_pending_count = 0;
    consumer->mesh_test_pending_count = 0;
    consumer->xfinity_test_pending_count = 0;
    consumer->home_test_pending_count = 0;
}

void consumer_app_trigger_subdoc_test( webconfig_consumer_t *consumer, consumer_test_sequence_t test_state)
{
    printf("%s:%d: consumer app trigger test:%d\n", __func__, __LINE__, test_state);
    consumer->test_input = test_state;
    switch (test_state) {
        case consumer_test_start_radio_subdoc:
            consumer->radio_test_pending_count = 0;
            consumer->test_state = consumer_test_state_radio_subdoc_test_pending;
            test_radio_subdoc_change(consumer);
            break;

        case consumer_test_start_private_subdoc:
            consumer->private_test_pending_count = 0;
            consumer->test_state = consumer_test_state_private_subdoc_test_pending;
            test_private_subdoc_change(consumer);
            break;

        case consumer_test_start_mesh_subdoc:
            consumer->mesh_test_pending_count = 0;
            consumer->test_state = consumer_test_state_mesh_subdoc_test_pending;
            test_mesh_subdoc_change(consumer);
            break;

        case consumer_test_start_xfinity_subdoc:
            consumer->xfinity_test_pending_count = 0;
            consumer->test_state = consumer_test_state_xfinity_subdoc_test_pending;
            test_xfinity_subdoc_change(consumer);
            break;

        case consumer_test_start_home_subdoc:
            consumer->home_test_pending_count = 0;
            consumer->test_state = consumer_test_state_home_subdoc_test_pending;
            test_home_subdoc_change(consumer);
            break;

        case consumer_test_start_macfilter_subdoc:
            consumer->macfilter_test_pending_count= 0;
            consumer->test_state = consumer_test_state_macfilter_subdoc_test_pending;
            test_macfilter_subdoc_change(consumer);
            break;

        case consumer_test_start_null_subdoc:
            consumer->null_test_pending_count= 0;
            consumer->test_state = consumer_test_state_null_subdoc_test_pending;
            test_null_subdoc_change(consumer);
        break;

        case consumer_test_start_mesh_sta_subdoc:
            consumer->mesh_test_pending_count = 0;
            consumer->test_state = consumer_test_state_mesh_sta_subdoc_test_pending;
            test_mesh_sta_subdoc_change(consumer);
        break;

        case consumer_test_start_band_steer_config_subdoc:
            consumer->steer_config_test_pending_count= 0;
            consumer->test_state = consumer_test_state_band_steer_config_test_pending;
            test_steerconfig_subdoc_change(consumer);
            break;

        case consumer_test_start_stats_config_subdoc:
            consumer->stats_config_test_pending_count= 0;
            consumer->test_state = consumer_test_state_stats_config_test_pending;
            test_statsconfig_subdoc_change(consumer);
            break;

        case consumer_test_start_band_steer_client_subdoc:
            consumer->steer_client_test_pending_count = 0;
            consumer->test_state = consumer_test_start_band_steer_client_subdoc;
            test_steeringclient_subdoc_change(consumer);
            break;

        case consumer_test_start_lnf_subdoc:
            consumer->lnf_test_pending_count = 0;
            consumer->test_state = consumer_test_state_lnf_subdoc_test_pending;
            test_lnf_subdoc_change(consumer);
            break;

       case consumer_test_start_vif_neighbors_subdoc:
            consumer->vif_neighbors_test_pending_count = 0;
            consumer->test_state = consumer_test_start_vif_neighbors_subdoc;
            test_vif_neighbors_subdoc_change(consumer);
            break;

        case consumer_test_start_all_subdoc:
            reset_all_test_pending_count();
            consumer->test_state = consumer_test_state_cache_init_complete;
            consumer_app_all_test_sequence(consumer);
            break;

        default:
            printf("%s:%d: [%d] This Test index not supported\r\n", __func__, __LINE__, test_state);
            break;
    }
}

void consumer_app_trigger_wan_test( webconfig_consumer_t *consumer, consumer_test_sequence_t test_state, bool status)
{
    printf("%s:%d: consumer app trigger test:%d\n", __func__, __LINE__, test_state);
    consumer->test_input = test_state;
    switch (test_state) {
        case consumer_test_start_wan_manager:
            webconfig_rbus_other_gateway_state_publish(consumer, status);
        break;

        default:
            printf("%s:%d: [%d] This Test index not supported\r\n", __func__, __LINE__, test_state);
        break;
    }
}

void generate_tunnel_event(bool status, rbusHandle_t handle)
{
    const char *evt_name = "TunnelStatus";
    const char *evt_val = status ? "TUNNEL_UP" : "TUNNEL_DOWN";

    rbusValue_t value;
    rbusObject_t rd;

    rbusValue_Init(&value);
    rbusValue_SetString(value, evt_val);

    rbusObject_Init(&rd, NULL);
    rbusObject_SetValue(rd, evt_name, value);

    rbusEvent_t event;
    event.name = evt_name;
    event.data = rd;
    event.type = RBUS_EVENT_GENERAL;

    int rc = rbusEvent_Publish(handle, &event);
    if(rc != RBUS_ERROR_SUCCESS){
        printf("%s:%d rbusEvent_Publish %s failed\n", __func__, __LINE__, event.name );
    }

    rbusValue_Release(value);
    rbusObject_Release(rd);
}

void copy_data(char *dest, char *src, unsigned char dest_len)
{
    if (src != NULL) {
        strcpy(dest, src);
    } else {
        memset(dest, 0 , dest_len);
    }
}

int webconfig_rbus_event_publish(webconfig_consumer_t *consumer, char *event_name, unsigned char event_type, unsigned char *data)
{
    bool l_bool_data;
    unsigned int l_uint_data;
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, event_name, value);
    if (event_type == rbus_bool_data) {
        memcpy(&l_bool_data, data, sizeof(l_bool_data));
        rbusValue_SetBoolean(value, l_bool_data);
    } else if (event_type == rbus_int_data) {
        memcpy(&l_uint_data, data, sizeof(l_uint_data));
        rbusValue_SetUInt32(value, l_uint_data);
    }
    event.name = event_name;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    if (rbusEvent_Publish(consumer->rbus_handle, &event) != RBUS_ERROR_SUCCESS) {
        printf( "%s:%d: rbusEvent_Publish Event failed for %s\n", __func__, __LINE__, event_name);
        return RETURN_ERR;
    } else {
        printf( "%s:%d: rbusEvent_Publish success for %s\n", __func__, __LINE__, event_name);
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return RETURN_OK;
}

int recv_data_decode(webconfig_consumer_t *consumer, webconfig_subdoc_data_t *data, const char *recv_data)
{
    webconfig_error_t ret = webconfig_error_none;

    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data->u.decoded.hal_cap, (unsigned char *)&consumer->hal_cap, sizeof(wifi_hal_capability_t));

    ret = webconfig_decode(&consumer->webconfig, data, recv_data);

    if (ret == webconfig_error_none) {
        return 0;
    } else {
        return -1;
    }
}

int get_device_network_mode_from_ctrl_thread(webconfig_consumer_t *consumer, unsigned int *device_network_mode)
{
    rbusValue_t value;
    const char *str;
    int len = 0;
    int rc = RBUS_ERROR_SUCCESS;
    webconfig_consumer_t l_consumer;
    webconfig_subdoc_data_t data;
    const char *paramNames[] = {WIFI_WEBCONFIG_INIT_DML_DATA};
    memset(&l_consumer, 0, sizeof(l_consumer));

    rc = rbus_get(consumer->rbus_handle, paramNames[0], &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf ("rbus_get failed for [%s] with error [%d]\n", paramNames[0], rc);
        return -1;
    }

    str = rbusValue_GetString(value, &len);
    if (str == NULL) {
        printf("%s Null pointer,Rbus set string len=%d\n",__FUNCTION__,len);
        return -1;
    }

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    rc = recv_data_decode(consumer, &data, str);
    if (rc == 0) {
        memcpy((unsigned char *)&l_consumer.config, (unsigned char *)&data.u.decoded.config, sizeof(wifi_global_config_t));
        *device_network_mode = l_consumer.config.global_parameters.device_network_mode;
        printf("%s:%d: get device network mode:%d\n", __func__, __LINE__, *device_network_mode);
    } else {
        printf("%s:%d: use default value\r\n", __func__, __LINE__);
        *device_network_mode = consumer->config.global_parameters.device_network_mode;
    }

    webconfig_data_free(&data);

    return 0;
}

int rbus_multi_get(webconfig_consumer_t *consumer, char *first_arg, char *next_arg)
{
    int rc = RBUS_ERROR_SUCCESS;
    int numOfInputParams = 0, numOfOutVals = 0;
    const char *pInputParam[RBUS_CLI_MAX_PARAM] = {0, 0};
    rbusProperty_t outputVals = NULL;
    int i = 0;

    if (first_arg != NULL) {
        pInputParam[numOfInputParams] = first_arg;
        numOfInputParams++;
    }

    if (next_arg != NULL) {
        pInputParam[numOfInputParams] = next_arg;
        numOfInputParams++;
    }

    if (numOfInputParams == 0) {
        printf("%s:%d: numOfInputParams = %d\r\n", __func__, __LINE__, numOfInputParams);
        return -1;
    }

    rc = rbus_getExt(consumer->rbus_handle, numOfInputParams, pInputParam, &numOfOutVals, &outputVals);
    if(RBUS_ERROR_SUCCESS == rc) {
        rbusProperty_t next = outputVals;
        for (i = 0; i < numOfOutVals; i++) {
            rbusValue_t val = rbusProperty_GetValue(next);
            rbusValueType_t type = rbusValue_GetType(val);
            char *pStrVal = rbusValue_ToString(val,NULL,0);

            printf ("Parameter %2d:\n\r", i+1);
            printf ("              Name  : %s\n\r", rbusProperty_GetName(next));
            printf ("              Type  : %d\n\r", type);
            printf ("              Value : %s\n\r", pStrVal);

            if(pStrVal) {
                free(pStrVal);
            }

            next = rbusProperty_GetNext(next);
        }
        /* Free the memory */
        rbusProperty_Release(outputVals);
    } else {
        printf ("Failed to get the data. Error : %d\n\r",rc);
        return -1;
    }

    return 0;
}

int decode_802_11_frame(webconfig_consumer_t *consumer, unsigned int vap_index, char *file_name)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    int rc;
    frame_data_t frame_data;
    FILE *fp = NULL;
    char tmp_buff[MAX_FRAME_SZ], *tmp;
    unsigned int count = 0, nlen = 0, pos = 0;
    struct ieee80211_frame *frame;

    if ((fp = fopen(file_name, "r")) == NULL) {
        printf("%s:%d: Can not open file to read 802.11 frame\n", __func__, __LINE__);
        return -1;
    }

    memset(tmp_buff, 0, MAX_FRAME_SZ);
    memset(frame_data.frame.data, 0, MAX_FRAME_SZ);
    while ((tmp = fgets(tmp_buff, MAX_FRAME_SZ, fp)) != NULL) {
        nlen = strlen(tmp);
        pos = 2;
        while (pos <= (nlen - 1)) {
            tmp_buff[pos] = 0;
            sscanf(tmp, "%02hhx", (uint8_t *)&frame_data.frame.data[count]);
            count++; pos += 3; tmp += 3;
        }
        memset(tmp_buff, 0, MAX_FRAME_SZ);
    }

    fclose(fp);

    frame = (struct ieee80211_frame *)&frame_data.frame;
    memcpy((uint8_t *)&frame_data.frame.sta_mac, (uint8_t *)&frame->i_addr2, sizeof(mac_address_t));
    frame_data.frame.ap_index = vap_index;
    frame_data.frame.len = count;
    frame_data.frame.type = WIFI_MGMT_FRAME_TYPE_ACTION;
    frame_data.frame.dir = wifi_direction_uplink;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, WIFI_FRAME_INJECTOR_TO_ONEWIFI, value);
    rbusValue_SetBytes(value, (uint8_t *)&frame_data, (sizeof(frame_data) - MAX_FRAME_SZ + count));
    event.name = WIFI_FRAME_INJECTOR_TO_ONEWIFI;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(consumer->rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        return -1;
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);
    return 0;
}

int decode_pcap(webconfig_consumer_t *consumer, unsigned int vap_index, char *file_name)
{
    // mac_address_t sta;
    FILE *fp = NULL;
    unsigned char buff[MAX_FRAME_SZ];
    struct ieee80211_frame *frame;
    wireshark_pkthdr_t  pkt_hdr;
    struct ieee80211_radiotap_header *radiotap_hdr;
    struct pcap_file_header  file_hdr;
    size_t sz;
    // int ret = 0, frames_parsed = 0, start_frame = 0, end_frame = 0;
    // bool all_frames = false;
    int frames_parsed = 0, start_frame = 0, end_frame = 0;
    bool is_mgmt_frame = false;
    wifi_mgmtFrameType_t    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_INVALID;

    frame_data_t frame_data;

    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;

    if ((fp = fopen(file_name, "r")) == NULL) {
        printf("%s:%d: Can not open file\n", __func__, __LINE__);
        return -1;
    }

    sz = fread(&file_hdr, 1, sizeof(struct pcap_file_header), fp);
    if (sz != sizeof(struct pcap_file_header)) {
        fclose(fp);
        return -1;
    }

    if (file_hdr.magic !=  0xa1b2c3d4) {
        fclose(fp);
        return -1;
    }
   start_frame = 1386;
   end_frame  = 1388;


/*  if (strcasecmp(frame_range, "all") == 0) {
        all_frames = true;
    } else {
        sscanf(frame_range, "%d-%d", &start_frame, &end_frame);
    } */

    while ((sz = fread(&pkt_hdr, 1, sizeof(wireshark_pkthdr_t), fp)) == sizeof(wireshark_pkthdr_t)) {
        memset(buff, 0, MAX_FRAME_SZ);
        sz = fread(buff, 1, pkt_hdr.caplen, fp);

        frames_parsed++;
        if(frames_parsed<start_frame)
               continue;

        if (sz != pkt_hdr.caplen) {
            continue;
        }

        is_mgmt_frame = false;
        mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_INVALID;

        radiotap_hdr = (struct ieee80211_radiotap_header *)buff;
        frame = (struct ieee80211_frame *)&buff[radiotap_hdr->it_len];
        if ((frame->i_fc[0] & 0x0c) == 0) {
            is_mgmt_frame = true;
            switch (frame->i_fc[0] >> 4) {
                case 0:
                    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_ASSOC_REQ;
                    break;
                case 1:
                    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_ASSOC_RSP;
                    break;
                case 2:
                    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_REASSOC_REQ;
                    break;
                case 3:
                    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_REASSOC_RSP;
                    break;
                case 4:
                    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_PROBE_REQ;
                    break;
                case 5:
                    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_PROBE_RSP;
                    break;
                case 8:
                    // mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_BEACON;
                    break;
                case 9:
                    // mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_ATIMS;
                    break;
                case 10:
                    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_DISASSOC;
                    break;
                case 11:
                    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_AUTH;
                    break;
                case 12:
                    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_DEAUTH;
                    break;
                case 13:
                    mgmt_frame_type = WIFI_MGMT_FRAME_TYPE_ACTION;
                    break;
                default:
                    break;
            }
        }
        // memcpy(&sta, frame->i_addr2, sizeof(mac_address_t));
        memcpy((uint8_t *)&frame_data.frame.sta_mac, (uint8_t *)&frame->i_addr2, sizeof(mac_address_t));
        frame_data.frame.ap_index = vap_index;
        frame_data.frame.len = (uint32_t)(sz - radiotap_hdr->it_len);
        frame_data.frame.type = mgmt_frame_type;
        memcpy((uint8_t *)&frame_data.data, &buff[radiotap_hdr->it_len], frame_data.frame.len);
        frame_data.frame.dir = wifi_direction_uplink;

        if(is_mgmt_frame && (mgmt_frame_type != WIFI_MGMT_FRAME_TYPE_INVALID)) {
            rbusValue_Init(&value);
            rbusObject_Init(&rdata, NULL);

            rbusObject_SetValue(rdata, WIFI_FRAME_INJECTOR_TO_ONEWIFI, value);
            rbusValue_SetBytes(value, (uint8_t *)&frame_data, (sizeof(frame_data) - MAX_FRAME_SZ + frame_data.frame.len));
            event.name = WIFI_FRAME_INJECTOR_TO_ONEWIFI;
            event.data = rdata;
            event.type = RBUS_EVENT_GENERAL;

            int rc = rbusEvent_Publish(consumer->rbus_handle, &event);
            if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
                fclose(fp);
                printf("%s:%d: rbus Publish Failure\n", __func__, __LINE__);
                return -1;
            }

	    rbusValue_Release(value);
            rbusObject_Release(rdata);
        }

   /**  if (all_frames == true) {
            ret = ((is_mgmt_frame == true) && (mgmt_frame_type != WIFI_MGMT_FRAME_TYPE_INVALID)) ?
                mgmt_wifi_frame_recv(1, sta, &buff[radiotap_hdr->it_len], (uint32_t)(sz - radiotap_hdr->it_len), mgmt_frame_type, wifi_direction_uplink):-1;
        } else if ((frames_parsed >= start_frame) && (frames_parsed <= end_frame)) {
            ret = ((is_mgmt_frame == true) && (mgmt_frame_type != WIFI_MGMT_FRAME_TYPE_INVALID)) ?
                mgmt_wifi_frame_recv(1, sta, &buff[radiotap_hdr->it_len], (uint32_t)(sz - radiotap_hdr->it_len), mgmt_frame_type, wifi_direction_uplink):-1;

        } **/
        if(frames_parsed >end_frame)
           return 0;

    }

    fclose(fp);

    printf("%s:%d: Frames Parsed: %d\n", __func__, __LINE__, frames_parsed);
    return 0;
}

int parse_input_parameters(char *first_input, char *second_input, char *input_file_name)
{
    webconfig_consumer_t *consumer = get_consumer_object();
    unsigned int device_network_mode = 0;
    unsigned int vap_index = 0;

    if (!strncmp(first_input, "-w", strlen("-w"))) {
        if (consumer->rbus_events_subscribed == true) {

            if (dml_init_sync == false) {
                printf("%s %d Test for DML subdoc testing\n", __func__, __LINE__);
                dml_init_sync = true;
                enable_ovsdb = false;
                is_ovs_init = false;
                test_initial_sync();
            }


            if (!strncmp(second_input, "radio", strlen("radio"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_radio_subdoc);
            } else if (!strncmp(second_input, "private", strlen("private"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_private_subdoc);
            } else if (!strncmp(second_input, "meshsta", strlen("meshsta"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_mesh_sta_subdoc);
            } else if (!strncmp(second_input, "mesh", strlen("mesh"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_mesh_subdoc);
            } else if (!strncmp(second_input, "xfinity", strlen("xfinity"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_xfinity_subdoc);
            } else if (!strncmp(second_input, "lnf", strlen("lnf"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_lnf_subdoc);
            } else if (!strncmp(second_input, "home", strlen("home"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_home_subdoc);
            } else if (!strncmp(second_input, "all", strlen("all"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_all_subdoc);
            } else if (!strncmp(second_input, "macfilter", strlen("macfilter"))) {
                copy_data(consumer->user_input_file_name, input_file_name, sizeof(consumer->user_input_file_name));
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_macfilter_subdoc);
            } else if (!strncmp(second_input, "sync", strlen("sync"))) {
                test_initial_sync();
            } else {
                printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
                return RETURN_ERR;
            }
        } else {
            printf("%s:%d: rbus event not subsctibed:\r\n", __func__, __LINE__);
        }
    } else if (!strncmp(first_input, "-c", strlen("-c"))) {
        if (!strncmp(second_input, "0", strlen("0"))) {
            get_device_network_mode_from_ctrl_thread(consumer, &device_network_mode);
            if (device_network_mode == rdk_dev_mode_type_ext) {
                consumer_app_trigger_wan_test(consumer, consumer_test_start_wan_manager, false);
            } else {
                printf("%s:%d: current mode is %d, wan manager test-case run only in extender(station) mode\r\n", __func__, __LINE__, device_network_mode);
            }
        } else if (!strncmp(second_input, "1", strlen("1"))) {
            get_device_network_mode_from_ctrl_thread(consumer, &device_network_mode);
            if (device_network_mode == rdk_dev_mode_type_ext) {
                consumer_app_trigger_wan_test(consumer, consumer_test_start_wan_manager, true);
            } else {
                printf("%s:%d: current mode is %d, wan manager test-case run only in extender(station) mode\r\n", __func__, __LINE__, device_network_mode);
            }
        } else {
            printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
            return RETURN_ERR;
        }
    } else if (!strncmp(first_input, "-t", strlen("-t"))) {
        if (!strncmp(second_input, "0", strlen("0"))) {
            generate_tunnel_event(false, consumer->rbus_handle);
        } else if (!strncmp(second_input, "1", strlen("1"))) {
            generate_tunnel_event(true, consumer->rbus_handle);
        } else {
            printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
            return RETURN_ERR;
        }
    } else if (!strncmp(first_input, "-o", strlen("-o"))) {
        if (consumer->rbus_events_subscribed == true) {

            enable_ovsdb = true;
            if (is_ovs_init == false) {
                printf("%s %d Test for subdoc testing for ovs\n", __func__, __LINE__);
                is_ovs_init = true;
                test_initial_sync();
                dml_init_sync = false;
            }

            if (!strncmp(second_input, "radio", strlen("radio"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_radio_subdoc);
            } else if (!strncmp(second_input, "meshsta", strlen("meshsta"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_mesh_sta_subdoc);
            } else if (!strncmp(second_input, "mesh", strlen("mesh"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_mesh_subdoc);
            } else if (!strncmp(second_input, "macfilter", strlen("macfilter"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_macfilter_subdoc);
            } else if (!strncmp(second_input, "sync", strlen("sync"))) {
                test_initial_sync();
            } else if (!strncmp(second_input, "null", strlen("null"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_null_subdoc);
            } else if (!strncmp(second_input, "private", strlen("private"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_private_subdoc);
            } else if (!strncmp(second_input, "lnf", strlen("lnf"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_lnf_subdoc);
            } else if (!strncmp(second_input, "home", strlen("home"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_home_subdoc);
            } else if (!strncmp(second_input, "xfinity", strlen("xfinity"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_xfinity_subdoc);
            } else if (!strncmp(second_input, "getsubdoc", strlen("getsubdoc"))) {
                test_getsubdoctype(consumer);
            } else if (!strncmp(second_input, "steerconfig", strlen("steerconfig"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_band_steer_config_subdoc);
            } else if (!strncmp(second_input, "statconfig", strlen("statconfig"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_stats_config_subdoc);
            } else if (!strncmp(second_input, "steerclient", strlen("steerclient"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_band_steer_client_subdoc);
            } else if (!strncmp(second_input, "neighbor", strlen("neighbor"))) {
                consumer_app_trigger_subdoc_test(consumer, consumer_test_start_vif_neighbors_subdoc);
            } else if (!strncmp(second_input, "disable", strlen("disable"))) {
                is_ovs_init = false;
                enable_ovsdb = false;
            } else {
                printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
                return RETURN_ERR;
            }
        } else {
            printf("%s:%d: rbus event not subsctibed:\r\n", __func__, __LINE__);
        }
    } else if (!strncmp(first_input, "-d", strlen("-d"))) {
        if (!strncmp(second_input, "1", strlen("1"))) {
            debug_enable = true;
        } else if (!strncmp(second_input, "0", strlen("0"))) {
            debug_enable = false;
        } else {
            printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
            return RETURN_ERR;
        }

    } else if (!strncmp(first_input, "-a", strlen("-a"))) {
        if (!strncmp(second_input, "DeviceNetworkMode", strlen("DeviceNetworkMode"))) {
            if ((!strncmp(input_file_name, "1", strlen("1"))) ||
                    (!strncmp(input_file_name, "0", strlen("0")))) {
                unsigned int device_mode = atoi(input_file_name);
                webconfig_rbus_event_publish(consumer, TEST_WIFI_DEVICE_MODE, rbus_int_data, (unsigned char *)&device_mode);
            } else {
                printf("%s:%d: wrong third argument:%s\r\n", __func__, __LINE__, input_file_name);
                return RETURN_ERR;
            }
        } else {
            printf("%s:%d: wrong second argument:%s\r\n", __func__, __LINE__, second_input);
            return RETURN_ERR;
        }

    } else if (!strncmp(first_input, "-kickmac", strlen("-kickmac"))) {
        rbus_setStr(consumer->rbus_handle, WIFI_WEBCONFIG_KICK_MAC, second_input);

    } else if (!strncmp(first_input, "wps", strlen("wps"))) {
        vap_index = atoi(second_input);
        if (vap_index < MAX_VAP) {
            webconfig_rbus_event_publish(consumer, RBUS_WIFI_WPS_PIN_START, rbus_int_data, (unsigned char *)&vap_index);
        } else {
            printf("%s:%d: wrong second argument:%s:vap_index:%d:%d\r\n", __func__, __LINE__, second_input, vap_index, MAX_VAP);
            return RETURN_ERR;
        }

    } else if (!strncmp(first_input, "rbusGet", strlen("rbusGet"))) {
        rbus_multi_get(consumer, second_input, input_file_name);
    } else if (!strncmp(first_input, "mgmtFrameSend", strlen("mgmtFrameSend"))) {
        vap_index = atoi(second_input);
        if (vap_index < MAX_VAP) {
            decode_802_11_frame(consumer, vap_index, input_file_name);
        } else {
            printf("%s:%d: wrong second argument:%s:vap_index:%d:%d\r\n", __func__, __LINE__, second_input, vap_index, MAX_VAP);
            return RETURN_ERR;
        }

    } else if (!strncmp(first_input, "mpcap", strlen("mpcap"))) {
        vap_index = atoi(second_input);
        if (vap_index < MAX_VAP) {
            decode_pcap(consumer, vap_index, input_file_name);
        } else {
            printf("%s:%d: wrong second argument:%s:vap_index:%d:%d\r\n", __func__, __LINE__, second_input, vap_index, MAX_VAP);
            return RETURN_ERR;
        }

    } else {
        printf("%s:%d: wrong first argument:%s\r\n", __func__, __LINE__, first_input);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int get_rbus_sta_interface_name(const char *paramNames)
{
    rbusValue_t value;
    int rc = RBUS_ERROR_SUCCESS;
    webconfig_consumer_t *consumer = get_consumer_object();

    rc = rbus_get(consumer->rbus_handle, paramNames, &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf ("rbus_get failed for [%s] with error [%d]\n", paramNames, rc);
        return -1;
    }

    printf(":%s:%d Sta interface name = [%s]\n", __func__, __LINE__, rbusValue_GetString(value, NULL));

    return 0;
}

void webconfig_consumer_sta_conn_status(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    bool conn_status;
    unsigned int index = 0;
    int len = 0;
    wifi_sta_conn_info_t sta_conn_info;
    memset(&sta_conn_info, 0, sizeof(wifi_sta_conn_info_t));
    mac_addr_str_t mac_str;
    const unsigned char *temp_buff;
    rbusValue_t value = rbusObject_GetValue(event->data, NULL );
    if(!value)
    {
        printf("%s:%d FAIL: value is NULL\n",__FUNCTION__, __LINE__);
        return;
    }

    printf("%s:%d Rbus event name=%s\n",__FUNCTION__, __LINE__, event->name);

    sscanf(event->name, "Device.WiFi.STA.%d.Connection.Status", &index);
    temp_buff = rbusValue_GetBytes(value, &len);
    if (temp_buff == NULL) {
        printf("%s:%d Rbus get string failure len=%d\n", __FUNCTION__, __LINE__, len);
        return;
    }

    memcpy(&sta_conn_info, temp_buff, len);
    conn_status = (sta_conn_info.connect_status == wifi_connection_status_connected) ? true:false;
    if (conn_status == true) {
        printf("%s:%d: Station successfully connected with external AP radio:%d\r\n",
                    __func__, __LINE__, index - 1);
        if (index == 1) {
            get_rbus_sta_interface_name(WIFI_STA_2G_INTERFACE_NAME);
        } else if (index == 2) {
            get_rbus_sta_interface_name(WIFI_STA_5G_INTERFACE_NAME);
        }
    } else {
        printf("%s:%d: Station disconnected with external AP:%d radio:%d\r\n",
                __func__, __LINE__, conn_status, index - 1);
    }
    printf("%s:%d: MAC address info:%s\r\n", __func__, __LINE__, to_mac_str(sta_conn_info.bssid, mac_str));

    return;
}

void webconfig_consumer_sta_interface_name(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    unsigned int index = 0;
    int len = 0;
    const char *temp_buff;
    rbusValue_t value = rbusObject_GetValue(event->data, NULL );
    if(!value)
    {
        printf("%s:%d FAIL: value is NULL\n",__FUNCTION__, __LINE__);
        return;
    }

    printf("%s:%d Rbus event name=%s\n",__FUNCTION__, __LINE__, event->name);

    sscanf(event->name, "Device.WiFi.STA.%d.InterfaceName", &index);

    temp_buff = rbusValue_GetString(value, &len);
    if (temp_buff == NULL) {
        printf("%s:%d Rbus get string failure len=%d\n", __FUNCTION__, __LINE__, len);
        return;
    }

    printf("%s:%d radio index:%d Rbus get string:%s len=%d\n",__FUNCTION__, __LINE__, index, temp_buff, len);
    return;
}

void consumer_queue_loop(webconfig_consumer_t *consumer)
{
    struct timespec time_to_wait;
    struct timespec tv_now;
    time_t  time_diff;
    int rc;
    consumer_event_t *queue_data = NULL;

    pthread_mutex_lock(&consumer->lock);
    while (consumer->exit_consumer == false) {
        clock_gettime(CLOCK_MONOTONIC, &tv_now);
        time_to_wait.tv_nsec = 0;
        time_to_wait.tv_sec = tv_now.tv_sec + consumer->poll_period;

        if (consumer->last_signalled_time.tv_sec > consumer->last_polled_time.tv_sec) {
            time_diff = consumer->last_signalled_time.tv_sec - consumer->last_polled_time.tv_sec;
            if ((UINT)time_diff < consumer->poll_period) {
                time_to_wait.tv_sec = tv_now.tv_sec + (consumer->poll_period - time_diff);
            }
        }

        rc = pthread_cond_timedwait(&consumer->cond, &consumer->lock, &time_to_wait);
        if ((rc == 0) || (queue_count(consumer->queue) > 0)) {
            while (queue_count(consumer->queue)) {
                queue_data = queue_pop(consumer->queue);
                if (queue_data == NULL) {
                    continue;
                }
                switch (queue_data->event_type) {
                    case consumer_event_type_webconfig:
                        printf("%s:%d consumer webconfig event subtype:%d\r\n",__func__, __LINE__, queue_data->sub_type);
                        handle_webconfig_consumer_event(consumer, queue_data->msg, queue_data->len, queue_data->sub_type);
                    break;

                    default:
                        printf("[%s]:WIFI consumer thread not supported this event %d\r\n",__FUNCTION__, queue_data->event_type);
                    break;
                }

                if(queue_data->msg) {
                    free(queue_data->msg);
                }

                free(queue_data);
                clock_gettime(CLOCK_MONOTONIC, &consumer->last_signalled_time);
            }
        } else if (rc == ETIMEDOUT) {
            clock_gettime(CLOCK_MONOTONIC, &consumer->last_polled_time);
            scheduler_execute(consumer->sched, consumer->last_polled_time, (consumer->poll_period*1000));

#ifndef WEBCONFIG_TESTS_OVER_QUEUE
            if (consumer->rbus_events_subscribed == false) {
                consumer_events_subscribe(consumer);
                if (consumer->rbus_events_subscribed == true) {
                    dml_init_sync = true;
                    enable_ovsdb = false;
                    is_ovs_init = false;
                    printf("%s %d Trigger initial sync message\r\n", __func__, __LINE__);
                    test_initial_sync();
                }
            }
#endif
            if (consumer->rbus_events_subscribed == true) {
                if ((consumer->test_input == consumer_test_start_all_subdoc) &&
                        (consumer->test_state != consumer_test_state_home_subdoc_test_complete)) {
                    consumer_app_all_test_sequence(consumer);
                }
            }

            if ((consumer->test_state == consumer_test_state_radio_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_radio_subdoc)) {
                consumer->radio_test_pending_count++;
                if (consumer->radio_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: Radio test failed, timed out\n", __func__, __LINE__);
                    consumer->radio_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_radio_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_private_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_private_subdoc)) {
                consumer->private_test_pending_count++;
                if (consumer->private_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: Private vap test failed, timed out\n", __func__, __LINE__);
                    consumer->private_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_private_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_mesh_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_mesh_subdoc)) {
                consumer->mesh_test_pending_count++;
                if (consumer->mesh_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: Mesh vap test failed, timed out\n", __func__, __LINE__);
                    consumer->mesh_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_mesh_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_xfinity_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_xfinity_subdoc)) {
                consumer->xfinity_test_pending_count++;
                if (consumer->xfinity_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: xfinity vap test failed, timed out\n", __func__, __LINE__);
                    consumer->xfinity_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_xfinity_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_home_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_home_subdoc)) {
                consumer->home_test_pending_count++;
                if (consumer->home_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: home vap test failed, timed out\n", __func__, __LINE__);
                    consumer->home_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_home_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_lnf_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_lnf_subdoc)) {
                consumer->lnf_test_pending_count++;
                if (consumer->lnf_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: lnf vap test failed, timed out\n", __func__, __LINE__);
                    consumer->lnf_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_lnf_subdoc_test_complete;
                }
            } else if ((consumer->test_state == consumer_test_state_macfilter_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_macfilter_subdoc)) {
                consumer->macfilter_test_pending_count++;
                if (consumer->macfilter_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: macfilter test failed, timed out\n", __func__, __LINE__);
                    consumer->macfilter_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_macfilter_subdoc_test_complete;
                }
            }  else if ((consumer->test_state == consumer_test_state_null_subdoc_test_pending) &&
                    (consumer->test_input == consumer_test_start_null_subdoc)) {
                consumer->null_test_pending_count++;
                if (consumer->null_test_pending_count > MAX_WAIT) {
                    printf("%s:%d: null test failed, timed out\n", __func__, __LINE__);
                    consumer->null_test_pending_count = 0;
                    consumer->test_state = consumer_test_state_null_subdoc_test_complete;
                }
            }

        } else {
            printf("RDK_LOG_WARN, WIFI %s: Invalid Return Status %d\n",__FUNCTION__,rc);
            continue;
        }
    }
    pthread_mutex_unlock(&consumer->lock);

    return;
}



int start_tests(webconfig_consumer_t *consumer)
{
    consumer->exit_consumer = false;
    consumer->radio_test_pending_count = 0;
    consumer->private_test_pending_count = 0;
    consumer->mesh_test_pending_count = 0;

    consumer->test_state = consumer_test_state_none;
    consumer_queue_loop(consumer);

    printf("%s:%d Exited queue_wifi_consumer_task.\n",__FUNCTION__,__LINE__);
    return 0;
}

void run_tests()
{
    if (init_tests(&webconfig_consumer) != 0) {
        printf("%s:%d: Failed to init\n", __func__, __LINE__);
        return;
    }

    create_cli_task();
    start_tests(&webconfig_consumer);

}

#ifdef WEBCONFIG_TESTS_OVER_QUEUE
void *webconfig_consumer_tests(void *arg)
{
    wifi_mgr_t *mgr = (wifi_mgr_t *)arg;

    pthread_mutex_lock(&mgr->lock);
    mgr->dml_init_status.condition = true;
    pthread_cond_signal(&mgr->dml_init_status.cv);
    pthread_mutex_unlock(&mgr->lock);
    printf("%s:%d:test program started\n", __func__, __LINE__);

    webconfig_consumer.test_over_rbus = false;

    run_tests();

    return NULL;

}
#endif

void set_test_data_radio()
{
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
    wifi_mgr_t *mgr = get_wifimgr_obj();
    rdk_wifi_radio_t    *radio = mgr->radio_config;
    wifi_radio_operationParam_t *oper;

    // Radio 1
    radio = &mgr->radio_config[0];

    strcpy(radio->name, "radio1");

    radio->vaps.radio_index = 0;
    radio->vaps.num_vaps = 8;
    radio->vaps.rdk_vap_array[0].vap_index = 0;
    strcpy((char *)radio->vaps.rdk_vap_array[0].vap_name, "private_ssid_2g");
    radio->vaps.rdk_vap_array[1].vap_index = 2;
    strcpy((char *)radio->vaps.rdk_vap_array[1].vap_name, "iot_ssid_2g");
    radio->vaps.rdk_vap_array[2].vap_index = 4;
    strcpy((char *)radio->vaps.rdk_vap_array[2].vap_name, "hotspot_open_2g");
    radio->vaps.rdk_vap_array[3].vap_index = 6;
    strcpy((char *)radio->vaps.rdk_vap_array[3].vap_name, "lnf_psk_2g");
    radio->vaps.rdk_vap_array[4].vap_index = 8;
    strcpy((char *)radio->vaps.rdk_vap_array[4].vap_name, "hotspot_secure_2g");
    radio->vaps.rdk_vap_array[5].vap_index = 10;
    strcpy((char *)radio->vaps.rdk_vap_array[5].vap_name, "lnf_radius_2g");
    radio->vaps.rdk_vap_array[6].vap_index = 12;
    strcpy((char *)radio->vaps.rdk_vap_array[6].vap_name, "mesh_backhaul_2g");
    radio->vaps.rdk_vap_array[7].vap_index = 14;
    strcpy((char *)radio->vaps.rdk_vap_array[7].vap_name, "mesh_sta_2g");

    oper = &radio->oper;
    oper->enable = true;
    oper->band = WIFI_FREQUENCY_2_4_BAND;
    oper->autoChannelEnabled = true;
    oper->channel = 6;
    oper->channelWidth = 1;

    // Radio 2
    radio = &mgr->radio_config[1];

    strcpy(radio->name, "radio2");

    radio->vaps.radio_index = 1;
    radio->vaps.num_vaps = 8;
    radio->vaps.rdk_vap_array[0].vap_index = 1;
    strcpy((char *)radio->vaps.rdk_vap_array[0].vap_name, "private_ssid_5g");
    radio->vaps.rdk_vap_array[1].vap_index = 3;
    strcpy((char *)radio->vaps.rdk_vap_array[1].vap_name, "iot_ssid_5g");
    radio->vaps.rdk_vap_array[2].vap_index = 5;
    strcpy((char *)radio->vaps.rdk_vap_array[2].vap_name, "hotspot_open_5g");
    radio->vaps.rdk_vap_array[3].vap_index = 7;
    strcpy((char *)radio->vaps.rdk_vap_array[3].vap_name, "lnf_psk_5g");
    radio->vaps.rdk_vap_array[4].vap_index = 9;
    strcpy((char *)radio->vaps.rdk_vap_array[4].vap_name, "hotspot_secure_5g");
    radio->vaps.rdk_vap_array[5].vap_index = 11;
    strcpy((char *)radio->vaps.rdk_vap_array[5].vap_name, "lnf_radius_5g");
    radio->vaps.rdk_vap_array[6].vap_index = 13;
    strcpy((char *)radio->vaps.rdk_vap_array[6].vap_name, "mesh_backhaul_5g");
    radio->vaps.rdk_vap_array[7].vap_index = 15;
    strcpy((char *)radio->vaps.rdk_vap_array[7].vap_name, "mesh_sta_5g");

    oper = &radio->oper;
    oper->enable = true;
    oper->band = WIFI_FREQUENCY_5_BAND;
    oper->autoChannelEnabled = true;
    oper->channel = 36;
    oper->channelWidth = 1;
#endif//WEBCONFIG_TESTS_OVER_QUEUE
}


void set_config_data()
{
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
    mac_address_t client_mac = {0x01, 0x21, 0x33, 0x45, 0x42, 0xdd};
    wifi_mgr_t *mgr = get_wifimgr_obj();
    wifi_global_config_t *config = &mgr->global_config;
    wifi_GASConfiguration_t *gas_config = &config->gas_config;;
    wifi_global_param_t *global_param = &config->global_parameters;

    // fill config
    gas_config->AdvertisementID = 0;
    gas_config->PauseForServerResponse = true;
    gas_config->ResponseTimeout = 1000;
    gas_config->ComeBackDelay = 40;
    gas_config->ResponseBufferingTime = 10;
    gas_config->QueryResponseLengthLimit = 100;

    global_param->notify_wifi_changes = true;
    global_param->prefer_private = true;
    global_param->prefer_private_configure = true;
    global_param->factory_reset = false;
    global_param->tx_overflow_selfheal = false;
    global_param->inst_wifi_client_enabled = false;
    global_param->inst_wifi_client_reporting_period = 10;
    memcpy(global_param->inst_wifi_client_mac, client_mac, sizeof(mac_address_t));
    strcpy(global_param->wps_pin, "1234");
    strcpy(global_param->wifi_region_code, "US");
    global_param->validate_ssid = true;
#endif//WEBCONFIG_TESTS_OVER_QUEUE
}

void set_test_data_vaps()
{
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
    wifi_mgr_t *mgr = get_wifimgr_obj();
    rdk_wifi_radio_t    *radio = (rdk_wifi_radio_t *)&mgr->radio_config;
    wifi_vap_info_map_t *map;
    wifi_vap_info_t *vap;

    // Radio 1
    radio = &mgr->radio_config[0];
    map = &radio->vaps.vap_map;
    map->num_vaps = 8;

    // private
    vap = &radio->vaps.vap_map.vap_array[0];
    vap->vap_index = 0;
    strcpy(vap->vap_name, "private_ssid_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_private_ssid_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // iot
    vap = &radio->vaps.vap_map.vap_array[1];
    vap->vap_index = 2;
    strcpy(vap->vap_name, "iot_ssid_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_iot_ssid_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // hotspot open
    vap = &radio->vaps.vap_map.vap_array[2];
    vap->vap_index = 4;
    strcpy(vap->vap_name, "hotspot_open_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_hotspot_open_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_none;

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // lnf psk
    vap = &radio->vaps.vap_map.vap_array[3];
    vap->vap_index = 6;
    strcpy(vap->vap_name, "lnf_psk_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_lnf_psk_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // hotspot secure
    vap = &radio->vaps.vap_map.vap_array[4];
    vap->vap_index = 8;
    strcpy(vap->vap_name, "hotspot_secure_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_hotspot_secure_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    vap->u.bss_info.security.u.radius.port = 22;
    strcpy(vap->u.bss_info.security.u.radius.key, "hotspot 2.4 radius key");
    strcpy(vap->u.bss_info.security.u.radius.identity, "hotspot 2.4 radius identity");
    strcpy((char *)vap->u.bss_info.security.u.radius.ip, "192.20.1.8");
    vap->u.bss_info.security.u.radius.s_port = 22;
    strcpy((char *)vap->u.bss_info.security.u.radius.s_ip, "192.20.1.9");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // lnf radius
    vap = &radio->vaps.vap_map.vap_array[5];
    vap->vap_index = 10;
    strcpy(vap->vap_name, "lnf_radius_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_lnf_radius_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    vap->u.bss_info.security.u.radius.port = 22;
    strcpy(vap->u.bss_info.security.u.radius.key, "lnf 2.4 radius key");
    strcpy(vap->u.bss_info.security.u.radius.identity, "lnf 2.4 radius identity");
    strcpy((char *)vap->u.bss_info.security.u.radius.ip, "192.20.1.8");
    vap->u.bss_info.security.u.radius.s_port = 22;
    strcpy((char *)vap->u.bss_info.security.u.radius.s_ip, "192.20.1.9");


    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // mesh backhaul
    vap = &radio->vaps.vap_map.vap_array[6];
    vap->vap_index = 12;
    strcpy(vap->vap_name, "mesh_backhaul_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_mesh_backhaul_2g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // mesh sta
    vap = &radio->vaps.vap_map.vap_array[7];
    vap->vap_index = 14;
    strcpy(vap->vap_name, "mesh_sta_2g");
    vap->radio_index = 0;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_sta;

    strcpy(vap->u.sta_info.ssid, "test_mesh_sta_2g");
    memset(vap->u.sta_info.bssid, 0, sizeof(bssid_t));
    vap->u.sta_info.enabled = true;

    vap->u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.sta_info.security.encr = wifi_encryption_aes;
    vap->u.sta_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.sta_info.security.u.key.key, "test1webconf");

    vap->u.sta_info.scan_params.period = 2;
    vap->u.sta_info.scan_params.channel.channel = 0;


    // Radio 2
    radio = &mgr->radio_config[1];
    map = &radio->vaps.vap_map;
    map->num_vaps = 8;

    // private
    vap = &radio->vaps.vap_map.vap_array[0];
    vap->vap_index = 1;
    strcpy(vap->vap_name, "private_ssid_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_private_ssid_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test2webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // iot
    vap = &radio->vaps.vap_map.vap_array[1];
    vap->vap_index = 3;
    strcpy(vap->vap_name, "iot_ssid_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_iot_ssid_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // hotspot open
    vap = &radio->vaps.vap_map.vap_array[2];
    vap->vap_index = 5;
    strcpy(vap->vap_name, "hotspot_open_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_hotspot_open_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_none;

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // lnf psk
    vap = &radio->vaps.vap_map.vap_array[3];
    vap->vap_index = 7;
    strcpy(vap->vap_name, "lnf_psk_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_lnf_psk_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // hotspot secure
    vap = &radio->vaps.vap_map.vap_array[4];
    vap->vap_index = 9;
    strcpy(vap->vap_name, "hotspot_secure_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_hotspot_secure_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    vap->u.bss_info.security.u.radius.port = 22;
    strcpy(vap->u.bss_info.security.u.radius.key, "hotspot 5 radius key");
    strcpy(vap->u.bss_info.security.u.radius.identity, "hotspot 5 radius identity");
    strcpy((char *)vap->u.bss_info.security.u.radius.ip, "192.20.1.8");
    vap->u.bss_info.security.u.radius.s_port = 22;
    strcpy((char *)vap->u.bss_info.security.u.radius.s_ip, "192.20.1.9");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // lnf radius
    vap = &radio->vaps.vap_map.vap_array[5];
    vap->vap_index = 11;
    strcpy(vap->vap_name, "lnf_radius_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_lnf_radius_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    vap->u.bss_info.security.u.radius.port = 22;
    strcpy(vap->u.bss_info.security.u.radius.key, "lnf 5 radius key");
    strcpy(vap->u.bss_info.security.u.radius.identity, "lnf 5 radius identity");
    strcpy((char *)vap->u.bss_info.security.u.radius.ip, "192.20.1.8");
    vap->u.bss_info.security.u.radius.s_port = 22;
    strcpy((char *)vap->u.bss_info.security.u.radius.s_ip, "192.20.1.9");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // mesh backhaul
    vap = &radio->vaps.vap_map.vap_array[6];
    vap->vap_index = 13;
    strcpy(vap->vap_name, "mesh_backhaul_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_ap;

    strcpy(vap->u.bss_info.ssid, "test_mesh_backhaul_5g");
    vap->u.bss_info.enabled = true;
    vap->u.bss_info.showSsid = true;

    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.bss_info.security.encr = wifi_encryption_aes;
    vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.bss_info.security.u.key.key, "test1webconf");

    strcpy(vap->u.bss_info.interworking.interworking.hessid, "11:22:33:44:55:66");

    strcpy(vap->u.bss_info.beaconRateCtl, "12345");

    // mesh sta
    vap = &radio->vaps.vap_map.vap_array[7];
    vap->vap_index = 15;
    strcpy(vap->vap_name, "mesh_sta_5g");
    vap->radio_index = 1;
    strcpy(vap->bridge_name, "brlan1");
    vap->vap_mode = wifi_vap_mode_sta;

    strcpy(vap->u.sta_info.ssid, "test_mesh_sta_5g");
    memset(vap->u.sta_info.bssid, 0, sizeof(bssid_t));
    vap->u.sta_info.enabled = true;

    vap->u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
    vap->u.sta_info.security.encr = wifi_encryption_aes;
    vap->u.sta_info.security.mfp = wifi_mfp_cfg_disabled;
    strcpy(vap->u.sta_info.security.u.key.key, "test1webconf");

    vap->u.sta_info.scan_params.period = 2;
    vap->u.sta_info.scan_params.channel.channel = 0;

#endif//WEBCONFIG_TESTS_OVER_QUEUE
}

void webconfig_consumer_set_test_data()
{
    set_config_data();
    set_test_data_radio();
    set_test_data_vaps();
}

void dump_subdoc(const char *str, webconfig_subdoc_type_t type)
{
    if (debug_enable == false) {
        return ;
    }
    FILE *fp = NULL;
    char file_name[128];

    //    getcwd(file_name, 128);
    strcpy(file_name, "/tmp");
    switch (type) {
        case webconfig_subdoc_type_private:
            strcat(file_name, "/log_private_subdoc");
        break;

        case webconfig_subdoc_type_radio:
            strcat(file_name, "/log_radio_subdoc");
        break;

        case webconfig_subdoc_type_mesh:
            strcat(file_name, "/log_mesh_subdoc");
        break;
        case webconfig_subdoc_type_xfinity:
            strcat(file_name, "/log_xfinity_subdoc");
        break;
        case webconfig_subdoc_type_lnf:
            strcat(file_name, "/log_lnf_subdoc");
        break;
        case webconfig_subdoc_type_home:
            strcat(file_name, "/log_home_subdoc");
        break;
        case webconfig_subdoc_type_mac_filter:
            strcat(file_name, "/log_mac_filter_subdoc");
        break;
        case webconfig_subdoc_type_dml:
            strcat(file_name, "/log_dml_subdoc");
        break;

        case webconfig_subdoc_type_associated_clients:
            strcat(file_name, "/log_assoc_clients_subdoc");
        break;

        case webconfig_subdoc_type_null:
            strcat(file_name, "/log_null_subdoc");
            break;

        case webconfig_subdoc_type_mesh_sta:
            strcat(file_name, "/log_mesh_sta_subdoc");
            break;

        case webconfig_subdoc_type_steering_config:
            strcat(file_name, "/log_steering_config_subdoc");
            break;

        default:
            return;
    }

    if ((fp = fopen(file_name, "w")) == NULL) {
        printf("%s:%d: error opening file:%s\n", __func__, __LINE__, file_name);
        return;
    }

    fputs(str, fp);
    fclose(fp);

    return;
}

wifi_vap_info_t *get_wifi_radio_vap_info(rdk_wifi_radio_t *wifi_radio, const char *vap_name_prefix)
{
    unsigned int vap_array_index;
    wifi_vap_info_t *vap_info = NULL;

    for (vap_array_index = 0; vap_array_index < wifi_radio->vaps.vap_map.num_vaps; ++vap_array_index) {
        if (!strncmp(wifi_radio->vaps.vap_map.vap_array[vap_array_index].vap_name, vap_name_prefix, strlen(vap_name_prefix))) {
            vap_info = &wifi_radio->vaps.vap_map.vap_array[vap_array_index];
        }
    }
    return vap_info;
}

rdk_wifi_vap_info_t *get_wifi_radio_rdkvap_info(rdk_wifi_radio_t *wifi_radio, const char *vap_name_prefix)
{
    unsigned int vap_array_index;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;

    for (vap_array_index = 0; vap_array_index < wifi_radio->vaps.num_vaps; ++vap_array_index) {
        if (!strncmp(wifi_radio->vaps.rdk_vap_array[vap_array_index].vap_name, vap_name_prefix, strlen(vap_name_prefix))) {
            rdk_vap_info = &wifi_radio->vaps.rdk_vap_array[vap_array_index];
        }
    }
    return rdk_vap_info;
}
