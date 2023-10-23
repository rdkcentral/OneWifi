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

#ifndef WIFI_WEBCONFIG_CONSUMER_H
#define WIFI_WEBCONFIG_CONSUMER_H

#include "rbus.h"
#include "wifi_webconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_WAIT            20
#define RBUS_CLI_MAX_PARAM  25

typedef enum {
    consumer_event_type_webconfig,
    consumer_event_type_max
} consumer_event_type_t;

typedef enum {
    // WebConfig event sub types
    consumer_event_webconfig_set_data,
    consumer_event_webconfig_get_data,
} consumer_event_subtype_t;

typedef enum {
    consumer_test_state_none,
    consumer_test_state_cache_init_pending,
    consumer_test_state_cache_init_complete,
    consumer_test_state_radio_subdoc_test_pending,
    consumer_test_state_radio_subdoc_test_complete,
    consumer_test_state_private_subdoc_test_pending,
    consumer_test_state_private_subdoc_test_complete,
    consumer_test_state_mesh_subdoc_test_pending,
    consumer_test_state_mesh_subdoc_test_complete,
    consumer_test_state_xfinity_subdoc_test_pending,
    consumer_test_state_xfinity_subdoc_test_complete,
    consumer_test_state_lnf_subdoc_test_pending,
    consumer_test_state_lnf_subdoc_test_complete,
    consumer_test_state_home_subdoc_test_pending,
    consumer_test_state_home_subdoc_test_complete,
    consumer_test_state_macfilter_subdoc_test_pending,
    consumer_test_state_macfilter_subdoc_test_complete,
    consumer_test_state_null_subdoc_test_pending,
    consumer_test_state_null_subdoc_test_complete,
    consumer_test_state_mesh_sta_subdoc_test_pending,
    consumer_test_state_mesh_sta_subdoc_test_complete,
    consumer_test_state_band_steer_config_test_pending,
    consumer_test_state_band_steer_config_test_complete,
    consumer_test_state_stats_config_test_pending,
    consumer_test_state_stats_config_test_complete,
    consumer_test_state_band_steer_client_test_pending,
    consumer_test_state_band_steer_client_test_complete,
    consumer_test_state_vif_neighbors_test_pending,
    consumer_test_state_vif_neighbors_test_complete,
} consumer_test_state_t;

typedef enum {
    consumer_test_start_none,
    consumer_test_start_radio_subdoc,
    consumer_test_start_private_subdoc,
    consumer_test_start_mesh_subdoc,
    consumer_test_start_xfinity_subdoc,
    consumer_test_start_lnf_subdoc,
    consumer_test_start_home_subdoc,
    consumer_test_start_all_subdoc,
    consumer_test_start_wan_manager,
    consumer_test_start_client_connection,
    consumer_test_start_macfilter_subdoc,
    consumer_test_start_null_subdoc,
    consumer_test_start_mesh_sta_subdoc,
    consumer_test_start_band_steer_config_subdoc,
    consumer_test_start_stats_config_subdoc,
    consumer_test_start_band_steer_client_subdoc,
    consumer_test_start_vif_neighbors_subdoc,
    consumer_all_test_completed
} consumer_test_sequence_t;

typedef struct {
    consumer_event_type_t     event_type;
    consumer_event_subtype_t  sub_type;
    void *msg;
    unsigned int len;
} __attribute__((__packed__)) consumer_event_t;

typedef struct {
    wifi_global_config_t    config;
    wifi_hal_capability_t   hal_cap;
    rdk_wifi_radio_t    radios[MAX_NUM_RADIOS];
    bool	        test_over_rbus;
    bool                exit_consumer;
    queue_t             *queue;
    pthread_mutex_t     lock;
    pthread_cond_t      cond;
    unsigned int        poll_period;
    struct timespec     last_signalled_time;
    struct timespec     last_polled_time;
    struct scheduler    *sched;
    webconfig_t         webconfig;
    rbusHandle_t        rbus_handle;
    bool                rbus_events_subscribed;
    consumer_test_state_t test_state;
    consumer_test_sequence_t test_input;
    char user_input_file_name[48];
    unsigned int        radio_test_pending_count;
    unsigned int        private_test_pending_count;
    unsigned int        mesh_test_pending_count;
    unsigned int        xfinity_test_pending_count;
    unsigned int        lnf_test_pending_count;
    unsigned int        home_test_pending_count;
    unsigned int        macfilter_test_pending_count;
    unsigned int        null_test_pending_count;
    unsigned char       sta_connect_test_pending_count;
    unsigned int        steer_config_test_pending_count;
    unsigned int        stats_config_test_pending_count;
    unsigned int        steer_client_test_pending_count;
    unsigned int        vif_neighbors_test_pending_count;
} webconfig_consumer_t;

rbusError_t webconfig_consumer_set_subdoc(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts);
void webconfig_consumer_sta_conn_status(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription);
void webconfig_consumer_sta_interface_name(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription);
webconfig_consumer_t *get_consumer_object();

#ifdef __cplusplus
}
#endif

#endif // WIFI_WEBCONFIG__CONSUMER_H
