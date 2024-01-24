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

#ifndef WIFI_SM_H
#define WIFI_SM_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wifi_app wifi_app_t;

typedef struct {
    hash_map_t           *sm_stats_config_map;
    hash_map_t           *report_tasks_map;
    unsigned int off_chan_report_counter[MAX_NUM_RADIOS];
    unsigned int on_chan_report_counter[MAX_NUM_RADIOS];
} sm_data_t;

typedef enum {
    sm_app_event_type_neighbor = 1,
    sm_app_event_type_survey,
    sm_app_event_type_capacity,
    sm_app_event_type_assoc_dev_diag,
    sm_app_event_type_assoc_dev_stats,
    sm_app_event_type_max
} sm_app_event_type_t;

int sm_init(wifi_app_t *app, unsigned int create_flag);
int sm_deinit(wifi_app_t *app);
int sm_event(wifi_app_t *app, wifi_event_t *event);

#ifdef __cplusplus
}
#endif

#endif // WIFI_SM_H
