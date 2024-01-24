/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2023 RDK Management

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

#ifndef SM_REPORT_H
#define SM_REPORT_H

#include "sm_cache.h"
#include "wifi_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wifi_app wifi_app_t;

int sm_report_start_task(stats_type_t type, wifi_app_t *app, wifi_mon_stats_request_state_t state,
    const stats_config_t *config);
int  sm_report_config_task(wifi_app_t *app, wifi_mon_stats_request_state_t state, const stats_config_t *config);
int  sm_report_deinit(wifi_app_t *app);
int  sm_report_init(wifi_app_t *app);
int  sm_report_send_to_qm_cb(void *args);
int survey_report_counter_publish_cb(void *args);

/* CLIENT */
int  sm_client_report_push_to_dpp(sm_client_cache_t *cache, wifi_freq_bands_t freq_band, unsigned int channel);

/* SURVEY */
int  sm_survey_report_push_to_dpp(sm_survey_cache_t *cache, wifi_freq_bands_t freq_band,
                                  survey_type_t survey_type, reporting_type_t report_type,
                                  unsigned int *report_counter);

/* NEIGHBOR */
int  sm_neighbor_report_push_to_dpp(sm_neighbor_cache_t *cache, wifi_freq_bands_t freq_band,
                                    survey_type_t survey_type, reporting_type_t report_type);

#ifdef __cplusplus
}
#endif

#endif // SM_REPORT_H
