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

#ifndef WIFI_LINKQUALITY_H
#define WIFI_LINKQUALITY_H

#define MAX_IGNITE_STR_LEN 32

#ifdef __cplusplus
extern "C" {
#endif
#include "run_qmgr.h"
#include "wifi_base.h"
#include "wifi_webconfig.h"
#include "wifi_hal.h"
#include "wifi_linkquality_libs.h"

#define MAX_STR_LEN_LQ 128
#define IGNITE_SCORE_LOG_INTERVAL_MS 900000 // 15 mins
#define IGNITE_INITIAL_PUBLISH_ITERATIONS 5


#define MAC_ADDRESS_LEN 6
typedef struct {
    double last_score;
    double last_threshold;
    int score_log_timer_id;
    int last_service_state;
    int iteration_count;
    char ignite_service_status[MAX_IGNITE_STR_LEN];
} ignite_lq_state_t;

typedef struct {
    stats_arg_t stats;
    server_arg_t server_arg;
    int size;
    ignite_lq_state_t ignite;
} linkquality_data_t;

typedef uint8_t mac_address_t[MAC_ADDRESS_LEN];

#define CTRL_CAP_SZ 8


#ifdef __cplusplus
}
#endif

#endif // WIFI_LINKQUALITY_H
