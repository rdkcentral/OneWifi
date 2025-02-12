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

#ifndef WIFI_EM_H
#define WIFI_EM_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wifi_app wifi_app_t;

typedef char short_string[32];
typedef struct {
    hash_map_t           *em_stats_config_map;
} em_data_t;

typedef struct {
    int interval;
    short_string managed_client;
} ap_metrics_policy_t;

typedef struct {
    int sta_count;
    mac_addr_t disallowed_sta[0];
} local_steering_disallowed_policy_t;

typedef struct {
    int sta_count;
    mac_addr_t disallowed_sta[0];
} btm_steering_disallowed_policy_t;

typedef struct {
    short_string backhaul_config;
} backhaul_bss_config_policy_t;

typedef struct {
    bool report_independent_channel_scan;
} channel_scan_reporting_policy_t;

typedef struct {
    unsigned int ruid;
    int sta_rcpi_threshhold;
    int sta_rcpi_hysteresis;
    int ap_util_threshold;
    bool traffic_stats;
    bool link_metrics;
    bool sta_status;

} radio_metrics_policy_t;
typedef struct {
    int radio_count;
    radio_metrics_policy_t radio_metrics_policy[0];
} radio_metrics_policies_t;

typedef struct {
    ap_metrics_policy_t ap_metric_policy;
    local_steering_disallowed_policy_t local_steering_dslw_policy;
    btm_steering_disallowed_policy_t btm_steering_dslw_policy;
    backhaul_bss_config_policy_t backhaul_bss_config_policy;
    channel_scan_reporting_policy_t channel_scan_reporting_policy;
    radio_metrics_policies_t radio_metrics_policies;
} em_policies_t;

typedef enum {
    em_app_event_type_assoc_dev_stats,
} em_app_event_type_t;

int em_init(wifi_app_t *app, unsigned int create_flag);
int em_deinit(wifi_app_t *app);
int em_event(wifi_app_t *app, wifi_event_t *event);

#ifdef __cplusplus
}
#endif

#endif // WIFI_EM_H
