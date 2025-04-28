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

#define WIFI_EM_CHANNEL_SCAN_REQUEST          "Device.WiFi.EM.ChannelScanRequest"
#define WIFI_EM_CHANNEL_SCAN_REPORT           "Device.WiFi.EM.ChannelScanReport"
#define WIFI_EM_BEACON_REPORT                 "Device.WiFi.EM.BeaconReport"
#define WIFI_EM_STA_LINK_METRICS_REPORT       "Device.WiFi.EM.STALinkMetricsReport"
#define WIFI_EM_ASSOCIATION_STATUS            "Device.WiFi.EM.AssociationStatus"
#define WIFI_SET_DISCONN_STEADY_STATE         "Device.WiFi.EM.SetDisconnSteadyState"
#define WIFI_SET_DISCONN_SCAN_NONE_STATE      "Device.WiFi.EM.SetDisconnScanNoneState"

typedef struct wifi_app wifi_app_t;

typedef char short_string[32];

typedef struct {
    em_config_t           em_config;
} em_data_t;

typedef struct {
    hash_map_t *client_type_map;
} sta_client_type_data_t;

typedef enum {
    em_app_event_type_assoc_dev_stats,
} em_app_event_type_t;

#ifdef __cplusplus
}
#endif

#endif // WIFI_EM_H
