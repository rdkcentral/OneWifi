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

#ifndef EXTERNAL_PROTO_OVSDB_H
#define EXTERNAL_PROTO_OVSDB_H

#define EXTERNAL_PROTO_IF_NAME_SIZE 32
#define EXTERNAL_PROTO_MAX_VAPS 24

typedef struct {
    char if_name[EXTERNAL_PROTO_IF_NAME_SIZE];
    bool exists;
} webconfig_external_vap_info_t;

#define MAX_MQTT_TOPIC_LEN 256
typedef struct {
    const struct schema_Wifi_Radio_Config **radio_config;
    const struct schema_Wifi_VIF_Config **vif_config;
    const struct schema_Wifi_Blaster_Config **blaster_config;
    const char awlan_mqtt_topic[MAX_MQTT_TOPIC_LEN];
    const struct schema_Wifi_Credential_Config **cred_config;
    const struct schema_Wifi_Radio_State **radio_state;
    const struct schema_Wifi_VIF_State   **vif_state;
    const struct schema_Wifi_Blaster_State   **blaster_state;
    const struct schema_Wifi_Associated_Clients **assoc_clients;
    const struct schema_Wifi_Stats_Config  **stats_config;
    const struct schema_Band_Steering_Config **band_steer_config;
    const struct schema_Band_Steering_Clients **band_steering_clients;
    const struct schema_Wifi_VIF_Neighbors **vif_neighbors;

    const unsigned int radio_config_row_count;
    const unsigned int vif_config_row_count;
    const unsigned int blaster_config_row_count;
    const unsigned int radio_state_row_count;
    const unsigned int vif_state_row_count;
    const unsigned int blaster_state_row_count;
    const unsigned int assoc_clients_row_count;
    const unsigned int stats_row_count;
    const unsigned int steer_row_count;
    const unsigned int steering_client_row_count;
    const unsigned int vif_neighbor_row_count;

    webconfig_external_vap_info_t vap_info[EXTERNAL_PROTO_MAX_VAPS];
    unsigned int num_vaps;

    bool sec_schema_is_legacy;

/* TBD: place for next arrays and other data, in particular
 *
 * * the supplementary STATE data read from OneWifi Manager
 * */

} webconfig_external_ovsdb_t;

#endif //EXTERNAL_PROTO_OVSDB_H
