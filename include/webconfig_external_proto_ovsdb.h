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

typedef struct {
    const struct schema_Wifi_Radio_Config **radio_config;
    const struct schema_Wifi_VIF_Config **vif_config;
    const struct schema_Wifi_Credential_Config **cred_config;
    const struct schema_Wifi_Radio_State **radio_state;
    const struct schema_Wifi_VIF_State   **vif_state;
    const struct schema_Wifi_Associated_Clients **assoc_clients;

    const unsigned int radio_config_row_count;
    const unsigned int vif_config_row_count;
    const unsigned int radio_state_row_count;
    const unsigned int vif_state_row_count;
    const unsigned int assoc_clients_row_count;

/* TBD: place for next arrays and other data, in particular
 *
 * * the supplementary STATE data read from OneWifi Manager
 * */

} webconfig_external_ovsdb_t;

#endif //EXTERNAL_PROTO_OVSDB_H
