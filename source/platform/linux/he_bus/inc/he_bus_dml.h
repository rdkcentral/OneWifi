/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

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
#ifndef HE_BUS_DML_H
#define HE_BUS_DML_H

#ifdef __cplusplus
extern "C" {
#endif

#include "he_bus_common.h"

#define WIFI_WEBCONFIG_INIT_DML_DATA "Device.WiFi.WebConfig.Data.Init_dml"

he_bus_error_t wifi_get_param_value(char *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t wifi_set_param_value(char *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t wifi_event_sub_handler(char *eventName, he_bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);
he_bus_error_t wifi_method_handler(char const *methodName, he_bus_raw_data_t *inParams,
    he_bus_raw_data_t *outParams, void *asyncHandle);

he_bus_error_t radio_get_param_value(char *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t radio_set_param_value(char *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t radio_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum);
he_bus_error_t radio_table_remove_row_handler(char const *rowName);
he_bus_error_t radio_event_sub_handler(char *eventName, he_bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);
he_bus_error_t radio_method_handler(char const *methodName, he_bus_data_object_t *inParams,
    he_bus_data_object_t *outParams, void *asyncHandle);

he_bus_error_t accesspoint_get_param_value(char *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t accesspoint_set_param_value(char *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t accesspoint_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum);
he_bus_error_t accesspoint_table_remove_row_handler(char const *rowName);
he_bus_error_t accesspoint_event_sub_handler(char *eventName, he_bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);
he_bus_error_t accesspoint_method_handler(char const *methodName, he_bus_raw_data_t *inParams,
    he_bus_raw_data_t *outParams, void *asyncHandle);

he_bus_error_t ssid_get_param_value(char *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t ssid_set_param_value(char *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t ssid_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum);
he_bus_error_t ssid_table_remove_row_handler(char const *rowName);
he_bus_error_t ssid_event_sub_handler(char *eventName, he_bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);
he_bus_error_t ssid_method_handler(char const *methodName, he_bus_raw_data_t *inParams,
    he_bus_raw_data_t *outParams, void *asyncHandle);

he_bus_error_t default_get_param_value(char *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t default_set_param_value(char *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t default_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum);
he_bus_error_t default_table_remove_row_handler(char const *rowName);
he_bus_error_t default_event_sub_handler(char *eventName, he_bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);
he_bus_error_t default_method_handler(char const *methodName, he_bus_raw_data_t *inParams,
    he_bus_raw_data_t *outParams, void *asyncHandle);

#ifdef __cplusplus
}
#endif
#endif // HE_BUS_DML_H
