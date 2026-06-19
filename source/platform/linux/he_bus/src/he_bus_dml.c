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
#include "he_bus_dml.h"
#include "he_bus_common.h"
#include "he_bus_core.h"
#include "he_bus_memory.h"
#include "he_bus_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NUM_RADIOS 2
#define MAX_NUM_VAPS 16

const char *private_subdoc = "{"
                             "\"Version\": \"1.0\","
                             "\"SubDocName\": \"private\","
                             "\"WifiVapConfig\": ["
                             "{"
                             "\"VapName\": \"private_ssid_2g\","
                             "\"BridgeName\": \"brlan0\""
                             "},"
                             "{"
                             "\"VapName\": \"private_ssid_5g\","
                             "\"BridgeName\": \"brlan0\""
                             "},"
                             "{"
                             "\"VapName\": \"private_ssid_6g\","
                             "\"BridgeName\": \"brlan0\""
                             "}"
                             "]"
                             "}";

he_bus_error_t wifi_get_param_value(char *event_name, he_bus_raw_data_t *p_data)
{
    (void)p_data;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    return he_bus_error_success;
}

he_bus_error_t wifi_set_param_value(char *event_name, he_bus_raw_data_t *p_data)
{
    (void)p_data;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    return he_bus_error_success;
}

he_bus_error_t wifi_event_sub_handler(char *eventName, he_bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    he_bus_dml_dbg_print("%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__, eventName,
        action, interval);
    return he_bus_error_success;
}

he_bus_error_t wifi_method_handler(char const *methodName, he_bus_raw_data_t *inParams,
    he_bus_raw_data_t *outParams, void *asyncHandle)
{
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, methodName);
    return he_bus_error_success;
}

he_bus_error_t radio_get_param_value(char *event_name, he_bus_raw_data_t *p_data)
{
    (void)p_data;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    return he_bus_error_success;
}

he_bus_error_t radio_set_param_value(char *event_name, he_bus_raw_data_t *p_data)
{
    (void)p_data;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    return he_bus_error_success;
}

he_bus_error_t radio_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)instNum;
    (void)aliasName;
    he_bus_dml_dbg_print("%s:%d enter\r\n", __func__, __LINE__);
    he_bus_dml_dbg_print("%s:%d Added table:%s\r\n", __func__, __LINE__, tableName);
    return he_bus_error_success;
}

he_bus_error_t radio_table_remove_row_handler(char const *rowName)
{
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    return he_bus_error_success;
}

he_bus_error_t radio_event_sub_handler(char *eventName, he_bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    he_bus_dml_dbg_print("%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__, eventName,
        action, interval);
    return he_bus_error_success;
}

he_bus_error_t radio_method_handler(char const *methodName, he_bus_data_object_t *inParams,
    he_bus_data_object_t *outParams, void *asyncHandle)
{
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, methodName);
    he_bus_dml_dbg_print("%s:%d =====>recv data name:%s\r\n", __func__, __LINE__, inParams->name);

    int index = 0;
    he_bus_raw_data_t payload_data = { 0 };

    while(index < 3) {
        payload_data.data_type = he_bus_data_type_uint32;
        payload_data.raw_data.u32 = index;
        payload_data.raw_data_len = sizeof(unsigned int);
        set_bus_object_data("device.wifi.aniket.output.enter", outParams, 0, payload_data, 0);
        index++;
    }
    return he_bus_error_success;
}

he_bus_error_t accesspoint_get_param_value(char *event_name, he_bus_raw_data_t *p_data)
{
    (void)p_data;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    return he_bus_error_success;
}

he_bus_error_t accesspoint_set_param_value(char *event_name, he_bus_raw_data_t *p_data)
{
    (void)p_data;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    return he_bus_error_success;
}

he_bus_error_t accesspoint_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)instNum;
    (void)aliasName;
    he_bus_dml_dbg_print("%s:%d enter\r\n", __func__, __LINE__);
    he_bus_dml_dbg_print("%s:%d Added table:%s\r\n", __func__, __LINE__, tableName);
    return he_bus_error_success;
}

he_bus_error_t accesspoint_table_remove_row_handler(char const *rowName)
{
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    return he_bus_error_success;
}

he_bus_error_t accesspoint_event_sub_handler(char *eventName, he_bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    he_bus_dml_dbg_print("%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__, eventName,
        action, interval);
    return he_bus_error_success;
}

he_bus_error_t accesspoint_method_handler(char const *methodName, he_bus_raw_data_t *inParams,
    he_bus_raw_data_t *outParams, void *asyncHandle)
{
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, methodName);
    return he_bus_error_success;
}

he_bus_error_t ssid_get_param_value(char *event_name, he_bus_raw_data_t *p_data)
{
    (void)p_data;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    return he_bus_error_success;
}

he_bus_error_t ssid_set_param_value(char *event_name, he_bus_raw_data_t *p_data)
{
    (void)p_data;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    return he_bus_error_success;
}

he_bus_error_t ssid_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)instNum;
    (void)aliasName;
    he_bus_dml_dbg_print("%s:%d enter\r\n", __func__, __LINE__);
    he_bus_dml_dbg_print("%s:%d Added table:%s\r\n", __func__, __LINE__, tableName);
    return he_bus_error_success;
}

he_bus_error_t ssid_table_remove_row_handler(char const *rowName)
{
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    return he_bus_error_success;
}

he_bus_error_t ssid_event_sub_handler(char *eventName, he_bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    he_bus_dml_dbg_print("%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__, eventName,
        action, interval);
    return he_bus_error_success;
}

he_bus_error_t ssid_method_handler(char const *methodName, he_bus_raw_data_t *inParams,
    he_bus_raw_data_t *outParams, void *asyncHandle)
{
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, methodName);
    return he_bus_error_success;
}

he_bus_error_t default_get_param_value(char *event_name, he_bus_raw_data_t *p_data)
{
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    if (!strncmp(event_name, (char *)WIFI_WEBCONFIG_INIT_DML_DATA, (strlen(event_name) + 1))) {
        p_data->raw_data_len = (strlen(private_subdoc) + 1);
        p_data->raw_data.bytes = he_bus_calloc(1, p_data->raw_data_len);
        p_data->data_type = he_bus_data_type_string;

        strncpy(p_data->raw_data.bytes, private_subdoc, p_data->raw_data_len);
    }
    return he_bus_error_success;
}

he_bus_error_t default_set_param_value(char *event_name, he_bus_raw_data_t *p_data)
{
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, event_name);
    if (p_data->data_type == he_bus_data_type_string) {
        he_bus_dml_dbg_print("%s:%d =====>[%s]set data:%s\r\n", __func__, __LINE__, event_name,
            (char *)p_data->raw_data.bytes);
    }
    return he_bus_error_success;
}

he_bus_error_t default_table_add_row_handler(char const *tableName, char const *aliasName,
    uint32_t *instNum)
{
    (void)instNum;
    (void)aliasName;
    he_bus_dml_dbg_print("%s:%d enter\r\n", __func__, __LINE__);
    he_bus_dml_dbg_print("%s:%d Added table:%s\r\n", __func__, __LINE__, tableName);
    return he_bus_error_success;
}

he_bus_error_t default_table_remove_row_handler(char const *rowName)
{
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, rowName);
    return he_bus_error_success;
}

he_bus_error_t default_event_sub_handler(char *eventName, he_bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    (void)autoPublish;
    he_bus_dml_dbg_print("%s:%d enter:%s: action:%d interval:%d\r\n", __func__, __LINE__, eventName,
        action, interval);
    return he_bus_error_success;
}

he_bus_error_t default_method_handler(char const *methodName, he_bus_raw_data_t *inParams,
    he_bus_raw_data_t *outParams, void *asyncHandle)
{
    (void)inParams;
    (void)outParams;
    (void)asyncHandle;
    he_bus_dml_dbg_print("%s:%d enter:%s\r\n", __func__, __LINE__, methodName);
    return he_bus_error_success;
}
