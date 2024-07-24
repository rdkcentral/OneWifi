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

#ifndef BUS_H
#define BUS_H

#include "bus_common.h"
#include "wifi_util.h"
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bus_handle {
    union {
        void *new_bus_handle;
    } u;
} bus_handle_t;

typedef struct bus_property {
    union {
        void *new_bus_property;
    } u;
} bus_property_t;

typedef struct bus_get_handler_options {
    union {
        void *new_bus_options;
    } u;
} bus_get_handler_options_t;

typedef struct bus_set_handler_options {
    union {
        void *new_bus_options;
    } u;
} bus_set_handler_options_t;

typedef struct bus_object {
    union {
        void *new_bus_object;
    } u;
} bus_object_t;

typedef struct bus_method_async_handle {
    union {
        void *new_bus_async_handle;
    } u;
} bus_method_async_handle_t;

typedef struct bus_filter {
    union {
        void *new_bus_event_filter;
    } u;
} bus_filter_t;

typedef struct bus_event {
    char *name;
    uint32_t type;
    bus_object_t data;
} bus_event_t;

typedef struct bus_event_sub_t bus_event_subs_t;

typedef bus_error_t (*bus_get_handler_t)(bus_handle_t handle, bus_property_t property,
    bus_get_handler_options_t options);
typedef bus_error_t (*bus_set_handler_t)(bus_handle_t handle, bus_property_t property,
    bus_set_handler_options_t options);
typedef bus_error_t (*bus_table_add_row_handler_t)(bus_handle_t handle, char const *tableName,
    char const *aliasName, uint32_t *instNum);
typedef bus_error_t (*bus_table_remove_row_handler_t)(bus_handle_t handle, char const *rowName);
typedef bus_error_t (*bus_method_handler_t)(bus_handle_t handle, char const *methodName,
    bus_object_t inParams, bus_object_t outParams, bus_method_async_handle_t asyncHandle);
typedef bus_error_t (*bus_event_sub_handler_t)(bus_handle_t handle, bus_event_sub_action_t action,
    char const *eventName, bus_filter_t filter, int32_t interval, bool *autoPublish);
typedef void (*bus_sub_async_resp_handler_t)(bus_handle_t handle, bus_event_subs_t *subscription,
    bus_error_t error);

typedef struct bus_event_sub {
    char const *event_name;
    void *filter;
    uint32_t interval;
    uint32_t duration;
    void *handler;
    void *user_data;
    void *handle;
    bus_sub_async_resp_handler_t async_handler;
    bool publish_on_sub;
} bus_event_sub_t;

typedef struct bus_callback_table {
    bus_get_handler_t get_handler;
    bus_set_handler_t set_handler;
    bus_table_add_row_handler_t table_add_row_handler;
    bus_table_remove_row_handler_t table_remove_row_handler;
    bus_event_sub_handler_t event_sub_handler;
    bus_method_handler_t method_handler;
} bus_callback_table_t;

typedef struct {
    char *full_name;
    bus_element_type_t type;
    bus_callback_table_t cb_table;
    bus_speed_t bus_speed;
    unsigned int num_of_table_row;
} bus_data_element_t;

/* Following are bus function pointers */
typedef bus_error_t (*wifi_bus_init_t)();
typedef bus_error_t (*wifi_bus_open_t)(bus_handle_t *handle, char *component_name);
typedef bus_error_t (*wifi_bus_close_t)(bus_handle_t handle);
typedef bus_error_t (*wifi_bus_get_t)(bus_handle_t handle, char const *name, raw_data_t *data);
typedef bus_error_t (*wifi_bus_set_t)(bus_handle_t handle, char const *name, raw_data_t *data);
typedef bus_error_t (
    *wifi_bus_event_publish_t)(bus_handle_t handle, char const *name, raw_data_t *data);
typedef bus_error_t (*wifi_bus_get_trace_context_t)(bus_handle_t handle, char *traceParent,
    uint32_t traceParentLength, char *traceState, uint32_t traceStateLength);
typedef bus_error_t (
    *wifi_bus_raw_event_publish_t)(bus_handle_t handle, char *name, void *data, uint32_t size);
typedef bus_error_t (
    *wifi_bus_set_str_t)(bus_handle_t handle, char const *param_name, char const *param_str);
typedef bus_error_t (*wifi_bus_event_subs_t)(bus_handle_t handle, char const *event_name, void *cb,
    void *userData, int timeout);
typedef bus_error_t (*wifi_bus_event_subscribe_ex_t)(bus_handle_t handle,
    bus_event_sub_t *l_sub_info_map, int num_sub, int timeout);
typedef bus_error_t (*wifi_bus_event_subscribe_ex_async_t)(bus_handle_t handle,
    bus_event_sub_t *l_sub_info_map, int num_sub, void *l_sub_handler, int timeout);
typedef bus_error_t (*wifi_bus_reg_elements_t)(bus_handle_t handle,
    bus_data_element_t *data_element, uint32_t num_of_element);
typedef bus_error_t (*wifi_bus_property_data_get_t)(bus_handle_t handle,
    bus_property_t l_bus_property, bus_set_handler_options_t l_options, raw_data_t *data);
typedef bus_error_t (*wifi_bus_property_data_set_t)(bus_handle_t handle,
    bus_property_t l_bus_property, bus_get_handler_options_t l_options, raw_data_t *data);
typedef bus_error_t (*wifi_bus_object_data_get_t)(bus_handle_t handle, bus_object_t l_bus_object,
    raw_data_t *data, char *str);
typedef bus_error_t (*wifi_bus_object_data_set_t)(bus_handle_t handle, bus_object_t l_bus_object,
    char *name, raw_data_t *data);
typedef char *(*wifi_bus_property_get_name_t)(bus_handle_t handle, bus_property_t property);
typedef bus_error_t (*wifi_bus_method_invoke_t)(bus_handle_t handle, void *paramName, char *event,
    char *input_data, char *output_data, bool input_bus_data);

typedef struct {
    wifi_bus_init_t bus_init_fn;
    wifi_bus_open_t bus_open_fn;
    wifi_bus_close_t bus_close_fn;
    wifi_bus_get_t bus_get_fn;
    wifi_bus_set_t bus_set_fn;
    wifi_bus_reg_elements_t bus_reg_data_element_fn;
    wifi_bus_event_publish_t bus_event_publish_fn;
    wifi_bus_raw_event_publish_t bus_raw_event_publish_fn;
    wifi_bus_set_str_t bus_set_string_fn;
    wifi_bus_event_subs_t bus_event_subs_fn;
    wifi_bus_event_subscribe_ex_t bus_event_subs_ex_fn;
    wifi_bus_event_subscribe_ex_async_t bus_event_subs_ex_async_fn;
    wifi_bus_property_data_get_t bus_property_data_get_fn;
    wifi_bus_property_data_set_t bus_property_data_set_fn;
    wifi_bus_object_data_get_t bus_object_data_get_fn;
    wifi_bus_method_invoke_t bus_method_invoke_fn;
    wifi_bus_object_data_set_t bus_object_data_set_fn;
    wifi_bus_property_get_name_t bus_property_get_name_fn;
    wifi_bus_get_trace_context_t bus_get_trace_context_fn;
} wifi_bus_desc_t;

typedef struct {
    wifi_bus_desc_t desc;
} wifi_bus_t;

wifi_bus_desc_t *get_bus_descriptor();

#ifdef __cplusplus
}
#endif

#endif // BUS_H
