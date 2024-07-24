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
#include "bus.h"
#include "bus_common.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

static wifi_bus_t g_bus;

static bus_error_t bus_init(void *dml)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

static int bus_open(bus_handle_t *handle, char *component_name)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

static bus_error_t bus_close(bus_handle_t handle)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

static bus_error_t bus_get_trace_context(bus_handle_t handle, char *traceParent,
    int traceParentLength, char *traceState, int traceStateLength)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

static bus_error_t bus_set(bus_handle_t handle, char const *name, raw_data_t *data)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

static bus_error_t bus_get(bus_handle_t handle, char const *name, raw_data_t *data)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

static bus_error_t bus_event_publish(bus_handle_t handle, char const *name, raw_data_t *data)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

static bus_error_t bus_raw_event_publish(bus_handle_t handle, char *name, void *data, int size)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

static bus_error_t bus_set_string(bus_handle_t handle, char const *param_name,
    char const *param_str)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

bus_error_t bus_reg_data_elements(bus_handle_t handle, bus_data_element_t *data_element,
    uint32_t num_of_element)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

bus_error_t bus_property_data_get(bus_handle_t handle, bus_property_t l_bus_property,
    bus_set_handler_options_t l_options, raw_data_t *data)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

bus_error_t bus_object_data_get(bus_handle_t handle, bus_object_t l_bus_object, raw_data_t *data,
    char *str)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

bus_error_t bus_object_data_set(bus_handle_t handle, bus_object_t l_bus_object, raw_data_t *data)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

bus_error_t bus_property_data_set(bus_handle_t handle, bus_property_t l_bus_property,
    bus_get_handler_options_t l_options, raw_data_t *data)
{
    bus_error_t ret = bus_error_success;
    return ret;
}

char *bus_property_get_name(bus_handle_t handle, bus_property_t property)
{
    char *c_ret = NULL;
    return c_ret;
}

bus_error_t bus_method_invoke(bus_handle_t handle, void *paramName, char *event, char *input_data,
    char *output_data, bool input_bus_data)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

bus_error_t bus_event_subscribe(bus_handle_t handle, char const *event_name, void *cb,
    void *userData, int timeout)
{
    bus_error_t ret = bus_error_success;
    return ret;
}

bus_error_t bus_event_subscribe_ex(bus_handle_t handle, bus_event_sub_t *l_sub_info_map,
    int num_sub, int timeout)
{
    bus_error_t ret = bus_error_success;
    return ret;
}

bus_error_t bus_event_subscribe_ex_async(bus_handle_t handle, bus_event_sub_t *l_sub_info_map,
    int num_sub, void *l_sub_handler, int timeout)
{
    bus_error_t ret = bus_error_success;
    return ret;
}

/* Function pointer address return */
wifi_bus_desc_t *get_bus_descriptor(void)
{
    return &g_bus.desc;
}

void wifi_bus_init(void)
{
    g_bus.desc.bus_init_fn = bus_init;
    g_bus.desc.bus_open_fn = bus_open;
    g_bus.desc.bus_close_fn = bus_close;
    g_bus.desc.bus_get_fn = bus_get;
    g_bus.desc.bus_set_fn = bus_set;
    g_bus.desc.bus_reg_data_element_fn = bus_reg_data_elements;
    g_bus.desc.bus_event_publish_fn = bus_event_publish;
    g_bus.desc.bus_raw_event_publish_fn = bus_raw_event_publish;
    g_bus.desc.bus_set_string_fn = bus_set_string;
    g_bus.desc.bus_event_subs_fn = bus_event_subscribe;
    g_bus.desc.bus_event_subs_ex_fn = bus_event_subscribe_ex;
    g_bus.desc.bus_event_subs_ex_async_fn = bus_event_subscribe_ex_async;
    g_bus.desc.bus_property_data_get_fn = bus_property_data_get;
    g_bus.desc.bus_property_data_set_fn = bus_property_data_set;
    g_bus.desc.bus_object_data_get_fn = bus_object_data_get;
    g_bus.desc.bus_object_data_set_fn = bus_object_data_set;
    g_bus.desc.bus_property_get_name_fn = bus_property_get_name;
    g_bus.desc.bus_method_invoke_fn = bus_method_invoke;
    g_bus.desc.bus_get_trace_context_fn = bus_get_trace_context;
}
