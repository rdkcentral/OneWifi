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
#include "he_bus_core.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

static wifi_bus_t g_bus;
static void bus_desc_init(wifi_bus_desc_t *desc);

/* Function pointer address return */
wifi_bus_desc_t *get_bus_descriptor(void)
{
    return &g_bus.desc;
}

bool is_server_process(void)
{
    char file_name[64] = { 0 };
    FILE *fp;

    snprintf(file_name, sizeof(file_name), "/proc/%d/comm", getpid());
    if ((fp = fopen(file_name, "r")) != NULL) {
        fgets(file_name, sizeof(file_name), fp);
        fclose(fp);

        if (strstr(file_name, BUS_SERVER_PROCESS_NAME)) {
            return true;
        }
    }

    return false;
}

bus_error_t bus_init(bus_handle_t *handle)
{
    VERIFY_NULL_WITH_RC(handle);
    bus_error_t rc = bus_error_success;

    wifi_bus_desc_t *p_bus_desc = NULL;
    p_bus_desc = get_bus_descriptor();
    memset(p_bus_desc, 0, sizeof(wifi_bus_desc_t));

    bus_desc_init(p_bus_desc);
    if (is_server_process() == true) {
        wifi_util_info_print(WIFI_BUS, "%s:%d: he bus server start:%s\n", __func__, __LINE__, BUS_SERVER_PROCESS_NAME);
        he_bus_server_init(&handle->u.he_bus_handle, BUS_SERVER_PROCESS_NAME);
        handle->is_bus_init = true;
    }
    wifi_util_info_print(WIFI_BUS, "%s:%d: bus_init() is successful.\n", __func__, __LINE__);

    return rc;
}

static bus_error_t bus_open(bus_handle_t *handle, char *component_name)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(component_name);

    he_bus_error_t rc = bus_error_success;

    if ((handle->is_bus_init == true) && (handle->u.he_bus_handle != NULL)) {
        wifi_util_info_print(WIFI_BUS, "%s:%d: Already he_bus_open() completed handle:%p\n", __func__, __LINE__, handle->u.he_bus_handle);
        return rc;
    }

    rc = he_bus_open(&handle->u.he_bus_handle, component_name);
    if (rc != he_bus_error_success) {
        wifi_util_error_print(WIFI_BUS,"%s:%d: he_bus_open(component_name:%s) failed:%d\n", __func__, __LINE__, component_name, rc);
        return (bus_error_t)rc;
    }
    handle->is_bus_init = true;
    wifi_util_info_print(WIFI_BUS, "%s:%d: bus: he_bus_open() is successful. rc:%d, handle:%p\n", __func__, __LINE__, rc, handle->u.he_bus_handle);

    return (bus_error_t)rc;
}

static bus_error_t bus_close(bus_handle_t *handle)
{
    VERIFY_NULL_WITH_RC(handle);
    he_bus_handle_t p_he_bus_handle = handle->u.he_bus_handle;

    he_bus_error_t rc = bus_error_success;

    rc = he_bus_close(p_he_bus_handle);
    if (rc != he_bus_error_success) {
        wifi_util_error_print(WIFI_BUS,"%s:%d: he_bus_close() failed:%d\n", __func__, __LINE__, rc);
        return (bus_error_t)rc;
    }
    wifi_util_info_print(WIFI_BUS, "%s:%d: bus: he_bus_close() is successful. rc:%d, handle:%p\n", __func__, __LINE__, rc, p_he_bus_handle);

    return (bus_error_t)rc;
}

static bus_error_t bus_get_trace_context(bus_handle_t *handle, char* traceParent, int traceParentLength, char* traceState, int traceStateLength)
{
    bus_error_t rc = bus_error_success;
    return rc;
}

static bus_error_t bus_set(bus_handle_t *handle, char const *name, raw_data_t *p_data)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(p_data);
    he_bus_error_t rc;
    he_bus_handle_t p_bus_handle = handle->u.he_bus_handle;

    rc = he_bus_set_data(p_bus_handle, name, (he_bus_raw_data_t *)p_data);

    return (bus_error_t)rc;
}

static bus_error_t bus_data_get(bus_handle_t *handle, char const *name, raw_data_t *p_data)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(p_data);
    he_bus_error_t rc;
    he_bus_handle_t p_bus_handle = handle->u.he_bus_handle;

    rc = he_bus_get_data(p_bus_handle, name, (he_bus_raw_data_t *)p_data);

    return (bus_error_t)rc;
}

static void  bus_data_free(raw_data_t *data)
{
    if ((data->raw_data.bytes) &&
        (data->data_type == bus_data_type_bytes || data->data_type == bus_data_type_string)) {
        free(data->raw_data.bytes);
    }
}

static bus_error_t bus_event_publish(bus_handle_t *handle, char const *name, raw_data_t *p_data)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(p_data);
    he_bus_error_t rc;
    he_bus_handle_t p_bus_handle = handle->u.he_bus_handle;

    rc = he_bus_publish_event(p_bus_handle, name, (he_bus_raw_data_t *)p_data);

    return (bus_error_t)rc;
}

static bus_error_t bus_raw_event_publish(bus_handle_t *handle, char *name, void *data, int size)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(data);
    he_bus_error_t rc;
    he_bus_handle_t p_bus_handle = handle->u.he_bus_handle;
    he_bus_raw_data_t raw_data = { 0 };

    raw_data.data_type = he_bus_data_type_bytes;
    raw_data.raw_data.bytes = data;
    raw_data.raw_data_len = size;

    rc = he_bus_publish_event(p_bus_handle, name, &raw_data);

    return (bus_error_t)rc;
}

static bus_error_t bus_set_string(bus_handle_t *handle, char const *name, char const* param_str)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(param_str);
    he_bus_error_t rc;
    he_bus_handle_t p_bus_handle = handle->u.he_bus_handle;
    he_bus_raw_data_t raw_data = { 0 };

    raw_data.data_type = he_bus_data_type_string;
    raw_data.raw_data.bytes = param_str;
    raw_data.raw_data_len = strlen(param_str) + 1;

    rc = he_bus_set_data(p_bus_handle, name, &raw_data);

    return (bus_error_t)rc;
}

bus_error_t bus_reg_data_elements(bus_handle_t *handle, bus_data_element_t *data_element, uint32_t num_of_element)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(data_element);

    he_bus_error_t rc;
    he_bus_handle_t p_bus_handle = handle->u.he_bus_handle;
    he_bus_data_element_t *p_data_elem_map;

    p_data_elem_map = calloc(1, num_of_element * sizeof(he_bus_data_element_t));
    if (p_data_elem_map == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d bus_reg_data_elem() calloc is failed:%d\n", __func__, __LINE__, num_of_element);
        return bus_error_out_of_resources;
    }

    for (uint32_t index = 0; index < num_of_element; index++) {
        p_data_elem_map[index].full_name = data_element[index].full_name;
        p_data_elem_map[index].type      = data_element[index].type;
        p_data_elem_map[index].type      = data_element[index].type;
        p_data_elem_map[index].num_of_table_row = data_element[index].num_of_table_row;

        p_data_elem_map[index].cb_table.get_handler  = data_element[index].cb_table.get_handler;
        p_data_elem_map[index].cb_table.set_handler  = data_element[index].cb_table.set_handler;
        p_data_elem_map[index].cb_table.table_add_row_handler  = data_element[index].cb_table.table_add_row_handler;
        p_data_elem_map[index].cb_table.table_remove_row_handler  = data_element[index].cb_table.table_remove_row_handler;
        p_data_elem_map[index].cb_table.event_sub_handler  = data_element[index].cb_table.event_sub_handler;
        p_data_elem_map[index].cb_table.methodHandler  = data_element[index].cb_table.method_handler;
    }

    rc = he_bus_reg_data_elem(p_bus_handle, p_data_elem_map, num_of_element);

    //for testing purpose only.
    printRegisteredElements(p_bus_handle->root_element, 0);

    free(p_data_elem_map);
    return (bus_error_t)rc;
}

bus_error_t bus_method_invoke(bus_handle_t *handle, void *paramName, char *event, char *data, bool *psm_notify_flag, int flag)
{
    int rc = bus_error_success;
    return ((rc != 0) ? -1 : 0);
}

bus_error_t bus_event_subscribe(bus_handle_t *handle, char const *event_name, void  *cb, void *userData, int timeout)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(event_name);
    VERIFY_NULL_WITH_RC(cb);

    he_bus_error_t rc;
    he_bus_handle_t p_bus_handle = handle->u.he_bus_handle;
    he_bus_event_consumer_sub_handler_t p_bus_cb = (he_bus_event_consumer_sub_handler_t *)cb;

    rc = he_bus_event_sub(p_bus_handle, event_name, p_bus_cb, timeout);

    return (bus_error_t)rc;
}

bus_error_t bus_event_subscribe_ex(bus_handle_t *handle, bus_event_sub_t *l_sub_info_map, uint32_t num_of_sub, int timeout)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(l_sub_info_map);

    he_bus_error_t rc;
    he_bus_handle_t p_bus_handle = handle->u.he_bus_handle;
    he_bus_event_sub_t  *p_sub_data_map;

    p_sub_data_map = calloc(1, num_of_sub * sizeof(he_bus_event_sub_t));
    if (p_sub_data_map == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d bus_event_sub_ex() calloc is failed:%d\n", __func__, __LINE__, num_of_sub);
        return bus_error_out_of_resources;
    }

    for (uint32_t index = 0; index < num_of_sub; index++) {

        p_sub_data_map[index].event_name = l_sub_info_map[index].event_name;
        p_sub_data_map[index].action     = he_bus_event_action_subscribe;
        p_sub_data_map[index].interval   = l_sub_info_map[index].interval;
        p_sub_data_map[index].handler.sub_handler = l_sub_info_map[index].handler;
        p_sub_data_map[index].handler.sub_ex_async_handler = l_sub_info_map[index].async_handler;

    }

    rc = he_bus_event_sub_ex(p_bus_handle, p_sub_data_map, num_of_sub, timeout);

    free(p_sub_data_map);
    return (bus_error_t)rc;
}

bus_error_t bus_event_subscribe_ex_async(bus_handle_t *handle, bus_event_sub_t *l_sub_info_map, uint32_t num_of_sub, void *l_sub_handler, int timeout)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(l_sub_info_map);

    he_bus_error_t rc;
    he_bus_handle_t p_bus_handle = handle->u.he_bus_handle;
    he_bus_event_sub_t  *p_sub_data_map;

    p_sub_data_map = calloc(1, num_of_sub * sizeof(he_bus_event_sub_t));
    if (p_sub_data_map == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d bus_event_sub_ex() calloc is failed:%d\n", __func__, __LINE__, num_of_sub);
        return bus_error_out_of_resources;
    }

    for (uint32_t index = 0; index < num_of_sub; index++) {

        p_sub_data_map[index].event_name = l_sub_info_map[index].event_name;
        p_sub_data_map[index].action     = he_bus_event_action_subscribe;
        p_sub_data_map[index].interval   = l_sub_info_map[index].interval;
        p_sub_data_map[index].handler.sub_handler = l_sub_info_map[index].handler;
        p_sub_data_map[index].handler.sub_ex_async_handler = l_sub_info_map[index].async_handler;

    }

    rc = he_bus_event_sub_ex_async(p_bus_handle, p_sub_data_map, num_of_sub, l_sub_handler, timeout);

    free(p_sub_data_map);
    return (bus_error_t)rc;
}

static bus_error_t bus_reg_table_row(bus_handle_t *handle, char const *name,
    uint32_t row_index, char const *alias)
{
    return bus_error_success;
}

static bus_error_t bus_unreg_table_row(bus_handle_t *handle, char const *name)
{
    return bus_error_success;
}

static bus_error_t bus_remove_table_row(bus_handle_t *handle, char const *name)
{
    return bus_error_success;
}

static void bus_desc_init(wifi_bus_desc_t *desc)
{
    desc->bus_init_fn                     = bus_init;
    desc->bus_open_fn                     = bus_open;
    desc->bus_close_fn                    = bus_close;
    desc->bus_data_get_fn                 = bus_data_get;
    desc->bus_data_free_fn                = bus_data_free;
    desc->bus_set_fn                      = bus_set;
    desc->bus_reg_data_element_fn         = bus_reg_data_elements;
    desc->bus_event_publish_fn            = bus_event_publish;
    desc->bus_raw_event_publish_fn        = bus_raw_event_publish;
    desc->bus_set_string_fn               = bus_set_string;
    desc->bus_event_subs_fn               = bus_event_subscribe;
    desc->bus_event_subs_ex_fn            = bus_event_subscribe_ex;
    desc->bus_event_subs_ex_async_fn      = bus_event_subscribe_ex_async;
    desc->bus_method_invoke_fn            = bus_method_invoke;
    desc->bus_get_trace_context_fn        = bus_get_trace_context;
    desc->bus_reg_table_row_fn            = bus_reg_table_row;
    desc->bus_unreg_table_row_fn          = bus_unreg_table_row;
    desc->bus_remove_table_row_fn         = bus_remove_table_row;
}
