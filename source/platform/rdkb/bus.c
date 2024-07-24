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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>

static wifi_bus_t g_bus;

/* Function pointer address return */
wifi_bus_desc_t *get_bus_descriptor(void)
{
    return &g_bus.desc;
}

void rdkb_bus_desc_init(wifi_bus_desc_t *desc);

bus_error_t bus_init(void)
{
    bus_error_t rc = bus_error_success;

    wifi_bus_desc_t *p_bus_desc = NULL;
    p_bus_desc = get_bus_descriptor();
    memset(p_bus_desc, 0, sizeof(wifi_bus_desc_t));

    rdkb_bus_desc_init(p_bus_desc);
    wifi_util_info_print(WIFI_CTRL, "%s:%d: bus: bus_init() is successful.\n", __func__, __LINE__);
    return (bus_error_t)rc;
}

static bus_error_t bus_open(bus_handle_t *handle, char *component_name)
{
    rbusError_t rc = bus_error_success;
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(component_name);

    rc = rbus_open(&handle->u.rbus_handle, component_name);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: bus: rbus_open() failed:%d, component:%s\n",
        __func__, __LINE__, rc, component_name);
        return (bus_error_t)rc;
    }
    wifi_util_info_print(WIFI_CTRL, "%s:%d: bus: rbus_open() is successful for component:%s, \
       rc:%d, handle:%p\n", __func__, __LINE__, component_name, rc, handle->u.rbus_handle);
    return (bus_error_t)rc;
}

static bus_error_t bus_close(bus_handle_t *handle)
{
    rbusError_t rc = bus_error_success;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rc = rbus_close(p_rbus_handle);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: bus: rbus_close() failed:%d\n", __func__, __LINE__, rc);
        return (bus_error_t)rc;
    }
    wifi_util_info_print(WIFI_CTRL, "%s:%d: bus: rbus_open() is successful. rc:%d, handle:%p\n",
        __func__, __LINE__, rc, handle->u.rbus_handle);
    return (bus_error_t)rc;
}

static bus_error_t bus_get_trace_context(bus_handle_t *handle, char *traceParent,
    uint32_t traceParentLength, char *traceState, uint32_t traceStateLength)
{
    rbusError_t rc = bus_error_success;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rc = rbusHandle_GetTraceContextAsString(p_rbus_handle, traceParent, traceParentLength,
        traceState, traceStateLength);
    wifi_util_info_print(WIFI_CTRL,
        "%s:%d: bus: rbusHandle_GetTraceContextAsString() is successful. rc:%d\n", __func__,
        __LINE__, rc);
    return (bus_error_t)rc;
}

static bus_error_t bus_set(bus_handle_t *handle, char const *name, raw_data_t *data)
{
    rbusError_t rc = bus_error_success;
    VERIFY_NULL_WITH_RC(name);

    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rbusValue_t value;

    rbusValue_Init(&value);

    switch (data->data_type) {
    case bus_data_type_boolean:
        rbusValue_SetBoolean(value, data->raw_data.b);
        data->data_type = bus_data_type_boolean;
        break;
    case bus_data_type_string:
        rbusValue_SetString(value, (char const *)data->raw_data.bytes);
        data->data_type = bus_data_type_string;
        break;
    case bus_data_type_uint32:
        rbusValue_SetUInt32(value, data->raw_data.u32);
        break;
    case bus_data_type_bytes:
        rbusValue_SetBytes(value, (uint8_t *)data->raw_data.bytes, data->raw_data_len);
        break;
    default:
        wifi_util_error_print(WIFI_CTRL, "%s:%d: bus: Invalid data_type:%d for name:%s.\n",
            __func__, __LINE__, data->data_type, name);
        break;
    };

    rc = rbus_set(p_rbus_handle, name, value, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d bus: rbus_set() failed:%d for name:%s\n",
          __func__, __LINE__, rc, name);
    }
    rbusValue_Release(value);
    return (bus_error_t)rc;
}

void bus_data_free(raw_data_t *data)
{
    if ((data->raw_data.bytes) &&
        (data->data_type == bus_data_type_bytes || data->data_type == bus_data_type_string)) {
        free(data->raw_data.bytes);
    }
}

/* Caller should responsible to free (call bus_data_free()) the memory */
static bus_error_t bus_data_get(bus_handle_t *handle, char const *name, raw_data_t *data)
{
    rbusValue_t value;
    rbusError_t rc = bus_error_success;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    void *ptr = NULL;
    int len = 0;

    rc = rbus_get(p_rbus_handle, name, &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d bus: rbus_get failed for [%s] with error [%d]\n",
            __func__, __LINE__, name, rc);
        return (bus_error_t)rc;
    }

    rbusValueType_t type = rbusValue_GetType(value);
    wifi_util_error_print(WIFI_CTRL, ":%s:%d bus: rbus_get(): rc:%d, name:%s, type:0x%x\n",
        __func__, __LINE__, rc, name, type);

    /* Defensive code as we deal with pointer for type string & bytes */
    data->raw_data.b = 0;
    data->raw_data_len = 0;
    data->raw_data.bytes = NULL;

    switch (type) {
    case RBUS_BOOLEAN:
        data->raw_data.b = rbusValue_GetBoolean(value);
        data->data_type = bus_data_type_boolean;
        break;
    case RBUS_STRING:
        ptr = (void *)rbusValue_GetString(value, &len);
        data->data_type = bus_data_type_string;
        data->raw_data_len = len;
        break;
    case RBUS_UINT32:
        data->raw_data.u32 = (uint32_t)rbusValue_GetUInt32(value);
        data->data_type = bus_data_type_uint32;
        break;
    case RBUS_BYTES:
        ptr = (void *)rbusValue_GetBytes(value, &len);
        data->data_type = bus_data_type_bytes;
        data->raw_data_len = len;
        break;
    default:
        wifi_util_error_print(WIFI_CTRL, "%s:%d: bus: Invalid data_type:%d for name:%s.\n",
            __func__, __LINE__, data->data_type, name);
        break;
    };

    wifi_util_dbg_print(WIFI_CTRL,
        "%s:%d: bus: bus_data_get: type:0x%x, data_type:0x%x, type_string:0x%x len=%d, name:%s\n",
        __func__, __LINE__, type, data->data_type, bus_data_type_string, data->raw_data_len, name);

    if ((ptr) && (name) &&
       (data->data_type == bus_data_type_bytes || data->data_type == bus_data_type_string)) {
           data->raw_data.bytes = (void *)calloc(len + 1, sizeof(char));
           memcpy(data->raw_data.bytes, ptr, len);
    }

    rbusValue_Release(value);

    return (bus_error_t)rc;
}

static bus_error_t bus_event_publish(bus_handle_t *handle, char const *name, raw_data_t *data)
{
    rbusError_t rc = bus_error_success;
    VERIFY_NULL_WITH_RC(name);
    // VERIFY_NULL_WITH_RC(data->raw_data.bytes);

    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);
    rbusObject_SetValue(rdata, name, value);

    switch (data->data_type) {
    case bus_data_type_boolean:
        rbusValue_SetBoolean(value, data->raw_data.b);
        data->data_type = bus_data_type_boolean;
        break;
    case bus_data_type_string:
        rbusValue_SetString(value, (char const *)data->raw_data.bytes);
        break;
    case bus_data_type_uint32:
        rbusValue_SetUInt32(value, data->raw_data.u32);
        break;
    case bus_data_type_bytes:
        rbusValue_SetBytes(value, (uint8_t *)data->raw_data.bytes, data->raw_data_len);
        break;
    default:
        wifi_util_error_print(WIFI_CTRL, "%s:%d: bus: Invalid data_type:%d for name:%s.\n",
            __func__, __LINE__, data->data_type, name);
        break;
    };

    event.name = name;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(p_rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: bus: rbusEvent_Publish Event failed:%d, \
            name:%s\n", __func__, __LINE__, rc, name);
    } else {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: bus: bus_event_publish() is successful. \
            name:%s, rc:%d\n", __func__, __LINE__, name, rc);
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);
    return (bus_error_t)rc;
}

static bus_error_t bus_raw_event_publish(bus_handle_t *handle, char *name, void *data,
    unsigned int size)
{
    rbusError_t rc = bus_error_success;
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(data);

    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rbusEventRawData_t event_data;
    event_data.name = name;
    event_data.rawData = data;
    event_data.rawDataLen = size;
    rc = rbusEvent_PublishRawData(p_rbus_handle, &event_data);
    wifi_util_info_print(WIFI_CTRL, "%s:%d: bus: bus_raw_event_publish() is successful \
        name:%s, rc:%d\n", __func__, __LINE__, name, rc);
    return (bus_error_t)rc;
}

static bus_error_t bus_set_string(bus_handle_t *handle, char const *param_name,
    char const *param_str)
{
    rbusError_t rc = bus_error_success;
    VERIFY_NULL_WITH_RC(param_name);
    VERIFY_NULL_WITH_RC(param_str);

    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rc = rbus_setStr(p_rbus_handle, param_name, param_str);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: bus: rbus_setStr() failed for param:%s, \
          rc:%d\n", __func__, __LINE__, param_name, rc);
    }
    wifi_util_info_print(WIFI_CTRL, "%s:%d: bus: bus_set_string() is successful for \
          param:%s, rc:%d\n", __func__, __LINE__, param_name, rc);
    return (bus_error_t)rc;
}

static bool remove_substring(char *str, const char *sub)
{
    char *match;
    size_t len = strlen(sub);
    bool ret = 0;
    while ((match = strstr(str, sub))) {
        memmove(match, match + len, strlen(match + len) + 1);
        ret = 1;
        wifi_util_info_print(WIFI_CTRL, "%s:%d: bus: removeSubstring is matched with %s\n",
            __func__, __LINE__, str);
    }
    return ret;
}

bus_error_t bus_reg_data_elements(bus_handle_t *handle, bus_data_element_t *data_element,
    uint32_t num_of_element)
{
    rbusError_t rc = bus_error_success;
    bus_name_string_t name = { 0 };
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusDataElement_t *rbus_dataElements;
    uint32_t index, table_index;
    char sub[] = ".{i}";

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d bus: bus_reg_data_elements() hdl:%p, \
        num_of_element:%d\n", __func__, __LINE__, p_rbus_handle, num_of_element);

    if (p_rbus_handle == NULL || data_element == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s bus: input param is NULL\n", __func__);
        return (bus_error_t)bus_error_invalid_input;
    }

    rbus_dataElements = calloc(1, num_of_element * sizeof(rbusDataElement_t));
    if (rbus_dataElements == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d bus: bus_reg_data_elements() calloc is failed\n",
            __func__, __LINE__);
        return (bus_error_t)bus_error_out_of_resources;
    }

    /* Do the conversion first */
    for (index = 0; index < num_of_element; index++) {
        rbus_dataElements[index].name = data_element[index].full_name;
        rbus_dataElements[index].type = data_element[index].type;
        rbus_dataElements[index].cbTable.getHandler =
            (void *)data_element[index].cb_table.get_handler;
        rbus_dataElements[index].cbTable.setHandler =
            (void *)data_element[index].cb_table.set_handler;
        rbus_dataElements[index].cbTable.tableAddRowHandler =
            (void *)data_element[index].cb_table.table_add_row_handler;
        rbus_dataElements[index].cbTable.tableRemoveRowHandler =
            (void *)data_element[index].cb_table.table_remove_row_handler;
        rbus_dataElements[index].cbTable.eventSubHandler =
            (void *)data_element[index].cb_table.event_sub_handler;
        rbus_dataElements[index].cbTable.methodHandler =
            (void *)data_element[index].cb_table.method_handler;
    }

    rc = rbus_regDataElements(p_rbus_handle, num_of_element, rbus_dataElements);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: bus: rbus_regDataElements failed. \
            rc:%d.\n", __func__, __LINE__, rc);
        rbus_unregDataElements(p_rbus_handle, num_of_element, rbus_dataElements);
        rbus_close(p_rbus_handle);
        free(rbus_dataElements);
        return (bus_error_t)rc;
    }

    wifi_util_info_print(WIFI_CTRL,
        "%s:%d: bus: rbus_regDataElements() is successful with number of elements:%d. rc:%d\n",
        __func__, __LINE__, num_of_element, rc);

    for (index = 0; index < num_of_element; index++) {
        // wifi_util_info_print(WIFI_CTRL, "%s:%d: bus: name:%s, type:%d.\n", __func__, __LINE__,
        // data_element[index].full_name, data_element[index].type);
        if (data_element[index].type == bus_element_type_table) {
            strncpy(name, data_element[index].full_name, strlen(data_element[index].full_name) + 1);
            // wifi_util_info_print(WIFI_CTRL, "%s:%d: rbusTable_addRow for %s,
            // num_of_table_row:%d.\n",__func__, __LINE__, name,
            // data_element[index].num_of_table_row);
            if ((data_element[index].num_of_table_row) && (remove_substring(name, sub) == 1)) {
                for (table_index = 1; table_index <= data_element[index].num_of_table_row;
                     table_index++) {
                    // wifi_util_info_print(WIFI_CTRL, "*%s() calling rbusTable_addRow for %s\n",
                    // __func__, name);
                    rc = rbusTable_addRow(p_rbus_handle, name, NULL, NULL);
                    if (rc != RBUS_ERROR_SUCCESS) {
                        wifi_util_info_print(WIFI_CTRL, "%s() bus: rbusTable_addRow failed:%d for %s\n",
                            __func__, rc, name);
                    }
                }
            }
        }
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d: bus: rbusTable_addRow() is successful. rc:%d\n",
        __func__, __LINE__, rc);
    free(rbus_dataElements);
    return (bus_error_t)rc;
}

bus_error_t bus_property_data_get(bus_handle_t *handle, bus_property_t l_bus_property,
    bus_set_handler_options_t l_options, raw_data_t *data)
{
    rbusError_t rc = bus_error_success;
    UNREFERENCED_PARAMETER(l_options);
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusProperty_t property = (rbusProperty_t)l_bus_property.u.rbus_property;

    if (p_rbus_handle == NULL || property == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s bus: input param is NULL\n", __func__);
        return (bus_error_t)bus_error_invalid_input;
    }

    char const *name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    rbusValueType_t type = rbusValue_GetType(value);
    int len = 0;

    //    wifi_util_dbg_print(WIFI_CTRL,"%s:%d: bus: property=%s, data_type:%d\n",__func__,
    //    __LINE__, name, data_type);

    switch (type) {
    case bus_data_type_boolean:
        data->raw_data.b = rbusValue_GetBoolean(value);
        data->raw_data_len = sizeof(bool);
        data->data_type = bus_data_type_boolean;
        break;
    case bus_data_type_string:
        data->raw_data.bytes = (void *)rbusValue_GetString(value, &len);
        data->raw_data_len = (unsigned int)len;
        data->data_type = bus_data_type_string;
        wifi_util_dbg_print(WIFI_CTRL, "%s bus: bus_property_data_get-string: string:%s, len=%d\n",
            __func__, data->raw_data.bytes, data->raw_data_len);
        break;
    case bus_data_type_uint32:
        data->raw_data.u32 = (uint32_t)rbusValue_GetUInt32(value);
        data->raw_data_len = sizeof(uint32_t);
        data->data_type = bus_data_type_uint32;
        break;
    case bus_data_type_bytes:
        data->raw_data.bytes = (void *)rbusValue_GetBytes(value, &len);
        data->raw_data_len = (unsigned int)len;
        data->data_type = bus_data_type_bytes;
        wifi_util_error_print(WIFI_CTRL, "%s bus: bus_property_data_get-bytes, len=%d\n", __func__,
            data->raw_data_len);
        break;
    default:
        wifi_util_error_print(WIFI_CTRL, "%s bus: value type not found =0x%x\n", __func__, type);
        rc = RBUS_ERROR_INVALID_INPUT;
        break;
    }

    /* Debug print */
    if ((rc != RBUS_ERROR_SUCCESS) || ((int)type != (int)data->data_type)) {
        wifi_util_error_print(WIFI_CTRL,
            "%s:%d bus: bus_property_data_get(): name:%s, type:0x%x, data->data_type:%d, len=%d, "
            "rc:%d\n",
            __func__, __LINE__, name, type, data->data_type, data->raw_data_len, rc);
        wifi_util_error_print(WIFI_CTRL, "%s bus: read failed for %s\n", __func__, name);
        return (bus_error_t)rc;
    }
    return (bus_error_t)rc;
}

bus_error_t bus_object_data_get(bus_handle_t *handle, bus_object_t l_bus_object, raw_data_t *data,
    char *str)
{
    rbusError_t rc = bus_error_success;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusObject_t inParams = (rbusObject_t)l_bus_object.u.rbus_object;

    if (p_rbus_handle == NULL || inParams == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s bus: input param is NULL\n", __func__);
        return (bus_error_t)bus_error_invalid_input;
    }

    rbusValue_t value = rbusObject_GetValue(inParams, str);
    int len = 0;

    rbusValueType_t type = rbusValue_GetType(value);

    switch (type) {
    case bus_data_type_boolean:
        data->raw_data.b = rbusValue_GetBoolean(value);
        data->raw_data_len = sizeof(bool);
        data->data_type = bus_data_type_boolean;
        break;
    case bus_data_type_string:
        data->raw_data.bytes = (void *)rbusValue_GetString(value, &len);
        data->raw_data_len = (unsigned int)len;
        break;
    case bus_data_type_uint32:
        data->raw_data.u32 = (uint32_t)rbusValue_GetUInt32(value);
        data->raw_data_len = sizeof(uint32_t);
        break;
    case bus_data_type_bytes:
        data->raw_data.bytes = (void *)rbusValue_GetBytes(value, &len);
        data->raw_data_len = (unsigned int)len;
        break;
    default:
        wifi_util_dbg_print(WIFI_CTRL, "%s bus: value type not found =0x%x\n", __func__, type);
        rc = RBUS_ERROR_INVALID_INPUT;
        break;
    }

    /* Debug print */
    if ((int)type != (int)data->data_type) {
        wifi_util_dbg_print(WIFI_CTRL,
            "%s:%d bus: bus_property_data_get(): type:0x%x, data->data_type:0x%x, len=%d\n",
            __func__, __LINE__, type, data->data_type, data->raw_data_len);
    }

    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s bus: read failed.\n", __func__);
        return ((bus_error_t)rc);
    }
    return ((bus_error_t)rc);
}

bus_error_t bus_object_data_set(bus_handle_t *handle, bus_object_t l_bus_object, char *name,
    raw_data_t *data)
{
    rbusError_t rc = bus_error_success;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusObject_t outParams = (rbusObject_t)l_bus_object.u.rbus_object;
    rbusValue_t value;

    VERIFY_NULL_WITH_RC(data->raw_data.bytes);
    if (p_rbus_handle == NULL || outParams == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s bus: input param is NULL\n", __func__);
        return (bus_error_t)bus_error_invalid_input;
    }

    rbusValue_Init(&value);
    rbusValue_SetBytes(value, (uint8_t *)data->raw_data.bytes, data->raw_data_len);
    rbusObject_SetValue(outParams, name, value);
    rbusValue_Release(value);
    return (bus_error_t)rc;
}

bus_error_t bus_property_data_set(bus_handle_t *handle, bus_property_t l_bus_property,
    bus_get_handler_options_t l_options, raw_data_t *data)
{
    rbusError_t rc = bus_error_success;
    UNREFERENCED_PARAMETER(l_options);
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusProperty_t property = (rbusProperty_t)l_bus_property.u.rbus_property;

    if (p_rbus_handle == NULL || property == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s bus: input param is NULL\n", __func__);
        return (bus_error_t)bus_error_invalid_input;
    }

    char const *name = rbusProperty_GetName(property);
    rbusValue_t value;

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d bus: property=%s\r\n", __func__, __LINE__, name);
    rbusValue_Init(&value);

    switch (data->data_type) {
    case bus_data_type_boolean:
        rbusValue_SetBoolean(value, data->raw_data.b);
        data->data_type = bus_data_type_boolean;
        break;
    case bus_data_type_string:
        rbusValue_SetString(value, (char const *)data->raw_data.bytes);
        break;
    case bus_data_type_uint32:
        rbusValue_SetUInt32(value, data->raw_data.u32);
        break;
    case bus_data_type_bytes:
        rbusValue_SetBytes(value, (uint8_t *)data->raw_data.bytes, data->raw_data_len);
        break;
    default:
        wifi_util_error_print(WIFI_CTRL, "bus: invalid data_type:%d passed for %s:%d\n", data->data_type,
            __func__, __LINE__);
        break;
    };
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return (bus_error_t)rc;
}

char *bus_property_get_name(bus_handle_t *handle, bus_property_t l_bus_property)
{
    char *c_ret = NULL;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusProperty_t property = (rbusProperty_t)l_bus_property.u.rbus_property;

    if (p_rbus_handle == NULL || property == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s bus: Input param is NULL\n", __func__);
        return c_ret;
    }

    c_ret = (char *)rbusProperty_GetName(property);
    return c_ret;
}

bus_error_t bus_method_invoke(bus_handle_t *handle, void *paramName, char *event,
    raw_data_t *input_data, raw_data_t *output_data, bool input_bus_data)
{
    rbusError_t rc = bus_error_success;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusValue_t value = NULL;
    rbusProperty_t prop = NULL;
    rbusObject_t inParams = NULL, outParams = NULL;
    int len = 0;

    rbusObject_Init(&inParams, NULL);
    rbusValue_Init(&value);

    if (input_bus_data == BUS_METHOD_SET) {
        if (input_data->data_type == bus_data_type_string) {
            if (false ==
                rbusValue_SetFromString(value, RBUS_STRING, (char *)input_data->raw_data.bytes)) {
                wifi_util_dbg_print(WIFI_CTRL, "%s: bus: Invalid value '%s' for the parameter %s\n\r",
                    __func__, input_data->raw_data.bytes, paramName);
            }
        } else {
            wifi_util_dbg_print(WIFI_CTRL, "%s: bus: Invalid data_type '%d' for the parameter %s\n\r",
                __func__, input_data->data_type, paramName);
        }
    }

    rbusProperty_Init(&prop, paramName, value);
    rbusObject_SetProperty(inParams, prop);
    rbusProperty_Release(prop);

    rc = rbusMethod_Invoke(p_rbus_handle, event, inParams, &outParams);
    if (inParams) {
        rbusObject_Release(inParams);
    }

    if ((RBUS_ERROR_SUCCESS == rc) && (input_bus_data == BUS_METHOD_GET)) {
        prop = rbusObject_GetProperties(outParams);
        value = rbusProperty_GetValue(prop);
        switch (output_data->data_type) {
        case bus_data_type_boolean:
            output_data->raw_data.b = rbusValue_GetBoolean(value);
            output_data->raw_data_len = sizeof(bool);
            output_data->data_type = bus_data_type_boolean;
            break;
        case bus_data_type_string:
            output_data->raw_data.bytes = (void *)rbusValue_GetString(value, &len);
            output_data->raw_data_len = (unsigned int)len;
            wifi_util_dbg_print(WIFI_CTRL, "%s bus: bus_method_invoke-string: string:%s, len=%d\n",
                __func__, output_data->raw_data.bytes, output_data->raw_data_len);
            break;
        case bus_data_type_uint32:
            output_data->raw_data.u32 = (uint32_t)rbusValue_GetUInt32(value);
            output_data->raw_data_len = sizeof(uint32_t);
            break;
        case bus_data_type_bytes:
            output_data->raw_data.bytes = (void *)rbusValue_GetBytes(value, &len);
            output_data->raw_data_len = (unsigned int)len;
            wifi_util_dbg_print(WIFI_CTRL, "%s bus: bus_method_invoke-bytes: len=%d\n", __func__,
                output_data->raw_data_len);
            break;
        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s bus:value type not found =0x%x\n", __func__,
                output_data->data_type);
            rc = RBUS_ERROR_INVALID_INPUT;
            break;
        }
    } else {
        wifi_util_error_print(WIFI_CTRL, " %s failed for  with err: '%s'\n\r", __func__,
            rbusError_ToString(rc));
    }

    rbusValue_Release(value);
    return (bus_error_t)rc;
}

bus_error_t bus_event_subscribe(bus_handle_t *handle, char const *event_name, void *cb,
    void *userData, int timeout)
{
    rbusError_t rc = bus_error_success;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusEventHandler_t event_callback = (rbusEventHandler_t)cb;

    rc = rbusEvent_Subscribe(p_rbus_handle, event_name, event_callback, userData, timeout);
    return (bus_error_t)rc;
}

bus_error_t bus_event_subscribe_ex(bus_handle_t *handle, bus_event_sub_t *l_sub_info_map,
    int num_sub, int timeout)
{
    rbusError_t ret = bus_error_success;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusEventSubscription_t *sub_info_map;

    if (p_rbus_handle == NULL || l_sub_info_map == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s bus: Input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }

    sub_info_map = calloc(1, num_sub * sizeof(rbusEventSubscription_t));
    if (sub_info_map == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d bus: bus_event_subscribe_ex() calloc is failed\n",
            __func__, __LINE__);
        return bus_error_out_of_resources;
    }

    for (int index = 0; index < num_sub; index++) {
        sub_info_map[index].eventName = l_sub_info_map[index].event_name;
        sub_info_map[index].filter = l_sub_info_map[index].filter;
        sub_info_map[index].interval = l_sub_info_map[index].interval;
        sub_info_map[index].duration = l_sub_info_map[index].duration;
        sub_info_map[index].handler = l_sub_info_map[index].handler;
        sub_info_map[index].userData = l_sub_info_map[index].user_data;
        sub_info_map[index].asyncHandler = (void *)l_sub_info_map[index].async_handler;
        sub_info_map[index].publishOnSubscribe = l_sub_info_map[index].publish_on_sub;
    }

    ret = rbusEvent_SubscribeEx(handle->u.rbus_handle, sub_info_map, num_sub, timeout);

    free(sub_info_map);
    return (bus_error_t)ret;
}

bus_error_t bus_event_subscribe_ex_async(bus_handle_t *handle, bus_event_sub_t *l_sub_info_map,
    int num_sub, void *l_sub_handler, int timeout)
{
    rbusError_t ret = bus_error_success;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusEventSubscription_t *sub_info_map;
    rbusSubscribeAsyncRespHandler_t sub_handler = (rbusSubscribeAsyncRespHandler_t)l_sub_handler;

    if (p_rbus_handle == NULL || l_sub_info_map == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s bus: Input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }

    sub_info_map = calloc(1, num_sub * sizeof(rbusEventSubscription_t));
    if (sub_info_map == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d bus: bus_event_subscribe_ex() calloc is failed\n",
            __func__, __LINE__);
        return bus_error_out_of_resources;
    }

    for (int index = 0; index < num_sub; index++) {
        sub_info_map[index].eventName = l_sub_info_map[index].event_name;
        sub_info_map[index].filter = l_sub_info_map[index].filter;
        sub_info_map[index].interval = l_sub_info_map[index].interval;
        sub_info_map[index].duration = l_sub_info_map[index].duration;
        sub_info_map[index].handler = l_sub_info_map[index].handler;
        sub_info_map[index].userData = l_sub_info_map[index].user_data;
        sub_info_map[index].asyncHandler = (void *)l_sub_info_map[index].async_handler;
        sub_info_map[index].publishOnSubscribe = l_sub_info_map[index].publish_on_sub;
    }

    ret = rbusEvent_SubscribeExAsync(p_rbus_handle, sub_info_map, num_sub, sub_handler, timeout);

    free(sub_info_map);
    return (bus_error_t)ret;
}

void rdkb_bus_desc_init(wifi_bus_desc_t *desc)
{
    desc->bus_init_fn = bus_init;
    desc->bus_open_fn = bus_open;
    desc->bus_close_fn = bus_close;
    desc->bus_data_get_fn = bus_data_get;
    desc->bus_data_free_fn = bus_data_free;
    desc->bus_set_fn = bus_set;
    desc->bus_reg_data_element_fn = bus_reg_data_elements;
    desc->bus_event_publish_fn = bus_event_publish;
    desc->bus_raw_event_publish_fn = bus_raw_event_publish;
    desc->bus_set_string_fn = bus_set_string;
    desc->bus_event_subs_fn = bus_event_subscribe;
    desc->bus_event_subs_ex_fn = bus_event_subscribe_ex;
    desc->bus_event_subs_ex_async_fn = bus_event_subscribe_ex_async;
    desc->bus_property_data_get_fn = bus_property_data_get;
    desc->bus_property_data_set_fn = bus_property_data_set;
    desc->bus_object_data_get_fn = bus_object_data_get;
    desc->bus_object_data_set_fn = bus_object_data_set;
    desc->bus_property_get_name_fn = bus_property_get_name;
    desc->bus_method_invoke_fn = bus_method_invoke;
    desc->bus_get_trace_context_fn = bus_get_trace_context;
}
