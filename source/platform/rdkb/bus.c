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
wifi_bus_t *get_bus_obj(void)
{
    return &g_bus;
}

wifi_bus_desc_t *get_bus_descriptor(void)
{
    return &g_bus.desc;
}

void rdkb_bus_desc_init(wifi_bus_desc_t *desc);

bus_element_type_t convert_rbus_to_bus_elem_type(rbusElementType_t rbus_elem_type)
{
    bus_element_type_t  bus_elem_type;

    switch(rbus_elem_type) {
        case RBUS_ELEMENT_TYPE_PROPERTY:
            bus_elem_type = bus_element_type_property;
        break;
        case RBUS_ELEMENT_TYPE_TABLE:
            bus_elem_type = bus_element_type_table;
        break;
        case RBUS_ELEMENT_TYPE_EVENT:
            bus_elem_type = bus_element_type_event;
        break;
        case RBUS_ELEMENT_TYPE_METHOD:
            bus_elem_type = bus_element_type_method;
        break;
        default:
            bus_elem_type = bus_element_type_property;
            wifi_util_error_print(WIFI_BUS, "%s:%d unsupported rbus element type:%d\r\n", __func__, __LINE__, rbus_elem_type);
        break;
    }

    return bus_elem_type;
}

rbusElementType_t convert_bus_to_rbus_elem_type(bus_element_type_t bus_elem_type)
{
    rbusElementType_t  rbus_elem_type;

    switch(bus_elem_type) {
        case bus_element_type_property:
            rbus_elem_type = RBUS_ELEMENT_TYPE_PROPERTY;
        break;
        case bus_element_type_table:
            rbus_elem_type = RBUS_ELEMENT_TYPE_TABLE;
        break;
        case bus_element_type_event:
            rbus_elem_type = RBUS_ELEMENT_TYPE_EVENT;
        break;
        case bus_element_type_method:
            rbus_elem_type = RBUS_ELEMENT_TYPE_METHOD;
        break;
        default:
            rbus_elem_type = RBUS_ELEMENT_TYPE_PROPERTY;
            wifi_util_error_print(WIFI_BUS, "%s:%d unsupported bus element type:%d\r\n", __func__, __LINE__, bus_elem_type);
        break;
    }

    return rbus_elem_type;
}

rbusEventSubAction_t convert_bus_to_rbus_sub_action_type(bus_event_sub_action_t bus_sub_action)
{
    rbusEventSubAction_t rbus_sub_action;

    switch(bus_sub_action) {
        case bus_event_action_subscribe:
            rbus_sub_action = RBUS_EVENT_ACTION_SUBSCRIBE;
        break;
        case bus_event_action_unsubscribe:
            rbus_sub_action = RBUS_EVENT_ACTION_UNSUBSCRIBE;
        break;
        default:
            rbus_sub_action = RBUS_EVENT_ACTION_UNSUBSCRIBE;
            wifi_util_error_print(WIFI_BUS, "%s:%d unsupported bus sub action:%02x\r\n", __func__, __LINE__, bus_sub_action);
        break;
    }

    return rbus_sub_action;
}

bus_event_sub_action_t convert_rbus_to_bus_sub_action_type(rbusEventSubAction_t rbus_sub_action)
{
    bus_event_sub_action_t bus_sub_action;

    switch(rbus_sub_action) {
        case RBUS_EVENT_ACTION_SUBSCRIBE:
            bus_sub_action = bus_event_action_subscribe;
        break;
        case RBUS_EVENT_ACTION_UNSUBSCRIBE:
            bus_sub_action = bus_event_action_unsubscribe;
        break;
        default:
            bus_sub_action = bus_event_action_unsubscribe;
            wifi_util_error_print(WIFI_BUS, "%s:%d unsupported bus sub action:%02x\r\n", __func__, __LINE__, rbus_sub_action);
        break;
    }

    return bus_sub_action;
}

bus_error_t convert_rbus_to_bus_error_code(rbusError_t rbus_error)
{
    bus_error_t bus_error;

    switch(rbus_error)
    {
        case RBUS_ERROR_SUCCESS:
            bus_error = bus_error_success;
        break;
        case RBUS_ERROR_BUS_ERROR:
            bus_error = bus_error_general;
        break;
        case RBUS_ERROR_INVALID_INPUT:
            bus_error = bus_error_invalid_input;
        break;
        case RBUS_ERROR_NOT_INITIALIZED:
            bus_error = bus_error_not_inttialized;
        break;
        case RBUS_ERROR_OUT_OF_RESOURCES:
            bus_error = bus_error_out_of_resources;
        break;
        case RBUS_ERROR_DESTINATION_NOT_FOUND:
            bus_error = bus_error_destination_not_found;
        break;
        case RBUS_ERROR_DESTINATION_NOT_REACHABLE:
            bus_error = bus_error_destination_not_reachable;
        break;
        case RBUS_ERROR_DESTINATION_RESPONSE_FAILURE:
            bus_error = bus_error_destination_response_failure;
        break;
        case RBUS_ERROR_INVALID_RESPONSE_FROM_DESTINATION:
            bus_error = bus_error_invalid_response_from_destination;
        break;
        case RBUS_ERROR_INVALID_OPERATION:
            bus_error = bus_error_invalid_operation;
        break;
        case RBUS_ERROR_INVALID_EVENT:
            bus_error = bus_error_invalid_event;
        break;
        case RBUS_ERROR_INVALID_HANDLE:
            bus_error = bus_error_invalid_handle;
        break;
        case RBUS_ERROR_SESSION_ALREADY_EXIST:
            bus_error = bus_error_session_already_exist;
        break;
        case RBUS_ERROR_COMPONENT_NAME_DUPLICATE:
            bus_error = bus_error_component_name_duplicate;
        break;
        case RBUS_ERROR_ELEMENT_NAME_DUPLICATE:
            bus_error = bus_error_element_name_duplicate;
        break;
        case RBUS_ERROR_ELEMENT_NAME_MISSING:
            bus_error = bus_error_element_name_missing;
        break;
        case RBUS_ERROR_COMPONENT_DOES_NOT_EXIST:
            bus_error = bus_error_component_does_not_exist;
        break;
        case RBUS_ERROR_ELEMENT_DOES_NOT_EXIST:
            bus_error = bus_error_element_does_not_exist;
        break;
        case RBUS_ERROR_ACCESS_NOT_ALLOWED:
            bus_error = bus_error_access_not_allowed;
        break;
        case RBUS_ERROR_INVALID_CONTEXT:
            bus_error = bus_error_invalid_context;
        break;
        case RBUS_ERROR_TIMEOUT:
            bus_error = bus_error_timeout;
        break;
        case RBUS_ERROR_ASYNC_RESPONSE:
            bus_error = bus_error_async_response;
        break;
        case RBUS_ERROR_INVALID_METHOD:
            bus_error = bus_error_invalid_method;
        break;
        case RBUS_ERROR_NOSUBSCRIBERS:
            bus_error = bus_error_nosubscribers;
        break;
        case RBUS_ERROR_SUBSCRIPTION_ALREADY_EXIST:
            bus_error = bus_error_subscription_already_exist;
        break;
        case RBUS_ERROR_INVALID_NAMESPACE:
            bus_error = bus_error_invalid_namespace;
        break;
        case RBUS_ERROR_DIRECT_CON_NOT_EXIST:
            bus_error = bus_error_direct_con_not_exist;
        break;
        default:
            bus_error = bus_error_general;
            wifi_util_error_print(WIFI_BUS, "%s:%d unsupported rbus error code:%02x\r\n", __func__, __LINE__, rbus_error);
        break;
    }
    return bus_error;
}

rbusError_t convert_bus_to_rbus_error_code(bus_error_t bus_error)
{
    rbusError_t rbus_error;

    switch(bus_error)
    {
        case bus_error_success:
            rbus_error = RBUS_ERROR_SUCCESS;
        break;
        case bus_error_general:
            rbus_error = RBUS_ERROR_BUS_ERROR;
        break;
        case bus_error_invalid_input:
            rbus_error = RBUS_ERROR_INVALID_INPUT;
        break;
        case bus_error_not_inttialized:
            rbus_error = RBUS_ERROR_NOT_INITIALIZED;
        break;
        case bus_error_out_of_resources:
            rbus_error = RBUS_ERROR_OUT_OF_RESOURCES;
        break;
        case bus_error_destination_not_found:
            rbus_error = RBUS_ERROR_DESTINATION_NOT_FOUND;
        break;
        case bus_error_destination_not_reachable:
            rbus_error = RBUS_ERROR_DESTINATION_NOT_REACHABLE;
        break;
        case bus_error_destination_response_failure:
            rbus_error = RBUS_ERROR_DESTINATION_RESPONSE_FAILURE;
        break;
        case bus_error_invalid_response_from_destination:
            rbus_error = RBUS_ERROR_INVALID_RESPONSE_FROM_DESTINATION;
        break;
        case bus_error_invalid_operation:
            rbus_error = RBUS_ERROR_INVALID_OPERATION;
        break;
        case bus_error_invalid_event:
            rbus_error = RBUS_ERROR_INVALID_EVENT;
        break;
        case bus_error_invalid_handle:
            rbus_error = RBUS_ERROR_INVALID_HANDLE;
        break;
        case bus_error_session_already_exist:
            rbus_error = RBUS_ERROR_SESSION_ALREADY_EXIST;
        break;
        case bus_error_component_name_duplicate:
            rbus_error = RBUS_ERROR_COMPONENT_NAME_DUPLICATE;
        break;
        case bus_error_element_name_duplicate:
            rbus_error = RBUS_ERROR_ELEMENT_NAME_DUPLICATE;
        break;
        case bus_error_element_name_missing:
            rbus_error = RBUS_ERROR_ELEMENT_NAME_MISSING;
        break;
        case bus_error_component_does_not_exist:
            rbus_error = RBUS_ERROR_COMPONENT_DOES_NOT_EXIST;
        break;
        case bus_error_element_does_not_exist:
            rbus_error = RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
        break;
        case bus_error_access_not_allowed:
            rbus_error = RBUS_ERROR_ACCESS_NOT_ALLOWED;
        break;
        case bus_error_invalid_context:
            rbus_error = RBUS_ERROR_INVALID_CONTEXT;
        break;
        case bus_error_timeout:
            rbus_error = RBUS_ERROR_TIMEOUT;
        break;
        case bus_error_async_response:
            rbus_error = RBUS_ERROR_ASYNC_RESPONSE;
        break;
        case bus_error_invalid_method:
            rbus_error = RBUS_ERROR_INVALID_METHOD;
        break;
        case bus_error_nosubscribers:
            rbus_error = RBUS_ERROR_NOSUBSCRIBERS;
        break;
        case bus_error_subscription_already_exist:
            rbus_error = RBUS_ERROR_SUBSCRIPTION_ALREADY_EXIST;
        break;
        case bus_error_invalid_namespace:
            rbus_error = RBUS_ERROR_INVALID_NAMESPACE;
        break;
        case bus_error_direct_con_not_exist:
            rbus_error = RBUS_ERROR_DIRECT_CON_NOT_EXIST;
        break;
        default:
            rbus_error = RBUS_ERROR_BUS_ERROR;
            wifi_util_error_print(WIFI_BUS, "%s:%d unsupported bus error code:%02x\r\n", __func__, __LINE__, bus_error);
        break;
    }
    return rbus_error;
}

bus_data_type_t convert_rbus_to_bus_data_type(rbusValueType_t rbus_data_type)
{
    bus_data_type_t bus_data_type;

    switch(rbus_data_type) {
        case RBUS_BOOLEAN:
            bus_data_type = bus_data_type_boolean;
        break;
        case RBUS_CHAR:
            bus_data_type = bus_data_type_char;
        break;
        case RBUS_BYTE:
            bus_data_type = bus_data_type_byte;
        break;
        case RBUS_INT8:
            bus_data_type = bus_data_type_int8;
        break;
        case RBUS_UINT8:
            bus_data_type = bus_data_type_uint8;
        break;
        case RBUS_INT16:
            bus_data_type = bus_data_type_int16;
        break;
        case RBUS_UINT16:
            bus_data_type = bus_data_type_uint16;
        break;
        case RBUS_INT32:
            bus_data_type = bus_data_type_int32;
        break;
        case RBUS_UINT32:
            bus_data_type = bus_data_type_uint32;
        break;
        case RBUS_INT64:
            bus_data_type = bus_data_type_init64;
        break;
        case RBUS_UINT64:
            bus_data_type = bus_data_type_uint64;
        break;
        case RBUS_SINGLE:
            bus_data_type = bus_data_type_single;
        break;
        case RBUS_DOUBLE:
            bus_data_type = bus_data_type_double;
        break;
        case RBUS_DATETIME:
            bus_data_type = bus_data_type_datetime;
        break;
        case RBUS_STRING:
            bus_data_type = bus_data_type_string;
        break;
        case RBUS_BYTES:
            bus_data_type = bus_data_type_bytes;
        break;
        case RBUS_PROPERTY:
            bus_data_type = bus_data_type_property;
        break;
        case RBUS_OBJECT:
            bus_data_type = bus_data_type_object;
        break;
        case RBUS_NONE:
            bus_data_type = bus_data_type_none;
        break;
        default:
            bus_data_type = bus_data_type_none;
            wifi_util_error_print(WIFI_BUS, "%s:%d unsupported bus data type:%02x\r\n", __func__, __LINE__, rbus_data_type);
        break;
    }

    return bus_data_type;
}

rbusValueType_t convert_bus_to_rbus_data_type(bus_data_type_t bus_data_type)
{
    rbusValueType_t rbus_data_type;

    switch(bus_data_type) {
        case bus_data_type_boolean:
            rbus_data_type = RBUS_BOOLEAN;
        break;
        case bus_data_type_char:
            rbus_data_type = RBUS_CHAR;
        break;
        case bus_data_type_byte:
            rbus_data_type = RBUS_BYTE;
        break;
        case bus_data_type_int8:
            rbus_data_type = RBUS_INT8;
        break;
        case bus_data_type_uint8:
            rbus_data_type = RBUS_UINT8;
        break;
        case bus_data_type_int16:
            rbus_data_type = RBUS_INT16;
        break;
        case bus_data_type_uint16:
            rbus_data_type = RBUS_UINT16;
        break;
        case bus_data_type_int32:
            rbus_data_type = RBUS_INT32;
        break;
        case bus_data_type_uint32:
            rbus_data_type = RBUS_UINT32;
        break;
        case bus_data_type_init64:
            rbus_data_type = RBUS_INT64;
        break;
        case bus_data_type_uint64:
            rbus_data_type = RBUS_UINT64;
        break;
        case bus_data_type_single:
            rbus_data_type = RBUS_SINGLE;
        break;
        case bus_data_type_double:
            rbus_data_type = RBUS_DOUBLE;
        break;
        case bus_data_type_datetime:
            rbus_data_type = RBUS_DATETIME;
        break;
        case bus_data_type_string:
            rbus_data_type = RBUS_STRING;
        break;
        case bus_data_type_bytes:
            rbus_data_type = RBUS_BYTES;
        break;
        case bus_data_type_property:
            rbus_data_type = RBUS_PROPERTY;
        break;
        case bus_data_type_object:
            rbus_data_type = RBUS_OBJECT;
        break;
        case bus_data_type_none:
            rbus_data_type = RBUS_NONE;
        break;
        default:
            rbus_data_type = RBUS_NONE;
            wifi_util_error_print(WIFI_BUS, "%s:%d unsupported bus data type:%02x\r\n", __func__, __LINE__, bus_data_type);
        break;
    }

    return rbus_data_type;
}

void free_raw_data_struct(raw_data_t *p_data)
{
    if ((p_data->data_type == bus_data_type_string || p_data->data_type == bus_data_type_bytes) && p_data->raw_data.bytes != NULL) {
        wifi_util_dbg_print(WIFI_BUS, "%s:%d free raw obj data type:%02x:%p\r\n", __func__,
            __LINE__, p_data->data_type, p_data->raw_data.bytes);
        free(p_data->raw_data.bytes);
        p_data->raw_data.bytes = NULL;
    }
}

void *get_bus_cb_data_info(elem_node_map_t *cb_root, char *name)
{
    elem_node_map_t *mux_elem = get_bus_node_info(cb_root, name);
    if (mux_elem != NULL) {
        return mux_elem->node_elem_data;
    }
    wifi_util_info_print(WIFI_BUS,"%s Rbus callback info not found=%s\n", __func__, name);
    return NULL;
}

bus_error_t get_rbus_property_data(char *event_name, rbusProperty_t property, raw_data_t *bus_data)
{
    bus_error_t ret = bus_error_success;
    rbusValue_t value = rbusProperty_GetValue(property);
    rbusValueType_t type = rbusValue_GetType(value);

    wifi_util_dbg_print(WIFI_BUS,"%s Rbus property=%s\n",__FUNCTION__, event_name);
    bus_data->data_type = convert_rbus_to_bus_data_type(type);
    switch(type) {
        case RBUS_STRING:
            bus_data->raw_data.bytes = (void *)rbusValue_GetString(value, (int *)&bus_data->raw_data_len);
            if (bus_data->raw_data.bytes == NULL) {
                wifi_util_error_print(WIFI_BUS,"%s Rbus get string failed len=%d\n",__FUNCTION__, bus_data->raw_data_len);
            }
        break;
        case RBUS_UINT32:
            bus_data->raw_data.u32 = rbusValue_GetUInt32(value);
            bus_data->raw_data_len = sizeof(uint32_t);
        break;
        case RBUS_INT32:
            bus_data->raw_data.i32 = rbusValue_GetInt32(value);
            bus_data->raw_data_len = sizeof(int32_t);
        break;
        case RBUS_BOOLEAN:
            bus_data->raw_data.b = rbusValue_GetBoolean(value);
            bus_data->raw_data_len = sizeof(bool);
        break;
        case RBUS_BYTES:
            bus_data->raw_data.bytes = (void *)rbusValue_GetBytes(value, (int *)&bus_data->raw_data_len);
            if (bus_data->raw_data.bytes == NULL) {
                wifi_util_error_print(WIFI_BUS,"%s Rbus get bytes is failed len=%d\n",__FUNCTION__, bus_data->raw_data_len);
            }
        break;
        default:
            wifi_util_error_print(WIFI_BUS,"%s Rbus:%s value type not found =%d\n",__FUNCTION__, event_name, bus_data->data_type);
            ret = bus_error_invalid_input;
        break;
    }

    return ret;
}

bus_error_t set_rbus_property_data(char *event_name, rbusProperty_t property, raw_data_t *bus_data)
{
    bus_error_t ret = bus_error_success;
    rbusValue_t value;

    wifi_util_dbg_print(WIFI_BUS,"%s:%d Rbus property:%s data type=%x set\r\n", __func__, __LINE__, event_name, bus_data->data_type);
    rbusValue_Init(&value);

    switch(bus_data->data_type) {
        case bus_data_type_string:
            // the encoded data is a string
            if (bus_data->raw_data.bytes != NULL) {
                rbusValue_SetString(value, (char *)bus_data->raw_data.bytes);
            }
        break;
        case bus_data_type_bytes:
            if (bus_data->raw_data.bytes != NULL) {
                rbusValue_SetBytes(value, (uint8_t *)bus_data->raw_data.bytes, bus_data->raw_data_len);
            }
        break;
        case bus_data_type_uint32:
            rbusValue_SetUInt32(value, bus_data->raw_data.u32);
        break;
        case bus_data_type_int32:
            rbusValue_SetInt32(value, bus_data->raw_data.i32);
        break;
        case bus_data_type_boolean:
            rbusValue_SetBoolean(value, bus_data->raw_data.b);
        break;
        case bus_data_type_object:
            wifi_util_error_print(WIFI_BUS,"%s Rbus:%s value type not supported =%d\n",__FUNCTION__, event_name, bus_data->data_type);
        break;
        default:
            wifi_util_error_print(WIFI_BUS,"%s Rbus:%s value type not found =%d\n",__FUNCTION__, event_name, bus_data->data_type);
            ret = bus_error_invalid_input;
        break;
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return ret;
}

bus_error_t get_rbus_object_data(char *name, rbusObject_t inParams, raw_data_t *bus_data)
{
    bus_error_t rc = bus_error_success;
    int len = 0;

    if (bus_data == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s:%d bus buff is NULL\n",__func__, __LINE__);
        return bus_error_invalid_input;
    }

    rbusValue_t value = rbusObject_GetValue(inParams, NULL);
    rbusValueType_t type = rbusValue_GetType(value);
    bus_data->data_type = convert_rbus_to_bus_data_type(type);

    switch(type) {
        case RBUS_STRING:
            bus_data->raw_data.bytes = (char *)rbusValue_GetString(value, &len);
            if (bus_data->raw_data.bytes != NULL) {
                bus_data->raw_data_len = (unsigned int)len;
                wifi_util_dbg_print(WIFI_BUS,"%s Rbus get string len=%d\n",__FUNCTION__,len);
            } else {
                rc = bus_error_invalid_input;
                wifi_util_error_print(WIFI_BUS,"%s Rbus get string failure len=%d\n",__FUNCTION__, len);
            }
        break;
        case RBUS_UINT32:
            bus_data->raw_data.u32 = rbusValue_GetUInt32(value);
            bus_data->raw_data_len = sizeof(uint32_t);
        break;
        case RBUS_INT32:
            bus_data->raw_data.i32 = rbusValue_GetInt32(value);
            bus_data->raw_data_len = sizeof(int32_t);
        break;
        case RBUS_BOOLEAN:
            bus_data->raw_data.b = rbusValue_GetBoolean(value);
            bus_data->raw_data_len = sizeof(bool);
        break;
        case RBUS_BYTES:
            bus_data->raw_data.bytes = (uint8_t *)rbusValue_GetBytes(value, &len);
            if (bus_data->raw_data.bytes != NULL) {
                bus_data->raw_data_len = (unsigned int)len;
                wifi_util_dbg_print(WIFI_BUS,"%s Rbus get bytes len=%d\n",__FUNCTION__, len);
            } else {
                rc = bus_error_invalid_input;
                wifi_util_error_print(WIFI_BUS,"%s Rbus get bytes failure len=%d\n",__FUNCTION__, len);
            }
        break;
        default:
            wifi_util_error_print(WIFI_BUS,"%s Rbus value type not found =%d\n",__FUNCTION__, type);
            rc = bus_error_invalid_input;
        break;
    }

    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_BUS,"%s rbus read failed for %s\n",__FUNCTION__, name);
        return rc;
    }

    return rc;
}

bus_error_t set_rbus_object_data(char *name, rbusObject_t outParams, raw_data_t *bus_data)
{
    bus_error_t rc = bus_error_success;
    rbusValue_t  value;

    rbusValue_Init(&value);
    wifi_util_dbg_print(WIFI_BUS,"%s:%d Rbus object:%s data type=%d set\r\n", __func__, __LINE__, name, bus_data->data_type);

    switch(bus_data->data_type) {
        case bus_data_type_bytes:
            rbusValue_SetBytes(value, (uint8_t *)bus_data->raw_data.bytes, bus_data->raw_data_len);
        break;
        default:
            wifi_util_error_print(WIFI_BUS,"%s Rbus:%s value type not found =%d\n",__FUNCTION__, name, bus_data->data_type);
            rc = bus_error_invalid_input;
        break;
    }

    rbusObject_SetValue(outParams, name, value);
    rbusValue_Release(value);

    return rc;
}

rbusError_t rbus_get_handler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* options)
{
    raw_data_t  bus_data = { 0 };
    bus_error_t ret = bus_error_success;
    char *event_name;
    event_name = (char *)rbusProperty_GetName(property);

    if (event_name == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d rbus event name is NULL\n", __func__, __LINE__);
        return RBUS_ERROR_INVALID_INPUT;
    } else if (options != NULL && options->requestingComponent != NULL) {
        wifi_util_info_print(WIFI_BUS,"%s:%d rbus data get end comp:%s\n", __func__, __LINE__, options->requestingComponent);
    }

    wifi_util_info_print(WIFI_BUS,"%s:%d rbus cb triggered for %s\n", __func__, __LINE__, event_name);
    rbusValue_t value = rbusProperty_GetValue(property);
    rbusValueType_t type = rbusValue_GetType(value);
    bus_data.data_type = convert_rbus_to_bus_data_type(type);

    bus_mux_reg_node_data_t *reg_node_data = get_bus_cb_data_info(get_bus_mux_reg_cb_map(), event_name);
    if (reg_node_data == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d rbus event name:%s, user cb not found\n", __func__, __LINE__, event_name);
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    bus_callback_table_t *user_cb = &reg_node_data->cb_table;
    if ((bus_data.data_type == bus_data_type_none) && (reg_node_data->data_model_prop.data_format != 0)) {
        bus_data.data_type = reg_node_data->data_model_prop.data_format;
    } else if (reg_node_data->data_model_prop.data_format != bus_data.data_type) {
#if 0
        wifi_util_info_print(WIFI_BUS,"%s:%d different data type:%x:%x for %s\n", __func__, __LINE__,
                            bus_data.data_type, reg_node_data->data_model_prop.data_format, event_name);
#endif
    }
    if (user_cb->get_handler != NULL) {
        ret = user_cb->get_handler(event_name, &bus_data);
        if (ret == bus_error_success) {
            ret = set_rbus_property_data(event_name, property, &bus_data);
        } else {
            wifi_util_error_print(WIFI_BUS,"%s:%d user cb processing failed:%d for %s\n", __func__, __LINE__, ret, event_name);
        }
        free_raw_data_struct(&bus_data);
    }

    return convert_bus_to_rbus_error_code(ret);
}

rbusError_t rbus_set_handler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* options)
{
    raw_data_t  bus_data = { 0 };
    bus_error_t ret = bus_error_success;
    char *event_name;
    event_name = (char *)rbusProperty_GetName(property);

    if (event_name == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d rbus event name is NULL\n", __func__, __LINE__);
        return RBUS_ERROR_INVALID_INPUT;
    } else if (options != NULL && options->requestingComponent != NULL) {
        wifi_util_info_print(WIFI_BUS,"%s:%d rbus data set end comp:%s\n", __func__, __LINE__, options->requestingComponent);
    }

    wifi_util_info_print(WIFI_BUS,"%s:%d rbus cb triggered for %s\n", __func__, __LINE__, event_name);
    bus_mux_reg_node_data_t *reg_node_data = get_bus_cb_data_info(get_bus_mux_reg_cb_map(), event_name);
    if (reg_node_data == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d rbus event name:%s, user cb not found\n", __func__, __LINE__, event_name);
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    bus_callback_table_t *user_cb = &reg_node_data->cb_table;
    if (user_cb->set_handler != NULL) {
        ret = get_rbus_property_data(event_name, property, &bus_data);
        if (ret == bus_error_success) {
#ifndef ONEWIFI_DML_SUPPORT
            int ret_status = validate_dm_set_parameters(&reg_node_data->data_model_prop, &bus_data);
            if (ret_status != RETURN_OK) {
                wifi_util_error_print(WIFI_BUS,"%s:%d rbus event:%s, invalid data:%x operation\n", __func__,
                    __LINE__, event_name, bus_data.data_type);
                return RBUS_ERROR_INVALID_OPERATION;
            }
#endif
            ret = user_cb->set_handler(event_name, &bus_data);
            if (ret != bus_error_success) {
                wifi_util_error_print(WIFI_BUS,"%s:%d user cb processing failed:%d for %s\n", __func__,
                    __LINE__, ret, event_name);
            }
        }
    }

    return convert_bus_to_rbus_error_code(ret);
}

rbusError_t rbus_table_add_row_handler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum)
{
    bus_error_t ret = bus_error_success;

    wifi_util_info_print(WIFI_BUS,"%s:%d rbus cb triggered for %s\n", __func__, __LINE__, tableName);
    bus_mux_reg_node_data_t *reg_node_data = get_bus_cb_data_info(get_bus_mux_reg_cb_map(), (char *)tableName);
    if (reg_node_data == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d rbus event name:%s, user cb not found\n", __func__, __LINE__, tableName);
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    bus_callback_table_t *user_cb = &reg_node_data->cb_table;
    if (user_cb->table_add_row_handler != NULL) {
        ret = user_cb->table_add_row_handler(tableName, aliasName, instNum);
        if (ret == bus_error_success) {
            bus_table_add_row(get_bus_mux_reg_cb_map(), (char *)tableName, *instNum);
        }
    }

    return convert_bus_to_rbus_error_code(ret);
}

rbusError_t rbus_table_remove_row_handler(rbusHandle_t handle, char const* rowName)
{
    bus_error_t ret = bus_error_success;

    wifi_util_info_print(WIFI_BUS,"%s:%d rbus cb triggered for %s\n", __func__, __LINE__, rowName);
    bus_mux_reg_node_data_t *reg_node_data = get_bus_cb_data_info(get_bus_mux_reg_cb_map(), (char *)rowName);
    if (reg_node_data == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d rbus event name:%s, user cb not found\n", __func__, __LINE__, rowName);
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    bus_callback_table_t *user_cb = &reg_node_data->cb_table;
    if (user_cb->table_remove_row_handler != NULL) {
        ret = user_cb->table_remove_row_handler(rowName);
        if (ret == bus_error_success) {
            bus_table_remove_row(get_bus_mux_reg_cb_map(), (char *)rowName);
        }
    }

    return convert_bus_to_rbus_error_code(ret);
}

rbusError_t rbus_method_handler(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle)
{
    raw_data_t  bus_input_data = { 0 }, bus_output_data = { 0 };
    bus_error_t ret = bus_error_success;

    wifi_util_info_print(WIFI_BUS,"%s:%d rbus cb triggered for %s\n", __func__, __LINE__, methodName);
    bus_mux_reg_node_data_t *reg_node_data = get_bus_cb_data_info(get_bus_mux_reg_cb_map(), (char *)methodName);
    if (reg_node_data == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d rbus event name:%s, user cb not found\n", __func__, __LINE__, methodName);
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    bus_callback_table_t *user_cb = &reg_node_data->cb_table;
    if (user_cb->method_handler != NULL) {
        ret = get_rbus_object_data((char *)methodName, inParams, &bus_input_data);
        if (ret == bus_error_success) {
            ret = user_cb->method_handler((char *)methodName, &bus_input_data, &bus_output_data, (void *)asyncHandle);
            if (ret != bus_error_success) {
                wifi_util_error_print(WIFI_BUS,"%s:%d user cb processing failed:%d for %s\n", __func__, __LINE__, ret, methodName);
            } else {
                ret = set_rbus_object_data((char *)methodName, outParams, &bus_output_data);
            }
            free_raw_data_struct(&bus_output_data);
	}
    }

    return convert_bus_to_rbus_error_code(ret);
}

rbusError_t rbus_event_sub_handler(rbusHandle_t handle, rbusEventSubAction_t action, char const* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    bus_event_sub_action_t bus_sub_action = convert_rbus_to_bus_sub_action_type(action);
    wifi_util_info_print(WIFI_BUS,"%s:%d rbus cb triggered for %s\n", __func__, __LINE__, eventName);
    bus_mux_reg_node_data_t *reg_node_data = get_bus_cb_data_info(get_bus_mux_reg_cb_map(), (char *)eventName);
    if (reg_node_data == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d rbus event name:%s, user cb not found\n", __func__, __LINE__, eventName);
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    bus_callback_table_t *user_cb = &reg_node_data->cb_table;
    if (user_cb->event_sub_handler != NULL) {
        user_cb->event_sub_handler((char *)eventName, bus_sub_action, interval, autoPublish);
    }

    return RBUS_ERROR_SUCCESS;
}

static void rbus_sub_handler(rbusHandle_t handle, rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    (void)handle;

    bus_error_t ret = bus_error_success;
    raw_data_t  bus_data = { 0 };
    char *event_name = (char *)subscription->eventName;

    wifi_util_info_print(WIFI_BUS,"%s:%d rbus sub cb triggered for %s\n", __func__, __LINE__, event_name);
    bus_mux_sub_node_data_t  *sub_node_data = get_bus_cb_data_info(get_bus_mux_sub_cb_map(), event_name);
    if (sub_node_data == NULL) {
        wifi_util_error_print(WIFI_BUS,"%s:%d rbus event name:%s, user cb not found\n", __func__, __LINE__, event_name);
        return;
    }
    bus_sub_callback_table_t *user_cb = &sub_node_data->cb_table;
    if (user_cb->sub_handler != NULL) {
        ret = get_rbus_object_data(event_name, event->data, &bus_data);
        if (ret == bus_error_success) {
            user_cb->sub_handler((char *)event_name, &bus_data);
        }
    }
}

void rbus_sub_ex_async_handler(rbusHandle_t handle, rbusEventSubscription_t* subscription, rbusError_t error)
{
    (void)handle;
    bus_error_t bus_error = convert_rbus_to_bus_error_code(error);

    wifi_util_info_print(WIFI_BUS,"%s:%d rbus sub ex async cb triggered\n", __func__, __LINE__);
    if (subscription) {
        char *event_name = (char *)subscription->eventName;
        wifi_util_dbg_print(WIFI_BUS, "%s: %d event name (%s) subscribe %s\n", __func__, __LINE__,
                        subscription->eventName, bus_error == bus_error_success ? "success" : "failed");
        bus_mux_sub_node_data_t  *sub_node_data = get_bus_cb_data_info(get_bus_mux_sub_cb_map(), event_name);
        if (sub_node_data == NULL) {
            wifi_util_error_print(WIFI_BUS,"%s:%d rbus event name:%s, user cb not found\n", __func__, __LINE__, event_name);
            return;
        }
        bus_sub_callback_table_t *user_cb = &sub_node_data->cb_table;
        if (user_cb->sub_ex_async_handler != NULL) {
            user_cb->sub_ex_async_handler((char *)event_name, bus_error);
        }
    }
}

static bool map_bus_user_cb_with_rbus(bus_data_element_t *data_element, rbusCallbackTable_t *cb_table)
{
    bool user_cb_set = false;
    bus_callback_table_t *user_cb = &data_element->cb_table;

    if (user_cb->get_handler != NULL) {
        cb_table->getHandler = rbus_get_handler;
        user_cb_set = true;
    }

    if (user_cb->set_handler != NULL) {
        cb_table->setHandler = rbus_set_handler;
        user_cb_set = true;
    }

    if (user_cb->table_add_row_handler != NULL) {
        cb_table->tableAddRowHandler = rbus_table_add_row_handler;
        user_cb_set = true;
    }

    if (user_cb->table_remove_row_handler != NULL) {
        cb_table->tableRemoveRowHandler = rbus_table_remove_row_handler;
        user_cb_set = true;
    }

    if (user_cb->event_sub_handler != NULL) {
        cb_table->eventSubHandler = rbus_event_sub_handler;
        user_cb_set = true;
    }

    if (user_cb->method_handler != NULL) {
        cb_table->methodHandler = rbus_method_handler;
        user_cb_set = true;
    }

    wifi_util_info_print(WIFI_BUS,"%s:%d user_cb_set:%d event_name:%s\n", __func__,
        __LINE__, user_cb_set, data_element->full_name);
    return user_cb_set;
}

static void mux_bus_cb_registration(bus_data_element_t *data_element, bool user_cb_set)
{
    bus_name_string_t        event_name = { 0 };

    strncpy(event_name, data_element->full_name, strlen(data_element->full_name) + 1);

    if (user_cb_set == true) {
        elem_node_map_t          *reg_cb_mux_map = get_bus_mux_reg_cb_map();
        bus_mux_reg_node_data_t  reg_node_data;
        bus_mux_data_elem_t      node_elem = { 0 };

        reg_node_data.cb_table         = data_element->cb_table;
        reg_node_data.data_model_prop  = data_element->data_model_prop;

        node_elem.full_name        = event_name;
        node_elem.type             = data_element->type;
        node_elem.node_data_type   = node_elem_reg_data;
        node_elem.cfg_data         = (void *)&reg_node_data;
        node_elem.cfg_data_len     = sizeof(bus_mux_reg_node_data_t);
        node_elem.num_of_table_row = data_element->num_of_table_row;

        if (bus_insert_elem_node(reg_cb_mux_map, &node_elem) == NULL) {
            wifi_util_error_print(WIFI_BUS,"%s:%d user_cb_set failure for event_name:%s\n", __func__, __LINE__, event_name);
            return;
        }
    } else {
        wifi_util_info_print(WIFI_BUS,"%s:%d user_cb_set:%d not needed for event:%s\n", __func__, __LINE__, user_cb_set, event_name);
    }
}

static void bus_sub_cb_registration(char *event_name, rbus_sub_callback_table_t *cb_table, bus_sub_callback_table_t *user_cb)
{
    bool user_cb_set = false;

    if (user_cb->sub_handler != NULL) {
        cb_table->sub_handler = rbus_sub_handler;
        user_cb_set = true;
    }

    if (user_cb->sub_ex_async_handler != NULL) {
        cb_table->sub_ex_async_handler = rbus_sub_ex_async_handler;
        user_cb_set = true;
    }

    wifi_util_info_print(WIFI_BUS,"%s:%d sub_user_cb_set:%d event_name:%s\n", __func__, __LINE__, user_cb_set, event_name);

    if (user_cb_set == true) {
        elem_node_map_t          *sub_cb_mux_map = get_bus_mux_sub_cb_map();
        bus_mux_sub_node_data_t  sub_node_data;
        bus_mux_data_elem_t      node_elem = { 0 };

        sub_node_data.cb_table.sub_handler = user_cb->sub_handler;
        sub_node_data.cb_table.sub_ex_async_handler = user_cb->sub_ex_async_handler;

        node_elem.full_name        = event_name;
        node_elem.type             = bus_element_type_event;
        node_elem.node_data_type   = node_elem_sub_data;
        node_elem.cfg_data         = &sub_node_data;
        node_elem.cfg_data_len     = sizeof(bus_mux_sub_node_data_t);
        node_elem.num_of_table_row = 0;

        if (bus_insert_elem_node(sub_cb_mux_map, &node_elem) == NULL) {
            wifi_util_error_print(WIFI_BUS,"%s:%d user_cb_set failure for event_name:%s\n", __func__, __LINE__, event_name);
            return;
        }
    } else {
        wifi_util_info_print(WIFI_BUS,"%s:%d user_sub_cb_set:%d not needed for event:%s\n", __func__, __LINE__, user_cb_set, event_name);
    }
}

bus_error_t bus_init(bus_handle_t *handle)
{
    (void)handle;
    bus_error_t rc = bus_error_success;

    wifi_bus_desc_t *p_bus_desc = NULL;
    p_bus_desc = get_bus_descriptor();
    memset(p_bus_desc, 0, sizeof(wifi_bus_desc_t));

    init_bus_mux_root();

    rdkb_bus_desc_init(p_bus_desc);
    wifi_util_info_print(WIFI_BUS, "%s:%d: bus: bus_init() is successful.\n", __func__, __LINE__);
    return rc;
}

static bus_error_t bus_open(bus_handle_t *handle, char *component_name)
{
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(component_name);

    rc = rbus_open(&handle->u.rbus_handle, component_name);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_BUS, "%s:%d: bus: rbus_open() failed:%d, component:%s\n",
        __func__, __LINE__, rc, component_name);
        return convert_rbus_to_bus_error_code(rc);
    }
    wifi_util_info_print(WIFI_BUS, "%s:%d: bus: rbus_open() is successful for component:%s, \
       rc:%d, handle:%p\n", __func__, __LINE__, component_name, rc, handle->u.rbus_handle);
    return convert_rbus_to_bus_error_code(rc);
}

static bus_error_t bus_close(bus_handle_t *handle)
{
    rbusError_t rc;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rc = rbus_close(p_rbus_handle);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_BUS, "%s:%d: bus: rbus_close() failed:%d\n", __func__, __LINE__, rc);
        return convert_rbus_to_bus_error_code(rc);
    }
    wifi_util_info_print(WIFI_BUS, "%s:%d: bus: rbus_open() is successful. rc:%d, handle:%p\n",
        __func__, __LINE__, rc, handle->u.rbus_handle);
    return convert_rbus_to_bus_error_code(rc);
}

static bus_error_t bus_get_trace_context(bus_handle_t *handle, char *traceParent,
    uint32_t traceParentLength, char *traceState, uint32_t traceStateLength)
{
    rbusError_t rc;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rc = rbusHandle_GetTraceContextAsString(p_rbus_handle, traceParent, traceParentLength,
        traceState, traceStateLength);
    wifi_util_info_print(WIFI_BUS,
        "%s:%d: bus: rbusHandle_GetTraceContextAsString() is successful. rc:%d\n", __func__,
        __LINE__, rc);
    return convert_rbus_to_bus_error_code(rc);
}

static bus_error_t bus_set(bus_handle_t *handle, char const *name, raw_data_t *data)
{
    rbusError_t rc = RBUS_ERROR_SUCCESS;
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
    case bus_data_type_int32:
        rbusValue_SetInt32(value, data->raw_data.i32);
        break;
    case bus_data_type_bytes:
        rbusValue_SetBytes(value, (uint8_t *)data->raw_data.bytes, data->raw_data_len);
        break;
    default:
        wifi_util_error_print(WIFI_BUS, "%s:%d: bus: Invalid data_type:%d for name:%s.\n",
            __func__, __LINE__, data->data_type, name);
        break;
    };

    rc = rbus_set(p_rbus_handle, name, value, NULL);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_BUS, "%s:%d bus: rbus_set() failed:%d for name:%s\n",
          __func__, __LINE__, rc, name);
    }
    rbusValue_Release(value);
    return convert_rbus_to_bus_error_code(rc);
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
    rbusError_t rc;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    void *ptr = NULL;
    int len = 0;

    rc = rbus_get(p_rbus_handle, name, &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_BUS, "%s:%d bus: rbus_get failed for [%s] with error [%d]\n",
            __func__, __LINE__, name, rc);
        return convert_rbus_to_bus_error_code(rc);
    }

    rbusValueType_t type = rbusValue_GetType(value);
    wifi_util_error_print(WIFI_BUS, ":%s:%d bus: rbus_get(): rc:%d, name:%s, type:0x%x\n",
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
    case RBUS_INT32:
        data->raw_data.i32 = (int32_t)rbusValue_GetInt32(value);
        data->data_type = bus_data_type_int32;
        break;
    case RBUS_BYTES:
        ptr = (void *)rbusValue_GetBytes(value, &len);
        data->data_type = bus_data_type_bytes;
        data->raw_data_len = len;
        break;
    default:
        wifi_util_error_print(WIFI_BUS, "%s:%d: bus: Invalid data_type:%d for name:%s.\n",
            __func__, __LINE__, data->data_type, name);
        break;
    };

    wifi_util_dbg_print(WIFI_BUS,
        "%s:%d: bus: bus_data_get: type:0x%x, data_type:0x%x, type_string:0x%x len=%d, name:%s\n",
        __func__, __LINE__, type, data->data_type, bus_data_type_string, data->raw_data_len, name);

    if ((ptr) && (name) &&
       (data->data_type == bus_data_type_bytes || data->data_type == bus_data_type_string)) {
           data->raw_data.bytes = (void *)calloc(len + 1, sizeof(char));
           if (data->raw_data.bytes == NULL) {
               wifi_util_error_print(WIFI_BUS, "%s:%d: bus: memory alloc is failed:%d for name:%s\n",
                   __func__, __LINE__, len, name);
               return bus_error_out_of_resources;
           }
           memcpy(data->raw_data.bytes, ptr, len);
    }

    rbusValue_Release(value);

    return convert_rbus_to_bus_error_code(rc);
}

static bus_error_t bus_event_publish(bus_handle_t *handle, char const *name, raw_data_t *data)
{
    rbusError_t rc;
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
    case bus_data_type_int32:
        rbusValue_SetInt32(value, data->raw_data.i32);
        break;
    case bus_data_type_bytes:
        rbusValue_SetBytes(value, (uint8_t *)data->raw_data.bytes, data->raw_data_len);
        break;
    default:
        wifi_util_error_print(WIFI_BUS, "%s:%d: bus: Invalid data_type:%d for name:%s.\n",
            __func__, __LINE__, data->data_type, name);
        break;
    };

    event.name = name;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(p_rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        wifi_util_error_print(WIFI_BUS, "%s:%d: bus: rbusEvent_Publish Event failed:%d, \
            name:%s\n", __func__, __LINE__, rc, name);
    } else {
        wifi_util_dbg_print(WIFI_BUS, "%s:%d: bus: bus_event_publish() is successful. \
            name:%s, rc:%d\n", __func__, __LINE__, name, rc);
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);
    return convert_rbus_to_bus_error_code(rc);
}

static bus_error_t bus_raw_event_publish(bus_handle_t *handle, char *name, void *data,
    unsigned int size)
{
    rbusError_t rc;
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(data);

    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rbusEventRawData_t event_data;
    event_data.name = name;
    event_data.rawData = data;
    event_data.rawDataLen = size;
    rc = rbusEvent_PublishRawData(p_rbus_handle, &event_data);
    wifi_util_info_print(WIFI_BUS, "%s:%d: bus: bus_raw_event_publish() is successful \
        name:%s, rc:%d\n", __func__, __LINE__, name, rc);
    return convert_rbus_to_bus_error_code(rc);
}

static bus_error_t bus_set_string(bus_handle_t *handle, char const *param_name,
    char const *param_str)
{
    rbusError_t rc;
    VERIFY_NULL_WITH_RC(param_name);
    VERIFY_NULL_WITH_RC(param_str);

    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rc = rbus_setStr(p_rbus_handle, param_name, param_str);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_BUS, "%s:%d: bus: rbus_setStr() failed for param:%s, \
          rc:%d\n", __func__, __LINE__, param_name, rc);
    }
    wifi_util_info_print(WIFI_BUS, "%s:%d: bus: bus_set_string() is successful for \
          param:%s, rc:%d\n", __func__, __LINE__, param_name, rc);
    return convert_rbus_to_bus_error_code(rc);
}

static bool remove_substring(char *str, const char *sub)
{
    size_t len = strlen(str);
    if (len > strlen(".{i}.")) {
        if(strcmp(str + (len - strlen(".{i}.")), ".{i}.") == 0) {
            str[(len - strlen("{i}."))] = 0;
        } else if(strcmp(str + (len - strlen(".{i}")), ".{i}") == 0) {
            str[(len - strlen("{i}"))] = 0;
        } else {
            return false;
        }
        wifi_util_info_print(WIFI_BUS, "%s:%d: bus: removeSubstring is matched with %s\n",
            __func__, __LINE__, str);
        return true;
    }

    return false;
}

bus_error_t bus_reg_data_elements(bus_handle_t *handle, bus_data_element_t *data_element,
    uint32_t num_of_element)
{
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    bus_name_string_t name = { 0 };
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusDataElement_t *rbus_dataElements;
    uint32_t index, table_index;
    char sub[] = ".{i}";
    bool user_cb_set;

    wifi_util_dbg_print(WIFI_BUS, "%s:%d bus: bus_reg_data_elements() hdl:%p, \
        num_of_element:%d\n", __func__, __LINE__, p_rbus_handle, num_of_element);

    if (p_rbus_handle == NULL || data_element == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s bus: input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }

    rbus_dataElements = calloc(1, num_of_element * sizeof(rbusDataElement_t));
    if (rbus_dataElements == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s:%d bus: bus_reg_data_elements() calloc is failed\n",
            __func__, __LINE__);
        return bus_error_out_of_resources;
    }

    /* Do the conversion first */
    for (index = 0; index < num_of_element; index++) {
        rbus_dataElements[index].name = data_element[index].full_name;
        rbus_dataElements[index].type = convert_bus_to_rbus_elem_type(data_element[index].type);
        user_cb_set = map_bus_user_cb_with_rbus(&data_element[index], &rbus_dataElements[index].cbTable);
        rc = rbus_regDataElements(p_rbus_handle, 1, &rbus_dataElements[index]);
        if (rc != RBUS_ERROR_SUCCESS) {
            wifi_util_error_print(WIFI_BUS, "%s:%d: bus: rbus_regDataElements failed. \
                rc:%d for %s\n", __func__, __LINE__, rc, data_element[index].full_name);
        } else {
            mux_bus_cb_registration(&data_element[index], user_cb_set);
        }
    }

    wifi_util_info_print(WIFI_BUS,
        "%s:%d: bus: rbus_regDataElements() is successful with number of elements:%d. rc:%d\n",
        __func__, __LINE__, num_of_element, rc);

    for (index = 0; index < num_of_element; index++) {
        // wifi_util_info_print(WIFI_BUS, "%s:%d: bus: name:%s, type:%d.\n", __func__, __LINE__,
        // data_element[index].full_name, data_element[index].type);
        if (data_element[index].type == bus_element_type_table) {
            strncpy(name, data_element[index].full_name, strlen(data_element[index].full_name) + 1);
            // wifi_util_info_print(WIFI_BUS, "%s:%d: rbusTable_addRow for %s,
            // num_of_table_row:%d.\n",__func__, __LINE__, name,
            // data_element[index].num_of_table_row);
            if ((data_element[index].num_of_table_row) && (remove_substring(name, sub) == 1)) {
                for (table_index = 1; table_index <= data_element[index].num_of_table_row;
                     table_index++) {
                    // wifi_util_info_print(WIFI_BUS, "*%s() calling rbusTable_addRow for %s\n",
                    // __func__, name);
                    rc = rbusTable_addRow(p_rbus_handle, name, NULL, NULL);
                    if (rc != RBUS_ERROR_SUCCESS) {
                        wifi_util_info_print(WIFI_BUS, "%s() bus: rbusTable_addRow failed:%d for %s\n",
                            __func__, rc, name);
                    }
                }
            }
        }
    }

    wifi_util_info_print(WIFI_BUS, "%s:%d: bus: rbus elem reg success. rc:%d\n", __func__, __LINE__, rc);
    free(rbus_dataElements);
    return convert_rbus_to_bus_error_code(rc);
}

bus_error_t bus_method_invoke(bus_handle_t *handle, void *paramName, char *event,
    raw_data_t *input_data, raw_data_t *output_data, bool input_bus_data)
{
    rbusError_t rc;
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
                wifi_util_dbg_print(WIFI_BUS, "%s: bus: Invalid value '%s' for the parameter %s\n\r",
                    __func__, input_data->raw_data.bytes, paramName);
            }
        } else {
            wifi_util_dbg_print(WIFI_BUS, "%s: bus: Invalid data_type '%d' for the parameter %s\n\r",
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
            wifi_util_dbg_print(WIFI_BUS, "%s bus: bus_method_invoke-string: string:%s, len=%d\n",
                __func__, output_data->raw_data.bytes, output_data->raw_data_len);
            break;
        case bus_data_type_uint32:
            output_data->raw_data.u32 = (uint32_t)rbusValue_GetUInt32(value);
            output_data->raw_data_len = sizeof(uint32_t);
            break;
        case bus_data_type_int32:
            output_data->raw_data.i32 = (int32_t)rbusValue_GetInt32(value);
            output_data->raw_data_len = sizeof(int32_t);
            break;
        case bus_data_type_bytes:
            output_data->raw_data.bytes = (void *)rbusValue_GetBytes(value, &len);
            output_data->raw_data_len = (unsigned int)len;
            wifi_util_dbg_print(WIFI_BUS, "%s bus: bus_method_invoke-bytes: len=%d\n", __func__,
                output_data->raw_data_len);
            break;
        default:
            wifi_util_dbg_print(WIFI_BUS, "%s bus:value type not found =0x%x\n", __func__,
                output_data->data_type);
            rc = RBUS_ERROR_INVALID_INPUT;
            break;
        }
    } else {
        wifi_util_error_print(WIFI_BUS, " %s failed for  with err: '%s'\n\r", __func__,
            rbusError_ToString(rc));
    }

    rbusValue_Release(value);
    return convert_rbus_to_bus_error_code(rc);
}

bus_error_t bus_event_subscribe(bus_handle_t *handle, char const *event_name, void *cb,
    void *userData, int timeout)
{
    rbusError_t rc = RBUS_ERROR_SUCCESS;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbus_sub_callback_table_t rbus_cb = { 0 };
    bus_sub_callback_table_t  user_cb;

    user_cb.sub_handler = cb;
    user_cb.sub_ex_async_handler = NULL;

    bus_sub_cb_registration((char *)event_name, &rbus_cb, &user_cb);

    rc = rbusEvent_Subscribe(p_rbus_handle, event_name, rbus_cb.sub_handler, userData, timeout);

    return convert_rbus_to_bus_error_code(rc);
}

bus_error_t bus_event_subscribe_ex(bus_handle_t *handle, bus_event_sub_t *l_sub_info_map,
    int num_sub, int timeout)
{
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusEventSubscription_t *sub_info_map;
    rbus_sub_callback_table_t rbus_cb = {0};
    bus_sub_callback_table_t  user_cb;

    if (p_rbus_handle == NULL || l_sub_info_map == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s bus: Input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }

    sub_info_map = calloc(1, num_sub * sizeof(rbusEventSubscription_t));
    if (sub_info_map == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s:%d bus: bus_event_subscribe_ex() calloc is failed\n",
            __func__, __LINE__);
        return bus_error_out_of_resources;
    }

    for (int index = 0; index < num_sub; index++) {
        user_cb.sub_handler = l_sub_info_map[index].handler;
        user_cb.sub_ex_async_handler = NULL;
        bus_sub_cb_registration((char *)l_sub_info_map[index].event_name, &rbus_cb, &user_cb);
        sub_info_map[index].eventName = l_sub_info_map[index].event_name;
        sub_info_map[index].filter = l_sub_info_map[index].filter;
        sub_info_map[index].interval = l_sub_info_map[index].interval;
        sub_info_map[index].duration = l_sub_info_map[index].duration;
        sub_info_map[index].handler = rbus_cb.sub_handler;
        sub_info_map[index].userData = l_sub_info_map[index].user_data;
        sub_info_map[index].asyncHandler = rbus_cb.sub_ex_async_handler;
        sub_info_map[index].publishOnSubscribe = l_sub_info_map[index].publish_on_sub;
    }

    ret = rbusEvent_SubscribeEx(p_rbus_handle, sub_info_map, num_sub, timeout);

    free(sub_info_map);
    return convert_rbus_to_bus_error_code(ret);
}

bus_error_t bus_event_subscribe_ex_async(bus_handle_t *handle, bus_event_sub_t *l_sub_info_map,
    int num_sub, void *l_sub_handler, int timeout)
{
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;
    rbusEventSubscription_t *sub_info_map;
    rbus_sub_callback_table_t rbus_cb = {0};
    bus_sub_callback_table_t  user_cb;

    if (p_rbus_handle == NULL || l_sub_info_map == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s bus: Input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }

    sub_info_map = calloc(1, num_sub * sizeof(rbusEventSubscription_t));
    if (sub_info_map == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s:%d bus: bus_event_subscribe_ex() calloc is failed\n",
            __func__, __LINE__);
        return bus_error_out_of_resources;
    }

    for (int index = 0; index < num_sub; index++) {
        user_cb.sub_handler = l_sub_info_map[index].handler;
        user_cb.sub_ex_async_handler = l_sub_handler;
        bus_sub_cb_registration((char *)l_sub_info_map[index].event_name, &rbus_cb, &user_cb);
        sub_info_map[index].eventName = l_sub_info_map[index].event_name;
        sub_info_map[index].filter = l_sub_info_map[index].filter;
        sub_info_map[index].interval = l_sub_info_map[index].interval;
        sub_info_map[index].duration = l_sub_info_map[index].duration;
        sub_info_map[index].handler = rbus_cb.sub_handler;
        sub_info_map[index].userData = l_sub_info_map[index].user_data;
        sub_info_map[index].asyncHandler = rbus_cb.sub_ex_async_handler;
        sub_info_map[index].publishOnSubscribe = l_sub_info_map[index].publish_on_sub;
    }

    ret = rbusEvent_SubscribeExAsync(p_rbus_handle, sub_info_map, num_sub, rbus_cb.sub_ex_async_handler, timeout);

    free(sub_info_map);
    return convert_rbus_to_bus_error_code(ret);
}

static bus_error_t bus_reg_table_row(bus_handle_t *handle, char const *name,
    uint32_t row_index, char const *alias)
{
    rbusError_t rc;
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(handle);

    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rc = rbusTable_registerRow(p_rbus_handle, name, row_index, alias);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_BUS, "%s:%d bus: rbusTable_registerRow failed for"
            " [%s] with error [%d] row_index:%d\n", __func__, __LINE__, name, rc, row_index);
    } else {
        if (bus_table_add_row(get_bus_mux_reg_cb_map(), (char *)name, row_index) != bus_error_success) {
            wifi_util_error_print(WIFI_BUS, "%s:%d bus: mux table add failed for"
            " [%s] row_index:%d\n", __func__, __LINE__, name, row_index);
        }
    }

    return convert_rbus_to_bus_error_code(rc);
}

static bus_error_t bus_unreg_table_row(bus_handle_t *handle, char const *name)
{
    rbusError_t rc;
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(handle);

    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rc = rbusTable_unregisterRow(p_rbus_handle, name);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_BUS, "%s:%d bus: rbusTable_unregisterRow failed for"
            " [%s] with error [%d]\n", __func__, __LINE__, name, rc);
    } else {
        if (bus_table_remove_row(get_bus_mux_reg_cb_map(), (char *)name) != bus_error_success) {
            wifi_util_error_print(WIFI_BUS, "%s:%d bus: mux table remove failed for"
            " [%s]\n", __func__, __LINE__, name);
        }
    }

    return convert_rbus_to_bus_error_code(rc);
}

static bus_error_t bus_remove_table_row(bus_handle_t *handle, char const *name)
{
    rbusError_t rc;
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(handle);

    rbusHandle_t p_rbus_handle = handle->u.rbus_handle;

    rc = rbusTable_removeRow(p_rbus_handle, name);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_BUS, "%s:%d bus: rbusTable_removeRow failed for"
            " [%s] with error [%d]\n", __func__, __LINE__, name, rc);
    }

    return convert_rbus_to_bus_error_code(rc);
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
    desc->bus_method_invoke_fn = bus_method_invoke;
    desc->bus_get_trace_context_fn = bus_get_trace_context;
    desc->bus_reg_table_row_fn = bus_reg_table_row;
    desc->bus_unreg_table_row_fn = bus_unreg_table_row;
    desc->bus_remove_table_row_fn = bus_remove_table_row;
}
