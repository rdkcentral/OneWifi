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
#include "wifi_base.h"
#include "wifi_ctrl.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUS_OPEN_TELEMETRY_DATA_MAX 512
static enum dataType_e convert_bus_to_ccsp_data_type(bus_data_type_t type);
static bus_data_type_t convert_ccsp_to_bus_data_type(enum dataType_e type);
static bool server_thread_start = false;
static void analyze_request_or_reply(parameterValStruct1_t **val, DBusMessage *reply);
static void handle_reg_event_handler(char *event_name, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish);

static bus_error_t add_dbus_handlers(bus_handle_t *handle);

void regex_check_for_elements(const char *str, char *modified)
{
    wifi_util_dbg_print(WIFI_BUS, "%s:%d string value =%s\n", __func__, __LINE__, str);
    const char replacement[] = "{i}";
    int i, j = 0;
    char temp[strlen(str) + 1];

    for (i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i])) {
            temp[j++] = str[i];
        } else {
            // Insert the replacement string
            for (int k = 0; replacement[k] != '\0'; k++) {
                temp[j++] = replacement[k];
            }
            // Skip consecutive digits
            while (isdigit(str[i + 1])) {
                i++;
            }
        }
    }
    temp[j] = '\0';
    strcpy(modified, temp);
    wifi_util_dbg_print(WIFI_BUS, "%s:%d modified string value =%s\n", __func__, __LINE__,
        modified);
}
/* Begin type definitions.*/
typedef struct _busOpenTelemetryContext {
    char otTraceParent[BUS_OPEN_TELEMETRY_DATA_MAX];
    char otTraceState[BUS_OPEN_TELEMETRY_DATA_MAX];
} busOpenTelemetryContext;

#define BUS_MIN(a, b) ((a) < (b) ? (a) : (b))

static pthread_once_t _open_telemetry_once = PTHREAD_ONCE_INIT;
static pthread_key_t _open_telemetry_key;
static busOpenTelemetryContext *bus_getOpenTelemetryContextFromThreadLocal();

static wifi_bus_t g_bus;

static hash_map_t *server_desc = NULL;

static pthread_mutex_t dbus_lock;

static void convert_dbus_message_to_raw_data(raw_data_t *data, int type, char *val)
{
    wifi_util_dbg_print(WIFI_BUS, "Enter %s:%d:type=%d\n", __func__, __LINE__, type);
    switch (type) {
        case bus_data_type_boolean:
            bool enabled;
            if (strcmp("true", val) == 0)
                enabled = 1;
            else
                enabled = 0;
            data->raw_data.b = enabled;
        break;

        case bus_data_type_string:
        case bus_data_type_bytes:
            data->raw_data_len = strlen(val);
        break;

        case bus_data_type_uint32:
            int value = 0;
            sscanf((const char *)val, "%d", &value);
            data->raw_data.u32 = (uint32_t)value;
        break;

        default:
            wifi_util_error_print(WIFI_BUS, "%s:%d: bus: Invalid data_type for .\n", __func__, __LINE__);
        break;
    }
    data->data_type = type;
}

static char *convert_raw_data_to_dbus_message(raw_data_t *data, int *type)
{
    char *str = NULL;
    wifi_util_dbg_print(WIFI_BUS, "%s: Enter %d  \n", __func__, __LINE__);
    switch (data->data_type) {
        case bus_data_type_boolean:
            *type = ccsp_boolean;
            str = (char *)malloc(12);
            if (data->raw_data.b)
                strcpy(str, "true");
            else
                strcpy(str, "false");
        break;
        case bus_data_type_string:
            *type = ccsp_string;
            str = (char *)data->raw_data.bytes;
            wifi_util_info_print(WIFI_BUS, "%s: Enter %d str=%s \n", __func__, __LINE__, str);
        break;

        case bus_data_type_bytes:
            *type = ccsp_byte;
            str = (char *)data->raw_data.bytes;
            wifi_util_info_print(WIFI_BUS, "%s: Enter %d str=%s \n", __func__, __LINE__, str);
        break;

        case bus_data_type_uint32:
            *type = ccsp_unsignedInt;
            str = (char *)malloc(12);
            sprintf(str, "%d", data->raw_data.u32);
        break;
        default:
            wifi_util_error_print(WIFI_BUS, "%s:%d: bus: Invalid data_type:%d.\n", __func__, __LINE__,
                data->data_type);
        break;
    };
    return str;
}

// Method handler functions//

DBusHandlerResult method_message_handler(DBusConnection *conn, DBusMessage *message,
    void *user_data)
{
    DBusMessage *reply = NULL;
    bus_handle_t *handle = NULL;
    DBusMessageIter iter = { 0 };
    const char *method_name;
    dbus_int32_t result = 0;
    const char *object_path = dbus_message_get_path(message);
    const char *interface = dbus_message_get_interface(message);
    wifi_util_info_print(WIFI_BUS, "%s:%d object_path =%s and interface= %s\n", __func__, __LINE__,
        object_path, interface);

    handle = (bus_handle_t *)hash_map_get(server_desc, object_path);

    if (!handle) {
        wifi_util_error_print(WIFI_BUS, "handle is NULL returning\n");
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    wifi_util_info_print(WIFI_BUS, "received path= %s  and interface = %s\n", object_path,
        interface);
    // Get the method name from the incoming message
    method_name = dbus_message_get_member(message);
    reply = dbus_message_new_method_return(message);
    if (!reply) {
        wifi_util_error_print(WIFI_BUS, "Out of memory!\n");
        return DBUS_HANDLER_RESULT_NEED_MEMORY;
    }
    if (!strcmp(DBUS_INTERFACE_BASE, interface) && !strcmp("setParameterValues", method_name)) {
        bus_data_type_t type = 0;
        raw_data_t data = { 0 };
        bus_data_element_t *result_element = NULL;
        result = -1;
        char reg_ex_match[256] = "";
        parameterValStruct1_t *val = NULL;
        analyze_request_or_reply(&val, message);
        if (!val || !val->parameterValue) {
            if (val) {
                free(val);
            }
            return DBUS_HANDLER_RESULT_HANDLED;
        }
        wifi_util_info_print(WIFI_BUS, " in set server name= %s  and value =%s\n",
            val->parameterName, val->parameterValue);
        if (val->parameterName && val->parameterValue) {
            wifi_util_info_print(WIFI_BUS, " %s: %d \n", __func__, __LINE__);
            bus_user_data_t *cb_handler = (bus_user_data_t *)handle;
            result_element = (bus_data_element_t *)hash_map_get(handle->method_callback,
                val->parameterName);
            if (result_element == NULL) {
                wifi_util_info_print(WIFI_BUS,
                    "result_element is not found hence trying with regex match in the hashmap\n");
                regex_check_for_elements(val->parameterName, reg_ex_match);
                wifi_util_info_print(WIFI_BUS, "reg_ex_match =%s\n", reg_ex_match);
                result_element = (bus_data_element_t *)hash_map_get(handle->method_callback,
                    reg_ex_match);
            }
            if (result_element != NULL) {
                type = convert_ccsp_to_bus_data_type(val->type);
                wifi_util_info_print(WIFI_BUS,
                    "Param name is available in the handler %s and val=%s bus_type=%d "
                    "bus_registered type=%d\n",
                    val->parameterName, val->parameterValue, type,
                    result_element->data_model_prop.data_format);
                if ((result_element->cb_table.set_handler != NULL) &&
                    (type == result_element->data_model_prop.data_format)) {
                    wifi_util_info_print(WIFI_BUS, "Call back sethandler is present\n");
                    convert_dbus_message_to_raw_data(&data, type, val->parameterValue);
                    if (val->parameterValue != NULL &&
                        (data.data_type == bus_data_type_bytes ||
                            data.data_type == bus_data_type_string)) {
                        wifi_util_info_print(WIFI_BUS, "This is an string value\n");
                        data.raw_data.bytes = (void *)val->parameterValue;
                    }
                    result = result_element->cb_table.set_handler(val->parameterName, &data,
                        cb_handler);
                }
            }
        }
        if (val->parameterValue)
            free(val->parameterValue);

        if (val->parameterName)
            free(val->parameterName);
        if (val)
            free(val);
        dbus_message_iter_init_append(reply, &iter);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &result);
        if (!dbus_connection_send(conn, reply, NULL))
            wifi_util_error_print(WIFI_BUS, "No memory\n");

        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    } else if (!strcmp(DBUS_INTERFACE_BASE, interface) &&
        !strcmp("getParameterValues", method_name)) {
        DBusMessageIter array_iter = { 0 }, struct_iter = { 0 };
        char *parameterNames = 0, *int_str = NULL;
        int type = 0;
        raw_data_t data = { 0 };
        result = -1;
        bus_data_element_t *result_element = NULL;
        char reg_ex_match[256] = "";
        dbus_message_iter_init(message, &iter);
        while (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
            dbus_message_iter_next(&iter);
            wifi_util_info_print(WIFI_BUS, "doing next in %d\n", __LINE__);
        }

        if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY) {
            // Get the array iterator
            dbus_message_iter_recurse(&iter, &array_iter);
            wifi_util_info_print(WIFI_BUS, "Inside array %d\n", __LINE__);

            // Loop through the array elements
            while (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_INVALID) {
                // For each element in the array, we expect a struct

                // Read the first element of the array iterator(string)
                if (dbus_message_iter_get_arg_type(&array_iter) == DBUS_TYPE_STRING) {
                    dbus_message_iter_get_basic(&array_iter, &parameterNames);
                    wifi_util_info_print(WIFI_BUS, "String value: %s\n", parameterNames);
                }
                // Move to the next struct in the array
                dbus_message_iter_next(&array_iter);
            }
        } else {
            wifi_util_info_print(WIFI_BUS, "Expected DBUS_TYP	E_ARRAY, found %d instead.\n",
                dbus_message_iter_get_arg_type(&iter));
        }
        if (parameterNames) {
            bus_user_data_t *cb_handler = (bus_user_data_t *)handle;
            result_element = (bus_data_element_t *)hash_map_get(handle->method_callback,
                parameterNames);
            if (result_element == NULL) {
                wifi_util_info_print(WIFI_BUS,
                    "result_element is not found hence trying with regex match in the hashmap\n");
                regex_check_for_elements(parameterNames, reg_ex_match);
                wifi_util_info_print(WIFI_BUS, "reg_ex_match =%s\n", reg_ex_match);
                result_element = (bus_data_element_t *)hash_map_get(handle->method_callback,
                    reg_ex_match);
            }
            if (result_element != NULL) {
                wifi_util_info_print(WIFI_BUS, "Param name is available in the handler\n");
                if (result_element->cb_table.get_handler != NULL) {
                    wifi_util_info_print(WIFI_BUS, "Call back gethandler is present\n");
                    result = result_element->cb_table.get_handler(parameterNames, &data,
                        cb_handler);
                }
            }
        } else {
            dbus_message_iter_init_append(reply, &iter);
            if (!dbus_connection_send(conn, reply, NULL))
                wifi_util_error_print(WIFI_BUS, "<%s> No memory\n", __func__);

            dbus_connection_flush(conn);
            dbus_message_unref(reply);
            return DBUS_HANDLER_RESULT_HANDLED;
        }

        wifi_util_dbg_print(WIFI_BUS, "%s:%d result = %d\n", __func__, __LINE__, result);
        dbus_message_iter_init_append(reply, &iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssi)", &array_iter);

        if (result == 0) {
            wifi_util_info_print(WIFI_BUS, "%s:%d result = %d\n", __func__, __LINE__, result);
            int_str = convert_raw_data_to_dbus_message(&data, &type);
            dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
            wifi_util_info_print(WIFI_BUS, " %s:%d int_str=%s and type=%d\n", __func__, __LINE__,
                int_str, type);
            DBUS_MESSAGE_APPEND_CSTRING(&struct_iter, parameterNames);
            dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &int_str);
            dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_INT32, &type);
            dbus_message_iter_close_container(&array_iter, &struct_iter);
        }
        dbus_message_iter_close_container(&iter, &array_iter);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &result);
        if (!dbus_connection_send(conn, reply, NULL))
            wifi_util_info_print(WIFI_BUS, "<%s> No memory\n", __func__);
        if (int_str) {
            wifi_util_error_print(WIFI_BUS, "%s:%d\n", __func__, __LINE__);
            free(int_str);
        }
        dbus_connection_flush(conn);
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    } else if (!strcmp(DBUS_INTERFACE_BASE, interface) &&
        ((!strcmp("AddTblRow", method_name)) || (!strcmp("DeleteTblRow", method_name)))) {
        uint32_t *instanceNumber = 0;
        char *table_name = NULL;
        bus_data_element_t *result_element = NULL;
        char reg_ex_match[256] = "";

        dbus_message_iter_init(message, &iter);

        if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
            dbus_message_iter_get_basic(&iter, &table_name);
        }
        dbus_message_iter_next(&iter);
        if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_INT32) {
            dbus_message_iter_get_basic(&iter, &instanceNumber);
        }
        if (table_name) {
            result_element = (bus_data_element_t *)hash_map_get(handle->method_callback,
                table_name);
            if (result_element == NULL) {
                wifi_util_info_print(WIFI_BUS,
                    "result_element is not found hence trying with regex match in the hashmap\n");
                regex_check_for_elements(table_name, reg_ex_match);
                wifi_util_info_print(WIFI_BUS, "reg_ex_match =%s\n", reg_ex_match);
                result_element = (bus_data_element_t *)hash_map_get(handle->method_callback,
                    reg_ex_match);
            }
            if (result_element != NULL) {
                wifi_util_info_print(WIFI_BUS, "Param name is available in the handler\n");
                if (!strcmp("AddTblRow", method_name) &&
                    (result_element->cb_table.table_add_row_handler != NULL)) {
                    wifi_util_info_print(WIFI_BUS, "Call back AddTblRow is present\n");
                    result = result_element->cb_table.table_add_row_handler(table_name, NULL,
                        instanceNumber);
                } else if (!strcmp("DeleteTblRow", method_name) &&
                    (result_element->cb_table.table_remove_row_handler != NULL)) {
                    wifi_util_info_print(WIFI_BUS,
                        "Call back table_remove_row_handler is present\n");
                    result = result_element->cb_table.table_remove_row_handler(table_name);
                }
            }
        } else {
            dbus_message_iter_init_append(reply, &iter);
            wifi_util_error_print(WIFI_BUS, "<%s :%d> no parameter\n", __func__, __LINE__);
            if (!dbus_connection_send(conn, reply, NULL))
                wifi_util_error_print(WIFI_BUS, "<%s> No memory\n", __func__);

            dbus_connection_flush(conn);
            dbus_message_unref(reply);
            return DBUS_HANDLER_RESULT_HANDLED;
        }
        dbus_message_iter_init_append(reply, &iter);
        if (!strcmp("AddTblRow", method_name))
            dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &instanceNumber);

        dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &result);
        if (!dbus_connection_send(conn, reply, NULL))
            wifi_util_error_print(WIFI_BUS, "No memory\n");

        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    } else if (!strcmp(DBUS_INTERFACE_BASE, interface) && !strcmp("eventHandler", method_name)) {
        char *event_name = NULL, *input = NULL;
        bool flag = false;
        wifi_util_info_print(WIFI_BUS, "eventHandler received\n");
        dbus_message_iter_init(message, &iter);
        if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
            dbus_message_iter_get_basic(&iter, &event_name);
            wifi_util_info_print(WIFI_BUS, "eventHandler received event_name =%s\n", event_name);

            dbus_message_iter_next(&iter);

            if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_STRING) {
                dbus_message_iter_get_basic(&iter, &input);
            }
        }
        if (event_name && input) {
            if (strcmp(input, "bus_event_action_subscribe") == 0) {
                handle_reg_event_handler(event_name, bus_event_action_subscribe, 0, &flag);
            } else {
                handle_reg_event_handler(event_name, bus_event_action_unsubscribe, 0, &flag);
            }
        }
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    } else if (!strcmp(DBUS_INTERFACE_BASE, interface) && !strcmp("OneWifiMethod", method_name)) {
        raw_data_t inParams = { 0 }, outParams = { 0 };
        DBusMessageIter array_iter = { 0 }, struct_iter = { 0 };
        char *int_str = NULL;
        int type1 = 0;
        bus_data_type_t type;
        bus_data_element_t *result_element = NULL;
        int result = -1;
        char reg_ex_match[256] = "";
        parameterValStruct1_t *val = NULL;
        wifi_util_info_print(WIFI_BUS, " here in OnewifiMethod\n");
        analyze_request_or_reply(&val, message);
        if (!val || !val->parameterValue || !val->parameterName) {
            if (val) {
                wifi_util_info_print(WIFI_BUS, " %s:%d\n", __func__, __LINE__);
                free(val);
            }
            wifi_util_info_print(WIFI_BUS, "Request doesnt have value\n");
            dbus_message_iter_init_append(reply, &iter);
            if (!dbus_connection_send(conn, reply, NULL))
                wifi_util_info_print(WIFI_BUS, "<%s> No memory\n", __func__);

            dbus_connection_flush(conn);
            dbus_message_unref(reply);
            return DBUS_HANDLER_RESULT_HANDLED;
        }
        wifi_util_info_print(WIFI_BUS, " in handling OneWifiMethod name= %s  and value =%s\n",
            val->parameterName, val->parameterValue);
        if (val->parameterName && val->parameterValue) {
            wifi_util_info_print(WIFI_BUS, " %s: %d \n", __func__, __LINE__);
            bus_user_data_t *cb_handler = (bus_user_data_t *)handle;
            result_element = (bus_data_element_t *)hash_map_get(handle->method_callback,
                val->parameterName);
            if (result_element == NULL) {
                wifi_util_info_print(WIFI_BUS,
                    "result_element is not found hence trying with regex match in the hashmap\n");
                regex_check_for_elements(val->parameterName, reg_ex_match);
                wifi_util_info_print(WIFI_BUS, "reg_ex_match =%s\n", reg_ex_match);
                result_element = (bus_data_element_t *)hash_map_get(handle->method_callback,
                    reg_ex_match);
            }
            if (result_element != NULL) {
                type = convert_ccsp_to_bus_data_type(val->type);
                wifi_util_info_print(WIFI_BUS,
                    "Param name is available in the handler %s and val=%s bus_type=%d "
                    "bus_registered type=%d\n",
                    val->parameterName, val->parameterValue, type,
                    result_element->data_model_prop.data_format);
                if ((result_element->cb_table.method_handler != NULL) &&
                    (type == result_element->data_model_prop.data_format)) {
                    wifi_util_info_print(WIFI_BUS, "Call back method is present\n");
                    convert_dbus_message_to_raw_data(&inParams, type, val->parameterValue);
                    if (val->parameterValue != NULL &&
                        (inParams.data_type == bus_data_type_bytes ||
                            inParams.data_type == bus_data_type_string)) {
                        wifi_util_info_print(WIFI_BUS, "This is an string value\n");
                        inParams.raw_data.bytes = (void *)val->parameterValue;
                    }
                    result = result_element->cb_table.method_handler(val->parameterName, &inParams,
                        &outParams, cb_handler);
                }
            }
        } else {
            dbus_message_iter_init_append(reply, &iter);
            if (!dbus_connection_send(conn, reply, NULL))
                wifi_util_error_print(WIFI_BUS, "<%s> No memory\n", __func__);

            dbus_connection_flush(conn);
            dbus_message_unref(reply);
            return DBUS_HANDLER_RESULT_HANDLED;
        }
        wifi_util_info_print(WIFI_BUS, "%s:%d result = %d\n", __func__, __LINE__, result);
        dbus_message_iter_init_append(reply, &iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssi)", &array_iter);

        if (result == 0) {
            int_str = convert_raw_data_to_dbus_message(&outParams, &type1);
            dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
            wifi_util_info_print(WIFI_BUS, " %s:%d int_str=%s and type=%d\n", __func__, __LINE__,
                int_str, type1);
            DBUS_MESSAGE_APPEND_CSTRING(&struct_iter, val->parameterName);
            dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &int_str);
            dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_INT32, &type1);
            dbus_message_iter_close_container(&array_iter, &struct_iter);
        }
        dbus_message_iter_close_container(&iter, &array_iter);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &result);
        if (!dbus_connection_send(conn, reply, NULL))
            wifi_util_error_print(WIFI_BUS, "No memory\n");

        if (int_str) {
            free(int_str);
        }

        dbus_connection_flush(conn);
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    return DBUS_HANDLER_RESULT_HANDLED;
}

bus_error_t send_reg_event_handler(bus_handle_t *handle, char const *event_name,
    bus_event_sub_action_t action, int32_t interval, bool *autoPublish)
{
    bus_error_t rc = bus_error_success;
    char *dbus_path = NULL, *dst_component_id = NULL;
    DBusMessage *message;
    char *input = NULL;
    DBusMessageIter iter;
    DBusError dbus_error;
    dbus_error_init(&dbus_error);

    VERIFY_NULL_WITH_RC(event_name);
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;

    if (!p_dbus_handle) {
        wifi_util_error_print(WIFI_BUS, "bus handler is not valid\n");
        return bus_error_invalid_input;
    }
    rc = find_destination_path(handle, event_name, &dbus_path, &dst_component_id);

    wifi_util_dbg_print(WIFI_BUS, "%s: at %d dbus_path=%s and dst_component_id=%s\n", __func__,
        __LINE__, dbus_path, dst_component_id);
    if ((rc != bus_error_success) || !dbus_path || !dst_component_id) {
        wifi_util_error_print(WIFI_BUS, "Destination component not found\n");
        return bus_error_invalid_input;
    }
    if (action == bus_event_action_subscribe) {
        wifi_util_info_print(WIFI_BUS, "action is event subscribe\n");
        input = "bus_event_action_subscribe";
    } else {
        wifi_util_info_print(WIFI_BUS, "action is event subscribe\n");
        input = "bus_event_action_unsubscribe";
    }
    message = dbus_message_new_method_call(dst_component_id, dbus_path, DBUS_INTERFACE_BASE,
        "eventHandler");

    if (!message) {
        wifi_util_error_print(WIFI_BUS, "No memory\n");
        return bus_error_out_of_resources;
    }

    dbus_message_iter_init_append(message, &iter);
    DBUS_MESSAGE_APPEND_CSTRING(&iter, event_name);
    dbus_message_append_args(message, DBUS_TYPE_STRING, &input, DBUS_TYPE_INVALID);

    if (!dbus_connection_send(p_dbus_handle, message, NULL))
        wifi_util_error_print(WIFI_BUS, "No memory\n");

    dbus_connection_flush(p_dbus_handle);
    dbus_message_unref(message);
    free(dbus_path);
    free(dst_component_id);
    return bus_error_success;
}

static void handle_reg_event_handler(char *event_name, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    bus_handle_t *handle;

    handle = (bus_handle_t *)hash_map_get_first(server_desc);
    while (handle != NULL) {
        bus_data_element_t *result_element = NULL;
        result_element = (bus_data_element_t *)hash_map_get(handle->method_callback, event_name);
        if (result_element != NULL) {
            if (result_element->cb_table.event_sub_handler != NULL) {
                wifi_util_info_print(WIFI_BUS, "Call back event handler is present\n");
                result_element->cb_table.event_sub_handler(event_name, action, interval,
                    autoPublish);
            }
        }
        handle = hash_map_get_next(server_desc, handle);
    }
}
static bus_error_t add_subscription_to_dbus_daemon(bus_handle_t *handle, const char *event_name)
{
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    char tmp[512] = { 0 };

    snprintf(tmp, sizeof(tmp), "type='signal',path='%s',interface='%s',member='%s'",
        DBUS_PATH_EVENT, DBUS_INTERFACE_EVENT, event_name);
    wifi_util_dbg_print(WIFI_BUS, "Match added to %s\n", tmp);
    dbus_bus_add_match(p_dbus_handle, tmp, NULL);
    dbus_connection_flush(p_dbus_handle);
    return bus_error_success;
}

bus_error_t remove_subscriber_events(bus_handle_t *handle, char const *event_name)
{
    bus_sub_callback_table_t *callback;
    callback = (bus_sub_callback_table_t *)hash_map_get(handle->subscribe_callback, event_name);
    if (callback != NULL) {
        pthread_mutex_lock(&dbus_lock);
        callback = hash_map_remove(handle->subscribe_callback, event_name);
        if (callback != NULL) {
            free(callback);
        }
        pthread_mutex_unlock(&dbus_lock);
        wifi_util_info_print(WIFI_BUS, "%s:Global bus updated %d\n", __func__, __LINE__);
    }
    return bus_error_success;
}

bus_error_t append_subscriber_events(bus_handle_t *handle, void *cb, char const *event_name)
{
    wifi_util_info_print(WIFI_BUS, "%s:Enter %d event_name =%s\n", __func__, __LINE__, event_name);
    bus_sub_callback_table_t *callback;
    pthread_mutex_lock(&dbus_lock);
    if ((callback = (bus_sub_callback_table_t *)hash_map_get(handle->subscribe_callback,
             event_name)) == NULL) {
        callback = (bus_sub_callback_table_t *)malloc(sizeof(bus_sub_callback_table_t));
        callback->sub_handler = cb;
        hash_map_put(handle->subscribe_callback, strdup(event_name), callback);
    }
    pthread_mutex_unlock(&dbus_lock);
    wifi_util_info_print(WIFI_BUS, "%s:Global bus updated %d\n", __func__, __LINE__);
    return bus_error_success;
}

bus_error_t remove_method_callback(bus_handle_t *handle, bus_data_element_t *element)
{
    wifi_util_info_print(WIFI_BUS, "%s:Enter %d fullname =%s\n", __func__, __LINE__,
        element->full_name);
    bus_data_element_t *result_element;
    result_element = (bus_data_element_t *)hash_map_get(handle->method_callback,
        element->full_name);
    if (result_element != NULL) {
        pthread_mutex_lock(&dbus_lock);

        result_element = hash_map_remove(handle->method_callback, element->full_name);
        if (result_element != NULL) {
            free(result_element);
        }
        pthread_mutex_unlock(&dbus_lock);
    }
    return bus_error_success;
}

bus_error_t append_method_callback(bus_handle_t *handle, bus_data_element_t *element)
{

    bus_data_element_t *result_element;
    pthread_mutex_lock(&dbus_lock);
    if ((result_element = (bus_data_element_t *)hash_map_get(handle->method_callback,
             element->full_name)) == NULL) {
        result_element = (bus_data_element_t *)malloc(sizeof(bus_data_element_t));
        memcpy(result_element, element, sizeof(bus_data_element_t));
        hash_map_put(handle->method_callback, strdup(element->full_name), result_element);
    }
    pthread_mutex_unlock(&dbus_lock);
    return bus_error_success;
}

void handle_signal_message(DBusConnection *connection, char *event_name, int type, char *val)
{
    wifi_util_info_print(WIFI_BUS, "%s:Enter %d event_name =%s connection=%p\n", __func__, __LINE__,
        event_name, connection);
    bus_sub_callback_table_t *callback = NULL;
    bus_handle_t *handle;
    char reg_ex_match[256] = "";
    raw_data_t data = { 0 };
    handle = (bus_handle_t *)hash_map_get_first(server_desc);
    while (handle != NULL) {
        if (handle->u.dbus_handle == connection) {
            callback = (bus_sub_callback_table_t *)hash_map_get(handle->subscribe_callback,
                event_name);
            if (callback == NULL) {
                wifi_util_info_print(WIFI_BUS,
                    "result_element is not found hence trying with regex match in the hashmap\n");
                regex_check_for_elements(event_name, reg_ex_match);
                wifi_util_info_print(WIFI_BUS, "reg_ex_match =%s\n", reg_ex_match);
                callback = (bus_sub_callback_table_t *)hash_map_get(handle->subscribe_callback,
                    reg_ex_match);
            }
            if (callback != NULL) {
                type = convert_ccsp_to_bus_data_type(type);
                wifi_util_info_print(WIFI_BUS,
                    "%s:Enter %d got subscription handler for =%s for handle=%p type=%d\n",
                    __func__, __LINE__, event_name, handle->u.dbus_handle, type);
                convert_dbus_message_to_raw_data(&data, type, val);
                if (val != NULL &&
                    (data.data_type == bus_data_type_bytes ||
                        data.data_type == bus_data_type_string)) {
                    wifi_util_info_print(WIFI_BUS, "%s:%d This is an string value\n", __func__,
                        __LINE__);
                    data.raw_data.bytes = (void *)val;
                }
                callback->sub_handler(event_name, &data, handle);
            }
        }
        handle = hash_map_get_next(server_desc, handle);
    }
}

// Signal handler function for signals
DBusHandlerResult signal_handler(DBusConnection *connection, DBusMessage *msg, void *user_data)
{
    DBusMessageIter args;
    char *event_name = NULL;
    char *sigValue = NULL;
    int type = 0;
    int msg_type = dbus_message_get_type(msg);
    switch (msg_type) {
        case DBUS_MESSAGE_TYPE_SIGNAL:
            const char *signal = dbus_message_get_member(msg);
            if (strcmp(signal, "OneWifi") == 0) {
                if (dbus_message_iter_init(msg, &args)) {
                    if (dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_STRING) {
                        dbus_message_iter_get_basic(&args, &event_name);
                        wifi_util_info_print(WIFI_BUS, "Received string 1: %s\n", event_name);
                        dbus_message_iter_next(&args);
                        if (dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_INT32) {
                            dbus_message_iter_get_basic(&args, &type);
                            wifi_util_info_print(WIFI_BUS, "Received type: %d\n", type);
                        }
                        dbus_message_iter_next(&args);
                        if (dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_STRING) {
                            dbus_message_iter_get_basic(&args, &sigValue);
                            wifi_util_info_print(WIFI_BUS, "Received string 2: \n");
                        }
                    }
                }
            } else if (strcmp(signal, "TunnelStatus") == 0) {
                if (dbus_message_iter_init(msg, &args)) {
                    if (dbus_message_iter_get_arg_type(&args) == DBUS_TYPE_STRING) {
                        dbus_message_iter_get_basic(&args, &sigValue);
                        event_name = "Device.X_COMCAST-COM_GRE.Tunnel.1.TunnelStatus";
                        wifi_util_info_print(WIFI_BUS, "Received string: %s\n", sigValue);
                        type = ccsp_string;
                    }
                }
            }
            if ((event_name != NULL) && (sigValue != NULL)) {
                wifi_util_info_print(WIFI_BUS, "Received an event =%s\n", event_name);
                handle_signal_message(connection, event_name, type, sigValue);
                return DBUS_HANDLER_RESULT_HANDLED;
            }
        break;

        case DBUS_MESSAGE_TYPE_METHOD_CALL:
            wifi_util_info_print(WIFI_BUS, "Got method handler\n");
        break;

        default:
            wifi_util_info_print(WIFI_BUS, "In default case\n");
        break;
    }
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void *server_loop_thread(void *)
{
    bus_handle_t *handle;
    int rc = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_lock(&mutex);
    // loop listening for signals being emmitted
    while (true) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);

        // Add 1 millisecond (1,000,000 nanoseconds) to current time
        ts.tv_nsec += 50000000; // 1 ms in nanoseconds
        if (ts.tv_nsec >= 1000000000) { // Handle nanosecond overflow
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }
        rc = pthread_cond_timedwait(&cond, &mutex, &ts);
        if (rc == ETIMEDOUT || rc == 0) {
            handle = (bus_handle_t *)hash_map_get_first(server_desc);
            while (handle != NULL) {
                // non blocking read of the next available message
                if (dbus_connection_read_write_dispatch(handle->u.dbus_handle, 0)) {
                    // Keep processing the incoming messages
                }
                handle = hash_map_get_next(server_desc, handle);
            }
        }
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}
static bus_error_t check_dbus_handlers(bus_handle_t *handle, char *dbus_path)
{
    bus_handle_t *server = NULL;
    if (server_desc == NULL) {
        wifi_util_error_print(WIFI_BUS, "server_desc is null\n");
        return bus_error_success;
    }
    if (handle == NULL) {
        // Handle the error
        return bus_error_success;
    }
    server = (bus_handle_t *)hash_map_get(server_desc, dbus_path);
    if (server == NULL) {
        wifi_util_error_print(WIFI_BUS, "This component is not present hence can add\n");
        return bus_error_success;
    }
    wifi_util_info_print(WIFI_BUS, "Giving handler to the caller handler = %p\n",
        server->u.dbus_handle);
    handle = server;
    return bus_error_general;
}

/* Add subscribe handlers and server handlers to server_desc[]*/
static bus_error_t add_dbus_handlers(bus_handle_t *handle)
{
    int ret;
    pthread_t dbus_thread;
    pthread_attr_t attr;
    bus_handle_t *server = NULL;
    wifi_util_info_print(WIFI_BUS, "%s:Enter %d and dbus_path =%s\n", __func__, __LINE__,
        handle->dbus_path);

    if (server_desc == NULL) {
        server_desc = hash_map_create();
        server_thread_start = true;
    }

    pthread_mutex_lock(&dbus_lock);
    server = (bus_handle_t *)hash_map_get(server_desc, handle->dbus_path);
    if (server == NULL) {
        wifi_util_info_print(WIFI_BUS, "%s: server is not added %d\n", __func__, __LINE__);
        server = (bus_handle_t *)malloc(sizeof(bus_handle_t));
        memcpy(server, handle, sizeof(bus_handle_t));
        hash_map_put(server_desc, strdup(handle->dbus_path), server);
    } else {
        wifi_util_info_print(WIFI_BUS, "%s: server is already present hence modifying %d:%s\n",
            __func__, __LINE__, handle->dbus_path);
        server = hash_map_remove(server_desc, handle->dbus_path);
        if (server != NULL) {
            free(server);
        }
        server = (bus_handle_t *)malloc(sizeof(bus_handle_t));
        memcpy(server, handle, sizeof(bus_handle_t));
        hash_map_put(server_desc, strdup(handle->dbus_path), server);
    }

    pthread_mutex_unlock(&dbus_lock);

    if (server_thread_start) {
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        ret = pthread_create(&dbus_thread, &attr, server_loop_thread, NULL);
        if (ret != 0) {
            wifi_util_error_print(WIFI_BUS,
                "%s:%d failed to create server_loop_thread, "
                "err %d (%s)\n",
                __func__, __LINE__, ret, strerror(ret));
            pthread_attr_destroy(&attr);
            return bus_error_general;
        }
        server_thread_start = false;
    }
    return bus_error_success;
}

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

void free_raw_data_struct(raw_data_t *p_data)
{
    if ((p_data->data_type == bus_data_type_string || p_data->data_type == bus_data_type_bytes) &&
        p_data->raw_data.bytes != NULL) {
        free(p_data->raw_data.bytes);
        p_data->raw_data.bytes = NULL;
    }
}

bus_error_t bus_init(bus_handle_t *handle)
{
    (void)handle;
    bus_error_t rc = bus_error_success;

    wifi_bus_desc_t *p_bus_desc = NULL;
    // dbus_threads_init_default() will make the application thread safe from dbus perspective.
    dbus_threads_init_default();
    p_bus_desc = get_bus_descriptor();
    memset(p_bus_desc, 0, sizeof(wifi_bus_desc_t));

    rdkb_bus_desc_init(p_bus_desc);
    wifi_util_info_print(WIFI_BUS, "%s:%d: bus: bus_init() is successful.\n", __func__, __LINE__);
    return rc;
}

static void bus_init_open_telemetry_thread_specific_key()
{
    wifi_util_info_print(WIFI_BUS, "%s:%d\n", __func__, __LINE__);
    pthread_key_create(&_open_telemetry_key, free);
}

busOpenTelemetryContext *bus_getOpenTelemetryContextFromThreadLocal()
{
    pthread_once(&_open_telemetry_once, &bus_init_open_telemetry_thread_specific_key);

    wifi_util_info_print(WIFI_BUS, "%s:%d\n", __func__, __LINE__);
    busOpenTelemetryContext *ot_ctx = (busOpenTelemetryContext *)pthread_getspecific(
        _open_telemetry_key);
    if (!ot_ctx) {
        ot_ctx = malloc(sizeof(busOpenTelemetryContext));
        if (ot_ctx) {
            memset(ot_ctx->otTraceParent, 0, sizeof(ot_ctx->otTraceParent));
            memset(ot_ctx->otTraceState, 0, sizeof(ot_ctx->otTraceState));
            pthread_setspecific(_open_telemetry_key, ot_ctx);
        }
    }
    wifi_util_info_print(WIFI_BUS, "%s:%d: Trace parent : %s state : %s\n", __func__, __LINE__,
        ot_ctx->otTraceParent, ot_ctx->otTraceState);

    return ot_ctx;
}

void bus_releaseOpenTelemetryContext()
{
    busOpenTelemetryContext *ot_ctx = bus_getOpenTelemetryContextFromThreadLocal();
    if (ot_ctx) {
        pthread_setspecific(_open_telemetry_key, NULL);
        free(ot_ctx);
        ot_ctx = NULL;
    }
}

void bus_getOpenTelemetryContext(const char **traceParent, const char **traceState)
{
    busOpenTelemetryContext *ot_ctx = bus_getOpenTelemetryContextFromThreadLocal();

    *traceParent = &ot_ctx->otTraceParent[0];
    *traceState = &ot_ctx->otTraceState[0];
    wifi_util_info_print(WIFI_BUS,
        "%s:%d: Trace parent : %s state : %s output Trace parent : %s state : %s\n", __func__,
        __LINE__, ot_ctx->otTraceParent, ot_ctx->otTraceState, *traceParent, *traceState);
}

void bus_setOpenTelemetryContext(const char *traceParent, const char *traceState)
{
    busOpenTelemetryContext *ot_ctx = bus_getOpenTelemetryContextFromThreadLocal();

    if (traceParent) {
        size_t tpLen = strlen(traceParent);
        if ((tpLen > 0) && (tpLen < (BUS_OPEN_TELEMETRY_DATA_MAX - 1))) {
            memset(ot_ctx->otTraceParent, '\0', sizeof(ot_ctx->otTraceParent));
            strncpy(ot_ctx->otTraceParent, traceParent, tpLen);
            ot_ctx->otTraceParent[tpLen + 1] = '\0';
        } else
            ot_ctx->otTraceParent[0] = '\0';
    } else
        ot_ctx->otTraceParent[0] = '\0';

    if (traceState) {
        size_t tsLen = strlen(traceState);
        if ((tsLen > 0) && (tsLen < (BUS_OPEN_TELEMETRY_DATA_MAX - 1))) {
            memset(ot_ctx->otTraceState, '\0', sizeof(ot_ctx->otTraceState));
            strncpy(ot_ctx->otTraceState, traceState, tsLen);
            ot_ctx->otTraceState[tsLen + 1] = '\0';
        } else
            ot_ctx->otTraceState[0] = '\0';
    } else
        ot_ctx->otTraceState[0] = '\0';
}

static bus_error_t bus_set_trace_context(bus_handle_t *handle, const char *traceParent,
    const char *traceState)
{
    if (!handle)
        return bus_error_general;

    bus_setOpenTelemetryContext(traceParent, traceState);

    return bus_error_success;
}
static bus_error_t bus_open(bus_handle_t *handle, char *component_name)
{
    VERIFY_NULL_WITH_RC(component_name);
    DBusError dbus_error;
    dbus_error_init(&dbus_error);
    int ret = -1;
    void *user_data = NULL;
    bus_error_t rc;

    snprintf(handle->dbus_path, sizeof(handle->dbus_path), DBUS_COMP_PATH, component_name);
    snprintf(handle->component_name, sizeof(handle->component_name), DBUS_COMP_NAME,
        component_name);
    rc = check_dbus_handlers(handle, handle->dbus_path);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_BUS, "the handler is %p\n", handle->u.dbus_handle);
        return bus_error_success;
    }
    handle->u.dbus_handle = dbus_bus_get_private(DBUS_BUS_SYSTEM, &dbus_error);
    if (dbus_error_is_set(&dbus_error)) {
        wifi_util_error_print(WIFI_BUS, "dbus_bus_get failed with %s\n", dbus_error.message);
        return bus_error_general;
    }

    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    if (!p_dbus_handle)
        return bus_error_general;
 
    wifi_util_info_print(WIFI_BUS, "%s:%d dbus_bus_request_name  with  comp_name %s:%s\n", __func__,
        __LINE__, handle->component_name, handle->dbus_path);
    // Get a well known name
    ret = dbus_bus_request_name(p_dbus_handle, handle->component_name,
        DBUS_NAME_FLAG_REPLACE_EXISTING, &dbus_error);
    if (dbus_error_is_set(&dbus_error)) {
        dbus_error_free(&dbus_error);
        wifi_util_error_print(WIFI_BUS, "%s:%d dbus_bus_request_name failed with  %s:%d\n", __func__,
            __LINE__, dbus_error.message, ret);
        return bus_error_component_name_duplicate;
    }

    if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        wifi_util_error_print(WIFI_BUS, "Dbus: not primary owner, ret = %d\n", ret);
        return bus_error_general;
    }

    // Register object path to handle methods asynchronously.
    handle->comp_vtable.message_function = method_message_handler;
    if (!dbus_connection_register_object_path(p_dbus_handle, handle->dbus_path,
            &handle->comp_vtable, &user_data)) {
        wifi_util_error_print(WIFI_BUS, "Failed to register object path\n");
        return -1;
    }

    // Add a filter to handle signals
    dbus_connection_add_filter(p_dbus_handle, signal_handler, NULL, NULL);

    handle->subscribe_callback = hash_map_create();
    if (handle->subscribe_callback == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s:%d subscribe_callback falied\r\n", __func__, __LINE__);
        return bus_error_general;
    }

    handle->method_callback = hash_map_create();
    if (handle->method_callback == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s:%d method_callback falied\r\n", __func__, __LINE__);
        return bus_error_general;
    }
    add_dbus_handlers(handle);
    wifi_util_info_print(WIFI_BUS, "%s:%d:  bus_open() is successful for component:%s, \
       ret:%d, handle:%p\n",
        __func__, __LINE__, component_name, ret, p_dbus_handle);
    return bus_error_success;
}
static bus_error_t bus_close(bus_handle_t *handle)
{
    bus_handle_t *elem;

    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    if (!p_dbus_handle) {
        wifi_util_error_print(WIFI_BUS, "dbus handler is NULL %s: %d\n", __func__, __LINE__);
        return bus_error_general;
    }
    dbus_connection_close(p_dbus_handle);
    dbus_connection_unref(p_dbus_handle);

    if (handle->subscribe_callback != NULL)
        hash_map_destroy(handle->subscribe_callback);

    if (handle->method_callback != NULL)
        hash_map_destroy(handle->method_callback);

    elem = hash_map_remove(server_desc, handle->dbus_path);
    if (elem != NULL) {
        free(elem);
    }
    wifi_util_info_print(WIFI_BUS, "bus_close is successfull\n");
    return bus_error_success;
}

static bus_error_t bus_get_trace_context(bus_handle_t *handle, char *traceParent,
    uint32_t traceParentLength, char *traceState, uint32_t traceStateLength)
{
    size_t n;
    char const *parent = NULL;
    char const *state = NULL;

    bus_getOpenTelemetryContext(&parent, &state);

    if (traceParent) {
        if (parent) {
            n = BUS_MIN(strlen(parent), traceParentLength - 1);
            strncpy(traceParent, parent, n);
            traceParent[n] = '\0';
        } else
            traceParent[0] = '\0';
    }
    wifi_util_info_print(WIFI_BUS, "%s:%d traceparent : %s\n", __func__, __LINE__, traceParent);

    if (traceState) {
        if (state) {
            n = BUS_MIN(strlen(state), traceStateLength - 1);
            strncpy(traceState, state, n);
            traceState[n] = '\0';
        } else
            traceState[0] = '\0';
    }
    wifi_util_info_print(WIFI_BUS, "%s:%d traceState : %s\n", __func__, __LINE__, traceState);

    return bus_error_success;
}

int handle_namespace_with_cr(bus_handle_t *handle, const char *subsystem_prefix,
    name_spaceType1_t *name_space, int size, bool sub_register

)
{
    DBusMessage *message, *reply = NULL;
    dbus_int32_t res, tmp;
    int ret = -1;
    int component_version = 1;
    DBusMessageIter iter, array_iter, struct_iter;
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    const char *comp_name = handle->component_name;
    const char *path = handle->dbus_path;
    DBusError dbus_error;
    dbus_error_init(&dbus_error);

    if (sub_register) {
        wifi_util_info_print(WIFI_BUS, "%s: at %d\n", __func__, __LINE__);
        message = dbus_message_new_method_call(CCSP_CR_COMPONENT_ID, CCSP_DBUS_PATH_CR,
            CCSP_DBUS_INTERFACE_CR, "registerCapabilities");
    } else {
        wifi_util_info_print(WIFI_BUS, "%s: at %d\n", __func__, __LINE__);
        message = dbus_message_new_method_call(CCSP_CR_COMPONENT_ID, CCSP_DBUS_PATH_CR,
            CCSP_DBUS_INTERFACE_CR, "unregisterNamespace");
    }
    if (!message) {
        wifi_util_error_print(WIFI_BUS, "No memory\n");
        return bus_error_general;
    }
    dbus_message_iter_init_append(message, &iter);
    if (sub_register) {
        wifi_util_info_print(WIFI_BUS, "%s: at %d component_name =%s:%s:%s\n", __func__, __LINE__,
            handle->component_name, handle->dbus_path, subsystem_prefix);
        DBUS_MESSAGE_APPEND_CSTRING(&iter, comp_name);

        dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &component_version);
        DBUS_MESSAGE_APPEND_CSTRING(&iter, path);
        DBUS_MESSAGE_APPEND_CSTRING(&iter, subsystem_prefix);

        ret = dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(si)", &array_iter);

        for (int i = 0; i < size; i++) {
            dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, "si", &struct_iter);

            DBUS_MESSAGE_APPEND_CSTRING(&struct_iter, name_space[i].name_space);
            tmp = name_space[i].dataType;
            ret = dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_INT32, &tmp);

            dbus_message_iter_close_container(&array_iter, &struct_iter);
        }

        ret = dbus_message_iter_close_container(&iter, &array_iter);

        tmp = size;
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &tmp);
    } else {
        DBUS_MESSAGE_APPEND_CSTRING(&iter, handle->component_name);
        DBUS_MESSAGE_APPEND_CSTRING(&iter, name_space[0].name_space);
        wifi_util_info_print(WIFI_BUS, "%s: at %d\n", __func__, __LINE__);
    }
    reply = dbus_connection_send_with_reply_and_block(p_dbus_handle, message, -1, &dbus_error);

    // Get the reply message

    if (reply == NULL) {
        wifi_util_error_print(WIFI_BUS, "Reply Null\n");
        dbus_message_unref(message);
        return bus_error_destination_response_failure;
    }

    if (reply) {
        DBusMessageIter iter;
        dbus_message_iter_init(reply, &iter);

        if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_INT32) {
            dbus_message_iter_get_basic(&iter, &res);
            ret = res;
        }

        dbus_message_unref(reply);
    }
    dbus_message_unref(message);
    return ret;
}

bus_error_t find_destination_path(bus_handle_t *handle, char const *namespace, char **bus_path,
    char **comp)
{
    bus_error_t ret = bus_error_success;
    if (strstr(namespace, "eRT.com.cisco") != NULL) {
        wifi_util_info_print(WIFI_BUS,
            "The substring '%s' was found in the string its psm module .\n", namespace);
        *comp = PSM_COMP_NAME;
        *bus_path = PSM_COMP_PATH;
        return ret;
    }
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    DBusError dbus_error;
    dbus_error_init(&dbus_error);
    char *subsystem_prefix = "eRT.";

    DBusMessage *message, *reply;
    DBusMessageIter iter;

    message = dbus_message_new_method_call(CCSP_CR_COMPONENT_ID, CCSP_DBUS_PATH_CR,
        CCSP_DBUS_INTERFACE_CR, "discComponentSupportingNamespace");

    if (!message) {
        wifi_util_error_print(WIFI_BUS, "No memory\n");
        return bus_error_general;
    }

    dbus_message_iter_init_append(message, &iter);
    DBUS_MESSAGE_APPEND_CSTRING(&iter, namespace);
    DBUS_MESSAGE_APPEND_CSTRING(&iter, subsystem_prefix);
    reply = dbus_connection_send_with_reply_and_block(p_dbus_handle, message, -1, &dbus_error);

    if (dbus_error_is_set(&dbus_error)) {
        wifi_util_error_print(WIFI_BUS, "Error sending message: %s\n", dbus_error.message);
        dbus_error_free(&dbus_error);
        dbus_message_unref(message);
        return bus_error_general;
    }

    if (reply == NULL) {
        wifi_util_error_print(WIFI_BUS, "Reply Null\n");
        dbus_message_unref(message);
        return bus_error_destination_response_failure;
    }
    if (reply) {
        DBusMessageIter iter, struct_iter, array_iter;
        dbus_message_iter_init(reply, &iter);
        DBusBasicValue val;
        // We expect the message to contain an array of structs
        if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY) {
            // Get the array iterator
            dbus_message_iter_recurse(&iter, &array_iter);

            // Loop through the array elements
            while (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_INVALID) {
                // For each element in the array, we expect a struct
                if (dbus_message_iter_get_arg_type(&array_iter) == DBUS_TYPE_STRUCT) {
                    // Recurse into the struct
                    dbus_message_iter_recurse(&array_iter, &struct_iter);

                    // Read the first element of the struct (string)
                    if (dbus_message_iter_get_arg_type(&struct_iter) == DBUS_TYPE_STRING) {
                        dbus_message_iter_get_basic(&struct_iter, &val);
                        *comp = strdup(val.str);
                        wifi_util_info_print(WIFI_BUS, "Comp value: %s\n", *comp);
                    }

                    // Read the second element of the struct (string)
                    dbus_message_iter_next(&struct_iter);
                    if (dbus_message_iter_get_arg_type(&struct_iter) == DBUS_TYPE_STRING) {
                        dbus_message_iter_get_basic(&struct_iter, &val);
                        *bus_path = strdup(val.str);
                        wifi_util_info_print(WIFI_BUS, "bus_path value: %s\n", *bus_path);
                    }

                    // Move to the next struct in the array
                    dbus_message_iter_next(&array_iter);
                } else {
                    // Something went wrong if we don’t find a struct here
                    wifi_util_error_print(WIFI_BUS, "Expected DBUS_TYPE_STRUCT, found %d instead.\n",
                        dbus_message_iter_get_arg_type(&array_iter));
                    return bus_error_general;
                }
            }
        } else {
            wifi_util_error_print(WIFI_BUS, "Expected DBUS_TYPE_ARRAY, found %d instead.\n",
                dbus_message_iter_get_arg_type(&iter));
        }

        dbus_message_unref(reply);
    }
    dbus_message_unref(message);
    return ret;
}

static bus_error_t bus_set(bus_handle_t *handle, char const *name, raw_data_t *data)
{
    bus_error_t rc = bus_error_success;
    char *dbus_path = NULL, *dst_component_id = NULL;
    DBusMessage *message, *reply = NULL;
    DBusMessageIter iter, array_iter = { 0 }, struct_iter = { 0 };
    dbus_int32_t tmp = 0;
    dbus_uint32_t utmp = 0;
    dbus_bool_t commit = true;
    DBusError dbus_error;
    dbus_error_init(&dbus_error);
    int type = 0, size = 1;
    char *int_str = NULL;
    VERIFY_NULL_WITH_RC(name);
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    utmp = 0, tmp = 0;

    if (!p_dbus_handle) {
        wifi_util_error_print(WIFI_BUS, "bus handler is not valid\n");
        return bus_error_general;
    }
    rc = find_destination_path(handle, name, &dbus_path, &dst_component_id);
    wifi_util_info_print(WIFI_BUS, "%s: at %d dbus_path=%s and dst_component_id=%s\n", __func__,
        __LINE__, dbus_path, dst_component_id);
    if ((rc != bus_error_success) || !dbus_path || !dst_component_id) {
        wifi_util_error_print(WIFI_BUS, "Destination component not found\n");
        return bus_error_general;
    }

    message = dbus_message_new_method_call(dst_component_id, dbus_path, DBUS_INTERFACE_BASE,
        "setParameterValues");

    if (!message) {
        wifi_util_error_print(WIFI_BUS, "No memory\n");
        return bus_error_out_of_resources;
    }

    dbus_message_iter_init_append(message, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &tmp);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &utmp);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssi)", &array_iter);
    int_str = convert_raw_data_to_dbus_message(data, &type);

    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
    DBUS_MESSAGE_APPEND_CSTRING(&struct_iter, name);
    dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &int_str);
    dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_INT32, &type);
    dbus_message_iter_close_container(&array_iter, &struct_iter);
    dbus_message_iter_close_container(&iter, &array_iter);
    tmp = size;
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &tmp);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &commit);

    reply = dbus_connection_send_with_reply_and_block(p_dbus_handle, message, -1, &dbus_error);
    wifi_util_info_print(WIFI_BUS, "Received reply\n");
    if (reply == NULL) {
        wifi_util_error_print(WIFI_BUS, "Reply Null\n");
        dbus_message_unref(message);
        return bus_error_destination_response_failure;
    }

    // Process the reply (for example, read an integer response)
    type = dbus_message_get_type(reply);

    if (type == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
        wifi_util_info_print(WIFI_BUS, "success return\n");
        rc = bus_error_success;
    } else {
        rc = bus_error_destination_not_reachable;
    }

    // Cleanup

    if (int_str) {
        wifi_util_error_print(WIFI_BUS, "int_str is not null\n");
        free(int_str);
    }
    dbus_message_unref(reply);
    dbus_message_unref(message);
    free(dbus_path);
    free(dst_component_id);
    return rc;
}

void bus_data_free(raw_data_t *data)
{
    if ((data->raw_data.bytes) &&
        (data->data_type == bus_data_type_bytes || data->data_type == bus_data_type_string)) {
        free(data->raw_data.bytes);
    }
}
static void analyze_request_or_reply(parameterValStruct1_t **val, DBusMessage *reply)
{
    DBusMessageIter iter, struct_iter = { 0 }, array_iter = { 0 };
    char *str = 0;
    dbus_int32_t tmp;

    wifi_util_info_print(WIFI_BUS, "%s:%d\n", __func__, __LINE__);
    dbus_message_iter_init(reply, &iter);
    while (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
        dbus_message_iter_next(&iter);
    }
    if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY) {
        // Get the array iterator
        dbus_message_iter_recurse(&iter, &array_iter);

        // Loop through the array elements
        while (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_INVALID) {
            // For each element in the array, we expect a struct
            if (dbus_message_iter_get_arg_type(&array_iter) == DBUS_TYPE_STRUCT) {
                // Recurse into the struct
                dbus_message_iter_recurse(&array_iter, &struct_iter);
                *val = (parameterValStruct1_t *)malloc(sizeof(parameterValStruct1_t));
                memset(*val, 0, sizeof(parameterValStruct1_t));

                // Read the first element of the struct (string)
                if (dbus_message_iter_get_arg_type(&struct_iter) == DBUS_TYPE_STRING) {
                    dbus_message_iter_get_basic(&struct_iter, &str);
                    wifi_util_info_print(WIFI_BUS, "param_name : %s\n", str);
                    if (str) {
                        (*val)->parameterName = (char *)malloc(strlen(str) + 1);
                        strcpy((*val)->parameterName, str);
                    } else {
                        (*val)->parameterName = NULL;
                    }
                }
                *str = 0;
                // Read the second element of the struct (string)
                dbus_message_iter_next(&struct_iter);
                if (dbus_message_iter_get_arg_type(&struct_iter) == DBUS_TYPE_STRING) {
                    dbus_message_iter_get_basic(&struct_iter, &str);
                    wifi_util_info_print(WIFI_BUS, "param value is present\n");
                    ;
                    if (str) {
                        (*val)->parameterValue = (char *)malloc(strlen(str) + 1);
                        wifi_util_info_print(WIFI_BUS, "error %s:%d \n", __func__, __LINE__);
                        strcpy((*val)->parameterValue, str);
                    } else {
                        (*val)->parameterValue = NULL;
                    }
                }
                *str = 0;
                // Read the third element of the struct (int)
                dbus_message_iter_next(&struct_iter);
                if (dbus_message_iter_get_arg_type(&struct_iter) == DBUS_TYPE_INT32) {
                    dbus_message_iter_get_basic(&struct_iter, &tmp);
                    wifi_util_info_print(WIFI_BUS, "type value: %d\n", tmp);
                    (*val)->type = tmp;
                }
                // Move to the next struct in the array
                dbus_message_iter_next(&array_iter);
            } else {
                // Something went wrong if we don’t find a struct here
                wifi_util_error_print(WIFI_BUS, "Expected DBUS_TYPE_STRUCT, found %d instead.\n",
                    dbus_message_iter_get_arg_type(&array_iter));
            }
        }
    } else {
        wifi_util_error_print(WIFI_BUS, "Expected DBUS_TYPE_ARRAY, found %d instead.\n",
            dbus_message_iter_get_arg_type(&iter));
    }
}
/* Caller should responsible to free (call bus_data_free()) the memory */
static bus_error_t bus_data_get(bus_handle_t *handle, char const *name, raw_data_t *data)
{
    DBusMessage *message, *reply;
    dbus_int32_t tmp;
    DBusMessageIter iter, array_iter;
    dbus_uint32_t utmp;
    bus_error_t rc = -1;
    parameterValStruct1_t *val = NULL;
    char *dbus_path = NULL, *dst_component_id = NULL;
    DBusError dbus_error;
    dbus_error_init(&dbus_error);
    int len = 0;

    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    if (!p_dbus_handle) {
        wifi_util_error_print(WIFI_BUS, "bus handler is not valid\n");
        return bus_error_general;
    }
    rc = find_destination_path(handle, name, &dbus_path, &dst_component_id);
    wifi_util_info_print(WIFI_BUS, "%s: at %d dbus_path=%s and dst_component_id=%s param=%s\n",
        __func__, __LINE__, dbus_path, dst_component_id, name);

    if ((rc != bus_error_success) || !dbus_path || !dst_component_id) {
        wifi_util_error_print(WIFI_BUS, "Destination component not found\n");
        return bus_error_general;
    }

    message = dbus_message_new_method_call(dst_component_id, dbus_path, DBUS_INTERFACE_BASE,
        "getParameterValues");
    if (!message) {
        wifi_util_error_print(WIFI_BUS, "No memory\n");
        return bus_error_out_of_resources;
    }

    dbus_message_iter_init_append(message, &iter);

    utmp = 0;
    if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &utmp))
        wifi_util_error_print(WIFI_BUS, "error %s:%d\n", __func__, __LINE__);

    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &array_iter);
    DBUS_MESSAGE_APPEND_CSTRING(&array_iter, name);

    dbus_message_iter_close_container(&iter, &array_iter);

    tmp = 1;

    dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &tmp);
    wifi_util_info_print(WIFI_BUS, "Sending getparam command %s: at %d\n", __func__, __LINE__);
    // Get the reply message
    reply = dbus_connection_send_with_reply_and_block(p_dbus_handle, message, -1, &dbus_error);
    wifi_util_info_print(WIFI_BUS, "%s:Enter %d\n", __func__, __LINE__);

    if (reply == NULL) {
        wifi_util_error_print(WIFI_BUS, "Reply is Nulli Line=%d\n", __LINE__);
        dbus_message_unref(message);
        return bus_error_destination_response_failure;
    }

    if (reply) {
        analyze_request_or_reply(&val, reply);
        dbus_message_unref(reply);
        dbus_message_unref(message);
    }

    if (!val || !val->parameterValue) {
        if (val) {
            free(val);
        }
        wifi_util_error_print(WIFI_BUS, "Reply doesnt have value\n");
        return bus_error_general;
    }

    /* Defensive code as we deal with pointer for type string & bytes */
    data->raw_data.b = 0;
    data->raw_data_len = 0;
    data->raw_data.bytes = NULL;
    bus_data_type_t type;
    type = convert_ccsp_to_bus_data_type(val->type);
    convert_dbus_message_to_raw_data(data, type, val->parameterValue);
    wifi_util_info_print(WIFI_BUS, "error %s:%d type=%d\n", __func__, __LINE__, type);
    if ((data->data_type == bus_data_type_bytes || data->data_type == bus_data_type_string) &&
        val->parameterValue) {
        data->raw_data.bytes = (void *)calloc((data->raw_data_len + 1), sizeof(char));
        if (data->raw_data.bytes == NULL) {
            wifi_util_error_print(WIFI_BUS, "%s:%d: bus: memory alloc is failed:%d for name:%s\n",
                __func__, __LINE__, len, name);
            return bus_error_out_of_resources;
        }
        memcpy(data->raw_data.bytes, val->parameterValue, data->raw_data_len);
    }
    if (val->parameterName) {
        free(val->parameterName);
    }
    if (val->parameterValue) {
        free(val->parameterValue);
    }
    if (val) {
        free(val);
    }
    free(dbus_path);
    free(dst_component_id);
    return bus_error_success;
}

static bus_error_t bus_event_publish(bus_handle_t *handle, char const *name, raw_data_t *data)
{
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(data);
    DBusMessage *message;
    dbus_int32_t tmp = 0;
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    char *int_str = NULL; // 12 is enough to hold a 32-bit integer as a string
    if (!p_dbus_handle) {
        wifi_util_error_print(WIFI_BUS, "%s:%d bus handler is not valid\n", __func__, __LINE__);
        return bus_error_general;
    }
    message = dbus_message_new_signal(DBUS_PATH_EVENT, DBUS_INTERFACE_EVENT, "OneWifi");

    if (!message)
        return bus_error_out_of_resources;

    dbus_message_append_args(message, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
    tmp = convert_bus_to_ccsp_data_type(data->data_type);
    dbus_message_append_args(message, DBUS_TYPE_INT32, &tmp, DBUS_TYPE_INVALID);

    switch (data->data_type) {
        case bus_data_type_boolean:
            const char *bool_str = data->raw_data.b ? "true" : "false";
            dbus_message_append_args(message, DBUS_TYPE_STRING, &bool_str, DBUS_TYPE_INVALID);
        break;
        case bus_data_type_string:
        case bus_data_type_bytes:
            char *str = (char *)data->raw_data.bytes;
            dbus_message_append_args(message, DBUS_TYPE_STRING, &str, DBUS_TYPE_INVALID);
        break;
        case bus_data_type_uint32:
            int_str = (char *)malloc(12);
            sprintf(int_str, "%u", data->raw_data.u32);
            dbus_message_append_args(message, DBUS_TYPE_STRING, &int_str, DBUS_TYPE_INVALID);
        break;
        default:
            wifi_util_error_print(WIFI_BUS, "%s:%d: bus: Invalid data_type:%d for name:%s.\n", __func__,
                __LINE__, data->data_type, name);
        break;
    };

    dbus_connection_send(p_dbus_handle, message, NULL);

    dbus_message_unref(message);
    if (int_str)
        free(int_str);
    return bus_error_success;
}

static bus_error_t bus_raw_event_publish(bus_handle_t *handle, char *name, void *data,
    unsigned int size)
{
    DBusMessage *message;
    VERIFY_NULL_WITH_RC(name);
    VERIFY_NULL_WITH_RC(data);
    char *str = (char *)data;
    dbus_int32_t tmp = ccsp_string;

    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    if (!p_dbus_handle) {
        wifi_util_error_print(WIFI_BUS, "%s:%d bus handler is not valid\n", __func__, __LINE__);
        return bus_error_general;
    }

    message = dbus_message_new_signal(DBUS_PATH_EVENT, DBUS_INTERFACE_EVENT, "OneWifi");

    if (!message)
        return bus_error_out_of_resources;

    dbus_message_append_args(message, DBUS_TYPE_STRING, &name, DBUS_TYPE_INT32, &tmp,
        DBUS_TYPE_STRING, &str, DBUS_TYPE_INVALID);

    dbus_connection_send(p_dbus_handle, message, NULL);

    dbus_message_unref(message);

    return bus_error_success;
}

static bus_error_t bus_set_string(bus_handle_t *handle, char const *param_name,
    char const *param_str)
{
    bus_error_t rc = bus_error_success;
    char *dbus_path = NULL, *dst_component_id = NULL;
    DBusMessage *message = NULL, *reply = NULL;
    DBusMessageIter iter, array_iter, struct_iter;
    dbus_int32_t tmp = 0;
    dbus_uint32_t utmp = 0;
    DBusError dbus_error;
    dbus_error_init(&dbus_error);

    dbus_bool_t commit = true;
    int size = 1;

    VERIFY_NULL_WITH_RC(param_name);
    VERIFY_NULL_WITH_RC(param_str);

    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    if (!p_dbus_handle) {
        wifi_util_info_print(WIFI_BUS, "bus handler is not valid\n");
        return bus_error_general;
    }
    rc = find_destination_path(handle, param_name, &dbus_path, &dst_component_id);

    if ((rc != bus_error_success) || !dbus_path || !dst_component_id) {
        wifi_util_error_print(WIFI_BUS, "Destination component not found\n");
        return bus_error_general;
    }

    message = dbus_message_new_method_call(dst_component_id, dbus_path, DBUS_INTERFACE_BASE,
        "setParameterValues");
    if (!message) {
        wifi_util_error_print(WIFI_BUS, "No memory\n");
        return bus_error_out_of_resources;
    }
    dbus_message_iter_init_append(message, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &tmp);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &utmp);

    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssi)", &array_iter);
    dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
    tmp = ccsp_string;
    DBUS_MESSAGE_APPEND_CSTRING(&struct_iter, param_name);
    dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &param_str);
    dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_INT32, &tmp);
    dbus_message_iter_close_container(&array_iter, &struct_iter);
    dbus_message_iter_close_container(&iter, &array_iter);

    tmp = size;
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &tmp);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &commit);
    // Get the reply message
    reply = dbus_connection_send_with_reply_and_block(p_dbus_handle, message, -1, &dbus_error);

    if (reply == NULL) {
        wifi_util_error_print(WIFI_BUS, "Reply Null\n");
        dbus_message_unref(message);
        return bus_error_destination_response_failure;
    }

    // Process the reply (for example, read an integer response)
    int type = dbus_message_get_type(reply);

    if (type == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
        wifi_util_info_print(WIFI_BUS, "success return\n");
        rc = bus_error_success;
    } else {
        wifi_util_error_print(WIFI_BUS, "Failure return\n");
        rc = bus_error_destination_not_found;
    }

    // Cleanup
    dbus_message_unref(reply);
    dbus_message_unref(message);
    free(dbus_path);
    free(dst_component_id);
    return rc;
}
bus_error_t bus_unreg_data_elements(bus_handle_t *handle, uint32_t num_of_element,
    bus_data_element_t *data_element)
{

    name_spaceType1_t *element_namespace = NULL;
    uint32_t index;
    bus_data_element_t dbus_dataElement = { 0 };
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    const char *subsystem_prefix = "eRT.";

    if (p_dbus_handle == NULL || data_element == NULL) {
        wifi_util_info_print(WIFI_BUS, "%s bus: input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }
    wifi_util_info_print(WIFI_BUS, "%s: Enter %d num_of_element=%d \n", __func__, __LINE__,
        num_of_element);
    element_namespace = (name_spaceType1_t *)calloc(num_of_element, sizeof(name_spaceType1_t));
    if (element_namespace == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s:%d calloc for namespace is failed\n", __func__,
            __LINE__);
        return bus_error_out_of_resources;
    }

    for (index = 0; index < num_of_element; index++) {
        dbus_dataElement.full_name = data_element[index].full_name;
        wifi_util_info_print(WIFI_BUS, "%s:%s\n", dbus_dataElement.full_name,
            data_element[index].full_name);
        remove_method_callback(handle, &dbus_dataElement);
        element_namespace[index].name_space = data_element[index].full_name;
        element_namespace[index].dataType = convert_bus_to_ccsp_data_type(
            data_element[index].data_model_prop.data_format);
    }
    handle_namespace_with_cr(handle, subsystem_prefix, element_namespace, num_of_element, false);
    add_dbus_handlers(handle);
    free(element_namespace);
    return bus_error_success;
}

bus_error_t bus_reg_data_elements(bus_handle_t *handle, bus_data_element_t *data_element,
    uint32_t num_of_element)
{
    name_spaceType1_t *element_namespace = NULL;
    uint32_t index;
    bus_data_element_t dbus_dataElement = { 0 };
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    const char *subsystem_prefix = "eRT.";
    wifi_util_info_print(WIFI_BUS, "%s: at %d\n", __func__, __LINE__);

    if (p_dbus_handle == NULL || data_element == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s bus: input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }

    element_namespace = (name_spaceType1_t *)calloc(num_of_element, sizeof(name_spaceType1_t));
    if (element_namespace == NULL) {
        wifi_util_error_print(WIFI_BUS,
            "%s:%d bus: bus_reg_data_elements() calloc for namespace is failed\n", __func__,
            __LINE__);
        return bus_error_out_of_resources;
    }
    for (index = 0; index < num_of_element; index++) {
        dbus_dataElement.full_name = data_element[index].full_name;
        dbus_dataElement.type = data_element[index].type;
        dbus_dataElement.data_model_prop.data_format =
            data_element[index].data_model_prop.data_format;
        dbus_dataElement.cb_table.get_handler = data_element[index].cb_table.get_handler;
        dbus_dataElement.cb_table.set_handler = data_element[index].cb_table.set_handler;
        dbus_dataElement.cb_table.table_add_row_handler =
            data_element[index].cb_table.table_add_row_handler;
        dbus_dataElement.cb_table.table_remove_row_handler =
            data_element[index].cb_table.table_remove_row_handler;
        dbus_dataElement.cb_table.event_sub_handler =
            data_element[index].cb_table.event_sub_handler;
        dbus_dataElement.cb_table.method_handler = data_element[index].cb_table.method_handler;
        append_method_callback(handle, &dbus_dataElement);

        element_namespace[index].name_space = data_element[index].full_name;
        element_namespace[index].dataType = convert_bus_to_ccsp_data_type(
            data_element[index].data_model_prop.data_format);
    }
    handle_namespace_with_cr(handle, subsystem_prefix, element_namespace, num_of_element, true);
    add_dbus_handlers(handle);
    free(element_namespace);
    return bus_error_success;
}
bus_error_t bus_method_invoke(bus_handle_t *handle, void *paramName, char *event,
    raw_data_t *input_data, raw_data_t *output_data, uint8_t input_bus_data)
{
    bus_error_t rc = bus_error_general;
    char *dbus_path = NULL, *dst_component_id = NULL;
    DBusMessage *message, *reply;
    DBusMessageIter iter;
    DBusMessageIter array_iter = { 0 }, struct_iter = { 0 };
    int type = 0;
    parameterValStruct1_t *val = NULL;
    char *int_str = NULL;

    DBusError dbus_error;
    dbus_error_init(&dbus_error);

    wifi_util_info_print(WIFI_BUS, "%s: Enter %d \n", __func__, __LINE__);
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    if (p_dbus_handle == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s bus: input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }
    switch (input_bus_data) {
        case BUS_METHOD_GET:
            wifi_util_info_print(WIFI_BUS, "In BUS_METHOD_GET \n");
            rc = bus_data_get(handle, (char const *)paramName, output_data);
        break;
        case BUS_METHOD_SET:
            wifi_util_info_print(WIFI_BUS, "In BUS_METHOD_SET \n");
            rc = bus_set(handle, (char const *)paramName, input_data);
        break;

        case BUS_METHOD_SET_GET:
            wifi_util_info_print(WIFI_BUS, "In BUS_METHOD_SET_GET \n");
            if (strcmp(event, "Device.WiFi.AP.STA.GetAssocRequest") == 0) {
                rc = find_destination_path(handle, event, &dbus_path, &dst_component_id);
                if ((rc != bus_error_success) || !dbus_path || !dst_component_id) {
                    wifi_util_error_print(WIFI_BUS, "Destination component not found\n");
                    return bus_error_general;
                }
                wifi_util_info_print(WIFI_BUS, "dbus_path = %s and component = %s\n", dbus_path,
                    dst_component_id);
                message = dbus_message_new_method_call(dst_component_id, dbus_path, DBUS_INTERFACE_BASE,
                    "OneWifiMethod");
                if (!message) {
                    wifi_util_error_print(WIFI_BUS, "No memory\n");
                    return bus_error_out_of_resources;
                }
                dbus_message_iter_init_append(message, &iter);
                dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "(ssi)", &array_iter);
                int_str = convert_raw_data_to_dbus_message(input_data, &type);
                wifi_util_info_print(WIFI_BUS, " type=%d and str = %s\n", type, int_str);
                dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
                DBUS_MESSAGE_APPEND_CSTRING(&struct_iter, event);
                dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &int_str);
                dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_INT32, &type);
                dbus_message_iter_close_container(&array_iter, &struct_iter);
                dbus_message_iter_close_container(&iter, &array_iter);
                if (int_str) {
                    wifi_util_error_print(WIFI_BUS, "freing memory\n");
                    free(int_str);
                }
                reply = dbus_connection_send_with_reply_and_block(p_dbus_handle, message, -1,
                    &dbus_error);

                if (reply == NULL) {
                    wifi_util_error_print(WIFI_BUS, "Reply Null\n");
                    dbus_message_unref(message);
                    return bus_error_destination_response_failure;
                } else {
                    wifi_util_info_print(WIFI_BUS, "Got an reply\n");
                    analyze_request_or_reply(&val, reply);
                    dbus_message_unref(reply);
                    dbus_message_unref(message);
                }
                if (!val || !val->parameterValue) {
                    if (val) {
                        free(val);
                    }
                    wifi_util_error_print(WIFI_BUS, "Reply doesnt have value\n");
                    return bus_error_general;
                }
                /* Defensive code as we deal with pointer for type string & bytes */
                output_data->raw_data.b = 0;
                output_data->raw_data_len = 0;
                output_data->raw_data.bytes = NULL;
                type = convert_ccsp_to_bus_data_type(val->type);
                convert_dbus_message_to_raw_data(output_data, type, val->parameterValue);
                wifi_util_info_print(WIFI_BUS, "%s:%d type=%d\n", __func__, __LINE__, type);
                if ((output_data->data_type == bus_data_type_bytes ||
                    output_data->data_type == bus_data_type_string) &&
                    val->parameterValue) {
                    output_data->raw_data.bytes = (void *)calloc((output_data->raw_data_len + 1),
                   sizeof(char));
                    if (output_data->raw_data.bytes == NULL) {
                        wifi_util_error_print(WIFI_BUS, "%s:%d: bus: memory alloc is failed\n");
                        return bus_error_out_of_resources;
                    }
                    memcpy(output_data->raw_data.bytes, val->parameterValue, output_data->raw_data_len);
                }
                if (val->parameterName) {
                    free(val->parameterName);
                }
                if (val->parameterValue) {
                    free(val->parameterValue);
                }
                if (val) {
                    free(val);
                }
                free(dbus_path);
                free(dst_component_id);
            }
        break;
        default:
        break;
    }
    return bus_error_success;
}

bus_error_t bus_event_subscribe(bus_handle_t *handle, char const *event_name, void *cb,
    void *userData, int timeout)
{
    wifi_util_info_print(WIFI_BUS, "%s: Enter %d \n", __func__, __LINE__);
    bus_error_t rc = bus_error_success;
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;

    if (p_dbus_handle == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s bus: Input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }

    rc = add_subscription_to_dbus_daemon(handle, "OneWifi");

    if (rc == bus_error_success) {
        rc = append_subscriber_events(handle, cb, event_name);
        if (rc == bus_error_success) {
            // Handle event handler in bus registration table
            send_reg_event_handler(handle, event_name, bus_event_action_subscribe, 0, false);
            wifi_util_info_print(WIFI_BUS,
                "Successfully appended subscription event to global array\n");
        }
    }
    add_dbus_handlers(handle);
    return rc;
}

bus_error_t bus_event_subscribe_ex(bus_handle_t *handle, bus_event_sub_t *l_sub_info_map,
    int num_sub, int timeout)
{
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    bus_error_t rc = bus_error_success;

    if (p_dbus_handle == NULL || l_sub_info_map == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s bus: Input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }
    rc = add_subscription_to_dbus_daemon(handle, "OneWifi");
    for (int index = 0; index < num_sub; index++) {
        rc = append_subscriber_events(handle, l_sub_info_map[index].handler,
            (char *)l_sub_info_map[index].event_name);
        if (rc == bus_error_success) {
            wifi_util_info_print(WIFI_BUS,
                "Successfully appended subscription event to global array\n");
            // Handle event handler in bus registration table
            send_reg_event_handler(handle, (char *)l_sub_info_map[index].event_name,
                bus_event_action_subscribe, 0, false);
        }
    }
    add_dbus_handlers(handle);
    return rc;
}

bus_error_t bus_event_unsubscribe(bus_handle_t *handle, char const *event_name)
{
    bus_error_t rc = bus_error_success;

    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    if (p_dbus_handle == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s bus: Input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }
    rc = remove_subscriber_events(handle, event_name);
    if (rc == bus_error_success) {
        wifi_util_info_print(WIFI_BUS, "Successfully removed subscription event from event map\n");
        send_reg_event_handler(handle, event_name, bus_event_action_unsubscribe, 0, false);
    }
    add_dbus_handlers(handle);
    return rc;
}

bus_error_t bus_event_subscribe_async(bus_handle_t *handle, char const *event_name, void *cb,
    void *async_cb, void *userData, int timeout)
{
    bus_error_t rc = bus_error_success;
    bus_event_sub_ex_async_handler_t async;

    DBusConnection *p_dbus_handle = handle->u.dbus_handle;

    if (p_dbus_handle == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s bus: Input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }

    rc = add_subscription_to_dbus_daemon(handle, "OneWifi");

    if (rc == bus_error_success) {
        rc = append_subscriber_events(handle, cb, event_name);
        if (rc == bus_error_success) {
            wifi_util_info_print(WIFI_BUS, "Successfully appended subscription event to map\n");
            send_reg_event_handler(handle, event_name, bus_event_action_subscribe, 0, false);
            async = async_cb;
            async((char *)event_name, rc, handle);
        }
    }
    add_dbus_handlers(handle);
    return rc;
}
char const *convert_bus_to_dbus_error_string(bus_error_t e)
{
#define busError_String(E, S) \
    case E:                   \
        s = S;                \
        break;

    char const *s = NULL;
    switch (e) {
        busError_String(bus_error_success, "ok");
        busError_String(bus_error_general, "generic error");
        busError_String(bus_error_invalid_input, "invalid input");
        busError_String(bus_error_not_inttialized, "not initialized");
        busError_String(bus_error_out_of_resources, "out of resources");
        busError_String(bus_error_destination_not_found, "destination not found");
        busError_String(bus_error_destination_not_reachable, "destination not reachable");
        busError_String(bus_error_destination_response_failure, "destination response failure");
        busError_String(bus_error_invalid_response_from_destination,
            "invalid response from destination");
        busError_String(bus_error_invalid_operation, "invalid operation");
        busError_String(bus_error_invalid_event, "invalid event");
        busError_String(bus_error_invalid_handle, "invalid handle");
        busError_String(bus_error_session_already_exist, "session already exists");
        busError_String(bus_error_component_name_duplicate, "duplicate component name");
        busError_String(bus_error_element_name_duplicate, "duplicate element name");
        busError_String(bus_error_element_name_missing, "name missing");
        busError_String(bus_error_component_does_not_exist, "component does not exist");
        busError_String(bus_error_element_does_not_exist, "element name does not exist");
        busError_String(bus_error_access_not_allowed, "access denied");
        busError_String(bus_error_invalid_context, "invalid context");
        busError_String(bus_error_timeout, "timeout");
        busError_String(bus_error_async_response, "async operation in progress");
        busError_String(bus_error_invalid_method, "invalid method");
        busError_String(bus_error_nosubscribers, "no subscribers");
        busError_String(bus_error_subscription_already_exist, "event subscription already exists");
        busError_String(bus_error_invalid_namespace, "invalid namespace");
    default:
        s = "unknown error";
    }
    return s;
}

char const *bus_error_to_string(bus_error_t bus_error)
{
    wifi_util_info_print(WIFI_BUS, "%s: Enter %d \n", __func__, __LINE__);
    return convert_bus_to_dbus_error_string(bus_error);
}

bus_error_t bus_event_subscribe_ex_async(bus_handle_t *handle, bus_event_sub_t *l_sub_info_map,
    int num_sub, void *l_sub_handler, int timeout)
{
    wifi_util_info_print(WIFI_BUS, "%s: Enter %d num_sub=%d\n", __func__, __LINE__, num_sub);
    bus_error_t rc = bus_error_success;
    bus_event_sub_ex_async_handler_t async;
    DBusConnection *p_dbus_handle = handle->u.dbus_handle;
    if (p_dbus_handle == NULL || l_sub_info_map == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s bus: Input param is NULL\n", __func__);
        return bus_error_invalid_input;
    }
    rc = add_subscription_to_dbus_daemon(handle, "OneWifi");
    for (int index = 0; index < num_sub; index++) {
        rc = append_subscriber_events(handle, l_sub_info_map[index].handler,
            (char *)l_sub_info_map[index].event_name);
        if (rc == bus_error_success) {
            wifi_util_info_print(WIFI_BUS,
                "Successfully appended subscription event to global array\n");
            async = l_sub_handler;
            async((char *)l_sub_info_map[index].event_name, rc, handle);
            send_reg_event_handler(handle, (char *)l_sub_info_map[index].event_name,
                bus_event_action_subscribe, 0, false);
            wifi_util_info_print(WIFI_BUS, "send_reg_event_handler is called for %s\n",
                (char *)l_sub_info_map[index].event_name);
        }
    }
    return rc;
}

static bus_data_type_t convert_ccsp_to_bus_data_type(enum dataType_e type)
{
    bus_data_type_t bus_data_type = ccsp_byte;
    switch (type) {
        case ccsp_boolean:
            bus_data_type = bus_data_type_boolean;
        break;
        case ccsp_byte:
            bus_data_type = bus_data_type_bytes;
        break;
        case ccsp_int:
            bus_data_type = bus_data_type_int32;
        break;
        case ccsp_unsignedInt:
            bus_data_type = bus_data_type_uint32;
        break;
        case ccsp_string:
            bus_data_type = bus_data_type_string;
        break;
        default:
        break;
    }
    return bus_data_type;
}
void *bus_convert_handle_to_ptr(bus_handle_t *handle)
{
    wifi_util_info_print(WIFI_BUS, "%s: %d\n", __func__, __LINE__);
    return &handle->u.dbus_handle;
}

static enum dataType_e convert_bus_to_ccsp_data_type(bus_data_type_t type)
{
    enum dataType_e ccsp_data_type = ccsp_none;
    switch (type) {
        case bus_data_type_boolean:
            ccsp_data_type = ccsp_boolean;
        break;
        case bus_data_type_int32:
            ccsp_data_type = ccsp_int;
        break;
        case bus_data_type_uint32:
            ccsp_data_type = ccsp_unsignedInt;
        break;
        case bus_data_type_bytes:
            ccsp_data_type = ccsp_byte;
        break;
        case bus_data_type_string:
            ccsp_data_type = ccsp_string;
        break;
        default:
        break;
    }
    return ccsp_data_type;
}

static bus_error_t bus_add_table_row(bus_handle_t *handle, char const *name,
    char const *alias, uint32_t *row_index)
{
    return bus_error_success;
}

static bus_error_t bus_event_unsubs_ex(bus_handle_t *handle,
    bus_event_sub_t *l_sub_info_map, int num_sub)
{
    return bus_error_success;
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
    desc->bus_unreg_data_element_fn = bus_unreg_data_elements;
    desc->bus_event_publish_fn = bus_event_publish;
    desc->bus_raw_event_publish_fn = bus_raw_event_publish;
    desc->bus_convert_handle_to_actual_ptr_fn = bus_convert_handle_to_ptr;
    desc->bus_set_string_fn = bus_set_string;
    desc->bus_event_subs_fn = bus_event_subscribe;
    desc->bus_event_subs_ex_fn = bus_event_subscribe_ex;
    desc->bus_event_subs_ex_async_fn = bus_event_subscribe_ex_async;
    desc->bus_event_subs_async_fn = bus_event_subscribe_async;
    desc->bus_event_unsubs_fn = bus_event_unsubscribe;
    desc->bus_event_unsubs_ex_fn = bus_event_unsubs_ex;
    desc->bus_method_invoke_fn = bus_method_invoke;
    desc->bus_get_trace_context_fn = bus_get_trace_context;
    desc->bus_set_trace_context_fn = bus_set_trace_context;
    desc->bus_error_to_string_fn = bus_error_to_string;
    desc->bus_add_table_row_fn = bus_add_table_row;
}
