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
#include "he_bus_json_decode.h"
#include "he_bus_common.h"
#include "he_bus_core.h"
#include "he_bus_dml.h"
#include "he_bus_memory.h"
#include "he_bus_utils.h"
#include <unistd.h>

int set_bus_callbackfunc_pointers(char *full_namespace, he_bus_callback_table_t *cb_table)
{
    he_bus_callback_table_t bus_cb_handlers[max_cb_func_list] = {
        // wifi event cb func: [index 0]
        { wifi_get_param_value,        wifi_set_param_value,        NULL,                          NULL,                                 wifi_event_sub_handler,
         wifi_method_handler                                                                                                                                                                   },

        // wifi radio event cb func: [index 1]
        { radio_get_param_value,       radio_set_param_value,       radio_table_add_row_handler,
         radio_table_remove_row_handler,                                                                                                 radio_event_sub_handler,   radio_method_handler       },

        // wifi accesspoint event cb func: [index 2]
        { accesspoint_get_param_value, accesspoint_set_param_value,
         accesspoint_table_add_row_handler,                                                        accesspoint_table_remove_row_handler,
         accesspoint_event_sub_handler,                                                                                                                             accesspoint_method_handler },

        // wifi ssid event cb func: [index 3]
        { ssid_get_param_value,        ssid_set_param_value,        ssid_table_add_row_handler,
         ssid_table_remove_row_handler,                                                                                                  ssid_event_sub_handler,    ssid_method_handler        },

        // wifi default event cb func: [index 4]
        { default_get_param_value,     default_set_param_value,     default_table_add_row_handler,
         default_table_remove_row_handler,                                                                                               default_event_sub_handler, default_method_handler     },
    };

    if (strncmp(full_namespace, WIFI_OBJ_TREE_NAME, strlen(WIFI_OBJ_TREE_NAME) + 1) == 0) {
        memcpy(cb_table, &bus_cb_handlers[wifi_cb_func], sizeof(he_bus_callback_table_t));
    } else if (strncmp(full_namespace, RADIO_OBJ_TREE_NAME, strlen(RADIO_OBJ_TREE_NAME) + 1) == 0) {
        memcpy(cb_table, &bus_cb_handlers[radio_cb_func], sizeof(he_bus_callback_table_t));
    } else if (strncmp(full_namespace, ACCESSPOINT_OBJ_TREE_NAME,
                   strlen(ACCESSPOINT_OBJ_TREE_NAME) + 1) == 0) {
        memcpy(cb_table, &bus_cb_handlers[accesspoint_cb_func], sizeof(he_bus_callback_table_t));
    } else if (strncmp(full_namespace, SSID_OBJ_TREE_NAME, strlen(SSID_OBJ_TREE_NAME) + 1) == 0) {
        memcpy(cb_table, &bus_cb_handlers[ssid_cb_func], sizeof(he_bus_callback_table_t));
    } else {
        memcpy(cb_table, &bus_cb_handlers[default_cb_func], sizeof(he_bus_callback_table_t));
    }

    return HE_BUS_RETURN_OK;
}

int bus_register_namespace(he_bus_handle_t handle, char *full_namespace,
    he_bus_element_type_t element_type, he_bus_callback_table_t cb_table,
    data_model_prop_t data_model_value, int num_of_rows)
{
    he_bus_core_error_print("%s:%d: register_namespace:[%s] element_type:%d\n", __func__, __LINE__,
        full_namespace, element_type);

    he_bus_data_element_t dataElements = { 0 };

    dataElements.full_name = full_namespace;
    // snprintf(dataElements.full_name, HE_BUS_MAX_NAME_LENGTH,"%s", full_namespace);
    dataElements.type = element_type;
    dataElements.cb_table = cb_table;
    if (element_type == he_bus_element_type_table) {
        //@TODO Add get handler to get table size.
        dataElements.num_of_table_row = num_of_rows;
        he_bus_core_info_print("%s:%d: Add number of row:%d\n", __func__, __LINE__,
            dataElements.num_of_table_row);
    }

    element_node_t *node = bus_insert_element(handle, handle->root_element, &dataElements);
    if (node != NULL) {
        node->data_model_value = data_model_value;
    }

    return HE_BUS_RETURN_OK;
}

int get_int_type_from_str(char *int_str_type, he_bus_data_type_t *data_format)
{
    if (!strncmp(int_str_type, "uint32_t", strlen("uint32_t"))) {
        *data_format = he_bus_data_type_uint32;
    } else if (!strncmp(int_str_type, "uint16_t", strlen("uint16_t"))) {
        *data_format = he_bus_data_type_uint16;
    } else if (!strncmp(int_str_type, "uint8_t", strlen("uint8_t"))) {
        *data_format = he_bus_data_type_uint8;
    } else if (!strncmp(int_str_type, "int32_t", strlen("int32_t"))) {
        *data_format = he_bus_data_type_int32;
    } else if (!strncmp(int_str_type, "int16_t", strlen("int16_t"))) {
        *data_format = he_bus_data_type_int16;
    } else if (!strncmp(int_str_type, "int8_t", strlen("int8_t"))) {
        *data_format = he_bus_data_type_int8;
    }
    return HE_BUS_RETURN_OK;
}

int decode_definition_str_type(char *str_value, char *data_str_type,
    he_bus_data_type_t *data_format)
{
    if (!strncmp(str_value, "integer", strlen("integer"))) {
        get_int_type_from_str(data_str_type, data_format);
    } else if (!strncmp(str_value, "bool", strlen("bool"))) {
        *data_format = he_bus_data_type_boolean;
    } else if (!strncmp(str_value, "string", strlen("string"))) {
        *data_format = he_bus_data_type_string;
    }

    return HE_BUS_RETURN_OK;
}

int get_data_model_prop(cJSON *wifi_def_obj, char *data_str_type,
    data_model_prop_t *data_model_value)
{
    cJSON *param;
    decode_json_param_object(wifi_def_obj, data_str_type, param);

    while (param != NULL) {
        if (!strncmp(param->string, "type", strlen("type"))) {
            decode_definition_str_type(param->valuestring, data_str_type,
                &data_model_value->data_format);
        } else if (!strncmp(param->string, "minimum", strlen("minimum"))) {
            data_model_value->min_data_range = param->valuedouble;
        } else if (!strncmp(param->string, "maximum", strlen("maximum"))) {
            data_model_value->max_data_range = param->valuedouble;
        } else if (!strncmp(param->string, "enum", strlen("enum"))) {
            data_model_value->num_of_str_validation = cJSON_GetArraySize(param);
            data_model_value->str_validation = he_bus_malloc(
                sizeof(char *) * data_model_value->num_of_str_validation);
            HE_BUS_VERIFY_NULL_WITH_RETURN_INT(data_model_value->str_validation);
            for (int i = 0; i < data_model_value->num_of_str_validation; i++) {
                cJSON *item = cJSON_GetArrayItem(param, i);
                if (item != NULL && cJSON_IsString(item)) {
                    data_model_value->str_validation[i] = he_bus_malloc(
                        strlen(item->valuestring) + 1);
                    strncpy(data_model_value->str_validation[i], item->valuestring,
                        strlen(item->valuestring) + 1);
                }
            }
        }
        param = param->next;
    }

    return HE_BUS_RETURN_OK;
}

static int construct_namespace_and_register(he_bus_handle_t handle, cJSON *cfg_param,
    cJSON *wifi_def_obj, char *l_name_prefix)
{
    he_bus_name_string_t name_prefix;
    he_bus_element_type_t element_type = he_bus_element_type_property;
    he_bus_callback_table_t cb_table = { 0 };
    data_model_prop_t data_model_value = { 0 };

    strcpy(name_prefix, l_name_prefix);
    he_bus_core_error_print("%s:%d: namespace:%s\n", __func__, __LINE__, name_prefix);

    if (cJSON_IsObject(cfg_param) == true) {
        // decode individual param and set it to bus.
        cJSON *current_element = cfg_param->child;
        cJSON *param;
        char full_namespace[128];
        element_type = he_bus_element_type_method;

        set_bus_callbackfunc_pointers(name_prefix, &cb_table);
        while (current_element != NULL) {
            validate_current_json_obj_param_name(current_element);
            snprintf(full_namespace, sizeof(full_namespace), "%s.%s", name_prefix,
                current_element->string);
            decode_json_param_string(current_element, "type", param);
            get_data_model_prop(wifi_def_obj, param->valuestring, &data_model_value);
            decode_json_param_bool(current_element, "writable", param);
            data_model_value.data_permission = (param->type & cJSON_True) ? true : false;
            bus_register_namespace(handle, full_namespace, element_type, cb_table, data_model_value,
                0);
            current_element = current_element->next;
        }
    } else if (cJSON_IsArray(cfg_param) == true) {
        cJSON *current_element;
        cJSON *param;
        char full_namespace[128];
        int num_of_tables = 0;

        if (cfg_param->prev != NULL && cfg_param->prev->string != NULL) {
            if ((strncmp(cfg_param->prev->string, MAX_NUM_OF_OBJECTS_NAME,
                     strlen(MAX_NUM_OF_OBJECTS_NAME) + 1) == 0) &&
                (cJSON_IsNumber(cfg_param->prev) == true)) {
                num_of_tables = cfg_param->prev->valuedouble;
            }
        }

        // snprintf(name_prefix, HE_BUS_MAX_NAME_LENGTH, "%s.%s", name_prefix, "{i}");
        strcat(name_prefix, ".");
        strcat(name_prefix, "{i}");
        element_type = he_bus_element_type_table;
        set_bus_callbackfunc_pointers(name_prefix, &cb_table);

        // main table register
        bus_register_namespace(handle, name_prefix, element_type, cb_table, data_model_value,
            num_of_tables);

        // We don't need table handlers callback for table paramters.
        cb_table.table_remove_row_handler = NULL;
        cb_table.table_add_row_handler = NULL;
        element_type = he_bus_element_type_property;

        int num_of_elements = cJSON_GetArraySize(cfg_param);
        for (int index = 0; index < num_of_elements; index++) {
            current_element = cJSON_GetArrayItem(cfg_param, index);
            current_element = current_element->child;
            HE_BUS_VERIFY_NULL_WITH_RETURN_INT(current_element);

            snprintf(full_namespace, sizeof(full_namespace), "%s.%s", name_prefix,
                current_element->string);
            decode_json_param_string(current_element, "type", param);
            get_data_model_prop(wifi_def_obj, param->valuestring, &data_model_value);
            decode_json_param_bool(current_element, "writable", param);
            data_model_value.data_permission = (param->type & cJSON_True) ? true : false;
            bus_register_namespace(handle, full_namespace, element_type, cb_table, data_model_value,
                0);
        }
    } else {
        he_bus_core_error_print("%s:%d: wrong wifi config object type\n", __func__, __LINE__);
        return HE_BUS_RETURN_ERR;
    }

    return HE_BUS_RETURN_OK;
}

static void decode_wifi_object_recurse(he_bus_handle_t handle, cJSON *node, cJSON *wifi_def_obj,
    char *l_name_prefix)
{
    HE_BUS_VERIFY_NULL(node);
    cJSON *child = node->child;
    he_bus_name_string_t name_prefix;
    char new_name_prefix[128];

    snprintf(name_prefix, HE_BUS_MAX_NAME_LENGTH, "%s", l_name_prefix);

    while (child) {
        cJSON *tmp = child;
        if (tmp->string != NULL &&
            strncmp(tmp->string, LIST_OF_DEFINITION_NAME, strlen(LIST_OF_DEFINITION_NAME)) == 0) {
            construct_namespace_and_register(handle, tmp, wifi_def_obj, name_prefix);
            child = child->next;
            continue;
        }
        snprintf(new_name_prefix, sizeof(new_name_prefix), "%s.%s", name_prefix, tmp->string);
        child = child->next;
        decode_wifi_object_recurse(handle, tmp, wifi_def_obj, new_name_prefix);
    }
}

static int decode_wifi_objects(he_bus_handle_t handle, cJSON *root_obj)
{
    if (root_obj == NULL) {
        return HE_BUS_RETURN_ERR;
    }
    cJSON *wifi_def_obj;

    decode_json_param_object(root_obj, WIFI_OBJ_DEFINITIONS_NAME, wifi_def_obj);

    cJSON *temp_obj = wifi_def_obj->next;
    he_bus_name_string_t name_prefix;

    while (temp_obj) {
        cJSON *tmp = temp_obj;
        snprintf(name_prefix, HE_BUS_MAX_NAME_LENGTH, "%s", tmp->string);
        temp_obj = temp_obj->next;
        decode_wifi_object_recurse(handle, tmp, wifi_def_obj, name_prefix);
    }
    return HE_BUS_RETURN_OK;
}

int decode_json_object(he_bus_handle_t handle, const char *json_name)
{
    char *raw_buffer;
    FILE *file = fopen(json_name, "r");
    if (file == NULL) {
        he_bus_core_error_print("Error: opening JSON file:%s\n", json_name);
        perror("Error opening file");
        return HE_BUS_RETURN_ERR;
    }

    // Seek to the end of the file
    fseek(file, 0, SEEK_END);

    // Get the current position (which is the size of the file)
    size_t fileSize = ftell(file);
    if ((long int)fileSize == HE_BUS_RETURN_ERR) {
        he_bus_core_error_print("Error getting file:%s size\n", json_name);
        fclose(file);
        return HE_BUS_RETURN_ERR;
    }

    raw_buffer = calloc(1, (fileSize + 1));
    printf("File size: %ld bytes\n", fileSize);

    // Seek to the start of the file
    fseek(file, 0, SEEK_SET);
    size_t bytesRead = fread(raw_buffer, 1, fileSize, file);
    fclose(file);

    if (fileSize != bytesRead) {
        he_bus_core_error_print("Error reading file:%s\n", json_name);
        he_bus_free(raw_buffer);
        return HE_BUS_RETURN_ERR;
    }

    raw_buffer[fileSize] = '\0'; // Null terminate the string

    cJSON *root_json = cJSON_Parse(raw_buffer);
    if (root_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            he_bus_core_error_print("Error before:%s\n", error_ptr);
        }
        he_bus_core_error_print("JSON parse failure for file:%s\n", json_name);
        he_bus_free(raw_buffer);
        cJSON_Delete(root_json);
        return HE_BUS_RETURN_ERR;
    }
    he_bus_core_info_print("[%s]JSON parse success for file:%s\njson content:\n%s\n",
        handle->component_name, json_name, raw_buffer);

    decode_wifi_objects(handle, root_json);

    he_bus_free(raw_buffer);
    // cJSON_free(root_json);
    cJSON_Delete(root_json);
    return HE_BUS_RETURN_OK;
}
