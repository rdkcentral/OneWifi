#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "bus.h"
#include "wifi_data_model_parse.h"
#include "wifi_data_model.h"
#include "wifi_dml_api.h"

int set_bus_callbackfunc_pointers(char *full_namespace, bus_callback_table_t *cb_table)
{
    bus_data_cb_func_t bus_data_cb[] = {
        //wifi event cb func
        { WIFI_OBJ_TREE_NAME,
            { wifi_get_param_value, wifi_set_param_value, NULL,
              NULL, wifi_event_sub_handler, NULL }},

        //wifi radio event cb func
        { RADIO_OBJ_TREE_NAME,
            { radio_get_param_value, radio_set_param_value, radio_table_add_row_handler,
              radio_table_remove_row_handler, radio_event_sub_handler, NULL }},

        //wifi accesspoint event cb func
        { ACCESSPOINT_OBJ_TREE_NAME,
            { accesspoint_get_param_value, accesspoint_set_param_value, accesspoint_table_add_row_handler,
              accesspoint_table_remove_row_handler, accesspoint_event_sub_handler, NULL }},

        //wifi ssid event cb func
        { SSID_OBJ_TREE_NAME,
            { ssid_get_param_value, ssid_set_param_value, ssid_table_add_row_handler,
              ssid_table_remove_row_handler, ssid_event_sub_handler, NULL }},

        //wifi security event cb func
        { SECURITY_OBJ_TREE_NAME,
            { security_get_param_value, security_set_param_value, NULL,
              NULL, security_event_sub_handler, NULL }},

        //wifi radius security event cb func
        { RADIUS_SEC_OBJ_TREE_NAME,
            { radius_sec_get_param_value, radius_sec_set_param_value, NULL,
              NULL, radius_sec_event_sub_handler, NULL }},

        //wifi radius security event cb func
        { AUTH_SEC_OBJ_TREE_NAME,
            { auth_sec_get_param_value, auth_sec_set_param_value, NULL,
              NULL, auth_sec_event_sub_handler, NULL }},

        //wifi macfilter event cb func
        { MACFILTER_OBJ_TREE_NAME,
            { macfilter_get_param_value, macfilter_set_param_value, macfilter_table_add_row_handler,
              macfilter_table_remove_row_handler, macfilter_event_sub_handler, NULL }},

        //wifi associated_sta event cb func
        { ASSOCIATED_STA_OBJ_TREE_NAME,
            { associated_sta_get_param_value, NULL, associated_sta_table_add_row_handler,
              associated_sta_table_remove_row_handler, associated_sta_event_sub_handler, NULL }},

        //wifi interworking event cb func
        { INTERWORKING_OBJ_TREE_NAME,
            { interworking_get_param_value, interworking_set_param_value, NULL,
              NULL, interworking_event_sub_handler, NULL }},

        //wifi connection control event cb func
        { CONN_CTRL_OBJ_TREE_NAME,
            { conn_ctrl_get_param_value, conn_ctrl_set_param_value, NULL,
              NULL, conn_ctrl_event_sub_handler, NULL }},

        //wifi pre connection control event cb func
        { PRE_CONN_CTRL_OBJ_TREE_NAME,
            { pre_conn_ctrl_get_param_value, pre_conn_ctrl_set_param_value, NULL,
              NULL, pre_conn_ctrl_event_sub_handler, NULL }},

        //wifi post connection control event cb func
        { POST_CONN_CTRL_OBJ_TREE_NAME,
            { post_conn_ctrl_get_param_value, post_conn_ctrl_set_param_value, NULL,
              NULL, post_conn_ctrl_event_sub_handler, NULL }},

        //wifi wps event cb func
        { WPS_OBJ_TREE_NAME,
            { wps_get_param_value, wps_set_param_value, NULL,
              NULL, wps_event_sub_handler, NULL }},

        //wifi interworking serv event cb func
        { INTERWORKING_SERV_OBJ_NAME,
            { interworking_serv_get_param_value, interworking_serv_set_param_value, NULL,
              NULL, interworking_serv_event_sub_handler, NULL }},

        //wifi passpoint event cb func
        { PASSPOINT_OBJ_TREE_NAME,
            { passpoint_get_param_value, passpoint_set_param_value, NULL,
              NULL, passpoint_event_sub_handler, NULL }},

        //wifi client report event cb func
        { WIFI_CLIENT_REPORT_OBJ_NAME,
            { wifi_client_report_get_param_value, wifi_client_report_set_param_value, NULL,
              NULL, wifi_client_report_event_sub_handler, NULL }},

        //wifi client default report event cb func
        { WIFI_CLIENT_DEF_REPORT_OBJ_NAME,
            { wifi_client_def_report_get_param_value, wifi_client_def_report_set_param_value, NULL,
              NULL, wifi_client_def_report_event_sub_handler, NULL }},

        //wifi event cb func
        { NEIG_WIFI_DIAG_OBJ_NAME,
            { neig_wifi_diag_get_param_value, neig_wifi_diag_set_param_value, NULL,
              NULL, neig_wifi_diag_event_sub_handler, NULL }},

        //wifi event cb func
        { NEIG_DIAG_RESULT_OBJ_NAME,
            { neig_diag_result_get_param_value, NULL,
              neig_diag_result_table_add_row_cb, neig_diag_result_table_remove_row_cb,
              neig_diag_result_event_sub_cb, NULL }},

        //wifi ap macfilter event cb func
        { AP_MACFILTER_TREE_NAME,
            { ap_macfilter_get_param_value, ap_macfilter_set_param_value, NULL,
              NULL, ap_macfilter_event_sub_handler, NULL }},

	//wifi region code event cb func
        { WIFI_REGION_OBJ_NAME,
            { wifi_region_code_get_param_value, wifi_region_code_set_param_value, NULL,
              NULL, NULL, NULL }}
    };

    bus_data_cb_func_t bus_default_data_cb = { " ",
        { default_get_param_value, default_set_param_value, default_table_add_row_handler,
          default_table_remove_row_handler, default_event_sub_handler, NULL }
    };

    uint32_t index = 0;
    bool     table_found = false;

    for (index = 0; index < (uint32_t)ARRAY_SZ(bus_data_cb); index++) {
        if (STR_CMP(full_namespace, bus_data_cb[index].cb_table_name)) {
            memcpy(cb_table, &bus_data_cb[index].cb_func, sizeof(bus_callback_table_t));
            table_found = true;
            break;
        }
    }

    if (table_found == false) {
        wifi_util_info_print(WIFI_DMCLI,"%s:%d:default cb set for namespace:[%s]\n", __func__, __LINE__, full_namespace);
        memcpy(cb_table, &bus_default_data_cb.cb_func, sizeof(bus_callback_table_t));
    }

    return RETURN_OK;
}

int bus_register_namespace(bus_handle_t *handle, char *full_namespace, bus_element_type_t element_type,
                            bus_callback_table_t cb_table, data_model_properties_t  data_model_value, int num_of_rows)
{   
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: register_namespace:[%s] element_type:%d\n", __func__, __LINE__, full_namespace, element_type);
        
    bus_data_element_t dataElements = { 0 };

    dataElements.full_name       = full_namespace;
    //snprintf(dataElements.full_name, BUS_MAX_NAME_LENGTH,"%s", full_namespace);
    dataElements.type            = element_type;
    dataElements.cb_table        = cb_table;
    dataElements.bus_speed       = slow_speed;
    dataElements.data_model_prop = data_model_value;

    if (element_type == bus_element_type_table) {
        //@TODO Add get handler to get table size.
        uint32_t num_of_table_rows;
        if (wifi_elem_num_of_table_row(full_namespace, &num_of_table_rows) == bus_error_success) {
            dataElements.num_of_table_row = num_of_table_rows;
        } else {
            dataElements.num_of_table_row = num_of_rows;
        }
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: Add number of row:%d input value:%d\n", __func__, __LINE__, dataElements.num_of_table_row, num_of_rows);

        //Tomporary added this @TODO TBD
        if (strcmp(full_namespace, ACCESSPOINT_OBJ_TREE_NAME) == 0) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: register_namespace avoid for this:[%s]\n", __func__, __LINE__, full_namespace);
            return 0;
        }
    }

#if 0
    element_node_t *node = bus_insert_element(handle, handle->root_element, &dataElements);
    if (node != NULL) {
        node->data_model_value = data_model_value;
    }
#else
    uint32_t num_elements = 1;

    bus_error_t rc = get_bus_descriptor()->bus_reg_data_element_fn(handle, &dataElements, num_elements);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d bus: bus_regDataElements failed:%s\n", __func__, __LINE__, full_namespace);
    }
#endif

    return RETURN_OK;
}

int get_int_type_from_str(char *int_str_type, bus_data_type_t *data_format)
{
    if (!strncmp(int_str_type, "uint32_t", strlen("uint32_t"))) {
        *data_format = bus_data_type_uint32;
    } else if (!strncmp(int_str_type, "uint16_t", strlen("uint16_t"))) {
        *data_format = bus_data_type_uint16;
    } else if (!strncmp(int_str_type, "uint8_t", strlen("uint8_t"))) {
        *data_format = bus_data_type_uint8;
    } else if (!strncmp(int_str_type, "int32_t", strlen("int32_t"))) {
        *data_format = bus_data_type_int32;
    } else if (!strncmp(int_str_type, "int16_t", strlen("int16_t"))) {
        *data_format = bus_data_type_int16;
    } else if (!strncmp(int_str_type, "int8_t", strlen("int8_t"))) {
        *data_format = bus_data_type_int8;
    } else {
        *data_format = bus_data_type_int32;
    }
    return RETURN_OK;
}

int decode_definition_str_type(char *str_value, char *data_str_type, bus_data_type_t *data_format)
{
    if (!strncmp(str_value, "integer", strlen("integer"))) {
        get_int_type_from_str(data_str_type, data_format);
    } else if (!strncmp(str_value, "bool", strlen("bool"))) {
        *data_format = bus_data_type_boolean;
    } else if (!strncmp(str_value, "string", strlen("string"))) {
        *data_format = bus_data_type_string;
    } else if (!strncmp(str_value, "unsigned_int", strlen("unsigned_int"))) {
        *data_format = bus_data_type_uint32;
    }

    return RETURN_OK;
}

int get_data_model_properties(cJSON *wifi_def_obj, char *data_str_type, data_model_properties_t *data_model_value)
{
    cJSON *param;
    decode_json_param_object(wifi_def_obj, data_str_type, param);

    param = param->child;
    while(param != NULL) {
        if (!strncmp(param->string, "type", strlen("type"))) {
            decode_definition_str_type(param->valuestring, data_str_type, &data_model_value->data_format);
	} else if (!strncmp(param->string, "minimum", strlen("minimum"))) {
            data_model_value->min_data_range = param->valuedouble;
        } else if (!strncmp(param->string, "maximum", strlen("maximum"))) {
            data_model_value->max_data_range = param->valuedouble;
        } else if (!strncmp(param->string, "enum", strlen("enum"))) {
            data_model_value->num_of_str_validation = cJSON_GetArraySize(param);
            data_model_value->str_validation = malloc(sizeof(char *) * data_model_value->num_of_str_validation);
            VERIFY_NULL_WITH_RETURN_INT(data_model_value->str_validation);
            for (uint32_t i = 0; i < data_model_value->num_of_str_validation; i++) {
                cJSON *item = cJSON_GetArrayItem(param, i);
                if (item != NULL && cJSON_IsString(item)) {
                    data_model_value->str_validation[i] = malloc(strlen(item->valuestring) + 1);
                    strncpy(data_model_value->str_validation[i], item->valuestring, strlen(item->valuestring) + 1);
                }
            }
        }
        param = param->next;
    }

    return RETURN_OK;
}

static int add_array_node_elem(cJSON *main_array_obj, uint32_t num_of_elements, char *name_prefix,
                                cJSON *wifi_def_obj, bus_handle_t *handle, bus_callback_table_t cb_table)
{
    cJSON *current_element;
    cJSON *param;
    char  full_namespace[128];
    bus_element_type_t      element_type     = bus_element_type_property;
    data_model_properties_t data_model_value = { 0 };

    for (uint32_t index = 0; index < num_of_elements; index++) {
        current_element = cJSON_GetArrayItem(main_array_obj, index);
        current_element = current_element->child;
        VERIFY_NULL_WITH_RETURN_INT(current_element);
        if (current_element->child != NULL) {
            param = current_element->child;
            if (strncmp(param->string, LIST_OF_DEFINITION_NAME, strlen(LIST_OF_DEFINITION_NAME)) == 0) {
                uint32_t sub_num_of_elem = cJSON_GetArraySize(param);
                bus_callback_table_t sub_elem_cb_table;
                snprintf(full_namespace, sizeof(full_namespace), "%s.%s", name_prefix, current_element->string);
                set_bus_callbackfunc_pointers(full_namespace, &sub_elem_cb_table);
                add_array_node_elem(param, sub_num_of_elem, full_namespace, wifi_def_obj, handle, sub_elem_cb_table);
                continue;
            } else if (strncmp(param->string, MAX_NUM_OF_OBJECTS_NAME, strlen(MAX_NUM_OF_OBJECTS_NAME) + 1) == 0) {
                uint32_t sub_num_of_elem = cJSON_GetArraySize(param->next);
                uint32_t l_num_of_tables = param->valuedouble;
                bus_element_type_t temp_element_type = bus_element_type_table;
                bus_callback_table_t   temp_cb_table, fetch_cb_table;

                //main table register
                snprintf(full_namespace, sizeof(full_namespace), "%s.%s", name_prefix, current_element->string);
                set_bus_callbackfunc_pointers(full_namespace, &fetch_cb_table);

                temp_cb_table = fetch_cb_table;
                temp_cb_table.get_handler = NULL;
                temp_cb_table.set_handler = NULL;

                strcat(full_namespace, ".{i}");
                memset(&data_model_value, 0, sizeof(data_model_value));
                bus_register_namespace(handle, full_namespace, temp_element_type, temp_cb_table, data_model_value, l_num_of_tables);

		//We don't need table handlers callback for table paramters.
                fetch_cb_table.table_remove_row_handler = NULL;
                fetch_cb_table.table_add_row_handler = NULL;
                add_array_node_elem(param->next, sub_num_of_elem, full_namespace, wifi_def_obj, handle, fetch_cb_table);
                continue;
	    }
        }
        snprintf(full_namespace, sizeof(full_namespace), "%s.%s", name_prefix, current_element->string);
        decode_json_param_string(current_element, "type", param);
        memset(&data_model_value, 0, sizeof(data_model_value));
        get_data_model_properties(wifi_def_obj, param->valuestring, &data_model_value);
        decode_json_param_bool(current_element, "writable", param);
        data_model_value.data_permission = (param->type & cJSON_True) ? true : false;
        bus_register_namespace(handle, full_namespace, element_type, cb_table, data_model_value, 0);
    }
    return RETURN_OK;
}

static int construct_namespace_and_register(bus_handle_t *handle, cJSON* cfg_param, cJSON *wifi_def_obj, char *l_name_prefix)
{
    bus_name_string_t      name_prefix;
    bus_element_type_t     element_type     = bus_element_type_property;
    bus_callback_table_t   cb_table         = { 0 };
    data_model_properties_t   data_model_value = { 0 };

    strcpy(name_prefix, l_name_prefix);
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: namespace:%s\n", __func__, __LINE__, name_prefix);

    if (cJSON_IsObject(cfg_param) == true) {
        //decode individual param and set it to bus.
        cJSON *current_element = cfg_param->child;
        cJSON *param;
        cJSON *tmp;
        char  full_namespace[128];
        element_type = bus_element_type_method;

        set_bus_callbackfunc_pointers(name_prefix, &cb_table);
        while(current_element != NULL) {
            validate_current_json_obj_param_name(current_element);
            snprintf(full_namespace, sizeof(full_namespace), "%s.%s", name_prefix, current_element->string);
            tmp = current_element->child;
            if (tmp->string != NULL && strncmp(tmp->string, LIST_OF_DEFINITION_NAME, strlen(LIST_OF_DEFINITION_NAME)) == 0) {
                construct_namespace_and_register(handle, tmp, wifi_def_obj, full_namespace);
            } else if (tmp->string != NULL && strncmp(tmp->string, MAX_NUM_OF_OBJECTS_NAME, strlen(MAX_NUM_OF_OBJECTS_NAME)) == 0) {
                construct_namespace_and_register(handle, tmp->prev, wifi_def_obj, full_namespace);
            } else {
                decode_json_param_string(current_element, "type", param);
                memset(&data_model_value, 0, sizeof(data_model_value));
                get_data_model_properties(wifi_def_obj, param->valuestring, &data_model_value);
                decode_json_param_bool(current_element, "writable", param);
                data_model_value.data_permission = (param->type & cJSON_True) ? true : false;
                bus_register_namespace(handle, full_namespace, element_type, cb_table, data_model_value, 0);
            }
            current_element = current_element->next;
        }
    } else if (cJSON_IsArray(cfg_param) == true) {
        int   num_of_tables = 0;

        if (cfg_param->prev != NULL && cfg_param->prev->string != NULL) {
            if ((strncmp(cfg_param->prev->string, MAX_NUM_OF_OBJECTS_NAME, strlen(MAX_NUM_OF_OBJECTS_NAME) + 1) == 0)
                    && (cJSON_IsNumber(cfg_param->prev) == true)) {
                num_of_tables = cfg_param->prev->valuedouble;
	    }
	}

        //snprintf(name_prefix, BUS_MAX_NAME_LENGTH, "%s.%s", name_prefix, "{i}");
	strcat(name_prefix, ".");
        strcat(name_prefix, "{i}");
        element_type = bus_element_type_table;
        set_bus_callbackfunc_pointers(name_prefix, &cb_table);

        bus_callback_table_t   temp_cb_table         = cb_table;
        temp_cb_table.get_handler = NULL;
        temp_cb_table.set_handler = NULL;
        memset(&data_model_value, 0, sizeof(data_model_value));
        //main table register
        bus_register_namespace(handle, name_prefix, element_type, temp_cb_table, data_model_value, num_of_tables);

        //We don't need table handlers callback for table paramters.
        cb_table.table_remove_row_handler = NULL;
        cb_table.table_add_row_handler = NULL;

        int num_of_elements = cJSON_GetArraySize(cfg_param);
        cJSON *current_element;

        for (int index = 0; index < num_of_elements; index++) {
            current_element = cJSON_GetArrayItem(cfg_param, index);
            if (current_element == NULL) {
                wifi_util_error_print(WIFI_DMCLI,"%s Item at index %d not found.\n", __func__, index);
                continue;
            }

            if(cJSON_IsObject(current_element) == true) {
                construct_namespace_and_register(handle, current_element, wifi_def_obj, name_prefix);
            } else {
                uint32_t temp_num_of_elements = cJSON_GetArraySize(cfg_param);
                add_array_node_elem(cfg_param, temp_num_of_elements, name_prefix, wifi_def_obj, handle, cb_table);
            }
        }
    } else {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: wrong wifi config object type\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

static void decode_wifi_object_recurse(bus_handle_t *handle, cJSON* node, cJSON *wifi_def_obj, char *l_name_prefix)
{   
    VERIFY_NULL(node);
    cJSON* child = node->child;
    bus_name_string_t name_prefix;
    char  new_name_prefix[128];
    
    snprintf(name_prefix, BUS_MAX_NAME_LENGTH, "%s", l_name_prefix);
    
    while(child)
    {   
        cJSON* tmp = child;
        if (tmp->string != NULL && strncmp(tmp->string, LIST_OF_DEFINITION_NAME, strlen(LIST_OF_DEFINITION_NAME)) == 0) {
            construct_namespace_and_register(handle, tmp, wifi_def_obj, name_prefix);
            child = child->next; 
            continue;
        }
        snprintf(new_name_prefix, sizeof(new_name_prefix), "%s.%s", name_prefix, tmp->string);
        child = child->next;
        decode_wifi_object_recurse(handle, tmp, wifi_def_obj, new_name_prefix);
    }
}

static int decode_wifi_objects(bus_handle_t *handle, cJSON *root_obj)
{
    if (root_obj == NULL) {
        return RETURN_ERR;
    }
    cJSON *wifi_def_obj;

    decode_json_param_object(root_obj, WIFI_OBJ_DEFINITIONS_NAME, wifi_def_obj);

    cJSON* temp_obj = wifi_def_obj->next;
    bus_name_string_t name_prefix;

    while(temp_obj)
    {
        cJSON* tmp = temp_obj;
        snprintf(name_prefix, BUS_MAX_NAME_LENGTH, "%s", tmp->string);
        temp_obj = temp_obj->next;
        decode_wifi_object_recurse(handle, tmp, wifi_def_obj, name_prefix);
    }
    return RETURN_OK;
}

int decode_json_obj(bus_handle_t *handle, const char *json_name)
{
    char *raw_buffer;
    FILE *file = fopen(json_name, "r");
    if (file == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"Error: opening JSON file:%s\n", json_name);
        perror("Error opening file");
        return RETURN_ERR;
    }

    // Seek to the end of the file
    fseek(file, 0, SEEK_END);

    // Get the current position (which is the size of the file)
    size_t fileSize = ftell(file);
    if ((long int)fileSize == RETURN_ERR) {
        wifi_util_error_print(WIFI_DMCLI,"Error getting file:%s size\n", json_name);
        fclose(file);
        return RETURN_ERR;
    }

    raw_buffer = calloc(1, (fileSize + 1));
    printf("File size: %d bytes\n", fileSize);

    // Seek to the start of the file
    fseek(file, 0, SEEK_SET);
    size_t bytesRead = fread(raw_buffer, 1, fileSize, file);
    fclose(file);

    if (fileSize != bytesRead) {
        wifi_util_error_print(WIFI_DMCLI,"Error reading file:%s\n", json_name);
        free(raw_buffer);
        return RETURN_ERR;
    }

    raw_buffer[fileSize] = '\0';  // Null terminate the string

    cJSON *root_json = cJSON_Parse(raw_buffer);
    if (root_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            wifi_util_error_print(WIFI_DMCLI,"Error before:%s\n", error_ptr);
        }
        wifi_util_error_print(WIFI_DMCLI,"JSON parse failure for file:%s\n", json_name);
        free(raw_buffer);
        cJSON_Delete(root_json);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_DMCLI,"[%s]JSON parse success for file:%s\njson content:\n%s\n", __func__,
                            json_name, raw_buffer);

    decode_wifi_objects(handle, root_json);

    free(raw_buffer);
    //cJSON_free(root_json);
    cJSON_Delete(root_json);

    return RETURN_OK;
}
