/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2025 RDK Management

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "bus.h"
#include "wifi_dml_api.h"
#include "wifi_dml_json_parser.h"
#include "wfa/wfa_data_model.h"

/* Forward declarations for JSON schema parsing functions */
static void traverse_schema(cJSON* root, cJSON* schema_node, const char* base_path, bus_handle_t *handle, bus_cb_setter_fn cb_setter);

static int bus_register_namespace(bus_handle_t *handle, char *full_namespace, bus_element_type_t element_type,
                                  bus_callback_table_t cb_table, data_model_properties_t  data_model_value, int num_of_rows)
{   
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: register_namespace:[%s] element_type:%d\n", __func__, __LINE__, full_namespace, element_type);

    bus_data_element_t dataElements = { 0 };

    dataElements.full_name       = full_namespace;
    dataElements.type            = element_type;
    dataElements.cb_table        = cb_table;
    dataElements.bus_speed       = slow_speed;
    dataElements.data_model_prop = data_model_value;

    if (element_type == bus_element_type_table) {
        uint32_t num_of_table_rows = 0;
        if (wifi_elem_num_of_table_row(full_namespace, &num_of_table_rows) == bus_error_success) {
            dataElements.num_of_table_row = num_of_table_rows;
        } else if (wfa_elem_num_of_table_row(full_namespace, &num_of_table_rows) == bus_error_success) {
            dataElements.num_of_table_row = num_of_table_rows;
        } else {
            dataElements.num_of_table_row = num_of_rows;
        }
        wifi_util_info_print(WIFI_DMCLI,"%s:%d: Add number of row:%d input value:%d\n", __func__, __LINE__, dataElements.num_of_table_row, num_of_rows);

        //Temporary added this @TODO TBD
        /* "Device.WiFi.AccessPoint.{i}" is already registered by core */
        if (strcmp(full_namespace, ACCESSPOINT_OBJ_TREE_NAME) == 0) {
            wifi_util_info_print(WIFI_DMCLI,"%s:%d: register_namespace avoid for this:[%s]\n", __func__, __LINE__, full_namespace);
            return 0;
        }
    }

    uint32_t num_elements = 1;

    bus_error_t rc = get_bus_descriptor()->bus_reg_data_element_fn(handle, &dataElements, num_elements);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d bus: bus_regDataElements failed:%s\n", __func__, __LINE__, full_namespace);
    }

    return RETURN_OK;
}

/* Convert YANG path to TR-181 path format */
static const char* yang_to_tr181(const char* yang_path)
{
    if (!yang_path) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Invalid input to yang_to_tr181\n", __func__, __LINE__);
        return NULL;
    }

    /* Mapping table for YANG to TR-181 conversions */
    struct yang_map {
        const char* yang;
        const char* tr181;
    };

    struct yang_map mappings[] = {
        { "DeviceList", "Device" },
        { "RadioList", "Radio" },
        { "BSSList", "BSS" },
        { "STAList", "STA" },
        { "NetworkSSIDList", "SSID" },
        { "OpClassScanList", "OpClassScan" },
        { "ChannelScanList", "ChannelScan" },
        { "NeighborList", "Neighbor" },
        { "ActiveChannelList", "CACActiveChannel" },
        { "AvailableChannelList", "CACAvailableChannel" },
        { "NonOccupancyChannelList", "CACNonOccupancyChannel" },
        { NULL, NULL }
    };

    /* Check for exact whole string match */
    for (int i = 0; mappings[i].yang != NULL; i++) {
        if (strcmp(yang_path, mappings[i].yang) == 0) {
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Path conversion: %s -> %s\n", __func__, __LINE__, mappings[i].yang, mappings[i].tr181);
            return mappings[i].tr181;
        }
    }

    /* It is tr181 path */
    return yang_path;
}

/* Resolve $ref like "#/definitions/Default8021Q_g" */
static cJSON* resolve_ref(cJSON* root, const char* ref_str)
{
    const char* path = NULL;
    char* path_copy = NULL;
    cJSON* node = NULL;
    char* token = NULL;

    if (!root || !ref_str || ref_str[0] != '#') {
        return NULL;
    }

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Resolving $ref: %s\n", __func__, __LINE__, ref_str);
    /* Skip "#/" prefix */
    path = ref_str;
    if (strncmp(path, "#/", 2) == 0) {
        path += 2;
    }

    /* Make a mutable copy of the path */
    path_copy = strdup(path);
    if (!path_copy) {
        return NULL;
    }

    node = root;
    token = strtok(path_copy, "/");

    while (token != NULL && node != NULL) {
        node = cJSON_GetObjectItem(node, token);
        token = strtok(NULL, "/");
    }

    free(path_copy);
    return node;
}

/* Merge ref_node properties into base object using references */
static cJSON* merge_with_references(cJSON* base, cJSON* ref_node)
{
    cJSON* child = NULL;

    if (!ref_node) {
        return base;
    }

    if (!base) {
        return ref_node;
    }

    /* Add references from ref_node to base */
    child = ref_node->child;
    while (child) {
        cJSON* existing = cJSON_GetObjectItem(base, child->string);

        if (!existing) {
            /* Key doesn't exist - add reference */
            cJSON_AddItemReferenceToObject(base, child->string, child);
        } else if (strcmp(child->string, "properties") == 0 &&
                   cJSON_IsObject(existing) && cJSON_IsObject(child)) {
            /* Both have "properties" object - recursively merge them */
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Recursively merging 'properties' objects\n",
                               __func__, __LINE__);
            merge_with_references(existing, child);
        }

        child = child->next;
    }

    return base;
}

/* Check if a variant is null-only */
static bool is_null_only_variant(cJSON* variant)
{
    cJSON* type = cJSON_GetObjectItem(variant, "type");

    if (!type) {
        return false;
    }

    if (cJSON_IsString(type)) {
        return strcmp(type->valuestring, "null") == 0;
    }

    if (cJSON_IsArray(type)) {
        cJSON* t = type->child;
        while (t) {
            if (cJSON_IsString(t) && strcmp(t->valuestring, "null") != 0) {
                return false;
            }
            t = t->next;
        }
        return true;
    }

    return false;
}

/* Resolve $ref if present on the node; otherwise return the node itself */
static cJSON* follow_ref_if_any(cJSON* root, cJSON* node)
{
    cJSON* ref = NULL;
    cJSON* resolved = NULL;
    cJSON* comb = NULL;
    cJSON* it = NULL;

    if (!node) {
        return NULL;
    }

    /* Resolve $ref and merge with current node */
    ref = cJSON_GetObjectItem(node, "$ref");
    if (ref && cJSON_IsString(ref)) {
        resolved = resolve_ref(root, ref->valuestring);
        if (resolved) {
            /* Recursively follow refs in the resolved object */
            resolved = follow_ref_if_any(root, resolved);
            if (resolved) {
                wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Merging $ref %s into parent node\n", 
                                   __func__, __LINE__, ref->valuestring);
                cJSON_DeleteItemFromObject(node, "$ref");
                merge_with_references(node, resolved);
                return node;
            }
        } else {
            wifi_util_info_print(WIFI_DMCLI, "%s:%d: Failed to resolve $ref: %s\n", 
                                __func__, __LINE__, ref->valuestring);
        }
    }

    /* Process oneOf/anyOf: merge all non-null variants */
    comb = cJSON_GetObjectItem(node, "oneOf");
    if (!comb) {
        comb = cJSON_GetObjectItem(node, "anyOf");
    }

    if (comb && cJSON_IsArray(comb)) {
        /* Check if already processed to avoid duplicate processing */
        if (cJSON_GetObjectItem(node, "_anyof_processed")) {
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Skipping already processed oneOf/anyOf\n", 
                               __func__, __LINE__);
            return node;
        }

        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Processing oneOf/anyOf with %d variants\n", 
                           __func__, __LINE__, cJSON_GetArraySize(comb));

        /* Process each variant - must complete iteration before deleting comb */
        it = comb->child;
        while (it) {
            cJSON* next_it = it->next;  /* Save next pointer before any modifications */

            /* Skip null-only variants */
            if (!is_null_only_variant(it)) {
                /* Resolve $ref if present in variant */
                cJSON* variant_ref = cJSON_GetObjectItem(it, "$ref");

                if (variant_ref && cJSON_IsString(variant_ref)) {
                    cJSON* ref_target = resolve_ref(root, variant_ref->valuestring);
                    if (ref_target) {
                        cJSON* variant_resolved = follow_ref_if_any(root, ref_target);
                        if (variant_resolved) {
                            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Merging variant $ref %s\n", 
                                              __func__, __LINE__, variant_ref->valuestring);
                            merge_with_references(node, variant_resolved);
                        }
                    }
                } else {
                    /* Inline variant - merge directly */
                    merge_with_references(node, it);
                }
            }
            it = next_it;  /* Use saved pointer for next iteration */
        }

        /* Mark as processed to prevent reprocessing on subsequent calls */
        cJSON_AddBoolToObject(node, "_anyof_processed", true);
    }

    return node;
}

/* Type string values MUST be one of the six primitive types
("null", "boolean", "object", "array", "number", or "string"),
or "integer" which matches any number with a zero fractional part. 
https://json-schema.org/draft/2020-12/json-schema-validation */
static void parse_property_type(cJSON* schema_node, data_model_properties_t* props)
{
    if (!schema_node || !props) {
        return;
    }

    cJSON* type = cJSON_GetObjectItem(schema_node, "type");

    if (type && cJSON_IsArray(type)) {
        cJSON* it = type->child;
        while (it) {
            /* Find first non-null type */
            if (cJSON_IsString(it) && strcmp(it->valuestring, "null") != 0) {
                break;
            }
            it = it->next;
        }
        type = it;
    }

    if (type && cJSON_IsString(type)) {
        if (strcmp(type->valuestring, "string") == 0) {
            props->data_format = bus_data_type_string;
        } else if (strcmp(type->valuestring, "boolean") == 0) {
            props->data_format = bus_data_type_boolean;
        } else if (strcmp(type->valuestring, "integer") == 0) {
            /* Integer types with minimum greater than or equal to 0 are unsigned */
            cJSON* minimum = cJSON_GetObjectItem(schema_node, "minimum");

            if (minimum && cJSON_IsNumber(minimum) && minimum->valuedouble >= 0) {
                props->data_format = bus_data_type_uint32;
            } else {
                props->data_format = bus_data_type_int32;
            }
        } else if (strcmp(type->valuestring, "number") == 0) {
            props->data_format = bus_data_type_double;
        } else if (strcmp(type->valuestring, "object") == 0) {
            props->data_format = bus_data_type_object;
        } else if (strcmp(type->valuestring, "array") == 0) {
            props->data_format = bus_data_type_none;
        } else {
            wifi_util_info_print(WIFI_DMCLI, "%s:%d: Unknown type: %s\n", __func__, __LINE__, type->valuestring);
        }
    }
}

/* Extract min/max range, type, enum, read/write from leaf node */
/* Expecting to enter after following all $ref / combiners */
static void parse_property_constraints(cJSON* schema_node, data_model_properties_t* props)
{
    if (!schema_node || !props) {
        return;
    }
    cJSON* writable = NULL;
    cJSON* minimum = NULL;
    cJSON* maximum = NULL;
    cJSON* str_enum = NULL;

    parse_property_type(schema_node, props);

    writable  = cJSON_GetObjectItem(schema_node, "writable");
    /* Default is read-only unless explicitly marked as writable */
    if (writable && cJSON_IsTrue(writable)) {
        props->data_permission = 1;
    } else {
        props->data_permission = 0;
        /* Skip validation parameters for read-only properties */
        return;     
    }

    /* min / max from JSON schema */
    minimum = cJSON_GetObjectItem(schema_node, "minimum");
    maximum = cJSON_GetObjectItem(schema_node, "maximum");

    if (minimum && cJSON_IsNumber(minimum)) {
        props->min_data_range = minimum->valuedouble;
    }

    if (maximum && cJSON_IsNumber(maximum)) {
        props->max_data_range = maximum->valuedouble;
    }

    str_enum = cJSON_GetObjectItem(schema_node, "enum");

    if (str_enum && cJSON_IsArray(str_enum)) {
        props->num_of_str_validation = cJSON_GetArraySize(str_enum);
        props->str_validation = malloc(sizeof(char *) * props->num_of_str_validation);
        if (props->str_validation == NULL) {
            props->num_of_str_validation = 0;
            return;
        }

        for (uint32_t i = 0; i < props->num_of_str_validation; i++) {
            cJSON *item = cJSON_GetArrayItem(str_enum, i);
            if (item != NULL && cJSON_IsString(item)) {
                props->str_validation[i] = malloc(strlen(item->valuestring) + 1);
                strncpy(props->str_validation[i], item->valuestring, strlen(item->valuestring) + 1);
            }
        }
    }
}

static bool schema_has_type(cJSON* schema, const char* want)
{
    if (!schema || !want) {
        return false;
    }
    
    cJSON* type = cJSON_GetObjectItem(schema, "type");
    if (!type) {
        return false;
    }
    
    if (cJSON_IsString(type)) {
        return strcmp(type->valuestring, want) == 0;
    }
    
    if (cJSON_IsArray(type)) {
        cJSON* it = type->child;
        while (it) {
            if (cJSON_IsString(it) && strcmp(it->valuestring, want) == 0) {
                return true;
            }
            it = it->next;
        }
    }
    return false;
}

/* Helper: get callbacks from parent object and clear table-specific handlers */
static void get_parent_callbacks(const char* tr181_path, bus_cb_setter_fn cb_setter,
                                 bus_callback_table_t* cb_table)
{
    bus_name_string_t parent_path = { 0 };
    const char* last_dot = strrchr(tr181_path, '.');

    if (!last_dot) {
        return;  /* No parent */
    }

    size_t parent_len = last_dot - tr181_path;
    snprintf(parent_path, sizeof(parent_path), "%.*s", (int)parent_len, tr181_path);

    cb_setter(parent_path, cb_table);

    /* Properties should not have table row handlers */
    cb_table->table_remove_row_handler = NULL;
    cb_table->table_add_row_handler = NULL;
}

/* Helper: register a property with callbacks and constraints */
static void register_property(const char* tr181_path, bus_handle_t *handle, 
                              bus_cb_setter_fn cb_setter,
                              const data_model_properties_t* props)
{
    bus_callback_table_t cb_table = { 0 };

    get_parent_callbacks(tr181_path, cb_setter, &cb_table);

    /* Clear set_handler for read-only properties */
    if (props->data_permission == 0) {
        cb_table.set_handler = NULL;
    }

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Registering property: %s (format=%d, permission=%d)\n", 
                       __func__, __LINE__, tr181_path, props->data_format, props->data_permission);
    bus_register_namespace(handle, (char*)tr181_path, bus_element_type_property,
                           cb_table, *props, 0);
}

/* Helper: register a leaf property with proper read/write permissions */
static void register_leaf_property(cJSON* schema_node, char* tr181_path,
                                   bus_handle_t *handle,
                                   bus_cb_setter_fn cb_setter)
{
    data_model_properties_t data_model_value = { 0 };

    parse_property_constraints(schema_node, &data_model_value);
    register_property(tr181_path, handle, cb_setter, &data_model_value);
}

/* Helper: register NumberOfEntries property for a table */
static void register_table_number_of_entries(const char* tr181_path, bus_handle_t *handle,
                                             bus_cb_setter_fn cb_setter)
{
    bus_name_string_t num_entries_path = { 0 };
    data_model_properties_t num_entries_props = {
        .data_format = bus_data_type_uint32,
        .data_permission = 0  /* Read-only */
    };

    snprintf(num_entries_path, sizeof(num_entries_path), "%sNumberOfEntries", tr181_path);

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Registering NumberOfEntries: %s\n", 
                        __func__, __LINE__, num_entries_path);
    register_property(num_entries_path, handle, cb_setter, &num_entries_props);
}

/* Handle ANY property under an object: decide if TABLE or PROPERTY */
static void handle_property_node(cJSON* root, char* tr181_path, cJSON* property_schema, bus_handle_t *handle, bus_cb_setter_fn cb_setter)
{
    bus_callback_table_t cb_table = { 0 };
    data_model_properties_t data_model_value = { 0 };
    cJSON* effective = NULL;
    cJSON* props_obj = NULL;
    cJSON* items = NULL;
    cJSON* items_eff = NULL;
    cJSON* item_props = NULL;
    bus_name_string_t table_name = { 0 };

    if (!property_schema || !tr181_path || !handle || !cb_setter) {
        return;
    }

    /* 1) follow top-level $ref / combiners if present */
    effective = follow_ref_if_any(root, property_schema);
    if (!effective) {
        return;
    }

    /* 2) If effective has properties -> expand (this handles $ref -> object with properties) */
    props_obj = cJSON_GetObjectItem(effective, "properties");
    if (props_obj && cJSON_IsObject(props_obj)) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Found object with properties at: %s\n", __func__, __LINE__, tr181_path);
        traverse_schema(root, effective, tr181_path, handle, cb_setter);
        return;
    }

    /* 3) If type is array -> register TABLE, and examine items, only if array type is object */
    if (schema_has_type(effective, "array")) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Found array type at: %s\n", __func__, __LINE__, tr181_path);
        items = cJSON_GetObjectItem(effective, "items");
        if (!items) {
            return;
        }

        items_eff = follow_ref_if_any(root, items);
        if (!items_eff) {
            return;
        }

        item_props = cJSON_GetObjectItem(items_eff, "properties");
        if (item_props && cJSON_IsObject(item_props)) {
            /* Object array - register as table */

            /* Register NumberOfEntries property for this table */
            register_table_number_of_entries(tr181_path, handle, cb_setter);

            snprintf(table_name, sizeof(table_name), "%s.{i}", tr181_path);
            parse_property_constraints(effective, &data_model_value);

            wifi_util_info_print(WIFI_DMCLI, "%s:%d: Registering table: %s\n", __func__, __LINE__, table_name);
            cb_setter(table_name, &cb_table);
            cb_table.get_handler = NULL;
            cb_table.set_handler = NULL;
            bus_register_namespace(handle, table_name, bus_element_type_table, cb_table, data_model_value, 0);

            traverse_schema(root, items_eff, table_name, handle, cb_setter);
        } else {
            /* Primitive array - register as property */
            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Found primitive array at: %s\n", __func__, __LINE__, tr181_path);
            register_leaf_property(items_eff, tr181_path, handle, cb_setter);
        }
        return;
    }

    /* 4) If type is object (but had no direct properties above) - treat as leaf object */
    if (schema_has_type(effective, "object")) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Found leaf object at: %s\n", __func__, __LINE__, tr181_path);
        register_leaf_property(effective, tr181_path, handle, cb_setter);
        return;
    }

    /* 5) Fallback: primitive (string/number/boolean/enum) */
    register_leaf_property(effective, tr181_path, handle, cb_setter);
}

/* Helper: check if property is auto-generated NumberOfEntries */
static bool is_number_of_entries_property(const char* property_name)
{
    if (!property_name) {
        return false;
    }
    
    size_t len = strlen(property_name);
    
    /* Check for *NumberOfEntries suffix (15 chars) */
    if (len > 15) {
        const char* suffix = property_name + len - 15;
        if (strcmp(suffix, "NumberOfEntries") == 0) {
            return true;
        }
    }
    
    /* Check for NumberOf* prefix (8 chars) */
    if (strncmp(property_name, "NumberOf", 8) == 0) {
        return true;
    }
    
    return false;
}

/* Traverse object schema and process all "properties" */
static void traverse_schema(cJSON* root, cJSON* schema_node, const char* base_path, bus_handle_t *handle, bus_cb_setter_fn cb_setter)
{
    cJSON* effective = NULL;
    cJSON* props = NULL;
    cJSON* child = NULL;
    bus_name_string_t tr181_path = { 0 };

    if (!schema_node || !handle || !cb_setter) {
        return;
    }

    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Traversing schema with base_path: %s\n", __func__, __LINE__, base_path ? base_path : "(null)");

    /* ensure we operate on resolved node (if schema_node is a wrapper with $ref) */
    effective = follow_ref_if_any(root, schema_node);
    if (!effective) {
        return;
    }

    props = cJSON_GetObjectItem(effective, "properties");
    if (!props || !cJSON_IsObject(props)) {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: No properties found at: %s\n", __func__, __LINE__, base_path ? base_path : "(null)");
        return;
    }

    child = props->child;
    while (child) {
        if (child->string) {
            const char* child_tr181 = NULL;

            /* Skip xxxxNumberOfEntries and NumberOfxxxx properties - they're auto-generated for tables */
            if (is_number_of_entries_property(child->string)) {
                wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Skipping auto-generated property: %s\n", 
                                   __func__, __LINE__, child->string);
                child = child->next;
                continue;
            }

            /* Convert child property name to TR-181 format first */
            child_tr181 = yang_to_tr181(child->string);

            /* Build TR-181 path */
            if (base_path == NULL || strlen(base_path) == 0) {
                snprintf(tr181_path, sizeof(tr181_path), "%s", child_tr181);
            } else if (base_path[strlen(base_path) - 1] != '.') {
                snprintf(tr181_path, sizeof(tr181_path), "%s.%s", base_path, child_tr181);
            } else {
                snprintf(tr181_path, sizeof(tr181_path), "%s%s", base_path, child_tr181);
            }

            wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Processing property: %s\n", __func__, __LINE__, tr181_path);
            handle_property_node(root, tr181_path, child, handle, cb_setter);
        }
        child = child->next;
    }
}

/* Internal function to process parsed JSON schema */
static int parse_and_register_schema_internal(bus_handle_t *handle, cJSON* root, const char* base_path,
    const char* search_key, bus_cb_setter_fn cb_setter)
{
    cJSON* props = NULL;
    cJSON* child = NULL;

    if (!handle || !root || !cb_setter) {
        return RETURN_ERR;
    }

    /* Find element matching search key */
    props = cJSON_GetObjectItem(root, "properties");
    if (!props) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: No properties found in schema root\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d: Starting schema registration with base_path: %s, search_key: %s\n", 
                         __func__, __LINE__, base_path ? base_path : "(null)", search_key ? search_key : "(null)");

    child = props->child;
    while (child) {
        if (base_path == NULL) {
            base_path = child->string;
        }
        /* If search_key is NULL, process all children, otherwise find matching child */
        if (search_key == NULL || (child->string && strstr(child->string, search_key) != NULL)) {
            traverse_schema(root, child, base_path, handle, cb_setter);
            if (search_key) {
                break;
            }
        }
        child = child->next;
    }

    return RETURN_OK;
}

/* Entry function to parse and register JSON schema from file */
static int parse_json_schema_file(bus_handle_t *handle, const char *filename, const char *base_path, const char *search_key, bus_cb_setter_fn cb_setter)
{
    FILE* f = NULL;
    long size = 0;
    char* buf = NULL;
    size_t read_bytes = 0;
    cJSON* root = NULL;
    int result = RETURN_ERR;

    /* Load file */
    f = fopen(filename, "rb");
    if (!f) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Failed to open file: %s\n", __func__, __LINE__, filename);
        return RETURN_ERR;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size < 0) {
        fclose(f);
        return RETURN_ERR;
    }

    buf = malloc(size + 1);
    if (!buf) {
        fclose(f);
        return RETURN_ERR;
    }

    read_bytes = fread(buf, 1, size, f);
    fclose(f);
    buf[read_bytes] = '\0';

    wifi_util_info_print(WIFI_DMCLI, "%s:%d: Loaded %zu bytes from %s\n", __func__, __LINE__, read_bytes, filename);

    root = cJSON_Parse(buf);
    free(buf);

    if (!root) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Failed to parse JSON file: %s\n", __func__, __LINE__, filename);
        return RETURN_ERR;
    }

    /* Parse schema with provided parameters */
    result = parse_and_register_schema_internal(handle, root, base_path, search_key, cb_setter);

    cJSON_Delete(root);
    return result;
}

int parse_json_schema_and_register(bus_handle_t *handle, const char *json_schema_filename, 
                                   const char *base_path, const char *search_key,
                                   bus_cb_setter_fn cb_setter)
{
    int rc = RETURN_ERR;

    if (!handle || !json_schema_filename || !cb_setter) {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Invalid parameters\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:%d: Parsing JSON schema: %s with base path: %s\n",
                         __func__, __LINE__, json_schema_filename, base_path ? base_path : "(null)");

    rc = parse_json_schema_file(handle, json_schema_filename, base_path, search_key, cb_setter);

    if (rc == RETURN_OK) {
        wifi_util_info_print(WIFI_DMCLI, "%s:%d: Successfully parsed and registered schema\n", 
                            __func__, __LINE__);
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Failed to parse schema: %s\n", 
                             __func__, __LINE__, json_schema_filename);
    }

    return rc;
}

int parse_and_register_wfa_schema(bus_handle_t *handle, const char *json_schema_filename)
{
    return parse_json_schema_and_register(handle, json_schema_filename, 
                                          "Device.WiFi.DataElements.Network", "wfa-dataelements:Network",
                                          wfa_set_bus_callbackfunc_pointers);
}

int parse_and_register_native_dml_schema(bus_handle_t *handle, const char *json_schema_filename)
{
    return parse_json_schema_and_register(handle, json_schema_filename, 
                                          NULL, NULL,
                                          wifi_set_bus_callbackfunc_pointers);
}
