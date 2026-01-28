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

#ifndef WIFI_DML_JSON_PARSER_H
#define WIFI_DML_JSON_PARSER_H

#include "bus.h"
#include "cJSON.h"

/* Callback function pointer type for setting bus callbacks */
typedef int (*bus_cb_setter_fn)(const char *full_namespace, bus_callback_table_t *cb_table);

/**
 * @brief Parse JSON Schema and register data model elements with bus system
 * 
 * This function parses JSON Schema files (draft 2020-12 format) and automatically registers
 * all data model elements with the bus system. It handles complex schema features including:
 * - $ref resolution (recursive references to definitions)
 * - oneOf/anyOf variant merging (combines properties from all non-null variants)
 * - YANG to TR-181 path conversions (e.g., "DeviceList" -> "Device")
 * - Automatic NumberOfEntries property generation for tables
 * - Type inference (string, integer, boolean, array, object)
 * - Read/write permission handling via "writable" attribute
 * - Validation constraints (min/max ranges, enums)
 * 
 * Supports both WFA Data Elements schemas and Native WiFi data models.
 * 
 * @param handle Pointer to the bus handle
 * @param json_schema_filename Path to the JSON schema file to parse
 * @param base_path Base TR-181 path for registration (e.g., "Device.WiFi.DataElements.Network")
 *                  or NULL to use root property names from schema
 * @param search_key Optional property name to search for (e.g., "wfa-dataelements:Network")
 *                   or NULL to process all root properties
 * @param callback_setter Function pointer to retrieve bus callbacks for each namespace
 *                        (e.g., wifi_set_bus_callbackfunc_pointers or wfa_set_bus_callbackfunc_pointers)
 * @return RETURN_OK on success, RETURN_ERR on failure
 */
int parse_json_schema_and_register(bus_handle_t *handle, const char *json_schema_filename, 
                                   const char *base_path, const char *search_key,
                                   bus_cb_setter_fn callback_setter);

/**
 * @brief Parse and register WFA Data Elements JSON schema
 * 
 * Wrapper that parses WFA Data Elements schema and registers all elements
 * under Device.WiFi.DataElements.Network namespace. Automatically handles WFA-specific
 * YANG naming conventions and converts them to TR-181 format.
 * 
 * @param handle Pointer to the bus handle
 * @param json_schema_filename Path to the WFA Data Elements JSON schema file
 * @return RETURN_OK on success, RETURN_ERR on failure
 */
int parse_and_register_wfa_schema(bus_handle_t *handle, const char *json_schema_filename);

/**
 * @brief Parse and register native WiFi data model JSON schema
 *
 * Wrapper that parses native WiFi data model schema and registers all elements.
 * Processes all root properties in the schema without filtering by search key.
 *
 * @param handle Pointer to the bus handle
 * @param json_schema_filename Path to the native DML JSON schema file
 * @return RETURN_OK on success, RETURN_ERR on failure
 */
int parse_and_register_native_dml_schema(bus_handle_t *handle, const char *json_schema_filename);

#endif // WIFI_DML_JSON_PARSER_H
