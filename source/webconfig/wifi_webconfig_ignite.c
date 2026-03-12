/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

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

#include "collection.h"
#include "wifi_webconfig.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

webconfig_subdoc_object_t wifi_ignite_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version"    },
    { webconfig_subdoc_object_type_subdoc,  "SubDocName" },
    { webconfig_subdoc_object_type_config,  "Parameters" }
};

webconfig_error_t init_ignite_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(wifi_ignite_objects) / sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&wifi_ignite_objects,
        sizeof(wifi_ignite_objects));
    return webconfig_error_none;
}

webconfig_error_t access_ignite_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_ignite_subdoc(webconfig_t *config,
    webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_ignite_subdoc(webconfig_t *config,
    webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_ignite_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj, *obj_array;
    char *str;
    webconfig_subdoc_decoded_data_t *params;
    
    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL data pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }
    
    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }
    
    json = cJSON_CreateObject();
    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to create JSON object\n", __func__, __LINE__);
        return webconfig_error_encode;
    }
    
    data->u.encoded.json = json;
    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "ignite config");
    
    // FIX: Create ARRAY instead of object
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "Parameters", obj_array);
    
    for (unsigned int i = 0; i < params->num_radios; i++) {
        obj = cJSON_CreateObject();
        cJSON_AddItemToArray(obj_array, obj);
        
        // FIX: Pass the correct ignite_config for this radio
        if (encode_ignite_object(&params->ignite_config[i], obj) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode ignite config\n",
                __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_encode;
        }
    }
    
    str = cJSON_Print(json);
    data->u.encoded.raw = (webconfig_subdoc_encoded_raw_t)calloc(strlen(str) + 1, sizeof(char));
    if (data->u.encoded.raw == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to allocate memory\n", __func__, __LINE__);
        cJSON_free(str);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }
    
    memcpy(data->u.encoded.raw, str, strlen(str));
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_free(str);
    cJSON_Delete(json);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: Encoded success\n", __func__, __LINE__);
    return webconfig_error_none;
}

webconfig_error_t decode_ignite_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *params;
    cJSON *obj_array;
    cJSON *obj_config;
    cJSON *json;
    unsigned int size;

    params = &data->u.decoded;
    json = data->u.encoded.json;

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Entering decode\n", __func__, __LINE__);
    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }
    // Get the Parameters array
    obj_array = cJSON_GetObjectItem(json, "Parameters");
    if (obj_array == NULL || !cJSON_IsArray(obj_array)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Parameters is not an array\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_decode;
    }
    // Get array size
    size = cJSON_GetArraySize(obj_array);
    if (size < MIN_NUM_RADIOS || size > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of vap objects: %d, expected: %d\n",
            __func__, __LINE__, size, params->hal_cap.wifi_prop.numRadios);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }
    // Clear the ignite configs
    memset(params->ignite_config, 0, sizeof(ignite_config_t) * params->num_radios);
    // Iterate through each array item
    for (unsigned int i = 0; i < params->hal_cap.wifi_prop.numRadios; i++) {
        // Get the i-th object from the array
        obj_config = cJSON_GetArrayItem(obj_array, i);
        if (obj_config == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to get array item %d\n",
                __func__, __LINE__, i);
            cJSON_Delete(json);
            return webconfig_error_decode;
        }
        // Decode this specific ignite config
        if (decode_ignite_object(obj_config, &params->ignite_config[i]) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Config object validation failed for index %d\n",
                __func__, __LINE__, i);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }
    }

    cJSON_Delete(json);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: Decoded success\n", __func__, __LINE__);
    return webconfig_error_none;
}
