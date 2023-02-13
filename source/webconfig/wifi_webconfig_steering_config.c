/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include "secure_wrapper.h"
#include "collection.h"
#include "msgpack.h"
#include "wifi_webconfig.h"
#include "wifi_monitor.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"

webconfig_subdoc_object_t   steering_config_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_steering_config, "WifiSteeringConfig" },
};

webconfig_error_t init_steering_config_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(steering_config_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&steering_config_objects, sizeof(steering_config_objects));

    return webconfig_error_none;
}

 webconfig_error_t access_check_steer_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}


webconfig_error_t translate_from_steering_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) == webconfig_data_descriptor_translate_to_ovsdb) {
        if (translate_to_ovsdb_tables(webconfig_subdoc_type_steering_config, data) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t translate_to_steering_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (translate_from_ovsdb_tables(webconfig_subdoc_type_steering_config, data) != webconfig_error_none) {
            return webconfig_error_translate_from_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) == webconfig_data_descriptor_translate_from_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t encode_steering_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *st_arr_obj;
    webconfig_subdoc_decoded_data_t *params;
    char *str;

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "steering config");

    // encode steering config objects
    st_arr_obj = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiSteeringConfig", st_arr_obj);

    if (encode_steering_config_object(params->steering_config_map, st_arr_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode steering config object\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    memset(data->u.encoded.raw, 0, MAX_SUBDOC_SIZE);
    str = cJSON_Print(json);
    memcpy(data->u.encoded.raw, str, strlen(str));
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_free(str);
    cJSON_Delete(json);

    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (free_steering_config_entries(data) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: steering config free failed\n", __func__, __LINE__);
            return webconfig_error_encode;
        }
    }

    return webconfig_error_none;
}

webconfig_error_t decode_steering_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *st_arr_obj;
    unsigned int i;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;

    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (json == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    char *str;
    str = cJSON_Print(json);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Decoded Str is : %s\n", __func__, __LINE__, str);
    cJSON_free(str);


    doc = &config->subdocs[data->type];

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }
    }

    // decode steering config objects
    st_arr_obj = cJSON_GetObjectItem(json, "WifiSteeringConfig");
    if ((st_arr_obj == NULL) && (cJSON_IsObject(st_arr_obj) == false)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Steer config object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }


    if (decode_steering_config_object(&params->steering_config_map, st_arr_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: error decoding steering config\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    cJSON_Delete(json);
    return webconfig_error_none;
}