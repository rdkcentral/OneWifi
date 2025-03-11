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
#include "collection.h"
#include "wifi_webconfig.h"
#include "wifi_monitor.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"

webconfig_subdoc_object_t   assocdev_stats_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_stats_config, "AssociatedDeviceStats" },
};

webconfig_error_t init_assocdev_stats_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(assocdev_stats_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&assocdev_stats_objects, sizeof(assocdev_stats_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_assocdev_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_assocdev_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_assocdev_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_associated_device_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json, *st_obj_arr;
    webconfig_subdoc_decoded_data_t *params;
    char *str;
    time_t response_time;
    struct tm *local_time;
    char time_str[32] = {0};


    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL data Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    json = cJSON_CreateObject();
    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "Associated_Device_Stats");

    wifi_provider_response_t *assoc_dev_stats = params->collect_stats.stats;

    response_time = assoc_dev_stats->response_time;
    local_time = localtime(&response_time);
    if (local_time != NULL) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", local_time);
        cJSON_AddStringToObject(json, "Timestamp", time_str);
    }

    cJSON_AddNumberToObject(json, "VapIndex", assoc_dev_stats->args.vap_index);

    // encode stats config objects
    st_obj_arr = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "AssociatedDeviceStats", st_obj_arr);
    
    // Handle zero neighbor case
    if ((assoc_dev_stats->stat_array_size != 0) && (assoc_dev_stats->stat_pointer != NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoding stats config object\n", __func__, __LINE__);
        if (encode_assocdevice_params(assoc_dev_stats, st_obj_arr) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode stats config object\n", __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_encode;
        }
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: No associated device stats to encode\n", __func__, __LINE__);
    }

    str = cJSON_Print(json);

    data->u.encoded.raw = (webconfig_subdoc_encoded_raw_t)calloc(strlen(str) + 1, sizeof(char));
    if (data->u.encoded.raw == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d Failed to allocate memory.\n", __func__,__LINE__);
        cJSON_free(str);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded data is %s\n", __func__, __LINE__, str);
    memcpy(data->u.encoded.raw, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);

    return webconfig_error_none;
}

webconfig_error_t decode_associated_device_stats_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    unsigned int i;
    cJSON *json;
    webconfig_subdoc_decoded_data_t *params;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d\n", __func__, __LINE__);

    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    json = data->u.encoded.json;
    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    char *str;
    str = cJSON_Print(json);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Decoded Str is : %s\n", __func__, __LINE__, str);
    cJSON_free(str);

    doc = &config->subdocs[data->type];

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }
    }

    wifi_provider_response_t **assoc_st = (wifi_provider_response_t **)&params->collect_stats.stats;
    if (decode_assocdev_stats_object(assoc_st, json) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to decode stats config\n", __func__, __LINE__);
        cJSON_Delete(json);
        free((*assoc_st)->stat_pointer);
        free(*assoc_st);
        return webconfig_error_invalid_subdoc;
    }

    cJSON_Delete(json);

    return webconfig_error_none;
}
