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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include "collection.h"
#include "wifi_monitor.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"

webconfig_subdoc_object_t   em_config_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_em_config, "WifiEMConfig" },
};

webconfig_error_t init_em_config_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(em_config_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&em_config_objects, sizeof(em_config_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_em_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_em_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_em_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_easymesh) == webconfig_data_descriptor_translate_from_easymesh) {
        if (config->proto_desc.translate_from(webconfig_subdoc_type_em_config, data) != webconfig_error_none) {
            if ((data->descriptor & webconfig_data_descriptor_translate_from_easymesh) == webconfig_data_descriptor_translate_from_easymesh) {
                return webconfig_error_translate_from_easymesh;
            }
        }
    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t encode_em_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json, *obj_emconfig, *device_list, *device_obj, *policy_obj;
    char *str;
    webconfig_subdoc_decoded_data_t *params;

    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: NULL data Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    json = cJSON_CreateObject();
    if (json == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: json create object failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "Easymesh Config");

    cJSON *array_emconfig = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiEMConfig", array_emconfig);

    obj_emconfig = cJSON_CreateObject();
    cJSON_AddItemToArray(array_emconfig, obj_emconfig);

    if (encode_em_config_object(&params->em_config, obj_emconfig) != webconfig_error_none) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Failed to encode wifi easymesh config\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    str = cJSON_Print(json);

    data->u.encoded.raw = (webconfig_subdoc_encoded_raw_t)calloc(strlen(str) + 1, sizeof(char));
    if (data->u.encoded.raw == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Failed to allocate memory.\n", __func__, __LINE__);
        cJSON_free(str);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    memcpy(data->u.encoded.raw, str, strlen(str));
    wifi_util_info_print(WIFI_EM, "%s:%d: encode success %s\n", __func__, __LINE__, str);
    cJSON_free(str);
    cJSON_Delete(json);
    return webconfig_error_none;
}

webconfig_error_t decode_em_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *params;
    cJSON *json, *em_config;
    
    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    json = data->u.encoded.json;
    if (json == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    memset(&params->em_config, 0, sizeof(em_config_t));

    em_config = cJSON_GetObjectItem(json, "WifiEMConfig");
    if (em_config == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: EMConfig object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_EM, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    if (cJSON_IsArray(em_config)) {
        int arr_sz = cJSON_GetArraySize(em_config);
        for (int i = 0; i < arr_sz; i++) {
            const cJSON *policy_cfg = cJSON_GetArrayItem(em_config, i);
            if (decode_em_policy_object(policy_cfg, &params->em_config) != webconfig_error_none) {
                wifi_util_error_print(WIFI_EM, "%s:%d: EM config object Validation Failed\n", __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_EM, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        }
    }

    cJSON_Delete(json);

    wifi_util_info_print(WIFI_EM, "%s:%d: decode success\n", __func__, __LINE__);

    return webconfig_error_none;
}

