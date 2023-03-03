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
#include "secure_wrapper.h"
#include "collection.h"
#include "msgpack.h"
#include "wifi_webconfig.h"
#include "wifi_monitor.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"

webconfig_subdoc_object_t   wifiapi_vap_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_vaps, "WifiVapConfig" },
};

webconfig_error_t init_wifiapivap_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(wifiapi_vap_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&wifiapi_vap_objects, sizeof(wifiapi_vap_objects));

    return webconfig_error_none;
}


webconfig_error_t access_check_wifiapivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_wifiapivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_wifiapivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_wifiapivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_not_permitted;
}

webconfig_error_t decode_wifiapivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *obj_vaps;
    cJSON *obj_vap;
    unsigned int i, size, vap_array_index, radio_index = 0;
    unsigned int blob_radio_index, vap_mode = 0;
    const cJSON  *obj_vap_mode;
    char *name;
    wifi_vap_info_t *vap_info;
    rdk_wifi_vap_info_t *rdk_vap_info;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;

    params = &data->u.decoded;
    doc = &config->subdocs[data->type];

    //memset(params, 0, sizeof(webconfig_subdoc_decoded_data_t));

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }
    }

    // decode VAP objects
    obj_vaps = cJSON_GetObjectItem(json, "WifiVapConfig");
    if (cJSON_IsArray(obj_vaps) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_vaps);
    if (size > MAX_NUM_VAP_PER_RADIO) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of vap objects: %d\n",
            __func__, __LINE__, size);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_vap, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(&params->hal_cap.wifi_prop, name);
        if ((int)radio_index < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio_index\n", __func__, __LINE__);
            continue;
        }
        if (i == 0) {
            blob_radio_index = radio_index;
        }
        if (blob_radio_index != radio_index) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap objects. Invalid vap '%s' for radio %d\n",
                __func__, __LINE__, name, blob_radio_index);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }
        vap_array_index = convert_vap_name_to_array_index(&params->hal_cap.wifi_prop, name);
        if ((int)vap_array_index < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_array_index\n", __func__, __LINE__);
            continue;
        }
        vap_info = &params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        rdk_vap_info = &params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];

        obj_vap_mode = cJSON_GetObjectItem(obj_vap, "VapMode");
        if (obj_vap_mode == NULL || cJSON_IsNumber(obj_vap_mode) == false) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Could not find VapMode\n", __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
        }
        vap_mode = obj_vap_mode->valuedouble;
        if (vap_mode == wifi_vap_mode_sta) {
            if (decode_mesh_sta_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else {
            if (decode_wifiapi_vap_object(obj_vap, vap_info, &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        }
    }
    
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);

    cJSON_Delete(json);
    return webconfig_error_none;
}
