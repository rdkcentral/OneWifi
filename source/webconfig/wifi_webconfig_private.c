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

webconfig_subdoc_object_t   private_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_vaps, "WifiVapConfig" },
};

webconfig_error_t init_private_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(private_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&private_objects, sizeof(private_objects));

    return webconfig_error_none;
}


webconfig_error_t access_check_private_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_private_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) == webconfig_data_descriptor_translate_to_ovsdb) {
        if (translate_to_ovsdb_tables(webconfig_subdoc_type_private, data) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t translate_to_private_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (translate_from_ovsdb_tables(webconfig_subdoc_type_private, data) != webconfig_error_none) {
            return webconfig_error_translate_from_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) == webconfig_data_descriptor_translate_from_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t encode_private_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj, *obj_array;
    unsigned int i, j;
    wifi_vap_info_map_t *map;
    wifi_vap_info_t *vap;
    webconfig_subdoc_decoded_data_t *params;
    char *str;

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "private");

    // ecode private vap objects
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiVapConfig", obj_array);

    for (i = 0; i < params->num_radios; i++) {
        map = &params->radios[i].vaps.vap_map;
        for (j = 0; j < map->num_vaps; j++) {
            vap = &map->vap_array[j];
            if (is_vap_private(&params->hal_cap.wifi_prop, vap->vap_index)) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_private_vap_object(vap, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode private vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            }
        }
    }

    memset(data->u.encoded.raw, 0, MAX_SUBDOC_SIZE);
    str = cJSON_Print(json);
    memcpy(data->u.encoded.raw, str, strlen(str));
  
    // wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_Delete(json);

    return webconfig_error_none;
}

webconfig_error_t decode_private_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *obj_vaps;
    cJSON *obj, *obj_vap;
    unsigned int i, j, size, radio_index, vap_array_index;
    unsigned int presence_count = 0;
    char *vap_names[MAX_NUM_RADIOS] = {
        "private_ssid_2g", "private_ssid_5g",
    };
    char *name;
    wifi_vap_info_t *vap_info;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;

    params = &data->u.decoded;
    doc = &config->subdocs[data->type];

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }
    }

    // decode VAP objects
    obj_vaps = cJSON_GetObjectItem(json, "WifiVapConfig");
    if (cJSON_IsArray(obj_vaps) == false) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_vaps);
    if (size < MIN_NUM_RADIOS || size > MAX_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of vap objects: %d, expected: %d\n",
            __func__, __LINE__, size, (sizeof(vap_names)/sizeof(char *)));
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    presence_count = 0;

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        // check presence of all vap names
        if ((obj = cJSON_GetObjectItem(obj_vap, "VapName")) == NULL) {
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }

        for (j = 0; j < size; j++) {
            if (strncmp(cJSON_GetStringValue(obj), vap_names[j], strlen(vap_names[j])) == 0) {
                presence_count++;
            }
        }
    }
    if (presence_count < MIN_NUM_RADIOS || presence_count > MAX_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    // first set the structure to all 0
    memset(&params->radios, 0, sizeof(rdk_wifi_radio_t)*MAX_NUM_RADIOS);
    for (i = 0; i < MAX_NUM_RADIOS; i++) {
        params->radios[i].vaps.vap_map.num_vaps = params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
        params->radios[i].vaps.num_vaps = params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
    }
    
    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_vap, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(&params->hal_cap.wifi_prop, name);
        vap_array_index = convert_vap_name_to_array_index(&params->hal_cap.wifi_prop, name);
        vap_info = &params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
//        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio index: %d , vap name: %s\n%s\n",
  //                 __func__, __LINE__, radio_index, name, cJSON_Print(obj_vap));

        if (!strncmp(name, "private_ssid", strlen("private_ssid"))) {
            if (decode_private_vap_object(obj_vap, vap_info, &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
        }
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation success\n", __func__, __LINE__);

    cJSON_Delete(json);
    return webconfig_error_none;
}
