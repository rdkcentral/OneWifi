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

webconfig_subdoc_object_t  xfinity_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_radios, "WifiVapConfig" },
};

webconfig_error_t init_xfinity_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(xfinity_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&xfinity_objects, sizeof(xfinity_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_xfinity_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_xfinity_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) == webconfig_data_descriptor_translate_to_ovsdb) {
        if (translate_to_ovsdb_tables(webconfig_subdoc_type_xfinity, data) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

        } else {

        } // no translation required
    }

    return webconfig_error_none;
}

webconfig_error_t translate_to_xfinity_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (translate_from_ovsdb_tables(webconfig_subdoc_type_xfinity, data) != webconfig_error_none) {
            return webconfig_error_translate_from_ovsdb;
        } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) == webconfig_data_descriptor_translate_from_tr181) {

        } else {

        } // no translation required
    }

    return webconfig_error_none;
}

webconfig_error_t encode_xfinity_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    // wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Enter\n", __FUNCTION__);
    cJSON *json;
    cJSON *obj, *obj_array;
    wifi_vap_info_map_t *map;
    wifi_vap_info_t *vap;
    webconfig_subdoc_decoded_data_t *params;
    char *str;

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "xfinity");

    // ecode xfinity vap objects
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiVapConfig", obj_array);

    for( unsigned int i = 0; i < params->num_radios; i++ ) {
        map = &params->radios[i].vaps.vap_map;
        for ( unsigned int j = 0; j < map->num_vaps; j++) {
            vap = &map->vap_array[j];
            if ((vap->vap_index == (unsigned int)convert_vap_name_to_index("hotspot_open_2g")) ||
                    (vap->vap_index == (unsigned int)convert_vap_name_to_index("hotspot_open_5g"))) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_hotspot_open_vap_object(vap, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode hotspot open vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;
                }
            } else {
                if ((vap->vap_index == (unsigned int)convert_vap_name_to_index("hotspot_secure_2g")) ||
                        (vap->vap_index == (unsigned int)convert_vap_name_to_index("hotspot_secure_5g"))) {
                    obj = cJSON_CreateObject();
                    cJSON_AddItemToArray(obj_array, obj);
                    if (encode_hotspot_secure_vap_object(vap, obj) != webconfig_error_none) {
                        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode hotspot open vap object\n", __func__, __LINE__);
                        cJSON_Delete(json);
                        return webconfig_error_encode;
                    }
                }
            }
        }
    }

    memset(data->u.encoded.raw, 0, MAX_SUBDOC_SIZE);
    str = cJSON_Print(json);
    memcpy(data->u.encoded.raw, str, strlen(str));

    cJSON_Delete(json);
    return webconfig_error_none;
}

webconfig_error_t decode_xfinity_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    // wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Enter\n", __FUNCTION__);

    webconfig_subdoc_t  *doc;
    cJSON *obj_vaps;
    cJSON *obj, *obj_vap;
    unsigned int size, radio_index;
    unsigned int presence_count = 0;
    char *vap_names[MAX_NUM_RADIOS * 2] = { "hotspot_open_2g", "hotspot_secure_2g", "hotspot_open_5g", "hotspot_secure_5g" };
    char *name;
    wifi_vap_info_t *vap_info;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;
    unsigned int i = 0, j = 0;

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
    if (size < (MIN_NUM_RADIOS * 2) || size > (MAX_NUM_RADIOS * 2)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of vap objects: %d, expected: %d\n",
                __func__, __LINE__, size, (sizeof(vap_names)/sizeof(char *)));
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

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

    if (presence_count < (MIN_NUM_RADIOS * 2) || presence_count > (MAX_NUM_RADIOS * 2)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    // first set the structure to all 0
    memset(&params->radios, 0, sizeof(rdk_wifi_radio_t) * MAX_NUM_RADIOS);

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_vap, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(name);
        vap_info = &params->radios[radio_index].vaps.vap_map.vap_array[params->radios[radio_index].vaps.vap_map.num_vaps];
        //wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio index: %d , vap name: %s\n%s\n",
        //            __func__, __LINE__, radio_index, name, cJSON_Print(obj_vap));

        if ((strcmp(name, "hotspot_open_2g") == 0) || (strcmp(name, "hotspot_open_5g") == 0)) {
            if (decode_hotspot_open_vap_object(obj_vap, vap_info) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            params->radios[radio_index].vaps.vap_map.num_vaps++;
        } else {
            if ((strcmp(name, "hotspot_secure_2g") == 0) || (strcmp(name, "hotspot_secure_5g") == 0)) {
                if (decode_hotspot_secure_vap_object(obj_vap, vap_info) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                            __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_decode;
                }
                params->radios[radio_index].vaps.vap_map.num_vaps++;
            }

        }
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation success\n", __func__, __LINE__);
    cJSON_Delete(json);
    return webconfig_error_none;
}
