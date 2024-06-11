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

webconfig_subdoc_object_t   vif_neighbors_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_vif_neighbors, "WifiVifNeighbors" },
};

webconfig_error_t init_vif_neighbors_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(vif_neighbors_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&vif_neighbors_objects, sizeof(vif_neighbors_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_vif_neighbors_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_vif_neighbors_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) == webconfig_data_descriptor_translate_to_ovsdb) {
        if (translate_to_ovsdb_tables(webconfig_subdoc_type_vif_neighbors, data) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t translate_to_vif_neighbors_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (translate_from_ovsdb_tables(webconfig_subdoc_type_vif_neighbors, data) != webconfig_error_none) {
            return webconfig_error_translate_from_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) == webconfig_data_descriptor_translate_from_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t free_vif_neighbors_entries(webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *decoded_params;
    vif_neighbors_t *vif_neighbors, *temp_vif_neighbors;
    char key[64] = {0};

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    if (data->u.decoded.vif_neighbors_map != NULL) {
        vif_neighbors = hash_map_get_first(data->u.decoded.vif_neighbors_map);
        while (vif_neighbors != NULL) {
            memset(key, 0, sizeof(key));
            snprintf(key, sizeof(key), "%s", vif_neighbors->bssid);
            vif_neighbors = hash_map_get_next(data->u.decoded.vif_neighbors_map, vif_neighbors);
            temp_vif_neighbors = hash_map_remove(data->u.decoded.vif_neighbors_map, key);
            if (temp_vif_neighbors != NULL) {
                free(temp_vif_neighbors);
            }
        }
        hash_map_destroy(data->u.decoded.vif_neighbors_map);
        data->u.decoded.vif_neighbors_map = NULL;
    }
    return webconfig_error_none;

}

webconfig_error_t encode_vif_neighbors_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json, *st_obj_arr;
    webconfig_subdoc_decoded_data_t *params;
    char *str;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d\n", __func__, __LINE__);

    if (data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL data Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    json = cJSON_CreateObject();
    if (json == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "vif neighbors");

    // encode vif neighbors config objects
    st_obj_arr = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiVifNeighbors", st_obj_arr);

    if (encode_vif_neighbors_object(params->vif_neighbors_map, st_obj_arr) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode vif neighbors config object\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_encode;
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

    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (free_vif_neighbors_entries(data) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vif neighbors config free failed\n", __func__, __LINE__);
            webconfig_data_free(data);
            return webconfig_error_encode;
        }
    }

    return webconfig_error_none;
}

webconfig_error_t decode_vif_neighbors_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    unsigned int i;
    cJSON *json, *st_arr_obj;
    webconfig_subdoc_decoded_data_t *params;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d\n", __func__, __LINE__);

    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    json = data->u.encoded.json;
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

    st_arr_obj = cJSON_GetObjectItem(json, "WifiVifNeighbors");
    if ((st_arr_obj == NULL) && (cJSON_IsObject(st_arr_obj) == false)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vif neighbors config object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    // decode vif neighbors config objects
    if (decode_vif_neighbors_object(&params->vif_neighbors_map, st_arr_obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to decode vif neighbors config\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    cJSON_Delete(json);
    return webconfig_error_none;
}
