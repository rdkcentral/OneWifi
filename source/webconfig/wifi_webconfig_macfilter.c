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
#include "wifi_util.h"
#include "wifi_ctrl.h"

webconfig_subdoc_object_t   mac_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_wifi_mac_filter, "WifiMacFilter" },
};

webconfig_error_t init_mac_filter_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(mac_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&mac_objects, sizeof(mac_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_mac_filter_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_mac_filter_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    // no translation required
    if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) == webconfig_data_descriptor_translate_to_ovsdb) {
        if (translate_to_ovsdb_tables(webconfig_subdoc_type_mac_filter, data) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t translate_to_mac_filter_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (translate_from_ovsdb_tables(webconfig_subdoc_type_mac_filter, data) != webconfig_error_none) {
            return webconfig_error_translate_from_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) == webconfig_data_descriptor_translate_from_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t free_vap_object_macfilter_entries(webconfig_subdoc_data_t *data)
{
    unsigned int i, j;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    rdk_wifi_vap_info_t *rdk_vap;
    acl_entry_t *temp_acl_entry, *acl_entry;
    mac_addr_str_t mac_str;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            rdk_vap = &decoded_params->radios[i].vaps.rdk_vap_array[j];
            if (rdk_vap == NULL){
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: rdk_vap is null", __func__, __LINE__);
                return webconfig_error_invalid_subdoc;
            }
            if(rdk_vap->acl_map != NULL) {
                acl_entry = hash_map_get_first(rdk_vap->acl_map);
                while(acl_entry != NULL) {
                    to_mac_str(acl_entry->mac,mac_str);
                    acl_entry = hash_map_get_next(rdk_vap->acl_map,acl_entry);
                    temp_acl_entry = hash_map_remove(rdk_vap->acl_map, mac_str);
                    if (temp_acl_entry != NULL) {
                        free(temp_acl_entry);
                    }
                }
                hash_map_destroy(rdk_vap->acl_map);
                rdk_vap->acl_map = NULL;
            }
        }
    }
    return webconfig_error_none;
}

webconfig_error_t encode_mac_filter_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj_array;
    unsigned int i,j;
    rdk_wifi_vap_info_t *rdk_vap_info;
    webconfig_subdoc_decoded_data_t *params;
    wifi_vap_info_map_t      *vap_map;
    char *str;

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
    cJSON_AddStringToObject(json, "SubDocName", "mac filter");

    //Encode mac object

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiMacFilter", obj_array);

    for(i = 0; i < params->num_radios; i++) {
        vap_map = &params->radios[i].vaps.vap_map;
        for (j = 0; j < vap_map->num_vaps; j++) {
            rdk_vap_info = &params->radios[i].vaps.rdk_vap_array[j];

            if (encode_mac_object(rdk_vap_info, obj_array) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode mac object\n", __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_encode;

            }
        }
    }

    str = cJSON_Print(json);

    data->u.encoded.raw = (webconfig_subdoc_encoded_raw_t)calloc(strlen(str) + 1, sizeof(char));
    if (data->u.encoded.raw == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d Failed to allocate memory.\n", __func__,__LINE__);
        cJSON_free(str);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    memcpy(data->u.encoded.raw, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);

    //Check the descriptor is ovsdb, free it
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (free_vap_object_macfilter_entries(data) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: mac entries free failed\n", __func__, __LINE__);
            webconfig_data_free(data);
            return webconfig_error_encode;
        }
    }
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success\n", __func__, __LINE__);
    return webconfig_error_none;
}

webconfig_error_t decode_mac_filter_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *obj_mac;
    cJSON *obj_acl;
    unsigned int i = 0, vap_array_index=0, size, radio_index;
    cJSON *json;
    webconfig_subdoc_decoded_data_t *params;
    rdk_wifi_vap_info_t *rdk_vap_info;
    char *name;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    int num_vaps;

    params = &data->u.decoded;
    if (params == NULL) {
        return webconfig_error_decode;
    }
    json = data->u.encoded.json;
    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }
    doc = &config->subdocs[data->type];

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, data->u.encoded.raw);

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }
    }

    num_vaps = get_list_of_vap_names(&params->hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
                                     8, VAP_PREFIX_PRIVATE, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE, \
                                     VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS, VAP_PREFIX_MESH_BACKHAUL, \
                                     VAP_PREFIX_MESH_STA, VAP_PREFIX_IOT);

    obj_mac = cJSON_GetObjectItem(json, "WifiMacFilter");
    if (cJSON_IsArray(obj_mac) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Mac object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_mac);
    if (num_vaps > (int)size) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of mac objects: %d\n",
                __func__, __LINE__, size);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }
    for (i = 0; i < size; i++) {
        obj_acl = cJSON_GetArrayItem(obj_mac, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_acl, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(&params->hal_cap.wifi_prop, name);
        vap_array_index = convert_vap_name_to_array_index(&params->hal_cap.wifi_prop, name);
        if (((int)radio_index < 0) || ((int)vap_array_index < 0)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid index\n", __func__, __LINE__);
            continue;
        }
        rdk_vap_info = &params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap_info->acl_map = NULL;
        rdk_vap_info->vap_index = convert_vap_name_to_index(&params->hal_cap.wifi_prop, name);
        if ((int)rdk_vap_info->vap_index < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid  vap_index\n", __func__, __LINE__);
            continue;
        }
        if (decode_mac_object(rdk_vap_info, obj_acl) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: mac state object validation failed\n",
                    __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
        }
    }

    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);
    cJSON_Delete(json);

    return webconfig_error_none;
}
