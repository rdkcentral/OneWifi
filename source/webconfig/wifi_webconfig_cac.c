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

webconfig_subdoc_object_t   cac_config_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_cac, "VapConnectionControl" },
};

webconfig_error_t init_cac_config_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(cac_config_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&cac_config_objects, sizeof(cac_config_objects));

    return webconfig_error_none;
}

 webconfig_error_t access_check_cac_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}


webconfig_error_t translate_from_cac_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_cac_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_cac_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj, *obj_array;
    unsigned int i, j;
    wifi_vap_info_t *vap;
    wifi_vap_info_map_t *map;
    rdk_wifi_radio_t *radio;
    webconfig_subdoc_decoded_data_t *params;
    char *str;

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "connection_control");

    // encode connection control objects
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "VapConnectionControl", obj_array);

    for (i = 0; i < params->num_radios; i++) {
        radio = &params->radios[i];
        map = &radio->vaps.vap_map;

        for (j = 0; j < map->num_vaps; j++) {
            vap = &map->vap_array[j];
            obj = cJSON_CreateObject();
            cJSON_AddItemToArray(obj_array, obj);

            if (encode_connection_ctrl_object(vap, obj) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode connection ctrl object\n", __func__, __LINE__);
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
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_free(str);
    cJSON_Delete(json);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success\n", __func__, __LINE__);

    return webconfig_error_none;
}

webconfig_error_t decode_cac_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *obj_cac, *obj_cacs;
    unsigned int i, size, radio_index, vap_array_index = 0;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;
    rdk_wifi_vap_info_t *rdk_vap_info;
    wifi_vap_info_t *vap_info;
    wifi_platform_property_t *wifi_prop;
    char *name;

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
    wifi_prop = &params->hal_cap.wifi_prop;

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }
    }

    // decode connection control
    obj_cacs = cJSON_GetObjectItem(json, "VapConnectionControl");
    if (cJSON_IsArray(obj_cacs) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Connection control object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_cacs);

    for (i = 0; i < size; i++) {
        obj_cac = cJSON_GetArrayItem(obj_cacs, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_cac, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, name);
        vap_array_index = convert_vap_name_to_array_index(wifi_prop, name);
        if (((int)radio_index < 0) || ((int)vap_array_index < 0)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid index\n", __func__, __LINE__);
            continue;
        }
        rdk_vap_info = &params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap_info->vap_index = convert_vap_name_to_index(wifi_prop, name);
        vap_info = &params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        strcpy(vap_info->vap_name, name);

        if ((int)rdk_vap_info->vap_index < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid  vap_index\n", __func__, __LINE__);
            continue;
        }
        if (decode_cac_object(vap_info, obj_cac) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: connection control object validation failed\n",
                    __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
        }
    }

    for (i = 0; i < params->hal_cap.wifi_prop.numRadios; i++) {
        params->radios[i].vaps.vap_map.num_vaps = params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
        params->radios[i].vaps.num_vaps = params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
    }

    cJSON_Delete(json);
    return webconfig_error_none;
}
