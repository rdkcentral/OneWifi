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

webconfig_error_t access_check_vap_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_vap_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_vap_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_vap_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
//    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Enter\n", __FUNCTION__);

    cJSON *json;
    cJSON *obj, *obj_array;
    const char *str;
    unsigned int i, j;
    webconfig_subdoc_decoded_data_t *params;
    schema_wifi_vap_state_t  *vap_state;
    rdk_wifi_vap_info_t      *rdk_vap_array;
    wifi_vap_info_map_t      *vap_map;
    char vap_name[64];

    params = &data->u.decoded;

    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "vap_status");

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "Wifi_VIF_State", obj_array);

    for (i = 0; i < params->num_radios; i++) {
        //To get the number of vaps
        vap_map = &params->radios[i].vaps.vap_map;
        for (j = 0; j < vap_map->num_vaps; j++) {
            //To get the vap_name
            rdk_vap_array = &params->radios[i].vaps.rdk_vap_array[j];
            //Compare the vap_names
            memset(vap_name, 0, sizeof(vap_name));
            strcpy(vap_name, (char *)rdk_vap_array->vap_name);
            if (strncmp(vap_name, "private_ssid", strlen("private_ssid")) == 0) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    cJSON_Delete(json);
                    return webconfig_error_encode;
                }
            } else if (strncmp(vap_name, "iot_ssid", strlen("iot_ssid")) == 0) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    cJSON_Delete(json);
                    return webconfig_error_encode;
                }
            } else if (strncmp(vap_name, "hotspot_open", strlen("hotspot_open")) == 0) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    cJSON_Delete(json);
                    return webconfig_error_encode;
                }
            } else if (strncmp(vap_name, "lnf_psk", strlen("lnf_psk")) == 0) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    cJSON_Delete(json);
                    return webconfig_error_encode;
                }
            } else if (strncmp(vap_name, "hotspot_secure", strlen("hotspot_secure")) == 0) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    cJSON_Delete(json);
                    return webconfig_error_encode;
                }
            } else if (strncmp(vap_name, "lnf_radius", strlen("lnf_radius")) == 0) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    cJSON_Delete(json);
                    return webconfig_error_encode;
                }
            } else if (strncmp(vap_name, "mesh_backhaul", strlen("mesh_backhaul")) == 0) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
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

webconfig_error_t decode_vap_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Enter\n", __FUNCTION__);
    webconfig_subdoc_t  *doc;
    webconfig_subdoc_decoded_data_t *params;
    cJSON *obj_vap_state, *obj_vap_state_arr;
    cJSON *json = data->u.encoded.json;
    unsigned int i = 0, size;
    int r_index = 0, v_arrayindex = 0;
    schema_wifi_vap_state_t temp_vap_state;
    schema_wifi_vap_state_t *vap_state;
    char vap_name[32];

    params = &data->u.decoded;
    doc = &config->subdocs[data->type];

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s Enter\n", __func__);

    memset(params, 0, sizeof(webconfig_subdoc_decoded_data_t));

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }
    }

    // decode VAP status objects
    obj_vap_state_arr = cJSON_GetObjectItem(json, "Wifi_VIF_State");
    if (cJSON_IsArray(obj_vap_state_arr) == false) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap status object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_vap_state_arr);

    for (i = 0; i < size; i++) {
        obj_vap_state = cJSON_GetArrayItem(obj_vap_state_arr, i);
        if (decode_vap_state_object(obj_vap_state, &temp_vap_state) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap state object validation failed\n",
                    __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_decode;
        }

        if (convert_ifname_to_vapname(&params->hal_cap.wifi_prop, temp_vap_state.if_name, vap_name, sizeof(vap_name)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed\n", __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }

        //get the radioindex
        r_index = convert_vap_name_to_radio_array_index(&params->hal_cap.wifi_prop, vap_name);

        //get the vap_array_index
        v_arrayindex =  convert_vap_name_to_array_index(&params->hal_cap.wifi_prop, vap_name);

        if ((v_arrayindex == -1) || (r_index == -1)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d\n", __func__, __LINE__, r_index, v_arrayindex);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }

        //update the vap_state structure
        vap_state = &params->radios[r_index].vaps.vap_state[v_arrayindex];
        memcpy(vap_state, &temp_vap_state, sizeof(schema_wifi_vap_state_t));
    }

    cJSON_Delete(json);
    return webconfig_error_none;
}
