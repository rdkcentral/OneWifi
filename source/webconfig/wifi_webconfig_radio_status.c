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

webconfig_error_t access_check_radio_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_radio_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_radio_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_radio_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj, *obj_array;
    schema_wifi_radio_state_t *radio_state;
    webconfig_subdoc_decoded_data_t *params;
    const char *str;
    unsigned int i;

    params = &data->u.decoded;

    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "radio_status");

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "Wifi_Radio_State", obj_array);

    for (i = 0; i < params->num_radios; i++) {
        radio_state = &params->radios[i].radio_state;
        if (radio_state == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to get radio state\n", __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_encode;
        }

        obj = cJSON_CreateObject();
        cJSON_AddItemToArray(obj_array, obj);
        if (encode_radio_state_object(radio_state, obj) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode radio state object\n", __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_encode;

        }
    }

    memset(data->u.encoded.raw, 0, MAX_SUBDOC_SIZE);

    str = cJSON_Print(json);

    memcpy(data->u.encoded.raw, str, strlen(str));
    // wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, str);

    cJSON_Delete(json);
    return webconfig_error_none;
}

webconfig_error_t decode_radio_status_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Enter\n", __FUNCTION__);

    cJSON *obj_radio_state, *obj_radio_state_arr;
    webconfig_subdoc_t  *doc;
    webconfig_subdoc_decoded_data_t *params;
    schema_wifi_radio_state_t  *radio_state;
    schema_wifi_radio_state_t  temp_radio_state;
    unsigned int i, size, radio_index =0;
    cJSON *json = data->u.encoded.json;

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

    obj_radio_state_arr = cJSON_GetObjectItem(json, "Wifi_Radio_State");
    if (cJSON_IsArray(obj_radio_state_arr) == false) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio state object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_radio_state_arr);
    if (size < MIN_NUM_RADIOS || size > MAX_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of radio objects: %d\n",
                __func__, __LINE__, size);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }
    params->num_radios = size;
    
    for (i = 0; i < size; i++) {
        obj_radio_state = cJSON_GetArrayItem(obj_radio_state_arr, i);
        memset(&temp_radio_state, 0, sizeof(schema_wifi_radio_state_t));

        //Update the temporary radio_state structure
        if (decode_radio_state_object(obj_radio_state, &temp_radio_state) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio State object validation failed for %d\n",
                    __func__, __LINE__, i);
            cJSON_Delete(json);
            return webconfig_error_decode;
        }

        //Get the radio_index from the temp structure
        if (convert_ifname_to_radio_index(&params->hal_cap.wifi_prop, temp_radio_state.if_name, &radio_index) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio State object invalid radio_index : %s\n",
                    __func__, __LINE__, temp_radio_state.if_name);
            cJSON_Delete(json);
            return webconfig_error_decode;
        }

        radio_state = &params->radios[radio_index].radio_state;
        memcpy(radio_state, &temp_radio_state, sizeof(schema_wifi_radio_state_t));
    }

    cJSON_Delete(json);
    return webconfig_error_none;
}
