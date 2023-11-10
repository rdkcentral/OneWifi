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

webconfig_subdoc_object_t   radio_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_radios, "WifiRadioConfig" },
};

webconfig_error_t init_radio_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(radio_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&radio_objects, sizeof(radio_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_radio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_radio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) == webconfig_data_descriptor_translate_to_ovsdb) {
        if (translate_to_ovsdb_tables(webconfig_subdoc_type_radio, data) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t translate_to_radio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (translate_from_ovsdb_tables(webconfig_subdoc_type_radio, data) != webconfig_error_none) {
            return webconfig_error_translate_from_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) == webconfig_data_descriptor_translate_from_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t encode_radio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj, *obj_array;
    unsigned int i;
    rdk_wifi_radio_t *radio;
    webconfig_subdoc_decoded_data_t *params;
    char *str;

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "radio");

    // encode radio object
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiRadioConfig", obj_array);

    for (i = 0; i < params->num_radios; i++) {
        radio = &params->radios[i];
        obj = cJSON_CreateObject();
        cJSON_AddItemToArray(obj_array, obj);

        if (wifi_radio_operationParam_validation(&params->hal_cap, &radio->oper) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Validation failed for radio object %s\n", __func__, __LINE__, radio->name);
            cJSON_Delete(json);
            return webconfig_error_encode;
        }

        if (encode_radio_object(radio, obj) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode radio object\n", __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_encode;
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
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success\n", __func__, __LINE__);
    return webconfig_error_none;
}

webconfig_error_t decode_radio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *obj_radios;
    cJSON *obj, *obj_radio;
    unsigned int i, j, size;
    unsigned int presence_count = 0;
    char radio_names[MAX_NUM_RADIOS][8];
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;

    params = &data->u.decoded;
    doc = &config->subdocs[data->type];

    for (i = 0; i < MAX_NUM_RADIOS; i++) {
        snprintf(radio_names[i], sizeof(radio_names[i]), "radio%d", i+1);
    }
    // wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, data->u.encoded.raw);

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }
    }

    // decode radio objects
    obj_radios = cJSON_GetObjectItem(json, "WifiRadioConfig");
    if (cJSON_IsArray(obj_radios) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_radios);
    if (size < MIN_NUM_RADIOS || size > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of radio objects: %d\n",
            __func__, __LINE__, size);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    for (i = 0; i < size; i++) {
        obj_radio = cJSON_GetArrayItem(obj_radios, i);
        // check presence of all radio names
        if ((obj = cJSON_GetObjectItem(obj_radio, "RadioName")) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Not all radio names present\n",
                __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }

        for (j = 0; j < size; j++) {
            if (strncmp(cJSON_GetStringValue(obj), radio_names[j], strlen(radio_names[j])) == 0) {
                presence_count++;
            }
        }
    }

    if (presence_count < MIN_NUM_RADIOS || presence_count > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present presence_count: %u\n", __func__, __LINE__ ,presence_count);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    params->num_radios = 0;
    for (i = 0; i < size; i++) {
        obj_radio = cJSON_GetArrayItem(obj_radios, i);
//        memset(&params->radios[i], 0, sizeof(rdk_wifi_radio_t));

        if (decode_radio_object(obj_radio, &params->radios[i]) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object validation failed\n",
                __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
        }

    }
    params->num_radios = size;

    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);
    cJSON_Delete(json);
    return webconfig_error_none;
}
