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

webconfig_subdoc_object_t   wifiapi_radio_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_radios, "WifiRadioConfig" },
};

webconfig_error_t init_wifiapiradio_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(wifiapi_radio_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&wifiapi_radio_objects, sizeof(wifiapi_radio_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_wifiapiradio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_wifiapiradio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_wifiapiradio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_wifiapiradio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_not_permitted;
}

webconfig_error_t decode_wifiapiradio_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *obj_radios;
    cJSON *obj, *obj_radio;
    unsigned int i, size, radio_index = 0;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;

    params = &data->u.decoded;
    doc = &config->subdocs[data->type];

    memset(params, 0, sizeof(webconfig_subdoc_decoded_data_t));

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
    if (size != 1) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of radio objects: %d\n",
            __func__, __LINE__, size);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }


    obj_radio = cJSON_GetArrayItem(obj_radios, 0);
    
    if ((obj = cJSON_GetObjectItem(obj_radio, "RadioName")) == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: radio name is not present\n",
            __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    convert_radio_name_to_index(&radio_index,cJSON_GetStringValue(obj));

    if (decode_radio_object(obj_radio, &params->radios[radio_index]) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object validation failed\n",
            __func__, __LINE__);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        cJSON_Delete(json);
        return webconfig_error_decode;
    }
    
    cJSON_Delete(json);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);
    return webconfig_error_none;
}
