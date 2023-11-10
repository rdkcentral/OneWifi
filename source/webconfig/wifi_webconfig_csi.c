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

webconfig_subdoc_object_t   csi_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_csi, "WifiCSI" },
};

webconfig_error_t init_csi_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(csi_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&csi_objects, sizeof(csi_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_csi_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_csi_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_csi_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_csi_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj_array;
    char *str;
    webconfig_subdoc_decoded_data_t *params;

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
    cJSON_AddStringToObject(json, "SubDocName", "csi data");

    //Encode mac object

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiCSI", obj_array);

    if (encode_csi_object(params->csi_data_queue, obj_array) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode mac object\n", __func__, __LINE__);
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

    memcpy(data->u.encoded.raw, str, strlen(str));
    cJSON_free(str);
    cJSON_Delete(json);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded data is %s\n", __func__, __LINE__, str);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success\n", __func__, __LINE__);
    return webconfig_error_none;
}

webconfig_error_t decode_csi_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    webconfig_subdoc_decoded_data_t *params;
    unsigned int size, i;
    cJSON *obj, *json, *obj_csi;

    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    json = data->u.encoded.json;
    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    doc = &config->subdocs[data->type];
    params->csi_data_queue = NULL;

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }
    }

    obj_csi = cJSON_GetObjectItem(json, "WifiCSI");
    if ((obj_csi == NULL) && (cJSON_IsArray(obj_csi) == false)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: CSI object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_csi);
    for (i = 0; i < size; i++){
        obj = cJSON_GetArrayItem(obj_csi, i);
        if (decode_csi_object(&params->csi_data_queue, obj) != webconfig_error_none) {
             wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: csi object validation failed\n",
                  __func__, __LINE__);
             cJSON_Delete(json);
             if (params->csi_data_queue != NULL) {
                queue_destroy(params->csi_data_queue);
             }
             wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
             return webconfig_error_decode;
        }
    }

    cJSON_Delete(json);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);
    return webconfig_error_none;
}

