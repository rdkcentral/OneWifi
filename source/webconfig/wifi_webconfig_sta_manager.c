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
#include "collection.h"
#include "wifi_ctrl.h"
#include "wifi_monitor.h"
#include "wifi_util.h"
#include "wifi_webconfig.h"
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

webconfig_subdoc_object_t sta_manager_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version"      },
    { webconfig_subdoc_object_type_subdoc,  "SubDocName"   },
    { webconfig_subdoc_object_type_csi,     "BeaconReport" },
};

webconfig_error_t init_sta_manager_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(sta_manager_objects) / sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&sta_manager_objects,
        sizeof(sta_manager_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_sta_manager_subdoc(webconfig_t *config,
    webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_sta_manager_subdoc(webconfig_t *config,
    webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_sta_manager_subdoc(webconfig_t *config,
    webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_sta_manager_object(sta_beacon_report_reponse_t *sta_data,
    cJSON **sta_manager_obj)
{
    unsigned int itr = 0;
    cJSON *object, *obj_array;
    if (sta_data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL sta_data Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (*sta_manager_obj == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL sta_manager_obj Pointer\n", __func__,
            __LINE__);
        return webconfig_error_encode;
    }

    obj_array = cJSON_CreateArray();
    mac_addr_str_t mac_str;
    cJSON_AddItemToObject(*sta_manager_obj, "BeaconReport", obj_array);
    beacon_response_data_t *bR_report = sta_data->data;
    for (itr = 0; (itr < sta_data->num_br_data) && (bR_report != NULL); itr++) {
        object = cJSON_CreateObject();
        cJSON_AddItemToArray(obj_array, object);
        to_mac_str(bR_report->bssid, mac_str);
        cJSON_AddStringToObject(object, "BSSID", mac_str);
        cJSON_AddNumberToObject(object, "Operating Class", bR_report->op_class);
        cJSON_AddNumberToObject(object, "Channel Number", bR_report->channel);
        cJSON_AddNumberToObject(object, "RCPI", bR_report->rcpi);
        cJSON_AddNumberToObject(object, "RSNI", bR_report->rssi);
        bR_report++;
    }

    return webconfig_error_none;
}

webconfig_error_t encode_sta_manager_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json, *object;
    // cJSON *obj_array;
    char *str;
    char *vap_name;
    webconfig_subdoc_decoded_data_t *params;
    mac_addr_str_t mac_str;

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
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__,
            __LINE__);
        return webconfig_error_encode;
    }

    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "Beacon Report");

    // Encode mac object

    object = cJSON_CreateObject();
    cJSON_AddItemToObject(json, "WiFiBeaconReport", object);
    vap_name = get_vap_name(&params->hal_cap.wifi_prop, params->stamgr.ap_index);
    cJSON_AddStringToObject(object, "VapName", vap_name);
    to_mac_str(params->stamgr.mac_addr, mac_str);
    cJSON_AddStringToObject(object, "MacAddress", mac_str);
    cJSON_AddNumberToObject(object, "NumofReport", params->stamgr.num_br_data);
    if (encode_sta_manager_object(&params->stamgr, &object) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode mac object\n", __func__,
            __LINE__);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    str = cJSON_Print(json);
    data->u.encoded.raw = (webconfig_subdoc_encoded_raw_t)calloc(strlen(str) + 1, sizeof(char));
    if (data->u.encoded.raw == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory.\n", __func__,
            __LINE__);
        cJSON_free(str);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    memcpy(data->u.encoded.raw, str, strlen(str));
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded data is %s\n", __func__, __LINE__, str);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success\n", __func__, __LINE__);
    cJSON_free(str);
    cJSON_Delete(json);
    return webconfig_error_none;
}

webconfig_error_t decode_sta_manager_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;

    webconfig_subdoc_decoded_data_t *params;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d\n", __func__, __LINE__);

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

    memset(&params->stamgr, 0, sizeof(sta_beacon_report_reponse_t));
    cJSON *obj_config = cJSON_GetObjectItem(json, "WiFiBeaconReport");
    if (obj_config == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    if (decode_sta_mgr_object(obj_config, &params->stamgr, &params->hal_cap.wifi_prop) !=
        webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object Validation Failed\n", __func__,
            __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_decode;
    }

    cJSON_Delete(json);
    return webconfig_error_none;
}
