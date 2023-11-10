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

webconfig_subdoc_object_t   harvester_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_harvester, "Parameters" },
};

webconfig_error_t init_harvester_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(harvester_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&harvester_objects, sizeof(harvester_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_harvester_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_harvester_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    // Need to be implemented
    return webconfig_error_none;
}

webconfig_error_t translate_to_harvester_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    // Need to be implemented
    return webconfig_error_none;
}

webconfig_error_t encode_harvester_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj;
    instant_measurement_config_t *harvester;
    webconfig_subdoc_decoded_data_t *params;
    char *str;

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encode JSON\n", __func__, __LINE__);
    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "instant measurement config");
    cJSON_AddStringToObject(json, "Schema", "WifiSingleClient.avsc");
    cJSON_AddStringToObject(json, "SchemaID", "8b27dafc-0c4d-40a1-b62c-f24a34074914/4388e585dd7c0d32ac47e71f634b579b");
    obj= cJSON_CreateObject();
    cJSON_AddItemToObject(json, "Parameters", obj);
    harvester = &params->harvester;
    cJSON_AddBoolToObject(obj, "Enabled", harvester->b_inst_client_enabled);
    cJSON_AddStringToObject(obj, "MacAddress", harvester->mac_address);
    cJSON_AddNumberToObject(obj, "ReportingPeriod", harvester->u_inst_client_reporting_period);
    cJSON_AddNumberToObject(obj, "DefReportingPeriod", harvester->u_inst_client_def_reporting_period);
    cJSON_AddNumberToObject(obj, "DefOverrideTTL", harvester->u_inst_client_def_override_ttl);

    str = cJSON_Print(json);

    data->u.encoded.raw = (webconfig_subdoc_encoded_raw_t)calloc(strlen(str) + 1, sizeof(char));
    if (data->u.encoded.raw == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d Failed to allocate memory.\n", __func__,__LINE__);
        cJSON_free(str);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    memcpy(data->u.encoded.raw, str, strlen(str));
    // wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, data->u.encoded.raw);
    cJSON_free(str);
    cJSON_Delete(json);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success\n", __func__, __LINE__);
    return webconfig_error_none;
}

webconfig_error_t decode_harvester_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *obj;
    cJSON *json = data->u.encoded.json;
    instant_measurement_config_t *harvester;
    unsigned int i;

    harvester = &data->u.decoded.harvester;
    doc = &config->subdocs[data->type];

    // wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, data->u.encoded.raw);

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                __func__, __LINE__, doc->objects[i].name);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }
    }

    // decode harvester objects
    obj = cJSON_GetObjectItem(json, "Parameters");
    if (obj == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: harvester object not present\n", __func__, __LINE__);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    if (decode_harvester_object(obj, harvester) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: harvester object validation failed\n",
            __func__, __LINE__);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_decode;
    }
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);
    return webconfig_error_none;
}

