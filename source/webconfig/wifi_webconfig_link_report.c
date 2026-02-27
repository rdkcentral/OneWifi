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
#include "collection.h"
#include "wifi_webconfig.h"
#include "wifi_monitor.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"

webconfig_subdoc_object_t   link_report_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_link_report, "LinkReport" },
};

webconfig_error_t init_link_report_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(link_report_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&link_report_objects, sizeof(link_report_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_link_report_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_link_report_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_easymesh) == webconfig_data_descriptor_translate_to_easymesh) {
        if (config->proto_desc.translate_to(webconfig_subdoc_type_link_report, data) != webconfig_error_none) {
            if ((data->descriptor & webconfig_error_translate_to_easymesh) == webconfig_error_translate_to_easymesh) {
                return webconfig_error_translate_to_easymesh;
            }
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

    } else {
        // no translation required
    }
    //no translation required
    return webconfig_error_none;
}

webconfig_error_t translate_to_link_report_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_link_report_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    char *str = NULL;
    unsigned int i = 0;
    cJSON *obj, *obj_array;

    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL data Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }
    report_batch_t *report = data->u.decoded.qmgr_report;


    json = cJSON_CreateObject();
    if (json == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: json create object failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

     data->u.encoded.json = json;
    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "LinkReport");
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "LinkReport", obj_array);
    for (i = 0; i < report->link_count ;i++)
    {
       link_report_t link = report->links[i];
       obj = cJSON_CreateObject();
        cJSON_AddItemToArray(obj_array, obj);
        cJSON_AddStringToObject(obj, "Mac", link.mac);
        cJSON_AddNumberToObject(obj, "VapIndex", link.vap_index);
        cJSON_AddStringToObject(obj, "ReportingTime", link.reporting_time);
        cJSON_AddNumberToObject(obj, "Threshold", link.threshold);
        cJSON_AddBoolToObject(obj, "Alarm", link.alarm);
        if (encode_link_score_sample_object(&link, obj) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode link object\n", __func__, __LINE__);
            cJSON_Delete(json); 
            return webconfig_error_encode;
        }


    }
    // Convert JSON object to string
    str = cJSON_Print(json);

    data->u.encoded.raw = (webconfig_subdoc_encoded_raw_t)calloc(strlen(str) + 1, sizeof(char));
    if (data->u.encoded.raw == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Failed to allocate memory.\n", __func__, __LINE__);
        cJSON_free(str);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    memcpy(data->u.encoded.raw, str, strlen(str));
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success %s\n", __func__, __LINE__, str);

    cJSON_free(str);
    cJSON_Delete(json);
    return webconfig_error_none;
}

webconfig_error_t decode_link_report_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *params;
    cJSON *json;
    params = &data->u.decoded;
    if (params == NULL) {
        return webconfig_error_decode;
    }   

    json = data->u.encoded.json;
    if (json == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    if (decode_link_report(json, &data->u.decoded.qmgr_report) != webconfig_error_none) {
        /* use qmgr_report */
         wifi_util_error_print(WIFI_WEBCONFIG," %s:%d Failed in decoding link report\n",__func__,__LINE__);
        return webconfig_error_decode;
    }
    return webconfig_error_none;
}
