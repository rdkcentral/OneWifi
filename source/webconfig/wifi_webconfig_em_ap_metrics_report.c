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

#ifdef EM_APP
webconfig_subdoc_object_t   em_ap_metrics_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_em_ap_metrics_report, "EMAPMetricsReport" },
};

webconfig_error_t init_em_ap_metrics_report_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(em_ap_metrics_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&em_ap_metrics_objects, sizeof(em_ap_metrics_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_em_ap_metrics_report_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_em_ap_metrics_report_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_easymesh) == webconfig_data_descriptor_translate_to_easymesh) {
        if (config->proto_desc.translate_to(webconfig_subdoc_type_em_ap_metrics_report, data) != webconfig_error_none) {
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

webconfig_error_t translate_to_em_ap_metrics_report_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_em_ap_metrics_report_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json, *emap_metrics_report_obj;
    char *str = NULL;
    webconfig_subdoc_decoded_data_t *params = NULL;
    rdk_wifi_radio_t *radio = NULL;
    em_ap_metrics_report_t *ap_report = &data->u.decoded.em_ap_metrics_report;

    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL data Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    radio = &params->radios[ap_report->radio_index];
    if (radio == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unable to find the interface map entry\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    json = cJSON_CreateObject();
    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "Easymesh AP Metrics Report");

    emap_metrics_report_obj = cJSON_CreateObject();
    if ((emap_metrics_report_obj == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return webconfig_error_encode;
    }
    cJSON_AddItemToObject(json, "EMAPMetricsReport", emap_metrics_report_obj);

    encode_em_ap_metrics_report_object(radio, ap_report, emap_metrics_report_obj);

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

webconfig_error_t decode_em_ap_metrics_report_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *params;
    cJSON *json;
    webconfig_subdoc_t  *doc;
    int i = 0;

    params = &data->u.decoded;
    if (params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    json = data->u.encoded.json;
    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    char *str;
    str = cJSON_Print(json);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Decoded Str is : %s\n", __func__, __LINE__, str);
    cJSON_free(str);

    memset(&params->em_ap_metrics_report, 0, sizeof(em_ap_metrics_report_t));

    doc = &config->subdocs[data->type];

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }
    }

    decode_em_ap_metrics_report_object(json, &params->em_ap_metrics_report);

    return webconfig_error_none;
}
#endif