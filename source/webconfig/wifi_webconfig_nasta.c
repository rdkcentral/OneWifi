/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2026 RDK Management

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
#include "wifi_webconfig.h"
#include "wifi_util.h"

/*
 * UnassocStaQuery subdoc — request decoder and response encoder.
 *
 * Request JSON (decoded by decode_nasta_query_subdoc):
 * {
 *   "Version": "1.0",
 *   "SubDocName": "UnassocStaQuery",
 *   "UnassocStaQueryList": [
 *     {
 *       "opclass": 115,
 *       "channels_length": 2,
 *       "channels": [
 *         { "channel": 36, "sta_list_length": 2,
 *           "sta_macs": ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"] },
 *         { "channel": 40, "sta_list_length": 1,
 *           "sta_macs": ["AA:BB:CC:DD:EE:03"] }
 *       ]
 *     }
 *   ]
 * }
 *
 * Response JSON (produced by encode_nasta_query_subdoc):
 * {
 *   "Version": "1.0",
 *   "SubDocName": "UnassocStaQuery",
 *   "UnassociatedSTALinkMetricsResponse": {
 *     "num_sta": 2,
 *     "sta_list": [
 *       { "sta_mac": "AA:BB:CC:DD:EE:FF", "channel": 6, "op_class": 81, "rcpi": 120 },
 *       ...
 *     ]
 *   }
 * }
 */

static const webconfig_subdoc_object_t nasta_query_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_nasta_query, "UnassocStaQueryList" },
};

webconfig_error_t init_nasta_query_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(nasta_query_objects) / sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&nasta_query_objects,
           sizeof(nasta_query_objects));
    return webconfig_error_none;
}

webconfig_error_t access_check_nasta_query_subdoc(webconfig_t *config,
    webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_nasta_query_subdoc(webconfig_t *config,
    webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_nasta_query_subdoc(webconfig_t *config,
    webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t encode_nasta_query_subdoc(webconfig_t *config,
    webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *resp_obj, *sta_array, *sta_obj;
    webconfig_subdoc_decoded_data_t *params;
    nasta_response_t *resp;
    char mac_str[18];
    char *str;
    unsigned int i;

    params = &data->u.decoded;
    resp = params->nasta_response;

    if (resp == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: nasta_response is NULL\n",
            __func__, __LINE__);
        return webconfig_error_encode;
    }

    json = cJSON_CreateObject();
    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to create JSON object\n",
            __func__, __LINE__);
        return webconfig_error_encode;
    }

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "UnassocStaQuery");

    resp_obj = cJSON_CreateObject();
    if (resp_obj == NULL) {
        cJSON_Delete(json);
        return webconfig_error_encode;
    }
    cJSON_AddItemToObject(json, "UnassociatedSTALinkMetricsResponse", resp_obj);

    cJSON_AddNumberToObject(resp_obj, "num_sta",
        (resp->num_sta > MAX_NASTA_RESPONSE_STAS) ? MAX_NASTA_RESPONSE_STAS : resp->num_sta);

    sta_array = cJSON_CreateArray();
    if (sta_array == NULL) {
        cJSON_Delete(json);
        return webconfig_error_encode;
    }
    cJSON_AddItemToObject(resp_obj, "sta_list", sta_array);

    for (i = 0; i < resp->num_sta && i < MAX_NASTA_RESPONSE_STAS; i++) {
        sta_obj = cJSON_CreateObject();
        if (sta_obj == NULL) {
            cJSON_Delete(json);
            return webconfig_error_encode;
        }
        cJSON_AddItemToArray(sta_array, sta_obj);

        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
            resp->sta_list[i].sta_mac[0], resp->sta_list[i].sta_mac[1],
            resp->sta_list[i].sta_mac[2], resp->sta_list[i].sta_mac[3],
            resp->sta_list[i].sta_mac[4], resp->sta_list[i].sta_mac[5]);

        cJSON_AddStringToObject(sta_obj, "sta_mac", mac_str);
        cJSON_AddNumberToObject(sta_obj, "channel", resp->sta_list[i].channel);
        cJSON_AddNumberToObject(sta_obj, "op_class", resp->sta_list[i].op_class);
        cJSON_AddNumberToObject(sta_obj, "rcpi", resp->sta_list[i].rcpi);
    }

    str = cJSON_Print(json);
    if (str == NULL) {
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    data->u.encoded.raw = (webconfig_subdoc_encoded_raw_t)calloc(strlen(str) + 1, sizeof(char));
    if (data->u.encoded.raw == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to allocate memory\n",
            __func__, __LINE__);
        cJSON_free(str);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    memcpy(data->u.encoded.raw, str, strlen(str));
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: NaSta Encoded JSON:\n%s\n",
        __func__, __LINE__, str);
    cJSON_free(str);
    cJSON_Delete(json);

    return webconfig_error_none;
}

webconfig_error_t decode_nasta_query_subdoc(webconfig_t *config,
    webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t *doc;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;
    nasta_query_t *query;
    unsigned int i, oc_size, ch_size, sta_size;
    cJSON *opclass_arr, *opclass_obj, *chan_arr, *chan_obj, *sta_arr, *sta_item;

    data->u.encoded.json = NULL; /* transfer ownership: local json var is responsible for cJSON_Delete */
    params = &data->u.decoded;
    if (params == NULL || json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    doc = &config->subdocs[data->type];

    /* Validate all expected top-level objects are present */
    for (i = 0; i < doc->num_objects; i++) {
        if (cJSON_GetObjectItem(json, doc->objects[i].name) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,
                "%s:%d: object:%s not present, validation failed\n",
                __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }
    }

    query = &params->nasta_query;
    memset(query, 0, sizeof(nasta_query_t));

    /* Extract VapIndex (injected by RBUS handler) */
    cJSON *vap_idx_obj = cJSON_GetObjectItem(json, "VapIndex");
    if (vap_idx_obj && cJSON_IsNumber(vap_idx_obj)) {
        query->vap_index = (unsigned int)cJSON_GetNumberValue(vap_idx_obj);
    }

    opclass_arr = cJSON_GetObjectItem(json, "UnassocStaQueryList");
    if (!cJSON_IsArray(opclass_arr)) {
        wifi_util_error_print(WIFI_WEBCONFIG,
            "%s:%d: UnassocStaQueryList is not an array\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    oc_size = cJSON_GetArraySize(opclass_arr);
    if (oc_size > MAX_NASTA_OPCLASS_ENTRIES) {
        wifi_util_error_print(WIFI_WEBCONFIG,
            "%s:%d: Too many opclass entries: %u (max %d)\n",
            __func__, __LINE__, oc_size, MAX_NASTA_OPCLASS_ENTRIES);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }
    query->num_opclass = oc_size;

    for (i = 0; i < oc_size; i++) {
        nasta_opclass_entry_t *oc = &query->opclass_list[i];
        unsigned int j;

        opclass_obj = cJSON_GetArrayItem(opclass_arr, i);
        if (!cJSON_IsObject(opclass_obj)) {
            cJSON_Delete(json);
            return webconfig_error_decode;
        }

        cJSON *oc_val = cJSON_GetObjectItem(opclass_obj, "opclass");
        if (!oc_val || !cJSON_IsNumber(oc_val)) {
            wifi_util_error_print(WIFI_WEBCONFIG,
                "%s:%d: Missing or invalid opclass field\n", __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_decode;
        }
        oc->opclass = (unsigned int)cJSON_GetNumberValue(oc_val);

        chan_arr = cJSON_GetObjectItem(opclass_obj, "channels");
        if (!cJSON_IsArray(chan_arr)) {
            wifi_util_error_print(WIFI_WEBCONFIG,
                "%s:%d: channels is not an array\n", __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_decode;
        }

        ch_size = cJSON_GetArraySize(chan_arr);
        if (ch_size > MAX_NASTA_CHANNELS) {
            wifi_util_error_print(WIFI_WEBCONFIG,
                "%s:%d: Too many channels: %u (max %d)\n",
                __func__, __LINE__, ch_size, MAX_NASTA_CHANNELS);
            cJSON_Delete(json);
            return webconfig_error_decode;
        }
        oc->channels_length = ch_size;

        for (j = 0; j < ch_size; j++) {
            nasta_channel_entry_t *ch = &oc->channels[j];
            unsigned int k;

            chan_obj = cJSON_GetArrayItem(chan_arr, j);
            if (!cJSON_IsObject(chan_obj)) {
                cJSON_Delete(json);
                return webconfig_error_decode;
            }

            cJSON *ch_val = cJSON_GetObjectItem(chan_obj, "channel");
            if (!ch_val || !cJSON_IsNumber(ch_val)) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: Missing or invalid channel field\n", __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            ch->channel = (unsigned int)cJSON_GetNumberValue(ch_val);

            sta_arr = cJSON_GetObjectItem(chan_obj, "sta_macs");
            if (sta_arr == NULL || !cJSON_IsArray(sta_arr)) {
                /* Zero STAs per channel is valid per spec */
                ch->sta_list_length = 0;
                continue;
            }

            sta_size = cJSON_GetArraySize(sta_arr);
            if (sta_size > MAX_NASTA_STA_PER_CHANNEL) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: Too many STAs per channel: %u (max %d)\n",
                    __func__, __LINE__, sta_size, MAX_NASTA_STA_PER_CHANNEL);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            ch->sta_list_length = sta_size;

            for (k = 0; k < sta_size; k++) {
                sta_item = cJSON_GetArrayItem(sta_arr, k);
                if (!cJSON_IsString(sta_item) || !sta_item->valuestring) {
                    wifi_util_error_print(WIFI_WEBCONFIG,
                        "%s:%d: Invalid STA MAC entry\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_decode;
                }

                unsigned int m[6];
                if (sscanf(sta_item->valuestring,
                        "%02x:%02x:%02x:%02x:%02x:%02x",
                        &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) {
                    wifi_util_error_print(WIFI_WEBCONFIG,
                        "%s:%d: Invalid MAC format: %s\n",
                        __func__, __LINE__, sta_item->valuestring);
                    cJSON_Delete(json);
                    return webconfig_error_decode;
                }
                ch->sta_macs[k][0] = (unsigned char)m[0];
                ch->sta_macs[k][1] = (unsigned char)m[1];
                ch->sta_macs[k][2] = (unsigned char)m[2];
                ch->sta_macs[k][3] = (unsigned char)m[3];
                ch->sta_macs[k][4] = (unsigned char)m[4];
                ch->sta_macs[k][5] = (unsigned char)m[5];
            }
        }
    }

    wifi_util_info_print(WIFI_WEBCONFIG,
        "%s:%d: NaSta query decoded: %u opclass entries, vap_index=%u\n",
        __func__, __LINE__, query->num_opclass, query->vap_index);

    cJSON_Delete(json);
    return webconfig_error_none;
}
