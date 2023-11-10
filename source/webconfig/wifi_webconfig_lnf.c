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

webconfig_subdoc_object_t  lnf_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_vaps, "WifiVapConfig" },
};

webconfig_error_t init_lnf_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(lnf_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&lnf_objects, sizeof(lnf_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_lnf_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_lnf_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) == webconfig_data_descriptor_translate_to_ovsdb) {
        if (translate_to_ovsdb_tables(webconfig_subdoc_type_lnf, data) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

        } else {

        } // no translation required
    }

    return webconfig_error_none;
}

webconfig_error_t translate_to_lnf_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (translate_from_ovsdb_tables(webconfig_subdoc_type_lnf, data) != webconfig_error_none) {
            return webconfig_error_translate_from_ovsdb;
        } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) == webconfig_data_descriptor_translate_from_tr181) {

        } else {

        } // no translation required
    }

    return webconfig_error_none;
}

webconfig_error_t encode_lnf_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Enter\n", __FUNCTION__);
    cJSON *json;
    cJSON *obj, *obj_array;
    wifi_vap_info_map_t *map;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_t *vap;
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_subdoc_decoded_data_t *params;
    char *str;

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "lnf");

    // ecode lnf vap objects
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiVapConfig", obj_array);

    for( unsigned int i = 0; i < params->num_radios; i++ ) {
        radio = &params->radios[i];
        map = &radio->vaps.vap_map;
        for ( unsigned int j = 0; j < map->num_vaps; j++) {
            vap = &map->vap_array[j];
            rdk_vap = &radio->vaps.rdk_vap_array[j];
            if (strncmp("lnf_psk", vap->vap_name, strlen("lnf_psk")) == 0) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_lnf_psk_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode lnf_psk psk vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;
                }
            } else {
                if (strncmp("lnf_radius", vap->vap_name, strlen("lnf_radius")) == 0) {
                    obj = cJSON_CreateObject();
                    cJSON_AddItemToArray(obj_array, obj);
                    if (encode_lnf_radius_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode lnf_radius vap object\n", __func__, __LINE__);
                        cJSON_Delete(json);
                        return webconfig_error_encode;
                    }
                }
            }
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

    json_param_obscure(str, "Passphrase");
    json_param_obscure(str, "RadiusSecret");
    json_param_obscure(str, "SecondaryRadiusSecret");
    json_param_obscure(str, "DasSecret");
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_free(str);
    cJSON_Delete(json);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success\n", __func__, __LINE__);
    return webconfig_error_none;
}


webconfig_error_t decode_lnf_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Enter\n", __FUNCTION__);

    webconfig_subdoc_t  *doc;
    cJSON *obj_vaps;
    cJSON *obj, *obj_vap;
    unsigned int size, radio_index, vap_array_index;
    unsigned int presence_count = 0;
    char *name;
    unsigned int num_lnf_ssid;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * 2];
    wifi_vap_info_t *vap_info;
    rdk_wifi_vap_info_t *rdk_vap_info;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;
    unsigned int i = 0, j = 0;
    char *str;

    str = cJSON_Print(json);
    json_param_obscure(str, "Passphrase");
    json_param_obscure(str, "RadiusSecret");
    json_param_obscure(str, "SecondaryRadiusSecret");
    json_param_obscure(str, "DasSecret");
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: decoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_free(str);

    params = &data->u.decoded;
    doc = &config->subdocs[data->type];

    /* get list of lnf_psk SSID */
    num_lnf_ssid = get_list_of_lnf_psk(&params->hal_cap.wifi_prop, MAX_NUM_RADIOS, vap_names);
    /* get list of lnf_radius SSID */
    num_lnf_ssid += get_list_of_lnf_radius(&params->hal_cap.wifi_prop, MAX_NUM_RADIOS, &vap_names[num_lnf_ssid]);

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }
    }

    // decode VAP objects
    obj_vaps = cJSON_GetObjectItem(json, "WifiVapConfig");
    if (cJSON_IsArray(obj_vaps) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_vaps);
    if (num_lnf_ssid > size) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of vap objects: %d, expected: %d\n",
                __func__, __LINE__, size, params->hal_cap.wifi_prop.numRadios);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        // check presence of all vap names
        if ((obj = cJSON_GetObjectItem(obj_vap, "VapName")) == NULL) {
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }

        for (j = 0; j < size; j++) {
            if (strncmp(cJSON_GetStringValue(obj), vap_names[j], strlen(vap_names[j])) == 0) {
                presence_count++;
            }
        }
    }

    if (presence_count != num_lnf_ssid) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap object not present\n", __func__, __LINE__);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    // first set the structure to all 0
    //memset(&params->radios, 0, sizeof(rdk_wifi_radio_t) *  params->hal_cap.wifi_prop.numRadios);
    for (i = 0; i <  params->hal_cap.wifi_prop.numRadios; i++) {
        params->radios[i].vaps.vap_map.num_vaps = params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
        params->radios[i].vaps.num_vaps = params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
    }

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_vap, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(&params->hal_cap.wifi_prop, name);
        vap_array_index = convert_vap_name_to_array_index(&params->hal_cap.wifi_prop, name);
        if (((int)radio_index < 0) || ((int)vap_array_index < 0)){
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid index\n", __func__, __LINE__);
            continue;
        }
        vap_info = &params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        rdk_vap_info = &params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        //wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio index: %d , vap name: %s\n%s\n",
        //            __func__, __LINE__, radio_index, name, cJSON_Print(obj_vap));

        if (!strncmp(name, "lnf_psk", strlen("lnf_psk"))) {
            memset(vap_info, 0, sizeof(wifi_vap_info_t));
            if (decode_lnf_psk_vap_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else {
            if (!strncmp(name, "lnf_radius", strlen("lnf_radius"))) {
                memset(vap_info, 0, sizeof(wifi_vap_info_t));
                if (decode_lnf_radius_vap_object(obj_vap, vap_info, rdk_vap_info,
                        &params->hal_cap.wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                            __func__, __LINE__);
                    cJSON_Delete(json);
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                    return webconfig_error_decode;
                }
            }
        }

    }

    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);
    cJSON_Delete(json);
    return webconfig_error_none;
}
