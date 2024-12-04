/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

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

extern webconfig_error_t encode_private_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj);
extern webconfig_error_t encode_hotspot_open_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj);
extern webconfig_error_t encode_hotspot_secure_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj);
extern webconfig_error_t encode_lnf_psk_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj);
extern webconfig_error_t encode_lnf_radius_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj);
extern webconfig_error_t encode_mesh_backhaul_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj);
extern webconfig_error_t encode_iot_vap_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj);
extern webconfig_error_t encode_mesh_sta_object(const wifi_vap_info_t *vap_info,
    const rdk_wifi_vap_info_t *rdk_vap_info, cJSON *vap_obj);

extern webconfig_error_t decode_private_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop);
extern webconfig_error_t decode_hotspot_open_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop);
extern webconfig_error_t decode_hotspot_secure_vap_object(const cJSON *vap,
    wifi_vap_info_t *vap_info, rdk_wifi_vap_info_t *rdk_vap_info,
    wifi_platform_property_t *wifi_prop);
extern webconfig_error_t decode_lnf_psk_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop);
extern webconfig_error_t decode_lnf_radius_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop);
extern webconfig_error_t decode_iot_vap_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop);
extern webconfig_error_t decode_mesh_backhaul_vap_object(const cJSON *vap,
    wifi_vap_info_t *vap_info, rdk_wifi_vap_info_t *rdk_vap_info,
    wifi_platform_property_t *wifi_prop);
extern webconfig_error_t decode_mesh_sta_object(const cJSON *vap, wifi_vap_info_t *vap_info,
    rdk_wifi_vap_info_t *rdk_vap_info, wifi_platform_property_t *wifi_prop);

webconfig_subdoc_object_t multivap_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version"       },
    { webconfig_subdoc_object_type_subdoc,  "SubDocName"    },
    { webconfig_subdoc_object_type_vaps,    "WifiVapConfig" },
};

webconfig_error_t init_multivap_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(multivap_objects) / sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&multivap_objects,
        sizeof(multivap_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_multivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_multivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if (((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) ==
            webconfig_data_descriptor_translate_to_ovsdb) ||
        ((data->descriptor & webconfig_data_descriptor_translate_to_easymesh) ==
            webconfig_data_descriptor_translate_to_easymesh)) {
        if (config->proto_desc.translate_to(data->type, data) != webconfig_error_none) {
            if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) ==
                webconfig_data_descriptor_translate_to_ovsdb) {
                return webconfig_error_translate_to_ovsdb;
            } else {
                return webconfig_error_translate_to_easymesh;
            }
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) ==
        webconfig_data_descriptor_translate_to_tr181) {
    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t translate_to_multivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if (((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) ==
            webconfig_data_descriptor_translate_from_ovsdb) ||
        ((data->descriptor & webconfig_data_descriptor_translate_from_easymesh) ==
            webconfig_data_descriptor_translate_from_easymesh)) {
        if (config->proto_desc.translate_from(data->type, data) != webconfig_error_none) {
            if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) ==
                webconfig_data_descriptor_translate_from_ovsdb) {
                return webconfig_error_translate_from_ovsdb;
            } else {
                return webconfig_error_translate_from_easymesh;
            }
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) ==
        webconfig_data_descriptor_translate_from_tr181) {
    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t encode_multivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj, *obj_array;
    wifi_vap_info_map_t *map;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_t *vap;
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_subdoc_decoded_data_t *params;
    int radio_index = -1;
    char *str;
    char mac_string[18] = { 0 };
    int primary_macaddr_added = 0;

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Enter subdoc_type:%d\n", __FUNCTION__, data->type);

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");

    switch (data->type) {
    case webconfig_subdoc_type_vap_24G:
        cJSON_AddStringToObject(json, "SubDocName", "Vap_2.4G");
        radio_index = 0;
        break;
    case webconfig_subdoc_type_vap_5G:
        cJSON_AddStringToObject(json, "SubDocName", "Vap_5G");
        radio_index = 1;
        break;
    case webconfig_subdoc_type_vap_6G:
        cJSON_AddStringToObject(json, "SubDocName", "Vap_6G");
        radio_index = 2;
        break;
    default:
        // Invalid type, set Radio index to -1
        radio_index = -1;
        break;
    }

    if (radio_index < 0 || radio_index >= params->num_radios) {
        wifi_util_error_print(WIFI_WEBCONFIG,
            "%s:%d radio index:%d not correct for num_radios:%d.\n", __func__, __LINE__,
            radio_index, params->num_radios);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Radio Index:%d\n", __func__, __LINE__, radio_index);
    // Based on the data->type determine the radio pointer.
    radio = &params->radios[radio_index];
    map = &radio->vaps.vap_map;

    // Add the mac address of the primary vapname
    for (unsigned int j = 0; j < map->num_vaps; j++) {
        vap = &map->vap_array[j];
        rdk_vap = &radio->vaps.rdk_vap_array[j];
        if (is_vap_private(&params->hal_cap.wifi_prop, vap->vap_index) &&
            (strlen(vap->vap_name) != 0)) {
            // Obtain the mac and add
            uint8_mac_to_string_mac((uint8_t *)vap->u.bss_info.bssid, mac_string);
            cJSON_AddStringToObject(json, "Primary MacAddress", mac_string);
            primary_macaddr_added = 1;
            break;
        }
    }
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Primary Macaddress %s\n", __func__, __LINE__,
        ((primary_macaddr_added == 0) ? "not added" : "added"));

    // encode multivap objects associated with the radio_index
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiVapConfig", obj_array);

    for (unsigned int j = 0; j < map->num_vaps; j++) {
        vap = &map->vap_array[j];
        rdk_vap = &radio->vaps.rdk_vap_array[j];
        if (is_vap_private(&params->hal_cap.wifi_prop, vap->vap_index) &&
            (strlen(vap->vap_name) != 0)) {
            obj = cJSON_CreateObject();
            cJSON_AddItemToArray(obj_array, obj);
            if (encode_private_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: Failed to encode private vap object for Radio index:%d\n", __func__,
                    __LINE__, radio_index);
                cJSON_Delete(json);
                return webconfig_error_encode;
            }
        } else if (is_vap_hotspot_open(&params->hal_cap.wifi_prop, vap->vap_index) &&
            (strlen(vap->vap_name) != 0)) {
            obj = cJSON_CreateObject();
            cJSON_AddItemToArray(obj_array, obj);
            if (encode_hotspot_open_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: Failed to encode hotspot open vap object for Radio index:%d\n",
                    __func__, __LINE__, radio_index);
                cJSON_Delete(json);
                return webconfig_error_encode;
            }
        } else if (is_vap_hotspot_secure(&params->hal_cap.wifi_prop, vap->vap_index) &&
            (strlen(vap->vap_name) != 0)) {
            obj = cJSON_CreateObject();
            cJSON_AddItemToArray(obj_array, obj);
            if (encode_hotspot_secure_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: Failed to encode hotspot secure vap object for Radio index:%d\n",
                    __func__, __LINE__, radio_index);
                cJSON_Delete(json);
                return webconfig_error_encode;
            }
        } else if (is_vap_lnf_psk(&params->hal_cap.wifi_prop, vap->vap_index) &&
            (strlen(vap->vap_name) != 0)) {
            obj = cJSON_CreateObject();
            cJSON_AddItemToArray(obj_array, obj);
            if (encode_lnf_psk_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: Failed to encode lnf_psk psk vap object for Radio index:%d\n", __func__,
                    __LINE__, radio_index);
                cJSON_Delete(json);
                return webconfig_error_encode;
            }
        } else if (is_vap_lnf_radius(&params->hal_cap.wifi_prop, vap->vap_index) &&
            (strlen(vap->vap_name) != 0)) {
            obj = cJSON_CreateObject();
            cJSON_AddItemToArray(obj_array, obj);
            if (encode_lnf_radius_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: Failed to encode lnf_radius vap object for Radio index:%d\n", __func__,
                    __LINE__, radio_index);
                cJSON_Delete(json);
                return webconfig_error_encode;
            }
        } else if (is_vap_mesh_backhaul(&params->hal_cap.wifi_prop, vap->vap_index) &&
            (strlen(vap->vap_name) != 0)) {
            obj = cJSON_CreateObject();
            cJSON_AddItemToArray(obj_array, obj);
            if (encode_mesh_backhaul_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: Failed to encode mesh backhaul vap object for Radio index:%d\n",
                    __func__, __LINE__, radio_index);
                cJSON_Delete(json);
                return webconfig_error_encode;
            }
        } else if (is_vap_mesh_sta(&params->hal_cap.wifi_prop, vap->vap_index) &&
            (strlen(vap->vap_name) != 0)) {
            obj = cJSON_CreateObject();
            cJSON_AddItemToArray(obj_array, obj);
            if (encode_mesh_sta_object(vap, rdk_vap, obj) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: Failed to encode mesh sta object for Radio index:%d\n", __func__,
                    __LINE__, radio_index);
                cJSON_Delete(json);
                return webconfig_error_encode;
            }
        } else if (is_vap_xhs(&params->hal_cap.wifi_prop, vap->vap_index) &&
            (strlen(vap->vap_name) != 0)) {
            obj = cJSON_CreateObject();
            cJSON_AddItemToArray(obj_array, obj);
            if (encode_iot_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,
                    "%s:%d: Failed to encode iot vap object for Radio index: %d\n", __func__,
                    __LINE__, radio_index);
                cJSON_Delete(json);
                return webconfig_error_encode;
            }
        } else {
            wifi_util_error_print(WIFI_WEBCONFIG,
                "%s:%d: Unknown vap:%s unable to encode for Radio index: %d\n", __func__, __LINE__,
                vap->vap_name, radio_index);
            cJSON_Delete(json);
            return webconfig_error_encode;
        }
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

webconfig_error_t decode_multivap_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t *doc;
    cJSON *obj_vaps;
    cJSON *obj, *obj_vap;
    unsigned int size, radio_index, vap_array_index;
    unsigned int presence_count = 0;
    char *name;
    unsigned int num_lnf_ssid;
    wifi_vap_name_t vap_names[MAX_NUM_VAP_PER_RADIO];
    wifi_vap_info_t *vap_info;
    rdk_wifi_vap_info_t *rdk_vap_info;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;
    unsigned int i = 0, j = 0;
    char *str;

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Enter subdoc_type:%d\n", __FUNCTION__, data->type);

    str = cJSON_Print(json);
    json_param_obscure(str, "Passphrase");
    json_param_obscure(str, "RadiusSecret");
    json_param_obscure(str, "SecondaryRadiusSecret");
    json_param_obscure(str, "DasSecret");
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: decoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_free(str);

    params = &data->u.decoded;
    doc = &config->subdocs[data->type];

    // decode VAP objects
    obj_vaps = cJSON_GetObjectItem(json, "WifiVapConfig");
    if (cJSON_IsArray(obj_vaps) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap object not present\n", __func__,
            __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_vaps);
    if (size > MAX_NUM_VAP_PER_RADIO) {
        wifi_util_error_print(WIFI_WEBCONFIG,
            "%s:%d: vap objects size: %d exceeding MAX_NUM_VAP_PER_RADIO:%d\n", __func__, __LINE__,
            size, MAX_NUM_VAP_PER_RADIO);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        // check presence of all vap names
        if ((obj = cJSON_GetObjectItem(obj_vap, "VapName")) == NULL) {
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "VapName not present.\n%s\n",
                (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }
    }

    for (i = 0; i < params->hal_cap.wifi_prop.numRadios; i++) {
        params->radios[i].vaps.vap_map.num_vaps =
            params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
        params->radios[i].vaps.num_vaps = params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
    }

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_vap, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(&params->hal_cap.wifi_prop, name);
        vap_array_index = convert_vap_name_to_array_index(&params->hal_cap.wifi_prop, name);
        if (((int)radio_index < 0) || ((int)vap_array_index < 0)) {
            wifi_util_error_print(WIFI_WEBCONFIG,
                "%s:%d: Invalid radio_index:%d or vap_array_index:%d\n", __func__, __LINE__,
                radio_index, vap_array_index);
            continue;
        }
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio index: %d , vap name: %s\n%s\n", __func__,
            __LINE__, radio_index, name, cJSON_Print(obj_vap));
        vap_info = &params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        rdk_vap_info = &params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        memset(vap_info, 0, sizeof(wifi_vap_info_t));
        if (strncmp(name, "private_ssid", strlen("private_ssid")) == 0) {
            if (decode_private_vap_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "hotspot_open", strlen("hotspot_open")) == 0) {
            if (decode_hotspot_open_vap_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "hotspot_secure", strlen("hotspot_secure")) == 0) {
            if (decode_hotspot_secure_vap_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "lnf_psk", strlen("lnf_psk")) == 0) {
            if (decode_lnf_psk_vap_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "lnf_radius", strlen("lnf_radius")) == 0) {
            if (decode_lnf_radius_vap_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "iot_ssid", strlen("iot_ssid")) == 0) {
            if (decode_iot_vap_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "mesh_backhaul", strlen("mesh_backhaul")) == 0) {
            if (decode_mesh_backhaul_vap_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "mesh_sta", strlen("mesh_sta")) == 0) {
            if (decode_mesh_sta_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                    __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Unknown Vap:%s unable to decode\n",
                __func__, __LINE__, name);
            cJSON_Delete(json);
            return webconfig_error_decode;
        }
    }

    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);
    cJSON_Delete(json);
    return webconfig_error_none;
}
