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

webconfig_subdoc_object_t   mesh_sta_objects[5] = {
    { webconfig_subdoc_object_type_version,     "Version" },
    { webconfig_subdoc_object_type_subdoc,      "SubDocName" },
    { webconfig_subdoc_object_type_radios,      "WifiRadioConfig" },
    { webconfig_subdoc_object_type_wificap,     "WiFiCap" },
    { webconfig_subdoc_object_type_vaps,        "WifiVapConfig" }
};

webconfig_error_t init_mesh_sta_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(mesh_sta_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&mesh_sta_objects, sizeof(mesh_sta_objects));

    return webconfig_error_none;
}


webconfig_error_t access_check_mesh_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_mesh_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) == webconfig_data_descriptor_translate_to_ovsdb) {
        if (translate_to_ovsdb_tables(webconfig_subdoc_type_mesh_sta, data) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t translate_to_mesh_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (translate_from_ovsdb_tables(webconfig_subdoc_type_mesh_sta, data) != webconfig_error_none) {
            return webconfig_error_translate_from_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) == webconfig_data_descriptor_translate_from_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t encode_mesh_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj, *obj_array, *hal_cap;
    unsigned int i, j;
    wifi_vap_info_map_t *map;
    wifi_vap_info_t *vap;
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_subdoc_decoded_data_t *params;
    char *str;
    char *vap_name;
    rdk_wifi_radio_t *radio;

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "mesh sta");

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

    unsigned int array_size = 0;
    wifi_interface_name_idex_map_t *interface_map;
    radio_interface_mapping_t *radio_interface_map;
    wifi_platform_property_t *wifi_prop;
    //encode hal cap

    hal_cap = cJSON_CreateObject();
    cJSON_AddItemToObject(json, "WiFiCap", hal_cap);

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(hal_cap, "WiFiRadioCap", obj_array);

    wifi_prop = &params->hal_cap.wifi_prop;
    if (encode_wifiradiocap(wifi_prop, obj_array, params->num_radios) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode radiocap object\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(hal_cap, "WiFiVapCap", obj_array);

    array_size = sizeof(params->hal_cap.wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t);

    for(i = 0; i < array_size; i++) {
        interface_map = &params->hal_cap.wifi_prop.interface_map[i];
        if (encode_wifivapcap(interface_map, obj_array) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode halcap object\n", __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_encode;
        }
    }

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(hal_cap, "WiFiRadioInterfaceCap", obj_array);

    array_size = sizeof(params->hal_cap.wifi_prop.radio_interface_map)/sizeof(radio_interface_mapping_t);

    for(i = 0; i < array_size; i++) {
        radio_interface_map = &params->hal_cap.wifi_prop.radio_interface_map[i];
        if (encode_wifiradiointerfacecap(radio_interface_map, obj_array) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode radiointerfacecap object\n", __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_encode;
        }
    }

    // ecode mesh vap objects
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiVapConfig", obj_array);

    for (i = 0; i < params->num_radios; i++) {
        radio = &params->radios[i];
        map = &radio->vaps.vap_map;
        for (j = 0; j < map->num_vaps; j++) {
            vap = &map->vap_array[j];
            rdk_vap = &radio->vaps.rdk_vap_array[j];
            vap_name = get_vap_name(&params->hal_cap.wifi_prop, vap->vap_index);
            if (strnlen(vap_name,sizeof(wifi_vap_name_t)) == 0) {
                continue;
            }

            if (strncmp("mesh_sta", vap_name, strlen("mesh_sta")) == 0) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_mesh_sta_object(vap, rdk_vap, obj) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode mesh sta vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;
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
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_free(str);
    cJSON_Delete(json);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success\n", __func__, __LINE__);
    return webconfig_error_none;
}

webconfig_error_t decode_mesh_sta_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *obj_vaps;
    cJSON *obj, *obj_vap;
    unsigned int i, j, size, radio_index, vap_array_index = 0;
    unsigned int presence_count = 0;
    unsigned int num_mesh_ssid;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS];
    unsigned int presence_mask = 0;
    char radio_names[MAX_NUM_RADIOS][8];
    char *name, *str;
    wifi_vap_info_t *vap_info;
    rdk_wifi_vap_info_t *rdk_vap_info;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;
    cJSON *obj_wificap, *object, *obj_radios, *obj_radio, *hal_cap;
    wifi_interface_name_idex_map_t *interface_map;
    radio_interface_mapping_t *radio_interface_map;
    wifi_platform_property_t *wifi_prop;

    params = &data->u.decoded;
    doc = &config->subdocs[data->type];

    for (i = 0; i < MAX_NUM_RADIOS; i++) {
        snprintf(radio_names[i], sizeof(radio_names[i]), "radio%d", i+1);
    }

    str = cJSON_Print(json);
    json_param_obscure(str, "Passphrase");
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: decoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_free(str);

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }
    }

    //decode Wifi Cap
    hal_cap = cJSON_GetObjectItem(json, "WiFiCap");

    obj_wificap = cJSON_GetObjectItem(hal_cap, "WiFiRadioCap");
    if (cJSON_IsArray(obj_wificap) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: HAL Cap not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    memset(&params->hal_cap.wifi_prop.radiocap[0], 0, sizeof(wifi_radio_capabilities_t)* (MAX_NUM_RADIOS));
    wifi_prop = &params->hal_cap.wifi_prop;
    if (decode_wifiradiocap(wifi_prop, obj_wificap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: hal cap object validation failed\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_decode;
    }

    obj_wificap = cJSON_GetObjectItem(hal_cap, "WiFiVapCap");
    if (cJSON_IsArray(obj_wificap) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: HAL Cap not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    memset(&params->hal_cap.wifi_prop.interface_map[0], 0, sizeof(wifi_interface_name_idex_map_t)* (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO));
    size = cJSON_GetArraySize(obj_wificap);
    for (i=0; i<size; i++) {
        object  = cJSON_GetArrayItem(obj_wificap, i);
        interface_map = &params->hal_cap.wifi_prop.interface_map[i];
        if (decode_wifivapcap(interface_map, object) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: hal cap object validation failed\n", __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
        }
    }

    for (i = 0; i < MAX_NUM_RADIOS; i++)
    {
        params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs = 0;
    }
    for (i=0; i<size; i++) {

        interface_map = &params->hal_cap.wifi_prop.interface_map[i];
        if (interface_map->vap_name[0] != '\0')
        {
            params->hal_cap.wifi_prop.radiocap[interface_map->rdk_radio_index].maxNumberVAPs++;
        }
    }

    obj_wificap = cJSON_GetObjectItem(hal_cap, "WiFiRadioInterfaceCap");
    if (cJSON_IsArray(obj_wificap) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio Interface Cap not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    memset(&params->hal_cap.wifi_prop.radio_interface_map[0], 0, sizeof(radio_interface_mapping_t)* (MAX_NUM_RADIOS));
    size = cJSON_GetArraySize(obj_wificap);
    for (i=0; i<size; i++) {
        object  = cJSON_GetArrayItem(obj_wificap, i);
        radio_interface_map = &params->hal_cap.wifi_prop.radio_interface_map[i];
        if (decode_wifiradiointerfacecap(radio_interface_map, object) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: radio interface cap object validation failed\n", __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
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
                presence_mask |= (1 << j);
            }
        }
    }

    if (size < MIN_NUM_RADIOS || size > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio count\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

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
        params->radios[i].vaps.vap_map.num_vaps = params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
        params->radios[i].vaps.num_vaps = params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
    }
    params->num_radios = size;
    params->hal_cap.wifi_prop.numRadios = size;

    /* get list of mesh_sta SSID */
    num_mesh_ssid = get_list_of_mesh_sta(&params->hal_cap.wifi_prop, MAX_NUM_RADIOS, vap_names);

    // decode VAP objects
    obj_vaps = cJSON_GetObjectItem(json, "WifiVapConfig");
    if (cJSON_IsArray(obj_vaps) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_vaps);
    if (num_mesh_ssid > size) {
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

    if (presence_count != num_mesh_ssid) {
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap object not present:%d:%d\n", __func__, __LINE__, presence_count, num_mesh_ssid);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_vap, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(&params->hal_cap.wifi_prop, name);
        vap_array_index = convert_vap_name_to_array_index(&params->hal_cap.wifi_prop, name);
        if (((int)radio_index < 0) || ((int)vap_array_index < 0)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid index\n", __func__, __LINE__);
            continue;
        }
        vap_info = &params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        rdk_vap_info = &params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];

        if (strncmp(name, "mesh_sta", strlen("mesh_sta")) == 0) {
            memset(vap_info, 0, sizeof(wifi_vap_info_t));
            if (decode_mesh_sta_object(obj_vap, vap_info, rdk_vap_info,
                    &params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        }
    }

    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);
    cJSON_Delete(json);

    return webconfig_error_none;
}

