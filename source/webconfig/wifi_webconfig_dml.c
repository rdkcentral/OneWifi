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

webconfig_subdoc_object_t   dml_objects[7] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_config, "WifiConfig" },
    { webconfig_subdoc_object_type_radios, "WifiRadioConfig" },
    { webconfig_subdoc_object_type_vaps, "WifiVapConfig" },
    { webconfig_subdoc_object_type_wifi_mac_filter, "WifiMacFilter" },
    { webconfig_subdoc_object_type_wificap, "WiFiCap" },
};

webconfig_error_t init_dml_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(dml_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&dml_objects, sizeof(dml_objects));

    return webconfig_error_none;
}

webconfig_error_t access_check_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) == webconfig_data_descriptor_translate_to_ovsdb) {
        if (translate_to_ovsdb_tables(webconfig_subdoc_type_dml, data) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

    } else {
        // no translation required
    }

    return webconfig_error_none;
}

webconfig_error_t translate_to_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (translate_from_ovsdb_tables(webconfig_subdoc_type_dml, data) != webconfig_error_none) {
            return webconfig_error_translate_from_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) == webconfig_data_descriptor_translate_from_tr181) {

    } else {
        // no translation required
    }

    return webconfig_error_none;
}

webconfig_error_t encode_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *obj, *obj_array, *hal_cap;
    unsigned int i, j, array_size = 0;
    wifi_vap_info_map_t *map;
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_vap_info_t *vap;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t      *vap_map;
    rdk_wifi_vap_info_t *rdk_vap_info;
    webconfig_subdoc_decoded_data_t *params;
    char *str;
    wifi_interface_name_idex_map_t *interface_map;
    radio_interface_mapping_t *radio_interface_map;
    char *vap_name;
    wifi_platform_property_t *wifi_prop;

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "dml");

    // encode config object
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(json, "WifiConfig", obj);
    if (encode_config_object(&params->config, obj) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi global config\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

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

    // encode private vap objects
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiVapConfig", obj_array);

    for (i = 0; i < params->num_radios; i++) {
        radio = &params->radios[i];
        map = &radio->vaps.vap_map;
        for (j = 0; j < map->num_vaps; j++) {
            vap = &map->vap_array[j];
            rdk_vap = &radio->vaps.rdk_vap_array[j];
            vap_name = get_vap_name(&params->hal_cap.wifi_prop, vap->vap_index);
            if (strncmp("private_ssid", vap_name, strlen("private_ssid")) == 0) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_private_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode private vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if (strncmp("iot_ssid", vap_name, strlen("iot_ssid")) == 0) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_private_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode private vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if (strncmp("hotspot_open", vap_name, strlen("hotspot_open")) == 0) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_hotspot_open_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode hotspot open vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if (strncmp("hotspot_secure", vap_name, strlen("hotspot_secure")) == 0) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_hotspot_secure_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode hotspot secure vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if (strncmp("lnf_psk", vap_name, strlen("lnf_psk")) == 0) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_lnf_psk_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode lnf psk vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if (strncmp("lnf_radius", vap_name, strlen("lnf_radius")) == 0) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_lnf_radius_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode lnf radius vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if (strncmp("mesh_backhaul", vap_name, strlen("mesh_backhaul")) == 0) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_mesh_backhaul_vap_object(vap, rdk_vap, obj) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode mesh backhaul vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if (strncmp("mesh_sta", vap_name, strlen("mesh_sta")) == 0) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_mesh_sta_object(vap, rdk_vap, obj) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode mesh sta object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            }
        }
    }

    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiMacFilter", obj_array);

    for(i = 0; i < params->num_radios; i++) {
        vap_map = &params->radios[i].vaps.vap_map;
        for (j = 0; j < vap_map->num_vaps; j++) {
            rdk_vap_info = &params->radios[i].vaps.rdk_vap_array[j];

            if (encode_mac_object(rdk_vap_info, obj_array) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode mac object\n", __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_encode;

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
    json_param_obscure(str, "WpsConfigPin");
    json_param_obscure(str, "RadiusSecret");
    json_param_obscure(str, "SecondaryRadiusSecret");
    json_param_obscure(str, "DasSecret");
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, str);

    cJSON_free(str);
    cJSON_Delete(json);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success\n", __func__, __LINE__);

    return webconfig_error_none;
}

webconfig_error_t decode_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *obj_config, *obj_radios, *obj_vaps;
    cJSON *obj, *obj_radio, *obj_vap, *obj_mac, *obj_acl, *obj_wificap, *object, *hal_cap;
    unsigned int i, j, size, radio_index, vap_array_index = 0;
    wifi_interface_name_idex_map_t *interface_map;
    radio_interface_mapping_t *radio_interface_map;
    rdk_wifi_vap_info_t *rdk_vap_info;
    unsigned int presence_mask = 0;
    //unsigned char should_apply_mask = 0;
    char *radio_names[MAX_NUM_RADIOS] = {"radio1", "radio2", "radio3"};
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    char *name;
    wifi_vap_info_t *vap_info;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;
    wifi_platform_property_t *wifi_prop;
    int num_vaps;
    char *str;

    str = cJSON_Print(json);
    json_param_obscure(str, "Passphrase");
    json_param_obscure(str, "WpsConfigPin");
    json_param_obscure(str, "RadiusSecret");
    json_param_obscure(str, "SecondaryRadiusSecret");
    json_param_obscure(str, "DasSecret");
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: decoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_free(str);

    params = &data->u.decoded;
    doc = &config->subdocs[data->type];
    wifi_prop = &params->hal_cap.wifi_prop;

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }
    }

    // decode config object
    memset(&params->config, 0, sizeof(wifi_global_config_t));
    obj_config = cJSON_GetObjectItem(json, "WifiConfig");
    if (decode_config_object(obj_config, &params->config) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Config Object validation failed\n",
                __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
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
        memset(&params->radios[i], 0, sizeof(rdk_wifi_radio_t));
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

    /* get the vap names interested */
    num_vaps = get_list_of_vap_names(wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
                                     8, VAP_PREFIX_PRIVATE, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE, \
                                     VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS, VAP_PREFIX_MESH_BACKHAUL, \
                                     VAP_PREFIX_MESH_STA, VAP_PREFIX_IOT);

    // decode VAP objects
    obj_vaps = cJSON_GetObjectItem(json, "WifiVapConfig");
    if (cJSON_IsArray(obj_vaps) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_vaps);
    if (num_vaps > (int)size) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of vap objects: %d, expected: %d\n",
                __func__, __LINE__, size, num_vaps);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    presence_mask = 0;

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
                presence_mask |= (1 << j);
            }
        }
    }

//    if (presence_mask != pow(2, MAX_NUM_VAP_PER_RADIO*params->num_radios) - 1) {
    /* check the present count against number of vaps found in vap_names array */
    if (presence_mask != (pow(2, num_vaps) - 1)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object not present, mask:%x\n",
                __func__, __LINE__, presence_mask);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    // first set the structure to all 0

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_vap, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, name);
        vap_array_index = convert_vap_name_to_array_index(wifi_prop, name);
        if (((int)radio_index < 0) || ((int)vap_array_index < 0)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid index\n", __func__, __LINE__);
            continue;
        }
        vap_info = &params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        rdk_vap_info = &params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];

/*        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio index: %d , vap name: %s\n%s\n",
                    __func__, __LINE__, radio_index, name, cJSON_Print(obj_vap));*/
        memset(vap_info, 0, sizeof(wifi_vap_info_t));
        if (strncmp(name, "private_ssid", strlen("private_ssid")) == 0) {
            if (decode_private_vap_object(obj_vap, vap_info, rdk_vap_info, wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "hotspot_open", strlen("hotspot_open")) == 0) {
            if (decode_hotspot_open_vap_object(obj_vap, vap_info, rdk_vap_info, wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "hotspot_secure", strlen("hotspot_secure")) == 0) {
            if (decode_hotspot_secure_vap_object(obj_vap, vap_info, rdk_vap_info, wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "lnf_psk", strlen("lnf_psk")) == 0) {
            if (decode_lnf_psk_vap_object(obj_vap, vap_info, rdk_vap_info, wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "lnf_radius", strlen("lnf_radius")) == 0) {
            if (decode_lnf_radius_vap_object(obj_vap, vap_info, rdk_vap_info, wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "iot_ssid", strlen("iot_ssid")) == 0) {
            if (decode_iot_vap_object(obj_vap, vap_info, rdk_vap_info, wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "mesh_backhaul", strlen("mesh_backhaul")) == 0) {
            if (decode_mesh_backhaul_vap_object(obj_vap, vap_info, rdk_vap_info, wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        } else if (strncmp(name, "mesh_sta", strlen("mesh_sta")) == 0) {
            if (decode_mesh_sta_object(obj_vap, vap_info, rdk_vap_info, wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
                return webconfig_error_decode;
            }
        }
    }

    //decode MACFilter

    obj_mac = cJSON_GetObjectItem(json, "WifiMacFilter");
    if (cJSON_IsArray(obj_mac) == false) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Mac object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_mac);
    if (num_vaps > (int)size) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of mac objects: %d\n",
                __func__, __LINE__, size);
        cJSON_Delete(json);
        wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
        return webconfig_error_invalid_subdoc;
    }
    for (i = 0; i < size; i++) {
        obj_acl = cJSON_GetArrayItem(obj_mac, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_acl, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, name);
        vap_array_index = convert_vap_name_to_array_index(wifi_prop, name);
        if (((int)radio_index < 0) || ((int)vap_array_index < 0)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid index\n", __func__, __LINE__);
            continue;
        }
        rdk_vap_info = &params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap_info->vap_index = convert_vap_name_to_index(wifi_prop, name);
        if ((int)rdk_vap_info->vap_index < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid  vap_index\n", __func__, __LINE__);
            continue;
        }
        if (decode_mac_object(rdk_vap_info, obj_acl) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: mac state object validation failed\n",
                    __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
        }
    }

    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);
    cJSON_Delete(json);

    return webconfig_error_none;
}
