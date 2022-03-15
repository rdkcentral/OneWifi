/************************************************************************************
  If not stated otherwise in this file or this component's Licenses.txt file the
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

webconfig_subdoc_object_t   dml_objects[5] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_config, "WifiConfig" },
    { webconfig_subdoc_object_type_radios, "WifiRadioConfig" },
    { webconfig_subdoc_object_type_vaps, "WifiVapConfig" },
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
    cJSON *obj, *obj_array;
    unsigned int i, j;
    wifi_vap_info_map_t *map;
    wifi_vap_info_t *vap;
    rdk_wifi_radio_t *radio;
    webconfig_subdoc_decoded_data_t *params;
    char *str;
#if 0
    schema_wifi_radio_state_t *radio_state, *state_obj;
    schema_wifi_vap_state_t  *vap_state;
    rdk_wifi_vap_info_t      *rdk_vap_array;
    wifi_vap_info_map_t      *vap_map;
    char vap_name[64];
#endif

    params = &data->u.decoded;
    json = cJSON_CreateObject();
    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "dml");

    // encode config object
    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(json, "WifiConfig", obj);
    if (encode_config_object(&params->config, obj) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi global config\n", __func__, __LINE__);
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

        if (encode_radio_object(radio, obj) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode radio object\n", __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_encode;

        }
    }

    // encode private vap objects
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json, "WifiVapConfig", obj_array);

    for (i = 0; i < params->num_radios; i++) {
        map = &params->radios[i].vaps.vap_map;
        for (j = 0; j < map->num_vaps; j++) {
            vap = &map->vap_array[j];
            if ((vap->vap_index == (unsigned int)convert_vap_name_to_index("private_ssid_2g")) ||
                    (vap->vap_index == (unsigned int)convert_vap_name_to_index("private_ssid_5g"))) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_private_vap_object(vap, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode private vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if ((vap->vap_index == (unsigned int)convert_vap_name_to_index("iot_ssid_2g")) ||
                    (vap->vap_index == (unsigned int)convert_vap_name_to_index("iot_ssid_5g"))) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_private_vap_object(vap, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode private vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if ((vap->vap_index == (unsigned int)convert_vap_name_to_index("hotspot_open_2g")) ||
                    (vap->vap_index == (unsigned int)convert_vap_name_to_index("hotspot_open_5g"))) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_hotspot_open_vap_object(vap, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode hotspot open vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if ((vap->vap_index == (unsigned int)convert_vap_name_to_index("hotspot_secure_2g")) ||
                    (vap->vap_index == (unsigned int)convert_vap_name_to_index("hotspot_secure_5g"))) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_hotspot_secure_vap_object(vap, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode hotspot secure vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if ((vap->vap_index == (unsigned int)convert_vap_name_to_index("lnf_psk_2g")) ||
                    (vap->vap_index == (unsigned int)convert_vap_name_to_index("lnf_psk_5g"))) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_lnf_psk_vap_object(vap, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode lnf psk vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if ((vap->vap_index == (unsigned int)convert_vap_name_to_index("lnf_radius_2g")) ||
                    (vap->vap_index == (unsigned int)convert_vap_name_to_index("lnf_radius_5g"))) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_lnf_radius_vap_object(vap, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode lnf radius vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if ((vap->vap_index == (unsigned int)convert_vap_name_to_index("mesh_backhaul_2g")) ||
                    (vap->vap_index == (unsigned int)convert_vap_name_to_index("mesh_backhaul_5g"))) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_mesh_backhaul_vap_object(vap, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode mesh backhaul vap object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            } else if ((vap->vap_index == (unsigned int)convert_vap_name_to_index("mesh_sta_2g")) ||
                    (vap->vap_index == (unsigned int)convert_vap_name_to_index("mesh_sta_5g"))) {
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_mesh_sta_object(vap, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode mesh sta object\n", __func__, __LINE__);
                    cJSON_Delete(json);
                    return webconfig_error_encode;

                }
            }
        }
    }

#if 0
    //wifi_state
    state_obj = cJSON_CreateObject();
    cJSON_AddItemToObject(json, "Wifi_State", state_obj);

    //encode wifi_radio_state
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(state_obj, "Wifi_Radio_State", obj_array);

    for (i = 0; i < NUM_RADIO_OBJS; i++) {
        radio_state = &data->u.decoded.radios[i].radio_state;
        if (radio_state == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to get radio state for %d\n", __func__, __LINE__, i);
            return webconfig_error_encode;
        }

        obj = cJSON_CreateObject();
        cJSON_AddItemToArray(obj_array, obj);
        if (encode_radio_state_object(radio_state, obj) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode radio state object for %d\n", __func__, __LINE__, i);
            return webconfig_error_encode;

        }
    }

    //encode wifi_vif_state
    obj_array = cJSON_CreateArray();
    cJSON_AddItemToObject(state_obj, "Wifi_VIF_State", obj_array);

    for (i = 0; i < NUM_RADIO_OBJS; i++) {
        //To get the number of vaps
        vap_map = &params->radios[i].vaps.vap_map;
        for (j = 0; j < vap_map->num_vaps; j++) {
            //To get the vap_name
            rdk_vap_array = &params->radios[i].vaps.rdk_vap_array[j];
            memset(vap_name, 0, sizeof(vap_name));
            strcpy(vap_name, (char *)rdk_vap_array->vap_name);
            //Compare the vap_names
            if ((strcmp(vap_name, "private_ssid_2g") == 0) ||
                    (strcmp(vap_name, "private_ssid_5g") == 0)) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    return webconfig_error_encode;
                }
            } else if ((strcmp(vap_name, "iot_ssid_2g") == 0) ||
                    (strcmp(vap_name, "iot_ssid_5g") == 0)) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    return webconfig_error_encode;
                }
            } else if ((strcmp(vap_name, "hotspot_open_2g") == 0) ||
                    (strcmp(vap_name, "hotspot_open_5g") == 0)) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    return webconfig_error_encode;
                }
            } else if ((strcmp(vap_name, "lnf_psk_2g") == 0) ||
                    (strcmp(vap_name, "lnf_psk_5g") == 0)) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    return webconfig_error_encode;
                }
            } else if ((strcmp(vap_name, "hotspot_secure_2g") == 0) ||
                    (strcmp(vap_name, "hotspot_secure_5g") == 0)) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    return webconfig_error_encode;
                }
            } else if ((strcmp(vap_name, "lnf_radius_2g") == 0) ||
                    (strcmp(vap_name, "lnf_radius_5g") == 0)) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    return webconfig_error_encode;
                }
            } else if ((strcmp(vap_name, "mesh_backhaul_2g") == 0) ||
                    (strcmp(vap_name, "mesh_backhaul_5g") == 0)) {
                vap_state = &params->radios[i].vaps.vap_state[j];
                obj = cJSON_CreateObject();
                cJSON_AddItemToArray(obj_array, obj);
                if (encode_vap_state_object(vap_state, obj) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Failed to encode wifi vap status for vap %d of radio %d\n", __func__, __LINE__, j, i);
                    return webconfig_error_encode;
                }
            }
        }
    }
#endif
    memset(data->u.encoded.raw, 0, MAX_SUBDOC_SIZE);
    str = cJSON_Print(json);
    memcpy(data->u.encoded.raw, str, strlen(str));

    //  wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Encoded JSON:\n%s\n", __func__, __LINE__, str);
    cJSON_Delete(json);

    return webconfig_error_none;
}

webconfig_error_t decode_dml_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    cJSON *obj_config, *obj_radios, *obj_vaps;
    cJSON *obj, *obj_radio, *obj_vap;
    unsigned int i, j, size, radio_index;
    unsigned int presence_mask = 0;
    //unsigned char should_apply_mask = 0;
    char *radio_names[MAX_NUM_RADIOS] = {"radio1", "radio2"};
    char *vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO] = {
        "private_ssid_2g", "private_ssid_5g",
        "hotspot_open_2g", "hotspot_open_5g",
        "hotspot_secure_2g", "hotspot_secure_5g",
        "lnf_psk_2g", "lnf_psk_5g",
        "lnf_radius_2g", "lnf_radius_5g",
        "mesh_backhaul_2g", "mesh_backhaul_5g",
        "mesh_sta_2g", "mesh_sta_5g",
        "iot_ssid_2g", "iot_ssid_5g",
    };
    char *name;
    wifi_vap_info_t *vap_info;
    cJSON *json = data->u.encoded.json;
    webconfig_subdoc_decoded_data_t *params;

    params = &data->u.decoded;
    doc = &config->subdocs[data->type];

    for (i = 0; i < doc->num_objects; i++) {
        if ((cJSON_GetObjectItem(json, doc->objects[i].name)) == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: object:%s not present, validation failed\n",
                    __func__, __LINE__, doc->objects[i].name);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }
    }

    // decode config object
    memset(&params->config, 0, sizeof(wifi_global_config_t));
    obj_config = cJSON_GetObjectItem(json, "WifiConfig");
    if (decode_config_object(obj_config, &params->config) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Config Object validation failed\n",
                __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    // decode radio objects
    obj_radios = cJSON_GetObjectItem(json, "WifiRadioConfig");
    if (cJSON_IsArray(obj_radios) == false) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_radios);
    if (size < MIN_NUM_RADIOS || size > MAX_NUM_RADIOS) {

        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of radio objects: %d\n",
                __func__, __LINE__, size);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    for (i = 0; i < size; i++) {
        obj_radio = cJSON_GetArrayItem(obj_radios, i);
        // check presence of all radio names
        if ((obj = cJSON_GetObjectItem(obj_radio, "RadioName")) == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Not all radio names present\n",
                    __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }

        for (j = 0; j < size; j++) {
            if (strncmp(cJSON_GetStringValue(obj), radio_names[j], strlen(radio_names[j])) == 0) {
                presence_mask |= (1 << j);
            }
        }
    }

    if (size < MIN_NUM_RADIOS || size > MAX_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid radio count\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    for (i = 0; i < size; i++) {
        obj_radio = cJSON_GetArrayItem(obj_radios, i);
        memset(&params->radios[i], 0, sizeof(rdk_wifi_radio_t));
        if (decode_radio_object(obj_radio, &params->radios[i]) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio object validation failed\n",
                    __func__, __LINE__);
            cJSON_Delete(json);
            return webconfig_error_decode;
        }
    }
    params->num_radios = size;

    // decode VAP objects
    obj_vaps = cJSON_GetObjectItem(json, "WifiVapConfig");
    if (cJSON_IsArray(obj_vaps) == false) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap object not present\n", __func__, __LINE__);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    size = cJSON_GetArraySize(obj_vaps);
    if (size < (MIN_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)|| size > (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Not correct number of vap objects: %d, expected: %d\n",
                __func__, __LINE__, size, (sizeof(vap_names)/sizeof(char *)));
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    presence_mask = 0;

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        // check presence of all vap names
        if ((obj = cJSON_GetObjectItem(obj_vap, "VapName")) == NULL) {
            cJSON_Delete(json);
            return webconfig_error_invalid_subdoc;
        }

        for (j = 0; j < size; j++) {
            if (strncmp(cJSON_GetStringValue(obj), vap_names[j], strlen(vap_names[j])) == 0) {
                presence_mask |= (1 << j);
            }
        }
    }

    if (presence_mask != pow(2, MAX_NUM_VAP_PER_RADIO*params->num_radios) - 1) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object not present, mask:%x\n",
                __func__, __LINE__, presence_mask);
        cJSON_Delete(json);
        return webconfig_error_invalid_subdoc;
    }

    // first set the structure to all 0

    for (i = 0; i < size; i++) {
        obj_vap = cJSON_GetArrayItem(obj_vaps, i);
        name = cJSON_GetStringValue(cJSON_GetObjectItem(obj_vap, "VapName"));
        radio_index = convert_vap_name_to_radio_array_index(name);
        vap_info = &params->radios[radio_index].vaps.vap_map.vap_array[params->radios[radio_index].vaps.vap_map.num_vaps];
        //wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio index: %d , vap name: %s\n%s\n",
        //            __func__, __LINE__, radio_index, name, cJSON_Print(obj_vap));
        memset(vap_info, 0, sizeof(wifi_vap_info_t));
        if ((strcmp(name, "private_ssid_2g") == 0) || (strcmp(name, "private_ssid_5g") == 0)) {
            if (decode_private_vap_object(obj_vap, vap_info) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            params->radios[radio_index].vaps.vap_map.num_vaps++;
        } else if ((strcmp(name, "hotspot_open_2g") == 0) || (strcmp(name, "hotspot_open_5g") == 0)) {
            if (decode_hotspot_open_vap_object(obj_vap, vap_info) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            params->radios[radio_index].vaps.vap_map.num_vaps++;
        } else if ((strcmp(name, "hotspot_secure_2g") == 0) || (strcmp(name, "hotspot_secure_5g") == 0)) {
            if (decode_hotspot_secure_vap_object(obj_vap, vap_info) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            params->radios[radio_index].vaps.vap_map.num_vaps++;
        } else if ((strcmp(name, "lnf_psk_2g") == 0) || (strcmp(name, "lnf_psk_5g") == 0)) {
            if (decode_lnf_psk_vap_object(obj_vap, vap_info) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            params->radios[radio_index].vaps.vap_map.num_vaps++;
        } else if ((strcmp(name, "lnf_radius_2g") == 0) || (strcmp(name, "lnf_radius_5g") == 0)) {
            if (decode_lnf_radius_vap_object(obj_vap, vap_info) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            params->radios[radio_index].vaps.vap_map.num_vaps++;
        } else if ((strcmp(name, "iot_ssid_2g") == 0) || (strcmp(name, "iot_ssid_5g") == 0)) {
            if (decode_iot_vap_object(obj_vap, vap_info) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            params->radios[radio_index].vaps.vap_map.num_vaps++;
        } else if ((strcmp(name, "mesh_backhaul_2g") == 0) || (strcmp(name, "mesh_backhaul_5g") == 0)) {
            if (decode_mesh_backhaul_vap_object(obj_vap, vap_info) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            params->radios[radio_index].vaps.vap_map.num_vaps++;
        } else if ((strcmp(name, "mesh_sta_2g") == 0) || (strcmp(name, "mesh_sta_5g") == 0)) {
            if (decode_mesh_sta_object(obj_vap, vap_info) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: VAP object validation failed\n",
                        __func__, __LINE__);
                cJSON_Delete(json);
                return webconfig_error_decode;
            }
            params->radios[radio_index].vaps.vap_map.num_vaps++;
        }
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Validation success\n", __func__, __LINE__);
    cJSON_Delete(json);

    return webconfig_error_none;
}
