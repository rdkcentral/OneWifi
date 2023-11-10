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

webconfig_error_t access_check_associated_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_associated_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) == webconfig_data_descriptor_translate_to_ovsdb) {
        if (translate_to_ovsdb_tables(webconfig_subdoc_type_associated_clients, data) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_to_tr181) == webconfig_data_descriptor_translate_to_tr181) {

    } else {
        // no translation required
    }
    //no translation required
    return webconfig_error_none;
}

webconfig_error_t translate_to_associated_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_ovsdb) == webconfig_data_descriptor_translate_from_ovsdb) {
        if (translate_from_ovsdb_tables(webconfig_subdoc_type_associated_clients, data) != webconfig_error_none) {
            return webconfig_error_translate_from_ovsdb;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_translate_from_tr181) == webconfig_data_descriptor_translate_from_tr181) {

    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t encode_associated_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    cJSON *json;
    cJSON *assoc_array;
    char *str;
    unsigned int i, j;
    webconfig_subdoc_decoded_data_t *params;
    wifi_vap_info_map_t *vap_map;
    rdk_wifi_vap_info_t *rdk_vap_info;

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
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: json create object failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    data->u.encoded.json = json;

    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "associated clients");

    if(params->assoclist_notifier_type == assoclist_notifier_full) {
        assoc_array = cJSON_CreateArray();
        cJSON_AddItemToObject(json, "WiFiAssociatedClients", assoc_array);

        for (i = 0; i < params->num_radios; i++) {
            //vap_info_map data
            vap_map = &params->radios[i].vaps.vap_map;

            for (j = 0; j < vap_map->num_vaps; j++) {
                rdk_vap_info = &params->radios[i].vaps.rdk_vap_array[j];
                encode_associated_client_object(rdk_vap_info, assoc_array, assoclist_type_full);
            }
        }
    } else if (params->assoclist_notifier_type == assoclist_notifier_diff) {

        assoc_array = cJSON_CreateArray();
        cJSON_AddItemToObject(json, "AddAssociatedClients", assoc_array);

        for (i = 0; i < params->num_radios; i++) {
            //vap_info_map data
            vap_map = &params->radios[i].vaps.vap_map;

            for (j = 0; j < vap_map->num_vaps; j++) {
                rdk_vap_info = &params->radios[i].vaps.rdk_vap_array[j];
                encode_associated_client_object(rdk_vap_info, assoc_array, assoclist_type_add);
            }
        }

        assoc_array = cJSON_CreateArray();
        cJSON_AddItemToObject(json, "RemoveWiFiAssociatedClients", assoc_array);
        for (i = 0; i < params->num_radios; i++) {
            //vap_info_map data
            vap_map = &params->radios[i].vaps.vap_map;

            for (j = 0; j < vap_map->num_vaps; j++) {
                rdk_vap_info = &params->radios[i].vaps.rdk_vap_array[j];
                encode_associated_client_object(rdk_vap_info, assoc_array, assoclist_type_remove);
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
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: %s\n", __func__, __LINE__, str);
    cJSON_free(str);
    cJSON_Delete(json);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: encode success\n", __func__, __LINE__);
    return webconfig_error_none;
}

webconfig_error_t decode_associated_clients_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *params;
    cJSON *obj_vaps;
    cJSON *json;
    rdk_wifi_vap_info_t *rdk_vap_info;
    wifi_vap_info_map_t *vap_map;
    unsigned int i = 0, j = 0;
    assoc_dev_data_t *assoc_dev_data, *temp_assoc_dev_data;
    mac_addr_str_t mac_str;

    params = &data->u.decoded;
    if (params == NULL) {
        return webconfig_error_decode;
    }

    json = data->u.encoded.json;
    if (json == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: NULL json pointer\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    for (i = 0; i < params->num_radios; i++) {
        //vap_info_map data
        vap_map = &params->radios[i].vaps.vap_map;

        for (j = 0; j < vap_map->num_vaps; j++) {
            rdk_vap_info = &params->radios[i].vaps.rdk_vap_array[j];
            if (rdk_vap_info != NULL) {
                //if not ovsdb setto associated_devices_map
                if ((data->descriptor & webconfig_data_descriptor_translate_to_ovsdb) != webconfig_data_descriptor_translate_to_ovsdb) {
                    rdk_vap_info->associated_devices_map = NULL;
                } else {
                    if (cJSON_GetObjectItem(json, "WiFiAssociatedClients") != NULL) {
                        if (rdk_vap_info->associated_devices_map != NULL) {
                            assoc_dev_data = hash_map_get_first(rdk_vap_info->associated_devices_map);
                            while(assoc_dev_data != NULL) {
                                to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, mac_str);
                                assoc_dev_data = hash_map_get_next(rdk_vap_info->associated_devices_map, assoc_dev_data);
                                temp_assoc_dev_data = hash_map_remove(rdk_vap_info->associated_devices_map, mac_str);
                                if (temp_assoc_dev_data != NULL) {
                                    free(temp_assoc_dev_data);
                                }
                            }
                        }
                    }
                }
                rdk_vap_info->associated_devices_diff_map = NULL;
            }
        }
    }

    if (cJSON_GetObjectItem(json, "WiFiAssociatedClients") != NULL) {
        params->assoclist_notifier_type = assoclist_notifier_full;
        obj_vaps = cJSON_GetObjectItem(json, "WiFiAssociatedClients");
        if ( (obj_vaps == NULL) && (cJSON_IsArray(obj_vaps) == false)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: associated clients object not present\n", __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }

        if (decode_associated_clients_object(data, obj_vaps, assoclist_type_full) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap state object validation failed full assoclist\n",
                    __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
        }
    } else if ((cJSON_GetObjectItem(json, "AddAssociatedClients") != NULL) && (cJSON_GetObjectItem(json, "RemoveWiFiAssociatedClients") != NULL)) {
        params->assoclist_notifier_type = assoclist_notifier_diff;
        obj_vaps = cJSON_GetObjectItem(json, "AddAssociatedClients");
        if ( (obj_vaps == NULL) && (cJSON_IsArray(obj_vaps) == false)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: associated clients object not present\n", __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }

        if (decode_associated_clients_object(data, obj_vaps, assoclist_type_add) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap state object validation failed for Add assoclist\n",
                    __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
        }

        obj_vaps = cJSON_GetObjectItem(json, "RemoveWiFiAssociatedClients");
        if ( (obj_vaps == NULL) && (cJSON_IsArray(obj_vaps) == false)) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: associated clients object not present\n", __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_invalid_subdoc;
        }

        if (decode_associated_clients_object(data, obj_vaps, assoclist_type_remove) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap state object validation failed for Remove assoclist\n",
                    __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
        }

    } else  {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid assoclist subdoc\n",
                    __func__, __LINE__);
            cJSON_Delete(json);
            wifi_util_error_print(WIFI_WEBCONFIG, "%s\n", (char *)data->u.encoded.raw);
            return webconfig_error_decode;
    }

    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: decode success\n", __func__, __LINE__);

    cJSON_Delete(json);
    return webconfig_error_none;
}
