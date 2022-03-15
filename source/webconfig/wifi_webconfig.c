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

#if 0
static webconfig_error_map_t    g_webconfig_erors[] =
{
    {webconfig_error_unpack, "Unpack Error"},
    {webconfig_error_not_map, "Not map"},
    {webconfig_error_key_absent, "Key not present"},
    {webconfig_error_invalid_subdoc, "Invalid Subdoc Error"},
    {webconfig_error_decode, "Decode Error"},
    {webconfig_error_apply, "Apply Error"},
    {webconfig_error_save, "Save Error"},
    {webconfig_error_empty_anqp, "Empty ANQP Entry"},
    {webconfig_error_venue_entries, "Exceeded Max number of Venue entries"},
    {webconfig_error_venue_name_size, "Invalid size for Venue name"},
    {webconfig_error_oui_entries, "Invalid number of OUIs"},
    {webconfig_error_oui_length, "Invalid OUI length"},
    {webconfig_error_oui_char, "Invalid OUI character"},
    {webconfig_error_ipaddress, "Invalid IPAddressTypeAvailabilityANQPElement"},
    {webconfig_error_realm_entries, "Exceeded max number of Realm entries"},
    {webconfig_error_realm_length, "Invalid Realm Length"},
    {webconfig_error_eap_entries, "Invalid number of EAP entries in realm"},
    {webconfig_error_eap_length, "Invalid EAP Length in NAIRealmANQPElement Data"},
    {webconfig_error_eap_value, "Invalid EAP value in NAIRealmANQPElement Data"},
    {webconfig_error_auth_entries, "Invalid number of Auth entries in EAP Method"},
    {webconfig_error_auth_param, "Auth param missing in RealANQP EAP Data"},
};
#endif//Temp OneWifi

webconfig_error_t webconfig_encode(webconfig_t *config, webconfig_subdoc_data_t *data, webconfig_subdoc_type_t type)
{
    data->signature = WEBCONFIG_MAGIC_SIGNATUTRE;
    data->type = type;
    data->descriptor |= webconfig_data_descriptor_decoded;

    return webconfig_set(config, data);
}

webconfig_error_t webconfig_decode(webconfig_t *config, webconfig_subdoc_data_t *data, const char *str)
{
    data->signature = WEBCONFIG_MAGIC_SIGNATUTRE;
    data->type = webconfig_subdoc_type_unknown;
    data->descriptor |= webconfig_data_descriptor_encoded;
    strcpy(data->u.encoded.raw, str);

    return webconfig_set(config, data);
}

webconfig_subdoc_type_t find_subdoc_type(webconfig_t *config, cJSON *json)
{
    unsigned int i;
    bool found = false;
    cJSON *obj;
    char *name;

    if ((obj = cJSON_GetObjectItem(json, "SubDocName")) == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Could not find SubDocName key in data",
            __func__, __LINE__);
        return webconfig_subdoc_type_unknown;
    }

    if (cJSON_IsString(obj) == false) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid value for subdoc", __func__, __LINE__);
        return webconfig_subdoc_type_unknown;
    }

    name = cJSON_GetStringValue(obj);

    for (i = 0; i < webconfig_subdoc_type_max; i++) {
        if (strncmp(name, config->subdocs[i].name, strlen(name)) == 0) {
            found = true;
            break;
        }
    }


    return (found == true) ? config->subdocs[i].type:webconfig_subdoc_type_unknown;
}

char *webconfig_get(webconfig_t * config)
{
    return NULL;
}

bool validate_subdoc_data(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_type_t type;

    if (data->signature != WEBCONFIG_MAGIC_SIGNATUTRE) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: webconfig subdoc data validation failed\n", __func__, __LINE__);
        return false;
    }


    if (((data->descriptor & webconfig_data_descriptor_decoded) == webconfig_data_descriptor_decoded) &&
            ((data->descriptor & webconfig_data_descriptor_encoded) == webconfig_data_descriptor_encoded)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid descriptor, both encoded and decoded are set\n",
                __func__, __LINE__);
            return false;

    } else if ((data->descriptor & webconfig_data_descriptor_decoded) == webconfig_data_descriptor_decoded) {
        if ((data->type < webconfig_subdoc_type_private) || (data->type >= webconfig_subdoc_type_max)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid subdoc type for decoded descriptor\n",
                __func__, __LINE__);
            return false;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_encoded) == webconfig_data_descriptor_encoded) {
        // data is encoded in the form of json
        data->u.encoded.json = cJSON_Parse(data->u.encoded.raw);
        if (data->u.encoded.json == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Could not parse raw data\n", __func__, __LINE__);
            return false;
        }

        if ((type = find_subdoc_type(config, data->u.encoded.json)) == webconfig_subdoc_type_unknown) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid value for subdoc", __func__, __LINE__);
            cJSON_Delete(data->u.encoded.json);
            return false;
        }

        data->type = type;
    } else {

        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: webconfig subdoc data validation failed\n", __func__, __LINE__);
        return false;
    }

    return true;
}

webconfig_error_t webconfig_set(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_t  *doc;
    webconfig_error_t err = RETURN_OK;

    if (validate_subdoc_data(config, data) == false) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid data .. not parsable", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    doc = &config->subdocs[data->type];
    if (doc->access_check_subdoc(config, data) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: invalid access for subdocument type:%d in entity:%d\n",
            __func__, __LINE__, doc->type, config->initializer);
        return webconfig_error_not_permitted;
    }

    if ((data->descriptor & webconfig_data_descriptor_decoded) == webconfig_data_descriptor_decoded) {
        if ((err = doc->translate_to_subdoc(config, data)) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Subdocument translation failed\n", __func__, __LINE__);
        } else if ((err = doc->encode_subdoc(config, data)) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Subdocument encode failed\n", __func__, __LINE__);
        } else if ((data->descriptor = webconfig_data_descriptor_encoded)
                    && (config->apply_data(doc, data)) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Subdocument apply failed\n", __func__, __LINE__);
            err = webconfig_error_apply;
        }
    } else if ((data->descriptor & webconfig_data_descriptor_encoded) == webconfig_data_descriptor_encoded) {
        if ((err = doc->decode_subdoc(config, data)) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Subdocument decode failed\n", __func__, __LINE__);
        } else if ((err = doc->translate_from_subdoc(config, data)) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Subdocument translation failed\n", __func__, __LINE__);
        } else if ((data->descriptor = webconfig_data_descriptor_decoded)
                    && (config->apply_data(doc, data)) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Subdocument apply failed\n", __func__, __LINE__);
            err = webconfig_error_apply;
        }
    }


    data->descriptor = 0;

    return err;

}

webconfig_error_t webconfig_init(webconfig_t *config)
{

    if ((config->initializer <= webconfig_initializer_none) || (config->initializer >= webconfig_initializer_max)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: initializer must be set to onewifi or dml or ovsdbmgr", __func__, __LINE__);
        return webconfig_error_init;
    }

    if (config->apply_data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: apply function must not be null\n", __func__, __LINE__);
        return webconfig_error_init;

    }

    config->subdocs[webconfig_subdoc_type_private].type = webconfig_subdoc_type_private;
    strcpy(config->subdocs[webconfig_subdoc_type_private].name, "privatessid");
    config->subdocs[webconfig_subdoc_type_private].major = 1;
    config->subdocs[webconfig_subdoc_type_private].minor = 1;
    config->subdocs[webconfig_subdoc_type_private].init_subdoc = init_private_subdoc;
    config->subdocs[webconfig_subdoc_type_private].init_subdoc(&config->subdocs[webconfig_subdoc_type_private]);
    config->subdocs[webconfig_subdoc_type_private].access_check_subdoc = access_check_private_subdoc;
    config->subdocs[webconfig_subdoc_type_private].encode_subdoc = encode_private_subdoc;
    config->subdocs[webconfig_subdoc_type_private].decode_subdoc = decode_private_subdoc;
    config->subdocs[webconfig_subdoc_type_private].translate_to_subdoc = translate_to_private_subdoc;
    config->subdocs[webconfig_subdoc_type_private].translate_from_subdoc = translate_from_private_subdoc;

    config->subdocs[webconfig_subdoc_type_home].type = webconfig_subdoc_type_home;
    strcpy(config->subdocs[webconfig_subdoc_type_home].name, "home");
    config->subdocs[webconfig_subdoc_type_home].major = 1;
    config->subdocs[webconfig_subdoc_type_home].minor = 1;
    config->subdocs[webconfig_subdoc_type_home].init_subdoc = init_home_subdoc;
    config->subdocs[webconfig_subdoc_type_home].init_subdoc(&config->subdocs[webconfig_subdoc_type_home]);
    config->subdocs[webconfig_subdoc_type_home].access_check_subdoc = access_check_home_subdoc;
    config->subdocs[webconfig_subdoc_type_home].encode_subdoc = encode_home_subdoc;
    config->subdocs[webconfig_subdoc_type_home].decode_subdoc = decode_home_subdoc;
    config->subdocs[webconfig_subdoc_type_home].translate_to_subdoc = translate_to_home_subdoc;
    config->subdocs[webconfig_subdoc_type_home].translate_from_subdoc = translate_from_home_subdoc;

    config->subdocs[webconfig_subdoc_type_xfinity].type = webconfig_subdoc_type_xfinity;
    strcpy(config->subdocs[webconfig_subdoc_type_xfinity].name, "xfinity");
    config->subdocs[webconfig_subdoc_type_xfinity].major = 1;
    config->subdocs[webconfig_subdoc_type_xfinity].minor = 1;
    config->subdocs[webconfig_subdoc_type_xfinity].init_subdoc = init_xfinity_subdoc;
    config->subdocs[webconfig_subdoc_type_xfinity].init_subdoc(&config->subdocs[webconfig_subdoc_type_xfinity]);
    config->subdocs[webconfig_subdoc_type_xfinity].access_check_subdoc = access_check_xfinity_subdoc;
    config->subdocs[webconfig_subdoc_type_xfinity].encode_subdoc = encode_xfinity_subdoc;
    config->subdocs[webconfig_subdoc_type_xfinity].decode_subdoc = decode_xfinity_subdoc;
    config->subdocs[webconfig_subdoc_type_xfinity].translate_to_subdoc = translate_to_xfinity_subdoc;
    config->subdocs[webconfig_subdoc_type_xfinity].translate_from_subdoc = translate_from_xfinity_subdoc;

    config->subdocs[webconfig_subdoc_type_dml].type = webconfig_subdoc_type_dml;
    strcpy(config->subdocs[webconfig_subdoc_type_dml].name, "dml");
    config->subdocs[webconfig_subdoc_type_dml].major = 1;
    config->subdocs[webconfig_subdoc_type_dml].minor = 1;
    config->subdocs[webconfig_subdoc_type_dml].init_subdoc = init_dml_subdoc;
    config->subdocs[webconfig_subdoc_type_dml].init_subdoc(&config->subdocs[webconfig_subdoc_type_dml]);
    config->subdocs[webconfig_subdoc_type_dml].access_check_subdoc = access_check_dml_subdoc;
    config->subdocs[webconfig_subdoc_type_dml].encode_subdoc = encode_dml_subdoc;
    config->subdocs[webconfig_subdoc_type_dml].decode_subdoc = decode_dml_subdoc;
    config->subdocs[webconfig_subdoc_type_dml].translate_to_subdoc = translate_to_dml_subdoc;
    config->subdocs[webconfig_subdoc_type_dml].translate_from_subdoc = translate_from_dml_subdoc;


    config->subdocs[webconfig_subdoc_type_radio].type = webconfig_subdoc_type_radio;
    strcpy(config->subdocs[webconfig_subdoc_type_radio].name, "radio");
    config->subdocs[webconfig_subdoc_type_radio].major = 1;
    config->subdocs[webconfig_subdoc_type_radio].minor = 1;
    config->subdocs[webconfig_subdoc_type_radio].init_subdoc = init_radio_subdoc;
    config->subdocs[webconfig_subdoc_type_radio].init_subdoc(&config->subdocs[webconfig_subdoc_type_radio]);
    config->subdocs[webconfig_subdoc_type_radio].access_check_subdoc = access_check_radio_subdoc;
    config->subdocs[webconfig_subdoc_type_radio].decode_subdoc = decode_radio_subdoc;
    config->subdocs[webconfig_subdoc_type_radio].encode_subdoc = encode_radio_subdoc;
    config->subdocs[webconfig_subdoc_type_radio].translate_to_subdoc = translate_to_radio_subdoc;
    config->subdocs[webconfig_subdoc_type_radio].translate_from_subdoc = translate_from_radio_subdoc;

    config->subdocs[webconfig_subdoc_type_mesh].type = webconfig_subdoc_type_mesh;
    strcpy(config->subdocs[webconfig_subdoc_type_mesh].name, "mesh");
    config->subdocs[webconfig_subdoc_type_mesh].major = 1;
    config->subdocs[webconfig_subdoc_type_mesh].minor = 1;
    config->subdocs[webconfig_subdoc_type_mesh].access_check_subdoc = access_check_mesh_subdoc;
    config->subdocs[webconfig_subdoc_type_mesh].init_subdoc = init_mesh_subdoc;
    config->subdocs[webconfig_subdoc_type_mesh].init_subdoc(&config->subdocs[webconfig_subdoc_type_mesh]);
    config->subdocs[webconfig_subdoc_type_mesh].decode_subdoc = decode_mesh_subdoc;
    config->subdocs[webconfig_subdoc_type_mesh].encode_subdoc = encode_mesh_subdoc;
    config->subdocs[webconfig_subdoc_type_mesh].translate_to_subdoc = translate_to_mesh_subdoc;
    config->subdocs[webconfig_subdoc_type_mesh].translate_from_subdoc = translate_from_mesh_subdoc;

    config->subdocs[webconfig_subdoc_type_radio_status].type = webconfig_subdoc_type_radio_status;
    strcpy(config->subdocs[webconfig_subdoc_type_radio_status].name, "radio_status");
    config->subdocs[webconfig_subdoc_type_radio_status].major = 1;
    config->subdocs[webconfig_subdoc_type_radio_status].minor = 1;
    config->subdocs[webconfig_subdoc_type_radio_status].access_check_subdoc = access_check_radio_status_subdoc;
    config->subdocs[webconfig_subdoc_type_radio_status].encode_subdoc = encode_radio_status_subdoc;
    config->subdocs[webconfig_subdoc_type_radio_status].decode_subdoc = decode_radio_status_subdoc;
    config->subdocs[webconfig_subdoc_type_radio_status].translate_to_subdoc = translate_to_radio_status_subdoc;
    config->subdocs[webconfig_subdoc_type_radio_status].translate_from_subdoc = translate_from_radio_status_subdoc;

    config->subdocs[webconfig_subdoc_type_vap_status].type = webconfig_subdoc_type_vap_status;
    strcpy(config->subdocs[webconfig_subdoc_type_vap_status].name, "vap_status");
    config->subdocs[webconfig_subdoc_type_vap_status].major = 1;
    config->subdocs[webconfig_subdoc_type_vap_status].minor = 1;
    config->subdocs[webconfig_subdoc_type_vap_status].access_check_subdoc = access_check_vap_status_subdoc;
    config->subdocs[webconfig_subdoc_type_vap_status].encode_subdoc = encode_vap_status_subdoc;
    config->subdocs[webconfig_subdoc_type_vap_status].decode_subdoc = decode_vap_status_subdoc;
    config->subdocs[webconfig_subdoc_type_vap_status].translate_to_subdoc = translate_to_vap_status_subdoc;
    config->subdocs[webconfig_subdoc_type_vap_status].translate_from_subdoc = translate_from_vap_status_subdoc;

    config->subdocs[webconfig_subdoc_type_associated_clients].type = webconfig_subdoc_type_associated_clients;
    strcpy(config->subdocs[webconfig_subdoc_type_associated_clients].name, "associated clients");
    config->subdocs[webconfig_subdoc_type_associated_clients].major = 1;
    config->subdocs[webconfig_subdoc_type_associated_clients].minor = 1;
    config->subdocs[webconfig_subdoc_type_associated_clients].access_check_subdoc = access_check_associated_clients_subdoc;
    config->subdocs[webconfig_subdoc_type_associated_clients].encode_subdoc = encode_associated_clients_subdoc;
    config->subdocs[webconfig_subdoc_type_associated_clients].decode_subdoc = decode_associated_clients_subdoc;
    config->subdocs[webconfig_subdoc_type_associated_clients].translate_to_subdoc = translate_to_associated_clients_subdoc;
    config->subdocs[webconfig_subdoc_type_associated_clients].translate_from_subdoc = translate_from_associated_clients_subdoc;

    config->subdocs[webconfig_subdoc_type_wifiapiradio].type = webconfig_subdoc_type_wifiapiradio;
    strcpy(config->subdocs[webconfig_subdoc_type_wifiapiradio].name, "wifiapiradio");
    config->subdocs[webconfig_subdoc_type_wifiapiradio].major = 1;
    config->subdocs[webconfig_subdoc_type_wifiapiradio].minor = 1;
    config->subdocs[webconfig_subdoc_type_wifiapiradio].init_subdoc = init_wifiapiradio_subdoc;
    config->subdocs[webconfig_subdoc_type_wifiapiradio].init_subdoc(&config->subdocs[webconfig_subdoc_type_wifiapiradio]);
    config->subdocs[webconfig_subdoc_type_wifiapiradio].access_check_subdoc = access_check_wifiapiradio_subdoc;
    config->subdocs[webconfig_subdoc_type_wifiapiradio].decode_subdoc = decode_wifiapiradio_subdoc;
    config->subdocs[webconfig_subdoc_type_wifiapiradio].encode_subdoc = encode_wifiapiradio_subdoc;
    config->subdocs[webconfig_subdoc_type_wifiapiradio].translate_to_subdoc = translate_to_wifiapiradio_subdoc;
    config->subdocs[webconfig_subdoc_type_wifiapiradio].translate_from_subdoc = translate_from_wifiapiradio_subdoc;

    config->subdocs[webconfig_subdoc_type_wifiapivap].type = webconfig_subdoc_type_wifiapivap;
    strcpy(config->subdocs[webconfig_subdoc_type_wifiapivap].name, "wifiapivap");
    config->subdocs[webconfig_subdoc_type_wifiapivap].major = 1;
    config->subdocs[webconfig_subdoc_type_wifiapivap].minor = 1;
    config->subdocs[webconfig_subdoc_type_wifiapivap].access_check_subdoc = access_check_wifiapivap_subdoc;
    config->subdocs[webconfig_subdoc_type_wifiapivap].init_subdoc = init_wifiapivap_subdoc;
    config->subdocs[webconfig_subdoc_type_wifiapivap].init_subdoc(&config->subdocs[webconfig_subdoc_type_wifiapivap]);
    config->subdocs[webconfig_subdoc_type_wifiapivap].decode_subdoc = decode_wifiapivap_subdoc;
    config->subdocs[webconfig_subdoc_type_wifiapivap].encode_subdoc = encode_wifiapivap_subdoc;
    config->subdocs[webconfig_subdoc_type_wifiapivap].translate_to_subdoc = translate_to_wifiapivap_subdoc;
    config->subdocs[webconfig_subdoc_type_wifiapivap].translate_from_subdoc = translate_from_wifiapivap_subdoc;

    config->subdocs[webconfig_subdoc_type_mac_filter].type = webconfig_subdoc_type_mac_filter;
    strcpy(config->subdocs[webconfig_subdoc_type_mac_filter].name, "mac filter");
    config->subdocs[webconfig_subdoc_type_mac_filter].major = 1;
    config->subdocs[webconfig_subdoc_type_mac_filter].minor = 1;
    config->subdocs[webconfig_subdoc_type_mac_filter].access_check_subdoc = access_check_mac_filter_subdoc;
    config->subdocs[webconfig_subdoc_type_mac_filter].encode_subdoc = encode_mac_filter_subdoc;
    config->subdocs[webconfig_subdoc_type_mac_filter].decode_subdoc = decode_mac_filter_subdoc;
    config->subdocs[webconfig_subdoc_type_mac_filter].translate_to_subdoc =  translate_to_mac_filter_subdoc;
    config->subdocs[webconfig_subdoc_type_mac_filter].translate_from_subdoc = translate_from_mac_filter_subdoc;
    
    config->subdocs[webconfig_subdoc_type_blaster].type = webconfig_subdoc_type_blaster;
    strcpy(config->subdocs[webconfig_subdoc_type_blaster].name, "blaster config");
    config->subdocs[webconfig_subdoc_type_blaster].major = 1;
    config->subdocs[webconfig_subdoc_type_blaster].minor = 1;
    config->subdocs[webconfig_subdoc_type_blaster].init_subdoc = init_blaster_subdoc;
    config->subdocs[webconfig_subdoc_type_blaster].access_check_subdoc = access_blaster_subdoc;
    config->subdocs[webconfig_subdoc_type_blaster].encode_subdoc = encode_blaster_subdoc;
    config->subdocs[webconfig_subdoc_type_blaster].decode_subdoc = decode_blaster_subdoc;
    config->subdocs[webconfig_subdoc_type_blaster].translate_to_subdoc = translate_to_blaster_subdoc;
    config->subdocs[webconfig_subdoc_type_blaster].translate_from_subdoc = translate_from_blaster_subdoc;

    config->subdocs[webconfig_subdoc_type_harvester].type = webconfig_subdoc_type_harvester;
    strcpy(config->subdocs[webconfig_subdoc_type_harvester].name, "instant measurement config");
    config->subdocs[webconfig_subdoc_type_harvester].major = 1;
    config->subdocs[webconfig_subdoc_type_harvester].minor = 1;
    config->subdocs[webconfig_subdoc_type_harvester].init_subdoc = init_harvester_subdoc;
    config->subdocs[webconfig_subdoc_type_harvester].access_check_subdoc = access_check_harvester_subdoc;
    config->subdocs[webconfig_subdoc_type_harvester].encode_subdoc = encode_harvester_subdoc;
    config->subdocs[webconfig_subdoc_type_harvester].decode_subdoc = decode_harvester_subdoc;
    config->subdocs[webconfig_subdoc_type_harvester].translate_to_subdoc = translate_to_harvester_subdoc;
    config->subdocs[webconfig_subdoc_type_harvester].translate_from_subdoc = translate_from_harvester_subdoc;

    config->subdocs[webconfig_subdoc_type_wifi_config].type = webconfig_subdoc_type_wifi_config;
    strcpy(config->subdocs[webconfig_subdoc_type_wifi_config].name, "Wifi global");
    config->subdocs[webconfig_subdoc_type_wifi_config].major = 1;
    config->subdocs[webconfig_subdoc_type_wifi_config].minor = 1;
    config->subdocs[webconfig_subdoc_type_wifi_config].init_subdoc = init_wifi_config_subdoc;
    config->subdocs[webconfig_subdoc_type_wifi_config].access_check_subdoc = access_wifi_config_subdoc;
    config->subdocs[webconfig_subdoc_type_wifi_config].encode_subdoc = encode_wifi_config_subdoc;
    config->subdocs[webconfig_subdoc_type_wifi_config].decode_subdoc = decode_wifi_config_subdoc;
    config->subdocs[webconfig_subdoc_type_wifi_config].translate_to_subdoc = translate_to_wifi_config_subdoc;
    config->subdocs[webconfig_subdoc_type_wifi_config].translate_from_subdoc = translate_from_wifi_config_subdoc;

    return webconfig_error_none;
}
