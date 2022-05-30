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
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>
#include "cJSON.h"
#include "wifi_webconfig.h"
#include "ctype.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"
#include "schema.h"
#include "schema_gen.h"
#include "webconfig_external_proto.h"


#define CONFIG_RDK_LEGACY_SECURITY_SCHEMA

static webconfig_subdoc_data_t  webconfig_ovsdb_data;
//static webconfig_external_ovsdb_t webconfig_ovsdb_external;

webconfig_error_t webconfig_ovsdb_encode(webconfig_t *config,
        const webconfig_external_ovsdb_t *data,
        webconfig_subdoc_type_t type,
        char **str)
{

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d\n", __func__, __LINE__);
    webconfig_ovsdb_data.u.decoded.external_protos = (webconfig_external_ovsdb_t *)data;
    webconfig_ovsdb_data.descriptor = webconfig_data_descriptor_translate_from_ovsdb;

    if (webconfig_encode(config, &webconfig_ovsdb_data, type) != webconfig_error_none) {
        *str = NULL;
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Encode failed", __func__, __LINE__);
        return webconfig_error_decode;
    }
    *str = webconfig_ovsdb_data.u.encoded.raw;
    return webconfig_error_none;
}

webconfig_error_t webconfig_ovsdb_decode(webconfig_t *config, const char *str,
        webconfig_external_ovsdb_t *data,
        webconfig_subdoc_type_t *type)
{
    webconfig_ovsdb_data.u.decoded.external_protos = (webconfig_external_ovsdb_t *)data;
    webconfig_ovsdb_data.descriptor = webconfig_data_descriptor_translate_to_ovsdb;

    if (webconfig_decode(config, &webconfig_ovsdb_data, str) != webconfig_error_none) {
        //        *data = NULL;
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Decode failed", __func__, __LINE__);
        return webconfig_error_decode;

    }

    *type = webconfig_ovsdb_data.type;

    return webconfig_error_none;
}

webconfig_error_t free_vap_object_macfilter_entries(webconfig_subdoc_data_t *data)
{
    unsigned int i, j;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    rdk_wifi_vap_info_t *rdk_vap;
    acl_entry_t *temp_acl_entry, *acl_entry;
    mac_addr_str_t mac_str;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            rdk_vap = &decoded_params->radios[i].vaps.rdk_vap_array[j];
            if (rdk_vap == NULL){
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: rdk_vap is null", __func__, __LINE__);
                return webconfig_error_invalid_subdoc;
            }
            if(rdk_vap->acl_map != NULL) {
                acl_entry = hash_map_get_first(rdk_vap->acl_map);
                while(acl_entry != NULL) {
                    to_mac_str(acl_entry->mac,mac_str);
                    acl_entry = hash_map_get_next(rdk_vap->acl_map,acl_entry);
                    temp_acl_entry = hash_map_remove(rdk_vap->acl_map, mac_str);
                    if (temp_acl_entry != NULL) {
                        free(temp_acl_entry);
                    }
                }
                hash_map_destroy(rdk_vap->acl_map);
                rdk_vap->acl_map = NULL;
            }
        }
    }
    return webconfig_error_none;
}

struct schema_Wifi_VIF_Config *get_vif_schema_from_vapindex(unsigned int vap_index, const struct schema_Wifi_VIF_Config *table[], unsigned int num_vaps, wifi_platform_property_t *wifi_prop)
{
    unsigned int i = 0;
    char  if_name[16];

    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif config schema is NULL\n", __func__, __LINE__);
        return NULL;
    }
    //convert if_name to vap_index
    if (convert_apindex_to_ifname(wifi_prop, vap_index, if_name, sizeof(if_name)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid vap_index : %d\n", __func__, __LINE__, vap_index);
        return NULL;
    }

    for (i = 0; i<num_vaps; i++) {
        if (table[i] == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif config schema is NULL\n", __func__, __LINE__);
            return NULL;
        }

        if (!strcmp(if_name, table[i]->if_name))
        {
            return (struct schema_Wifi_VIF_Config *)table[i];
        }

    }

    return NULL;
}

webconfig_error_t translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(const rdk_wifi_vap_info_t *rdk_vap, struct schema_Wifi_VIF_Config *row)
{
    acl_entry_t *acl_entry;
    char mac_string[18] = {0};
    unsigned int count = 0;

    if ((rdk_vap == NULL) || (row == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguements are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if(rdk_vap->acl_map != NULL) {
        acl_entry = hash_map_get_first(rdk_vap->acl_map);
        while(acl_entry != NULL) {
            memset(&mac_string,0,18);
            snprintf(mac_string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", acl_entry->mac[0], acl_entry->mac[1],
                    acl_entry->mac[2], acl_entry->mac[3], acl_entry->mac[4], acl_entry->mac[5]);
            if (row->mac_list[count] == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: mac_list is NULL\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
            snprintf(row->mac_list[count], sizeof(row->mac_list[count]), "%s", mac_string);
            count++;
            acl_entry = hash_map_get_next(rdk_vap->acl_map, acl_entry);
        }
    }
    row->mac_list_len = count;
    return webconfig_error_none;
}

webconfig_error_t translate_macfilter_from_rdk_vap_to_ovsdb_vif_state(const rdk_wifi_vap_info_t *rdk_vap, struct schema_Wifi_VIF_State *row)
{
    acl_entry_t *acl_entry;
    char mac_string[18] = {0};
    unsigned int count = 0;

    if ((rdk_vap == NULL) || (row == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguements are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if(rdk_vap->acl_map != NULL) {
        acl_entry = hash_map_get_first(rdk_vap->acl_map);
        while(acl_entry != NULL) {
            memset(&mac_string,0,18);
            snprintf(mac_string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", acl_entry->mac[0], acl_entry->mac[1],
                    acl_entry->mac[2], acl_entry->mac[3], acl_entry->mac[4], acl_entry->mac[5]);
            if (row->mac_list[count] == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: mac_list is NULL\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
            snprintf(row->mac_list[count], sizeof(row->mac_list[count]), "%s", mac_string);
            count++;
            acl_entry = hash_map_get_next(rdk_vap->acl_map, acl_entry);
        }
    }
    row->mac_list_len = count;
    return webconfig_error_none;
}

webconfig_error_t translate_macfilter_from_ovsdb_to_rdk_vap(const struct schema_Wifi_VIF_Config *row, rdk_wifi_vap_info_t *rdk_vap)
{
    int i = 0;
    mac_address_t mac;
    char *mac_str;
    acl_entry_t *acl_entry;

    if ((rdk_vap == NULL) || (row == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguements are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    rdk_vap->acl_map = hash_map_create();
    if (rdk_vap->acl_map == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: hash map create failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    for (i = 0; i < row->mac_list_len; i++) {
        mac_str = (char *)row->mac_list[i];
        if (mac_str == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: mac_str is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }
        str_to_mac_bytes(mac_str, mac);
        acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
        if (acl_entry == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer \n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }
        memset(acl_entry, 0, (sizeof(acl_entry_t)));

        memcpy(&acl_entry->mac, mac, sizeof(mac_address_t));
        hash_map_put(rdk_vap->acl_map, strdup(mac_str), acl_entry);
    }

    return webconfig_error_none;
}

webconfig_error_t translate_radio_obj_to_ovsdb_radio_state(const wifi_radio_operationParam_t *oper_param, struct schema_Wifi_Radio_State *row, wifi_platform_property_t *wifi_prop)
{
    int radio_index = 0;
    if ((oper_param == NULL) || (row == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguements are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (freq_band_conversion((wifi_freq_bands_t *)&oper_param->band, (char *)row->freq_band, sizeof(row->freq_band), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_freq_band_to_radio_index(oper_param->band, &radio_index) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: frequency band to radio_index failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_radio_index_to_ifname(wifi_prop, radio_index, row->if_name, sizeof(row->if_name)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: radio_index to ifname failed failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (country_code_conversion((wifi_countrycode_type_t *)&oper_param->countryCode, row->country, sizeof(row->country), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: country conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    if (hw_mode_conversion((wifi_ieee80211Variant_t *)&oper_param->variant, row->hw_mode, sizeof(row->hw_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Hw mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    if (ht_mode_conversion((wifi_channelBandwidth_t *)&oper_param->channelWidth, row->ht_mode, sizeof(row->ht_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Ht mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (channel_mode_conversion((BOOL *)&oper_param->autoChannelEnabled, row->channel_mode, sizeof(row->channel_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Channel mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    if (get_radio_if_hw_type(row->hw_type, sizeof(row->hw_type)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: get hw type failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    row->enabled = oper_param->enable;
    row->channel = oper_param->channel;
    row->tx_power = oper_param->transmitPower;
    row->bcn_int = oper_param->beaconInterval;

    //Not updated as part of RDK structures
    //dfs_demo
    //hw_type
    //mac
    //thermal_shutdown
    //thermal_downgrade_temp
    //thermal_upgrade_temp
    //thermal_integration
    //thermal_downgraded
    //tx_chainmask
    //thermal_tx_chainmask
    return webconfig_error_none;

}


webconfig_error_t translate_radio_obj_to_ovsdb(const wifi_radio_operationParam_t *oper_param, struct schema_Wifi_Radio_Config *row, wifi_platform_property_t *wifi_prop)
{
    int radio_index = 0;

    if ((oper_param == NULL) || (row == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguements are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (freq_band_conversion((wifi_freq_bands_t *)&oper_param->band, (char *)row->freq_band, sizeof(row->freq_band), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_freq_band_to_radio_index(oper_param->band, &radio_index) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: frequency band to radio_index failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_radio_index_to_ifname(wifi_prop, radio_index, row->if_name, sizeof(row->if_name)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: radio_index to ifname failed failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (country_code_conversion((wifi_countrycode_type_t *)&oper_param->countryCode, row->country, sizeof(row->country), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: country conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    if (hw_mode_conversion((wifi_ieee80211Variant_t *)&oper_param->variant, row->hw_mode, sizeof(row->hw_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Hw mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    if (ht_mode_conversion((wifi_channelBandwidth_t *)&oper_param->channelWidth, row->ht_mode, sizeof(row->ht_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Ht mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (channel_mode_conversion((BOOL *)&oper_param->autoChannelEnabled, row->channel_mode, sizeof(row->channel_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: channel mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (get_radio_if_hw_type(row->hw_type, sizeof(row->hw_type)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: get hw type failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    row->enabled = oper_param->enable;
    row->channel = oper_param->channel;
    row->tx_power = oper_param->transmitPower;
    row->bcn_int = oper_param->beaconInterval;
    return webconfig_error_none;
}

struct schema_Wifi_Radio_Config *get_radio_schema_from_radioindex(unsigned int radio_index, const struct schema_Wifi_Radio_Config *table[], unsigned int num_radios, wifi_platform_property_t *wifi_prop)
{
    unsigned int i = 0;
    unsigned int schema_radio_index = 0;

    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: radio config schema is NULL\n", __func__, __LINE__);
        return NULL;
    }

    for (i = 0; i<num_radios; i++) {
        if (table[i] == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: radio config schema is NULL\n", __func__, __LINE__);
            return NULL;
        }

        if (convert_ifname_to_radio_index(wifi_prop, (char *)table[i]->if_name, &schema_radio_index) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: radio if name to schema radio index failed for %s\n", __func__, __LINE__, table[i]->if_name);
            return NULL;
        }

        if (schema_radio_index == radio_index) {
            return (struct schema_Wifi_Radio_Config *)table[i];
        }

    }

    return NULL;
}


webconfig_error_t   translate_radio_object_to_ovsdb_radio_config_for_dml(webconfig_subdoc_data_t *data)
{
    //Note : schema_Wifi_Radio_Config will be replaced to schema_Wifi_Radio_Config, after we link to the ovs headerfile
    const struct schema_Wifi_Radio_Config **table;
    struct schema_Wifi_Radio_Config *row;
    wifi_radio_operationParam_t  *oper_param;
    webconfig_subdoc_decoded_data_t *decoded_params;
    unsigned int i = 0;
    int radio_index = 0;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0;
    unsigned int *row_count = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    table = proto->radio_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    for (i= 0; i < decoded_params->num_radios; i++) {

        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        if (radio_index == -1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: invalid radio_index for  %s\n",
                    __func__, __LINE__, decoded_params->radios[i].name);
            return webconfig_error_translate_to_ovsdb;
        }

        oper_param = &decoded_params->radios[radio_index].oper;

        row = (struct schema_Wifi_Radio_Config *)table[radio_index];

        if (translate_radio_obj_to_ovsdb(oper_param, row, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate radio_obj to ovsdb %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_ovsdb;
        }
        presence_mask |= (1 << radio_index);

    }

    if (presence_mask != pow(2, decoded_params->num_radios) - 1) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_invalid_subdoc;
    }

    row_count = (unsigned int *)&proto->radio_config_row_count;
    *row_count = decoded_params->num_radios;

    for (i= 0; i < decoded_params->num_radios; i++) {
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        oper_param = &decoded_params->radios[radio_index].oper;
        memcpy(&webconfig_ovsdb_data.u.decoded.radios[radio_index].oper, oper_param, sizeof(wifi_radio_operationParam_t));
        strncpy(webconfig_ovsdb_data.u.decoded.radios[radio_index].name, decoded_params->radios[radio_index].name,  sizeof(webconfig_ovsdb_data.u.decoded.radios[radio_index].name));
    }
    return webconfig_error_none;
}

webconfig_error_t translate_radio_object_to_ovsdb_radio_state_for_dml(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_Radio_State **table;
    struct schema_Wifi_Radio_State *row;
    unsigned int i = 0;
    int radio_index = 0;
    webconfig_external_ovsdb_t *proto;
    wifi_radio_operationParam_t  *oper_param;
    webconfig_subdoc_decoded_data_t *decoded_params;
    unsigned int *row_count = 0;
    unsigned int presence_mask = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    table = proto->radio_state;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    for (i= 0; i < decoded_params->num_radios; i++) {
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        if (radio_index == -1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: invalid radio_index for  %s\n",
                    __func__, __LINE__, decoded_params->radios[i].name);
            return webconfig_error_translate_to_ovsdb;
        }

        oper_param = &decoded_params->radios[radio_index].oper;

        row = (struct schema_Wifi_Radio_State *)table[radio_index];

        if (translate_radio_obj_to_ovsdb_radio_state(oper_param, row, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate radio_obj to ovsdb state %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_ovsdb;
        }

        presence_mask |= (1 << radio_index);
    }

    if (presence_mask != pow(2, decoded_params->num_radios) - 1) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_invalid_subdoc;
    }

    row_count = (unsigned int *)&proto->radio_state_row_count;
    *row_count = decoded_params->num_radios;
    return webconfig_error_none;
}


//Note: Modify this function for the security
webconfig_error_t translate_vap_info_to_ovsdb_personal_sec(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_Config *vap_row)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (macfilter_conversion(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), (wifi_vap_info_t *)vap, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Mac filter conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }
#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    int  index = 0;
    if (vap->u.bss_info.security.mode != wifi_security_mode_none) {
        char str_mode[128] = {0};
        char str_encryp[128] = {0};

        memset(str_mode, 0, sizeof(str_mode));
        memset(str_encryp, 0, sizeof(str_encryp));
        if ((key_mgmt_conversion_legacy((wifi_security_modes_t *)&vap->u.bss_info.security.mode, (wifi_encryption_method_t *)&vap->u.bss_info.security.encr, str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp), ENUM_TO_STRING)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }

        set_translator_config_security_key_value(vap_row, &index, "encryption", str_encryp);
        set_translator_config_security_key_value(vap_row, &index, "mode", str_mode);
        set_translator_config_security_key_value(vap_row, &index, "key", vap->u.bss_info.security.u.key.key);
    } else {
        set_translator_config_security_key_value(vap_row, &index, "encryption", "OPEN");
    }


#else
    if (vap->u.bss_info.security.mode == wifi_security_mode_none) {
        vap_row->wpa = false;
    } else {
        if ((vap->u.bss_info.security.mode == wifi_security_mode_wpa2_enterprise) || (vap->u.bss_info.security.mode == wifi_security_mode_wpa3_enterprise)
                || (vap->u.bss_info.security.mode == wifi_security_mode_wpa_wpa2_enterprise) || (vap->u.bss_info.security.mode == wifi_security_mode_wpa_enterprise)){
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: enterprise mode is not supported\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }
        vap_row->wpa_key_mgmt_len = 1;
        if ((key_mgmt_conversion((wifi_security_modes_t *)&vap->u.bss_info.security.mode, vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), ENUM_TO_STRING)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }

        vap_row->wpa = true;

        if ((strlen(vap->u.bss_info.security.u.key.key) < MIN_PWD_LEN) || (strlen(vap->u.bss_info.security.u.key.key) > MAX_PWD_LEN)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }

        snprintf(vap_row->wpa_psks[0], sizeof(vap_row->wpa_psks[0]), "%s", vap->u.bss_info.security.u.key.key);
        vap_row->wpa_psks_len = 1;

    }
#endif

    vap_row->group_rekey = vap->u.bss_info.security.rekey_interval;

    return webconfig_error_none;
}

webconfig_error_t translate_vap_info_to_ovsdb_no_sec(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_Config *vap_row)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    snprintf(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), "none");
    vap_row->wpa = false;

    return webconfig_error_none;
}


webconfig_error_t translate_vap_info_to_ovsdb_radius_settings(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_Config *vap_row)
{
    wifi_radius_settings_t *radius;
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    radius = (wifi_radius_settings_t *)&vap->u.bss_info.security.u.radius;

    if (radius == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: radius is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vap_row->radius_srv_port = radius->port;
    snprintf(vap_row->radius_srv_secret, sizeof(vap_row->radius_srv_secret), "%s", radius->key);

#ifndef WIFI_HAL_VERSION_3_PHASE2
    snprintf(vap_row->radius_srv_addr, sizeof(vap_row->radius_srv_addr), "%s", radius->ip);
#else
    getIpStringFromAdrress(vap_row->radius_srv_addr, &(radius->ip));
#endif
    return webconfig_error_none;
}

webconfig_error_t translate_vap_info_to_ovsdb_enterprise_sec(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_Config *vap_row)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (macfilter_conversion(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), (wifi_vap_info_t *)vap, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Mac filter conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vap_row->group_rekey = vap->u.bss_info.security.rekey_interval;
    vap_row->wpa = true;

    if (translate_vap_info_to_ovsdb_radius_settings(vap, vap_row) !=  webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius settings from vap to ovsdb failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    return webconfig_error_none;
}

webconfig_error_t translate_vap_info_to_ovsdb_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_ifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    if (ssid_broadcast_conversion(vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), (BOOL *)&vap->u.bss_info.showSsid, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: ssid broadbcast conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap_mode_conversion((wifi_vap_mode_t *)&vap->vap_mode, vap_row->mode, ARRAY_SZ(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vap_row->enabled = vap->u.bss_info.enabled;
    strncpy(vap_row->ssid, vap->u.bss_info.ssid, sizeof(vap_row->ssid));
    strncpy(vap_row->bridge, vap->bridge_name, sizeof(vap_row->bridge));
    vap_row->uapsd_enable = vap->u.bss_info.UAPSDEnabled;
    vap_row->ap_bridge = vap->u.bss_info.isolation;
    vap_row->btm = vap->u.bss_info.bssTransitionActivated;
    vap_row->rrm = vap->u.bss_info.nbrReportActivated;
    vap_row->wps = vap->u.bss_info.wps.enable;
    strncpy(vap_row->wps_pbc_key_id, vap->u.bss_info.wps.pin, sizeof(vap_row->wps_pbc_key_id));
    vap_row->vlan_id = iface_map->vlan_id;
    return webconfig_error_none;
}

webconfig_error_t  translate_sta_vap_info_to_ovsdb_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if ((vap == NULL) || (vap_row == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Input arguements are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_ifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap_mode_conversion((wifi_vap_mode_t *)&vap->vap_mode, vap_row->mode, ARRAY_SZ(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode is not station moode\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    snprintf(vap_row->parent, sizeof(vap_row->parent), "%02X:%02X:%02X:%02X:%02X:%02X",
                                                vap->u.sta_info.bssid[0], vap->u.sta_info.bssid[1],
                                                vap->u.sta_info.bssid[2], vap->u.sta_info.bssid[3],
                                                vap->u.sta_info.bssid[4], vap->u.sta_info.bssid[5]);

    snprintf(vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), "%s", "disabled");
    snprintf(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), "%s", "none");

    strncpy(vap_row->bridge, vap->bridge_name, sizeof(vap_row->bridge));
    vap_row->enabled = vap->u.sta_info.enabled;
    vap_row->vlan_id = iface_map->vlan_id;

    return webconfig_error_none;
}

webconfig_error_t translate_private_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_iot_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_hotspot_open_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_no_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for no security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_lnf_psk_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_secure_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_enterprise_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_lnf_radius_secure_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_enterprise_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_mesh_backhaul_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_mesh_sta_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_sta_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


//Translate from webconfig to ovsdb structure
webconfig_error_t   translate_vap_object_to_ovsdb_vif_config_for_dml(webconfig_subdoc_data_t *data)
{
    struct schema_Wifi_VIF_Config *vap_row;
    const struct schema_Wifi_VIF_Config **vif_table;
    unsigned int i, j, k;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    //  struct schema_Wifi_Credential_Config **cred_table;
    //   struct schema_Wifi_Credential_Config  *cred_row;

    unsigned int presence_mask = 0;
    unsigned int *row_count = NULL;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;

    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        if (radio->vaps.num_vaps !=  MAX_NUM_VAP_PER_RADIO) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of vaps: %x\n", __func__, __LINE__, radio->vaps.num_vaps);
            return webconfig_error_invalid_subdoc;
        }
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[vap->vap_index];
            if (vap_row == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_iot_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_hotspot_open(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_hotspot_open_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_lnf_psk_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_hotspot_secure(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_hotspot_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh backhaul to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if ((is_vap_mesh_sta(wifi_prop, vap->vap_index) != TRUE) && (is_vap_hotspot(wifi_prop, vap->vap_index) != TRUE) ) {
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
            }
        }
    }

    if (presence_mask != (pow(2, (MAX_NUM_VAP_PER_RADIO*decoded_params->num_radios)) - 1)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    row_count = (unsigned int *)&proto->vif_config_row_count;
    *row_count = decoded_params->num_radios * MAX_NUM_VAP_PER_RADIO;

    for (i = 0; i < decoded_params->num_radios; i++) {
        memcpy(&webconfig_ovsdb_data.u.decoded.radios[i].vaps, &decoded_params->radios[i].vaps, sizeof(rdk_wifi_vap_map_t));
    }

    return webconfig_error_none;
}

#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
const char* security_config_find_by_key(
        const struct schema_Wifi_VIF_Config *vconf,
        char *key)
{
    int  i;
    for (i = 0; i < vconf->security_len; i++) {
        if (!strcmp(vconf->security_keys[i], key)) {
            return vconf->security[i];
        }
    }
    return NULL;
}


int set_translator_state_security_key_value(
        struct schema_Wifi_VIF_State *vstate,
        int *index,
        const char *key,
        const char *value)
{
    strcpy(vstate->security_keys[*index], key);
    strcpy(vstate->security[*index], value);

    *index += 1;
    vstate->security_len = *index;

    return *index;
}

int set_translator_config_security_key_value(
        struct schema_Wifi_VIF_Config *vconfig,
        int *index,
        const char *key,
        const char *value)
{
    strcpy(vconfig->security_keys[*index], key);
    strcpy(vconfig->security[*index], value);

    *index += 1;
    vconfig->security_len = *index;

    return *index;
}
#endif

webconfig_error_t translate_vap_info_to_vif_state_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_ifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    if (ssid_broadcast_conversion(vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), (BOOL *)&vap->u.bss_info.showSsid, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: ssid broadbcast conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap_mode_conversion((wifi_vap_mode_t *)&vap->vap_mode, vap_row->mode, ARRAY_SZ(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }
    sprintf(vap_row->mac, "%02X:%02X:%02X:%02X:%02X:%02X", vap->u.bss_info.bssid[0], vap->u.bss_info.bssid[1],
                                                    vap->u.bss_info.bssid[2], vap->u.bss_info.bssid[3],
                                                    vap->u.bss_info.bssid[4], vap->u.bss_info.bssid[5]);
    vap_row->enabled = vap->u.bss_info.enabled;
    strncpy(vap_row->ssid, vap->u.bss_info.ssid, sizeof(vap_row->ssid));
    strncpy(vap_row->bridge, vap->bridge_name, sizeof(vap_row->bridge));
    vap_row->uapsd_enable = vap->u.bss_info.UAPSDEnabled;
    vap_row->ap_bridge = vap->u.bss_info.isolation;
    vap_row->btm = vap->u.bss_info.bssTransitionActivated;
    vap_row->rrm = vap->u.bss_info.nbrReportActivated;
    vap_row->wps = vap->u.bss_info.wps.enable;
    strncpy(vap_row->wps_pbc_key_id, vap->u.bss_info.wps.pin, sizeof(vap_row->wps_pbc_key_id));
    vap_row->vlan_id = iface_map->vlan_id;
    return webconfig_error_none;
}

webconfig_error_t translate_vap_info_to_vif_state_radius_settings(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_State *vap_row)
{
    wifi_radius_settings_t *radius;
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    radius = (wifi_radius_settings_t *)&vap->u.bss_info.security.u.radius;

    if (radius == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: radius is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vap_row->radius_srv_port = radius->port;
    snprintf(vap_row->radius_srv_secret, sizeof(vap_row->radius_srv_secret), "%s", radius->key);

#ifndef WIFI_HAL_VERSION_3_PHASE2
    snprintf(vap_row->radius_srv_addr, sizeof(vap_row->radius_srv_addr), "%s", radius->ip);
#else
    getIpStringFromAdrress(vap_row->radius_srv_addr, &(radius->ip));
#endif
    return webconfig_error_none;
}

webconfig_error_t translate_vap_info_to_vif_state_personal_sec(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_State *vap_row)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (macfilter_conversion(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), (wifi_vap_info_t *)vap, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Mac filter conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vap_row->group_rekey = vap->u.bss_info.security.rekey_interval;

#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    int sec_index = 0;
    if (vap->u.bss_info.security.mode != wifi_security_mode_none) {
        char str_mode[128] = {0};
        char str_encryp[128] = {0};

        memset(str_mode, 0, sizeof(str_mode));
        memset(str_encryp, 0, sizeof(str_encryp));
        if ((key_mgmt_conversion_legacy((wifi_security_modes_t *)&vap->u.bss_info.security.mode, (wifi_encryption_method_t *)&vap->u.bss_info.security.encr, str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp), ENUM_TO_STRING)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }

        set_translator_state_security_key_value(vap_row, &sec_index, "encryption", str_encryp);
        set_translator_state_security_key_value(vap_row, &sec_index, "mode", str_mode);
        set_translator_state_security_key_value(vap_row, &sec_index, "key", vap->u.bss_info.security.u.key.key);

    } else {
        set_translator_state_security_key_value(vap_row, &sec_index, "encryption", "OPEN");
    }
#else
    if (vap->u.bss_info.security.mode == wifi_security_mode_none) {
        vap_row->wpa = false;
    } else {
        if ((vap->u.bss_info.security.mode == wifi_security_mode_wpa2_enterprise) || (vap->u.bss_info.security.mode == wifi_security_mode_wpa3_enterprise)
                || (vap->u.bss_info.security.mode == wifi_security_mode_wpa_wpa2_enterprise) || (vap->u.bss_info.security.mode == wifi_security_mode_wpa_enterprise)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: enterprise mode is not supported\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }
        vap_row->wpa_key_mgmt_len = 1;
        if ((key_mgmt_conversion((wifi_security_modes_t *)&vap->u.bss_info.security.mode, vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), ENUM_TO_STRING)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }

        vap_row->wpa = true;

        if ((strlen(vap->u.bss_info.security.u.key.key) < MIN_PWD_LEN) || (strlen(vap->u.bss_info.security.u.key.key) > MAX_PWD_LEN)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }

        snprintf(vap_row->wpa_psks[0], sizeof(vap_row->wpa_psks[0]), "%s", vap->u.bss_info.security.u.key.key);
        vap_row->wpa_psks_len = 1;
    }
#endif

    return webconfig_error_none;
}

webconfig_error_t translate_vap_info_to_vif_state_no_sec(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_State *vap_row)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    snprintf(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), "none");
    vap_row->wpa = false;
    return webconfig_error_none;
}

webconfig_error_t translate_vap_info_to_vif_state_enterprise_sec(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_State *vap_row)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (macfilter_conversion(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), (wifi_vap_info_t *)vap, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Mac filter conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vap_row->group_rekey = vap->u.bss_info.security.rekey_interval;
    vap_row->wpa = true;
    if (translate_vap_info_to_vif_state_radius_settings(vap, vap_row) !=  webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius settings from vap to ovsdb failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }
    return webconfig_error_none;
}

webconfig_error_t  translate_sta_vap_info_to_vif_state_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if ((vap == NULL) || (vap_row == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Input arguements are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_ifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap_mode_conversion((wifi_vap_mode_t *)&vap->vap_mode, vap_row->mode, ARRAY_SZ(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode is not station moode\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    strncpy(vap_row->bridge, vap->bridge_name, sizeof(vap_row->bridge));
    vap_row->enabled = vap->u.sta_info.enabled;
    snprintf(vap_row->mac, sizeof(vap_row->mac), "%02X:%02X:%02X:%02X:%02X:%02X", vap->u.sta_info.mac[0], vap->u.sta_info.mac[1],
                                                    vap->u.sta_info.mac[2], vap->u.sta_info.mac[3],
                                                    vap->u.sta_info.mac[4], vap->u.sta_info.mac[5]);
     snprintf(vap_row->parent, sizeof(vap_row->parent), "%02X:%02X:%02X:%02X:%02X:%02X", vap->u.sta_info.bssid[0], vap->u.sta_info.bssid[1],
                                                    vap->u.sta_info.bssid[2], vap->u.sta_info.bssid[3],
                                                    vap->u.sta_info.bssid[4], vap->u.sta_info.bssid[5]);
    vap_row->vlan_id = iface_map->vlan_id;

    return webconfig_error_none;
}

webconfig_error_t translate_private_vap_info_to_vif_state(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_open_vap_info_to_vif_state(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_no_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for no security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_iot_vap_info_to_vif_state(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_lnf_psk_vap_info_to_vif_state(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_secure_vap_info_to_vif_state(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_enterprise_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_lnf_radius_secure_vap_info_to_vif_state(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_enterprise_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_mesh_backhaul_vap_info_to_vif_state(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_mesh_sta_vap_info_to_vif_state(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_sta_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_vap_object_to_ovsdb_associated_clients(const rdk_wifi_vap_info_t *rdk_vap_info, const struct schema_Wifi_Associated_Clients **clients_table, unsigned int *client_count, wifi_platform_property_t *wifi_prop)
{
    int count = 0, i = 0;
    assoc_dev_data_t *assoc_dev_data = NULL;
    struct schema_Wifi_Associated_Clients *client_row;
    unsigned int associated_client_count = 0;
    if ((rdk_vap_info == NULL) || (clients_table == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Input arguements are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (rdk_vap_info->associated_devices_queue != NULL) {
        count = queue_count(rdk_vap_info->associated_devices_queue);
    }

    associated_client_count = *client_count;
    for (i=0; i<count; i++) {
        assoc_dev_data = (assoc_dev_data_t *)queue_peek(rdk_vap_info->associated_devices_queue, i);
        if (assoc_dev_data == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d NULL pointer\n", __func__, __LINE__);
            return webconfig_error_encode;
        }
        client_row = (struct schema_Wifi_Associated_Clients *)clients_table[associated_client_count];
        if (client_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: client row empty for the client number %d\n", __func__, __LINE__, associated_client_count);
            return webconfig_error_translate_to_ovsdb;
        }
        snprintf(client_row->mac, sizeof(client_row->mac), "%02x:%02x:%02x:%02x:%02x:%02x", assoc_dev_data->dev_stats.cli_MACAddress[0], assoc_dev_data->dev_stats.cli_MACAddress[1],
                assoc_dev_data->dev_stats.cli_MACAddress[2], assoc_dev_data->dev_stats.cli_MACAddress[3], assoc_dev_data->dev_stats.cli_MACAddress[4],
                assoc_dev_data->dev_stats.cli_MACAddress[5]);

        if (assoc_dev_data->dev_stats.cli_Active == true) {
            snprintf(client_row->state, sizeof(client_row->state), "active");
        } else {
            snprintf(client_row->state, sizeof(client_row->state), "idle");
        }
        if ((strlen( assoc_dev_data->dev_stats.cli_OperatingStandard) != 0)) {
            snprintf(client_row->capabilities[0], sizeof(client_row->capabilities[0]), "11%s", assoc_dev_data->dev_stats.cli_OperatingStandard);
        } else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid Capabilities\n", __func__, __LINE__);
            //return webconfig_error_translate_to_ovsdb;
        }
        if (convert_vapname_to_ifname(wifi_prop, (char *)rdk_vap_info->vap_name, client_row->_uuid.uuid, sizeof(client_row->_uuid.uuid)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vapname to interface name conversion failed\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }
        associated_client_count++;
    }
    *client_count = associated_client_count;

    return webconfig_error_none;
}

webconfig_error_t translate_vap_object_to_ovsdb_associated_clients_for_assoclist(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_Associated_Clients **clients_table;
    unsigned int i, j;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    webconfig_external_ovsdb_t *proto;

    unsigned int presence_mask = 0;
    unsigned int *row_count = NULL;
    unsigned int client_count = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    clients_table = proto->assoc_clients;
    if (clients_table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;

    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        if (radio->vaps.num_vaps !=  MAX_NUM_VAP_PER_RADIO) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of vaps: %x\n", __func__, __LINE__, radio->vaps.num_vaps);
            return webconfig_error_invalid_subdoc;
        }
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            if (vap == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (is_vap_private(&decoded_params->hal_cap.wifi_prop, vap->vap_index) == TRUE) {
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_xhs(&decoded_params->hal_cap.wifi_prop, vap->vap_index) == TRUE) {
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_hotspot(&decoded_params->hal_cap.wifi_prop, vap->vap_index) == TRUE) {
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_lnf_psk(&decoded_params->hal_cap.wifi_prop, vap->vap_index) == TRUE) {
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_hotspot_secure(&decoded_params->hal_cap.wifi_prop, vap->vap_index) == TRUE) {
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_lnf_radius(&decoded_params->hal_cap.wifi_prop, vap->vap_index) == TRUE) {
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_mesh_backhaul(&decoded_params->hal_cap.wifi_prop, vap->vap_index) == TRUE) {
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_mesh_sta(&decoded_params->hal_cap.wifi_prop, vap->vap_index) == TRUE) {
                presence_mask |= (1 << vap->vap_index);
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_associated_clients(&decoded_params->radios[i].vaps.rdk_vap_array[j], clients_table, &client_count, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of associated clients failed for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
        }
    }

    if (presence_mask != (pow(2, decoded_params->num_radios * MAX_NUM_VAP_PER_RADIO) - 1)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }
    row_count = (unsigned int *)&proto->assoc_clients_row_count;
    *row_count = client_count;

    return webconfig_error_none;
}


webconfig_error_t   translate_vap_object_to_ovsdb_vif_state_for_dml(webconfig_subdoc_data_t *data)
{
    struct schema_Wifi_VIF_State *vap_row;
    const struct schema_Wifi_VIF_State **vif_table;
    unsigned int i, j, k;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    wifi_platform_property_t *wifi_prop;
    //  struct schema_Wifi_Credential_Config **cred_table;
    //   struct schema_Wifi_Credential_Config  *cred_row;

    unsigned int presence_mask = 0;
    unsigned int *row_count = NULL;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_state;
    if (vif_table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;

    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    hal_cap = &decoded_params->hal_cap;
    wifi_prop = &decoded_params->hal_cap.wifi_prop;
    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        if (radio->vaps.num_vaps !=  MAX_NUM_VAP_PER_RADIO) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of vaps: %x\n", __func__, __LINE__, radio->vaps.num_vaps);
            return webconfig_error_invalid_subdoc;
        }
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            vap_row = (struct schema_Wifi_VIF_State *)vif_table[vap->vap_index];
            if (vap_row == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_iot_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_hotspot_open(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_hotspot_open_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_lnf_psk_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_hotspot_secure(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_hotspot_secure_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_secure_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh backhaul to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if ((is_vap_mesh_sta(wifi_prop, vap->vap_index) != TRUE) && (is_vap_hotspot(wifi_prop, vap->vap_index) != TRUE) ) {
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_state(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
            }
        }
    }

    if (presence_mask != (pow(2, decoded_params->num_radios * MAX_NUM_VAP_PER_RADIO) - 1)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }
    row_count = (unsigned int *)&proto->vif_state_row_count;
    *row_count = decoded_params->num_radios * MAX_NUM_VAP_PER_RADIO;

    return webconfig_error_none;
}


webconfig_error_t translate_ovsdb_to_vap_info_personal_sec(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (macfilter_conversion((char *)vap_row->mac_list_type, sizeof(vap_row->mac_list_type), vap, STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: mac filter conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    const char *str_encryp;
    const char *str_mode;
    const char *val;

    str_encryp = security_config_find_by_key(vap_row, "encryption");
    if (str_encryp == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: encryption is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (!strcmp(str_encryp, "OPEN")) {
        vap->u.bss_info.security.mode = wifi_security_mode_none;
        vap->u.bss_info.security.encr = wifi_encryption_none;
    } else {
        str_mode = security_config_find_by_key(vap_row, "mode");
        if (str_mode == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: mode is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((key_mgmt_conversion_legacy(&vap->u.bss_info.security.mode, &vap->u.bss_info.security.encr, (char *)str_mode, strlen(str_mode)+1, (char *)str_encryp, strlen(str_encryp)+1, STRING_TO_ENUM)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        val = security_config_find_by_key(vap_row, "key");
        if (val == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: mode is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((strlen(val) < MIN_PWD_LEN) || (strlen(val) > MAX_PWD_LEN)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        snprintf(vap->u.bss_info.security.u.key.key, sizeof(vap->u.bss_info.security.u.key.key), "%s", val);
    }

#else
    if (vap_row->wpa == false) {
        vap->u.bss_info.security.mode = wifi_security_mode_none;
    } else {
        if (vap_row->wpa_key_mgmt_len == 0)  {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: wpa_key_mgmt_len is 0\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((key_mgmt_conversion(&vap->u.bss_info.security.mode, (char *)vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), STRING_TO_ENUM)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((vap->u.bss_info.security.mode == wifi_security_mode_wpa2_enterprise) || (vap->u.bss_info.security.mode == wifi_security_mode_wpa3_enterprise) ||
                (vap->u.bss_info.security.mode == wifi_security_mode_wpa_wpa2_enterprise) || (vap->u.bss_info.security.mode == wifi_security_mode_wpa_enterprise)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: enterprise mode is not supported\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if (vap_row->wpa_psks_len == 0)  {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: wpa_psks_len is 0\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((strlen(vap_row->wpa_psks[0]) < MIN_PWD_LEN) || (strlen(vap_row->wpa_psks[0]) > MAX_PWD_LEN)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        snprintf(vap->u.bss_info.security.u.key.key, sizeof(vap->u.bss_info.security.u.key.key), "%s", vap_row->wpa_psks[0]);

    }

#endif

    vap->u.bss_info.security.rekey_interval = vap_row->group_rekey;
    return webconfig_error_none;
}



webconfig_error_t translate_ovsdb_to_vap_info_radius_settings(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    wifi_radius_settings_t *radius;

    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    radius = (wifi_radius_settings_t *)&vap->u.bss_info.security.u.radius;

    if (radius == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: radius is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    radius->port = vap_row->radius_srv_port;
    snprintf(radius->key, sizeof(radius->key), "%s", vap_row->radius_srv_secret);

#ifndef WIFI_HAL_VERSION_3_PHASE2
    snprintf((char *)radius->ip, sizeof(radius->ip), "%s", vap_row->radius_srv_addr);
#else
    getIpAddressFromString(vap_row->radius_srv_addr, &(radius->ip));
#endif

    return webconfig_error_none;
}



webconfig_error_t translate_ovsdb_to_vap_info_enterprise_sec(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (macfilter_conversion((char *)vap_row->mac_list_type, sizeof(vap_row->mac_list_type), vap, STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: mac filter conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_radius_settings(vap_row, vap) !=  webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius settings from ovsdb to vap_info failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (vap_row->wpa == false) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Open security is not supported\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    } else {
        if (vap_row->wpa_key_mgmt_len == 0)  {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: wpa_key_mgmt_len is 0\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((key_mgmt_conversion(&vap->u.bss_info.security.mode, (char *)vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), STRING_TO_ENUM)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((vap->u.bss_info.security.mode != wifi_security_mode_wpa2_enterprise) && (vap->u.bss_info.security.mode == wifi_security_mode_wpa_wpa2_enterprise)
                && (vap->u.bss_info.security.mode != wifi_security_mode_wpa3_enterprise) && (vap->u.bss_info.security.mode == wifi_security_mode_wpa_enterprise)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Security mode is not enterprise\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

    }


    vap->u.bss_info.security.rekey_interval = vap_row->group_rekey;
    return webconfig_error_none;
}


webconfig_error_t translate_ovsdb_to_vap_info_no_sec(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    macfilter_conversion("none", strlen("none"), vap, STRING_TO_ENUM);

    if (vap_row->wpa == false) {
        vap->u.bss_info.security.mode = wifi_security_mode_none;
    } else {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid security mode\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    vap->u.bss_info.security.rekey_interval = vap_row->group_rekey;
    return webconfig_error_none;
}



webconfig_error_t translate_ovsdb_to_vap_info_common(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }


    if (vap_mode_conversion(&vap->vap_mode, (char *)vap_row->mode, ARRAY_SZ(vap_row->mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (ssid_broadcast_conversion((char *)vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), &vap->u.bss_info.showSsid, STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: ssid broadcast conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    vap->u.bss_info.enabled = vap_row->enabled;

    if  (is_ssid_name_valid((char *)vap_row->ssid) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ssid name\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    strncpy(vap->u.bss_info.ssid, vap_row->ssid, sizeof(vap->u.bss_info.ssid));
    strncpy(vap->bridge_name, vap_row->bridge, sizeof(vap->bridge_name));
    vap->u.bss_info.UAPSDEnabled = vap_row->uapsd_enable;
    vap->u.bss_info.isolation = vap_row->ap_bridge;
    vap->u.bss_info.bssTransitionActivated = vap_row->btm;
    vap->u.bss_info.nbrReportActivated = vap_row->rrm;
    vap->u.bss_info.wps.enable = vap_row->wps;
    strncpy(vap->u.bss_info.wps.pin, vap_row->wps_pbc_key_id, sizeof(vap->u.bss_info.wps.pin));

    return webconfig_error_none;
}

webconfig_error_t translate_private_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_personal_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_iot_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_personal_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_open_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_no_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for no security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_secure_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_enterprise_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_lnf_radius_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_enterprise_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_lnf_psk_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_personal_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_mesh_backhaul_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_personal_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_ovsdb_to_sta_vap_info_common(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (vap_mode_conversion(&vap->vap_mode, (char *)vap_row->mode, ARRAY_SZ(vap_row->mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode is not station moode\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    vap->u.sta_info.enabled = vap_row->enabled;
    strncpy(vap->bridge_name, vap_row->bridge, sizeof(vap->bridge_name));


    return webconfig_error_none;
}

webconfig_error_t translate_mesh_sta_vap_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_sta_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

//Translate from ovsdb schema to webconfig structures
webconfig_error_t   translate_vap_object_from_ovsdb_vif_config_for_dml(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_VIF_Config **table;
    unsigned int i = 0;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_vap_info_t *vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask =0;
    wifi_platform_property_t *wifi_prop;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;

    if (proto->vif_config_row_count < (MIN_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO) || proto->vif_config_row_count > (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: invalid vif config row count : %x\n", __func__, __LINE__, proto->vif_config_row_count);
        return webconfig_error_translate_to_ovsdb;
    }

    wifi_prop = &decoded_params->hal_cap.wifi_prop;
    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n", __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        if (is_vap_private(wifi_prop, vap_index) == TRUE) {
            if (translate_private_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_xhs(wifi_prop, vap_index) == TRUE) {
            if (translate_iot_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_hotspot_open(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_open_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_lnf_psk(wifi_prop, vap_index) == TRUE) {
            if (translate_lnf_psk_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_hotspot_secure(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_secure_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_lnf_radius(wifi_prop, vap_index) == TRUE) {
            if (translate_lnf_radius_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf radius to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_backhaul(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_backhaul_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mesh backhaul failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_sta(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_sta_vap_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mesh sta failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }
    }

    if (presence_mask != (pow(2, proto->vif_config_row_count) - 1)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t  translate_vap_object_from_ovsdb_vif_config_for_macfilter(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_VIF_Config **table;
    unsigned int i = 0;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_vap_info_t *vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask =0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
	
    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;

    if (proto->vif_config_row_count < (MIN_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO) || proto->vif_config_row_count > (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: invalid vif config row count : %x\n", __func__, __LINE__, proto->vif_config_row_count);
        return webconfig_error_translate_from_ovsdb;
    }

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n", __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        if (is_vap_private(wifi_prop, vap_index) == TRUE) {
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_xhs(wifi_prop, vap_index) == TRUE) {
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_hotspot(wifi_prop, vap_index) == TRUE) {
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_lnf_psk(wifi_prop, vap_index) == TRUE) {
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_hotspot_secure(wifi_prop, vap_index) == TRUE) {
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_lnf_radius(wifi_prop, vap_index) == TRUE) {
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_backhaul(wifi_prop, vap_index) == TRUE) {
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_sta(wifi_prop, vap_index) == TRUE) {
            presence_mask  |= (1 << vap_index);
        } else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }
        //Update the Macfilter
        if ((is_vap_hotspot(wifi_prop, vap_index) != TRUE) && (is_vap_mesh_sta(wifi_prop, vap_index) != TRUE)) {
            if (translate_macfilter_from_ovsdb_to_rdk_vap(vap_row, &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index]) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
        }
    }

    if (presence_mask != (pow(2, proto->vif_config_row_count) - 1)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_radio_object_from_ovsdb(const struct schema_Wifi_Radio_Config *row, wifi_radio_operationParam_t *oper_param)
{
    if ((row == NULL) || (oper_param == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    //Update the values of oper_param
    if (freq_band_conversion(&oper_param->band, (char *)row->freq_band, sizeof(row->freq_band), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (country_code_conversion(&oper_param->countryCode, (char *)row->country, sizeof(row->country), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: country conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    //As part of southbound variant will not be updated
    /*
      if (hw_mode_conversion(&oper_param->variant, (char *)row->hw_mode, sizeof(row->hw_mode), STRING_TO_ENUM) != RETURN_OK) {
      wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Hw mode conversion failed\n", __func__, __LINE__);
      return webconfig_error_translate_from_ovsdb;
      }*/

    if (ht_mode_conversion(&oper_param->channelWidth, (char *)row->ht_mode, sizeof(row->ht_mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Ht mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (channel_mode_conversion(&oper_param->autoChannelEnabled, (char *)row->channel_mode, sizeof(row->channel_mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: channel mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    oper_param->enable = row->enabled;

    if (is_wifi_channel_valid(oper_param->band, row->channel) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d Radio Channel failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    oper_param->channel = row->channel;
    oper_param->transmitPower = row->tx_power;
    oper_param->beaconInterval = row->bcn_int;

    return webconfig_error_none;
}

webconfig_error_t   translate_radio_object_from_ovsdb_radio_config_for_dml(webconfig_subdoc_data_t *data)
{
    unsigned int radio_index = 0;
    unsigned int i = 0;
    struct schema_Wifi_Radio_Config *row;
    const struct schema_Wifi_Radio_Config **table;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_radio_operationParam_t  *oper_param;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Enter\n", __func__, __LINE__);

    // From ovsdb structure to webconfig
    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->radio_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    presence_mask = 0;

    if (proto->radio_config_row_count > MAX_NUM_RADIOS || proto->radio_config_row_count < MIN_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    for (i= 0; i < proto->radio_config_row_count; i++) {

        row = (struct schema_Wifi_Radio_Config *)table[i];
        if (row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: row is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }

        //Convert the ifname to radioIndex
        if (convert_ifname_to_radio_index(&decoded_params->hal_cap.wifi_prop, row->if_name, &radio_index) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Conversion of if_name to radio_index failed for  %s\n", __func__, __LINE__, row->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        oper_param = &decoded_params->radios[radio_index].oper;

        if (translate_radio_object_from_ovsdb(row, oper_param) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate ovsdb to radio_object for %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_from_ovsdb;

        }
        convert_radio_index_to_radio_name(radio_index, decoded_params->radios[radio_index].name);
        presence_mask |= (1 << radio_index);
    }

    if (presence_mask != pow(2, proto->radio_config_row_count) - 1) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }


    return webconfig_error_none;
}

webconfig_error_t   translate_radio_object_to_ovsdb_radio_config_for_radio(webconfig_subdoc_data_t *data)
{
    //Note : schema_Wifi_Radio_Config will be replaced to schema_Wifi_Radio_Config, after we link to the ovs headerfile
    const struct schema_Wifi_Radio_Config **table;
    struct schema_Wifi_Radio_Config *row;
    wifi_radio_operationParam_t  *oper_param;
    webconfig_subdoc_decoded_data_t *decoded_params;
    unsigned int i = 0;
    int radio_index = 0;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0;
    rdk_wifi_radio_t *radio;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Enter\n", __func__, __LINE__);

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    table = proto->radio_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    if (decoded_params->num_radios <  MIN_NUM_RADIOS || decoded_params->num_radios > MAX_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    for (i= 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        radio_index = convert_radio_name_to_radio_index(radio->name);
        if (radio_index == -1) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: invalid radio_index for  %s\n",
                    __func__, __LINE__, decoded_params->radios[i].name);
            return webconfig_error_translate_to_ovsdb;
        }

        oper_param = &radio->oper;

        row = get_radio_schema_from_radioindex(radio_index, table, proto->radio_config_row_count, &decoded_params->hal_cap.wifi_prop);

        if (translate_radio_obj_to_ovsdb(oper_param, row, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate radio_obj to ovsdb %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_ovsdb;
        }

        presence_mask |= (1 << radio_index);
    }
    if (presence_mask != pow(2, decoded_params->num_radios) - 1) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present %s\n", __func__, __LINE__, presence_mask);
        return webconfig_error_invalid_subdoc;
    }

    return webconfig_error_none;
}


webconfig_error_t   translate_radio_object_from_ovsdb_radio_config_for_radio(webconfig_subdoc_data_t *data)
{
    unsigned int radio_index = 0;
    unsigned int i = 0;
    struct schema_Wifi_Radio_Config *row;
    const struct schema_Wifi_Radio_Config **table;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_radio_operationParam_t  *oper_param;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0;
    rdk_wifi_radio_t *radio;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Enter\n", __func__, __LINE__);

    // From ovsdb structure to webconfig
    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->radio_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    presence_mask = 0;

    if (proto->radio_config_row_count <  MIN_NUM_RADIOS || proto->radio_config_row_count > MAX_NUM_RADIOS) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    for (i= 0; i < proto->radio_config_row_count; i++) {

        row = (struct schema_Wifi_Radio_Config *)table[i];
        if (row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: row is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }

        //Convert the ifname to radioIndex
        if (convert_ifname_to_radio_index(&decoded_params->hal_cap.wifi_prop, row->if_name, &radio_index) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Conversion of if_name to radio_index failed for  %s\n", __func__, __LINE__, row->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        radio = &decoded_params->radios[radio_index];

        oper_param = &radio->oper;

        convert_radio_index_to_radio_name(radio_index, radio->name);
        if (translate_radio_object_from_ovsdb(row, oper_param) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate ovsdb to radio_object for %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_from_ovsdb;

        }

        presence_mask |= (1 << radio_index);
    }
    if (presence_mask != pow(2, proto->radio_config_row_count) - 1) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present %x\n\n", __func__, __LINE__, presence_mask);
        return webconfig_error_invalid_subdoc;
    }

    return webconfig_error_none;
}

webconfig_error_t   translate_vap_object_to_ovsdb_vif_config_for_private(webconfig_subdoc_data_t *data)
{
    struct schema_Wifi_VIF_Config *vap_row;
    const struct schema_Wifi_VIF_Config **vif_table;
    unsigned int i, j, k;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, private_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    private_vap_mask = ((1 << convert_vap_name_to_index(wifi_prop, "private_ssid_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "private_ssid_5g")));

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            vap_row = get_vif_schema_from_vapindex(vap->vap_index, vif_table, proto->vif_config_row_count, wifi_prop);
            if (vap_row == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

        }

    }
    if (presence_mask != private_vap_mask) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t   translate_vap_object_to_ovsdb_vif_config_for_mesh(webconfig_subdoc_data_t *data)
{
    struct schema_Wifi_VIF_Config *vap_row;
    const struct schema_Wifi_VIF_Config **vif_table;
    unsigned int i, j, k;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, mesh_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    mesh_vap_mask = ((1 << convert_vap_name_to_index(wifi_prop, "mesh_backhaul_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "mesh_backhaul_5g")) |
            (1 << convert_vap_name_to_index(wifi_prop, "mesh_sta_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "mesh_sta_5g")));

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            vap_row = get_vif_schema_from_vapindex(vap->vap_index, vif_table, proto->vif_config_row_count, wifi_prop);
            if (vap_row == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh backhaul vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
            } else if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
            }
            else {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

        }

    }
    if (presence_mask != mesh_vap_mask) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t   translate_vap_object_to_ovsdb_vif_config_for_home(webconfig_subdoc_data_t *data)
{
    struct schema_Wifi_VIF_Config *vap_row;
    const struct schema_Wifi_VIF_Config **vif_table;
    unsigned int i, j, k;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, home_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    home_vap_mask = ((1 << convert_vap_name_to_index(wifi_prop, "iot_ssid_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "iot_ssid_5g")));

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            vap_row = get_vif_schema_from_vapindex(vap->vap_index, vif_table, proto->vif_config_row_count, wifi_prop);
            if (vap_row == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_iot_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
        }

    }

    if (presence_mask != home_vap_mask) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t   translate_vap_object_to_ovsdb_vif_config_for_xfinity(webconfig_subdoc_data_t *data)
{
    struct schema_Wifi_VIF_Config *vap_row;
    const struct schema_Wifi_VIF_Config **vif_table;
    unsigned int i, j, k;
    webconfig_subdoc_decoded_data_t *decoded_params;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, home_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    home_vap_mask = ((1 << convert_vap_name_to_index(wifi_prop, "hotspot_open_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "hotspot_open_5g")) |
            (1 << convert_vap_name_to_index(wifi_prop, "hotspot_secure_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "hotspot_secure_5g")) );

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            vap_row = get_vif_schema_from_vapindex(vap->vap_index, vif_table, proto->vif_config_row_count, wifi_prop);
            if (vap_row == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (is_vap_hotspot_open(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_hotspot_open_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);

            } else  if (is_vap_hotspot_secure(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_hotspot_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
        }

    }
    if (presence_mask != home_vap_mask) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t   translate_vap_object_from_ovsdb_vif_config_for_private(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_VIF_Config **table;
    unsigned int i = 0;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_vap_info_t *vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, private_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    private_vap_mask = ((1 << convert_vap_name_to_index(wifi_prop, "private_ssid_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "private_ssid_5g")));

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }
        if (is_vap_private(wifi_prop, vap_index) == TRUE) {
            if (translate_private_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        }
    }

    if (presence_mask != private_vap_mask) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x supported mask : %x\n", __func__, __LINE__, presence_mask, private_vap_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t   translate_vap_object_from_ovsdb_vif_config_for_mesh(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_VIF_Config **table;
    unsigned int i = 0;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_vap_info_t *vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, mesh_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    mesh_vap_mask = ((1 << convert_vap_name_to_index(wifi_prop, "mesh_backhaul_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "mesh_backhaul_5g")) |
            (1 << convert_vap_name_to_index(wifi_prop, "mesh_sta_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "mesh_sta_5g")));

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed %s\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }
        if (is_vap_mesh_backhaul(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_backhaul_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mesh backhaul failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_sta(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_sta_vap_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mesh sta failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } /*else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
            }*/
        if (is_vap_mesh_sta(wifi_prop, vap_index) != TRUE) {
            if (translate_macfilter_from_ovsdb_to_rdk_vap(vap_row, &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index]) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
        }
    }

    if (presence_mask != mesh_vap_mask) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t   translate_vap_object_from_ovsdb_vif_config_for_home(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_VIF_Config **table;
    unsigned int i = 0;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_vap_info_t *vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, home_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    home_vap_mask = ((1 << convert_vap_name_to_index(wifi_prop, "iot_ssid_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "iot_ssid_5g")));

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
wifi_util_dbg_print(WIFI_WEBCONFIG, "%s : %s : %d convert_vap_name_to_array_index()\n", __FILE__, __func__, __LINE__);
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }
        if (is_vap_xhs(wifi_prop, vap_index) == TRUE) {
            if (translate_iot_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }

            presence_mask  |= (1 << vap_index);
        } else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }
    }

    if (presence_mask != home_vap_mask) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t   translate_vap_object_from_ovsdb_vif_config_for_xfinity(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_VIF_Config **table;
    unsigned int i = 0;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_vap_info_t *vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, xfinity_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    xfinity_vap_mask = ((1 << convert_vap_name_to_index(wifi_prop, "hotspot_open_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "hotspot_open_5g")) |
            (1 << convert_vap_name_to_index(wifi_prop, "hotspot_secure_2g")) | (1 << convert_vap_name_to_index(wifi_prop, "hotspot_secure_5g")));

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        if (is_vap_hotspot_open(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_open_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_hotspot_secure(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_secure_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }
    }

    if (presence_mask != xfinity_vap_mask) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t   translate_to_ovsdb_tables(webconfig_subdoc_type_t type, webconfig_subdoc_data_t *data)
{
    if (data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Input data is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }
    switch (type) {
        case webconfig_subdoc_type_private:
            if (translate_vap_object_to_ovsdb_vif_config_for_private(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_home:
            if (translate_vap_object_to_ovsdb_vif_config_for_home(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_xfinity:
            if (translate_vap_object_to_ovsdb_vif_config_for_xfinity(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_radio:
            if (translate_radio_object_to_ovsdb_radio_config_for_radio(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_mesh:
            if (translate_vap_object_to_ovsdb_vif_config_for_mesh(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_dml:
            // translate rif, vif tables for all rows
            if (translate_radio_object_to_ovsdb_radio_config_for_dml(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_dml(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_radio_object_to_ovsdb_radio_state_for_dml(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio state translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_state_for_dml(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap state translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }


            if (free_vap_object_macfilter_entries(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: mac entries free failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

        break;

        case webconfig_subdoc_type_associated_clients:
            if (translate_vap_object_to_ovsdb_associated_clients_for_assoclist(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: associated clients translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_radio_status:
        break;

        case webconfig_subdoc_type_vap_status:
        break;

        default:
        break;

    }
    return webconfig_error_none;
}

webconfig_error_t   translate_from_ovsdb_tables(webconfig_subdoc_type_t type, webconfig_subdoc_data_t *data)
{
    if (data == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Input data is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    switch (type) {
        case webconfig_subdoc_type_private:
            if (translate_vap_object_from_ovsdb_vif_config_for_private(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_home:
            if (translate_vap_object_from_ovsdb_vif_config_for_home(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_xfinity:
            if (translate_vap_object_from_ovsdb_vif_config_for_xfinity(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_radio:
            if (translate_radio_object_from_ovsdb_radio_config_for_radio(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_mesh:
            if (translate_vap_object_from_ovsdb_vif_config_for_mesh(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_dml:
            // translate rif, vif tables for all rows
            if (translate_radio_object_from_ovsdb_radio_config_for_dml(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }

            if (translate_vap_object_from_ovsdb_vif_config_for_dml(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_mac_filter:
            if (translate_vap_object_from_ovsdb_vif_config_for_macfilter(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_radio_status:
        break;

        case webconfig_subdoc_type_vap_status:
        break;

        default:
        break;

    }
    return webconfig_error_none;
}
