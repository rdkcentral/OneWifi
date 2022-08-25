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
#include "const.h"
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
static webconfig_subdoc_data_t  webconfig_ovsdb_default_data;
//static webconfig_external_ovsdb_t webconfig_ovsdb_external;
const char* security_state_find_by_key(const struct  schema_Wifi_VIF_State *vstate,
        char *key);
const char* security_config_find_by_key(const struct schema_Wifi_VIF_Config *vconf,
        char *key);

void radio_config_ovs_schema_dump(const struct schema_Wifi_Radio_Config *radio)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, "if_name                   : %s\n",   radio->if_name);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "freq_band                 : %s\n",   radio->freq_band);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "enabled                   : %d\n",   radio->enabled);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "dfs_demo                  : %d\n",   radio->dfs_demo);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "hw_type                   : %s\n", radio->hw_type);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "hw_config                 : %s\n", radio->hw_config);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "country                   : %s\n",   radio->country);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "channel                   : %d\n",   radio->channel);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "channel_sync              : %d\n",   radio->channel_sync);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "channel_mode              : %s\n",   radio->channel_mode);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "hw_mode                   : %s\n",   radio->hw_mode);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "ht_mode                   : %s\n",   radio->ht_mode);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "thermal_shutdown          : %d\n",   radio->thermal_shutdown);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "thermal_downgrade_temp    : %d\n",   radio->thermal_downgrade_temp);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "thermal_upgrade_temp      : %d\n",   radio->thermal_upgrade_temp);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "thermal_integration       : %d\n",   radio->thermal_integration);
    //wifi_util_dbg_print(WIFI_WEBCONFIG, "temperature_control       : %s\n",   radio->temperature_control);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "tx_power                  : %d\n",   radio->tx_power);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "bcn_int                   : %d\n",   radio->bcn_int);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "tx_chainmask              : %d\n",   radio->tx_chainmask);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "thermal_tx_chainmask      : %d\n",   radio->thermal_tx_chainmask);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "zero_wait_dfs             : %s\n",   radio->zero_wait_dfs);

    return;
}

void radio_state_ovs_schema_dump(const struct schema_Wifi_Radio_State *radio)
{
    int i = 0;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "if_name                   : %s\n",   radio->if_name);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "freq_band                 : %s\n",   radio->freq_band);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "enabled                   : %d\n",   radio->enabled);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "dfs_demo                  : %d\n",   radio->dfs_demo);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "hw_type                   : %s\n",   radio->hw_type);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "hw_config                 : %s\n",   radio->hw_config);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "country                   : %s\n",   radio->country);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "channel                   : %d\n",   radio->channel);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "channel_sync              : %d\n",   radio->channel_sync);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "channel_mode              : %s\n",   radio->channel_mode);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "hw_mode                   : %s\n",   radio->hw_mode);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "ht_mode                   : %s\n",   radio->ht_mode);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "thermal_shutdown          : %d\n",   radio->thermal_shutdown);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "thermal_downgrade_temp    : %d\n",   radio->thermal_downgrade_temp);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "thermal_upgrade_temp      : %d\n",   radio->thermal_upgrade_temp);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "thermal_integration       : %d\n",   radio->thermal_integration);
    //wifi_util_dbg_print(WIFI_WEBCONFIG, "temperature_control       : %s\n",   radio->temperature_control);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "tx_power                  : %d\n",   radio->tx_power);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "bcn_int                   : %d\n",   radio->bcn_int);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "tx_chainmask              : %d\n",   radio->tx_chainmask);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "thermal_tx_chainmask      : %d\n",   radio->thermal_tx_chainmask);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "zero_wait_dfs             : %s\n",   radio->zero_wait_dfs);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "mac                       : %s\n",   radio->mac);
    wifi_util_dbg_print(WIFI_WEBCONFIG, "allowedchannels           : ");
    for (i = 0; i < radio->allowed_channels_len; i++) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%d,", radio->allowed_channels[i]);
    }
    wifi_util_dbg_print(WIFI_WEBCONFIG, "\n");
    //channels

    return;
}

void vif_config_ovs_schema_dump(const struct schema_Wifi_VIF_Config *vif)
{
    int i = 0;
    wifi_util_dbg_print(WIFI_WEBCONFIG, " if_name                   : %s\n",   vif->if_name);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " enabled                   : %d\n",   vif->enabled);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " mode                      : %s\n",   vif->mode);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " vif_radio_idx             : %d\n",   vif->vif_radio_idx);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " vif_dbg_lvl               : %d\n",   vif->vif_dbg_lvl);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " wds                       : %d\n",   vif->wds);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " ssid                      : %s\n",   vif->ssid);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " ssid_broadcast            : %s\n",   vif->ssid_broadcast);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " bridge                    : %s\n",   vif->bridge);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " mac_list_type             : %s\n",   vif->mac_list_type);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " vlan_id                   : %d\n",   vif->vlan_id);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " min_hw_mode               : %s\n",   vif->min_hw_mode);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " uapsd_enable              : %d\n",   vif->uapsd_enable);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " group_rekey               : %d\n",   vif->group_rekey);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " ap_bridge                 : %d\n",   vif->ap_bridge);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " ft_psk                    : %d\n",   vif->ft_psk);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " ft_mobility_domain        : %d\n",   vif->ft_mobility_domain);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " rrm                       : %d\n",   vif->rrm);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " btm                       : %d\n",   vif->btm);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " dynamic_beacon            : %d\n",   vif->dynamic_beacon);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " mcast2ucast               : %d\n",   vif->mcast2ucast);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " multi_ap                  : %s\n",   vif->multi_ap);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " wps                       : %d\n",   vif->wps);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " wps_pbc                   : %d\n",   vif->wps_pbc);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " wps_pbc_key_id            : %s\n",   vif->wps_pbc_key_id);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " wpa                       : %d\n",   vif->wpa);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " parent                    : %s\n",   vif->parent);
    const char *str;

    str = security_config_find_by_key(vif, "encryption");
    if (str != NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, " encryption                : %s\n",   str);
    }

    str = security_config_find_by_key(vif, "mode");
    if (str != NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, " wpa_key_mgmt              : %s\n",   str);
    }

    str = security_config_find_by_key(vif, "key");
    if (str != NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, " wpa_psk                   : %s\n",   str);
    }
    for (i=0; i<vif->mac_list_len; i++) {
        if (vif->mac_list[i] != NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, " mac_list                : %s\n",   vif->mac_list[i]);
        }
    }
    wifi_util_dbg_print(WIFI_WEBCONFIG, " radius_srv_addr           : %s\n",   vif->radius_srv_addr);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " radius_srv_port           : %d\n",   vif->radius_srv_port);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " radius_srv_secret         : %s\n",   vif->radius_srv_secret);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " default_oftag             : %s\n",   vif->default_oftag);

    return;
}

void vif_state_ovs_schema_dump(const struct schema_Wifi_VIF_State *vif)
{
    int i = 0;
    wifi_util_dbg_print(WIFI_WEBCONFIG, " if_name                   : %s\n",   vif->if_name);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " enabled                   : %d\n",   vif->enabled);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " mode                      : %s\n",   vif->mode);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " vif_radio_idx             : %d\n",   vif->vif_radio_idx);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " mac                       : %s\n",   vif->mac);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " wds                       : %d\n",   vif->wds);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " ssid                      : %s\n",   vif->ssid);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " ssid_broadcast            : %s\n",   vif->ssid_broadcast);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " bridge                    : %s\n",   vif->bridge);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " mac_list_type             : %s\n",   vif->mac_list_type);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " vlan_id                   : %d\n",   vif->vlan_id);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " min_hw_mode               : %s\n",   vif->min_hw_mode);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " uapsd_enable              : %d\n",   vif->uapsd_enable);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " group_rekey               : %d\n",   vif->group_rekey);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " ap_bridge                 : %d\n",   vif->ap_bridge);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " ft_psk                    : %d\n",   vif->ft_psk);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " ft_mobility_domain        : %d\n",   vif->ft_mobility_domain);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " rrm                       : %d\n",   vif->rrm);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " btm                       : %d\n",   vif->btm);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " dynamic_beacon            : %d\n",   vif->dynamic_beacon);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " mcast2ucast               : %d\n",   vif->mcast2ucast);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " multi_ap                  : %s\n",   vif->multi_ap);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " wps                       : %d\n",   vif->wps);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " wps_pbc                   : %d\n",   vif->wps_pbc);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " wps_pbc_key_id            : %s\n",   vif->wps_pbc_key_id);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " wpa                       : %d\n",   vif->wpa);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " parent                    : %s\n",   vif->parent);
    const char *str;

    str = security_state_find_by_key(vif, "encryption");
    if (str != NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, " encryption                : %s\n",   str);
    }

    str = security_state_find_by_key(vif, "mode");
    if (str != NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, " sec mode                  : %s\n",   str);
    }

    str = security_state_find_by_key(vif, "key");
    if (str != NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, " key                       : %s\n",   str);
    }
    for (i=0; i<vif->mac_list_len; i++) {
        if (vif->mac_list[i] != NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, " mac_list                  : %s\n",   vif->mac_list[i]);
        }
    }
    wifi_util_dbg_print(WIFI_WEBCONFIG, " radius_srv_addr           : %s\n",   vif->radius_srv_addr);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " radius_srv_port           : %d\n",   vif->radius_srv_port);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " radius_srv_secret         : %s\n",   vif->radius_srv_secret);

    return;
}

void debug_external_protos(const webconfig_subdoc_data_t *data, const char *func, int line)
{
    webconfig_external_ovsdb_t *proto;
    const struct schema_Wifi_Radio_Config *radio_config_row;
    const struct schema_Wifi_Radio_State *radio_state_row;
    const struct schema_Wifi_VIF_Config *vif_config_row;
    const struct schema_Wifi_VIF_State *vif_state_row;
    unsigned int i;

    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Input data is NULL\n", __func__, __LINE__);
        return;
    }

    wifi_util_info_print(WIFI_WEBCONFIG, "%s: calling from %s:%d\n", __func__, func, line);

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: proto is NULL\n", __func__, __LINE__);
        return;
    }
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: radio_config_row_count %d \n", __func__, proto->radio_config_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: vif_config_row_count %d\n", __func__, proto->vif_config_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: radio_state_row_count %d\n", __func__, proto->radio_state_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: vif_state_row_count %d\n", __func__, proto->vif_state_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: assoc_clients_row_count %d\n", __func__, proto->assoc_clients_row_count);

    if ((access("/tmp/wifiOvsdbDbg", F_OK)) != 0) {
        return;
    }

    for (i=0; i<proto->radio_config_row_count; i++) {
        radio_config_row = (struct schema_Wifi_Radio_Config *)proto->radio_config[i];
        if (radio_config_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio_config_row is NULL\n", __func__, __LINE__);
            return;
        }
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Radio Config radio[%d] ifname '%s'\n", __func__, i, radio_config_row->if_name);
        radio_config_ovs_schema_dump(radio_config_row);
    }

    for (i=0; i<proto->radio_state_row_count; i++) {
        radio_state_row = (struct schema_Wifi_Radio_State *)proto->radio_state[i];
        if (radio_state_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio_state_row is NULL\n", __func__, __LINE__);
            return;
        }
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: Radio State radio[%d] ifname '%s'\n", __func__, i, radio_state_row->if_name);
        radio_state_ovs_schema_dump(radio_state_row);
    }


    for (i=0; i<proto->vif_config_row_count; i++) {
        vif_config_row = (struct schema_Wifi_VIF_Config *)proto->vif_config[i];
        if (vif_config_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vif_config_row is NULL\n", __func__, __LINE__);
            return;
        }
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: VIF Config VIF[%d] ifname '%s'\n", __func__, i, vif_config_row->if_name);
        vif_config_ovs_schema_dump(vif_config_row);
    }

    for (i=0; i<proto->vif_state_row_count; i++) {
        vif_state_row = (struct schema_Wifi_VIF_State *)proto->vif_state[i];
        if (vif_state_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vif_state_row is NULL\n", __func__, __LINE__);
            return;
        }
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s: VIF State VIF[%d] ifname '%s'\n", __func__, i, vif_state_row->if_name);
        vif_state_ovs_schema_dump(vif_state_row);
    }

}


webconfig_error_t translator_ovsdb_init(webconfig_subdoc_data_t *data)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d\n", __func__, __LINE__);
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_hal_capability_t *hal_cap;
    unsigned int i = 0;
    unsigned int num_ssid = 0;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    int vapIndex = 0;
    unsigned int radioIndx = 256; // some impossible values
    unsigned int vapArrayIndx = 256;
    char wps_pin[128] = {0};
    char password[128] = {0};
    char ssid[128] = {0};
    wifi_radio_operationParam_t  *oper_param;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    hal_cap = &decoded_params->hal_cap;
    memcpy(&webconfig_ovsdb_default_data.u.decoded.hal_cap, hal_cap, sizeof(wifi_hal_capability_t));

    /* get list of private SSID */
    num_ssid = get_list_of_private_ssid(&hal_cap->wifi_prop, MAX_NUM_RADIOS, vap_names);
    /* get list of mesh_backhaul SSID */
    num_ssid += get_list_of_mesh_backhaul(&hal_cap->wifi_prop, MAX_NUM_RADIOS, &vap_names[num_ssid]);
    /* get list of lnf psk SSID */
    num_ssid += get_list_of_lnf_psk(&hal_cap->wifi_prop, MAX_NUM_RADIOS, &vap_names[num_ssid]);
    /* get list of lnf_radiusSSID */
    num_ssid += get_list_of_lnf_radius(&hal_cap->wifi_prop, MAX_NUM_RADIOS, &vap_names[num_ssid]);
    /* get list of iot SSID */
    num_ssid += get_list_of_iot_ssid(&hal_cap->wifi_prop, MAX_NUM_RADIOS, &vap_names[num_ssid]);

    for (i = 0; i < num_ssid; i++) {
        vapIndex =  convert_vap_name_to_index(&hal_cap->wifi_prop, vap_names[i]);
        if(vapIndex == RETURN_ERR) {
            continue;
        }

        radioIndx = convert_vap_name_to_radio_array_index(&hal_cap->wifi_prop, vap_names[i]);
        if ((int)radioIndx == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: wrong index:%d vap_name %s\n", __func__, __LINE__, i, vap_names[i]);
            return webconfig_error_invalid_subdoc;
        }
        vapArrayIndx = convert_vap_name_to_array_index(&hal_cap->wifi_prop, vap_names[i]);
        if ((int)vapArrayIndx == RETURN_ERR) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: wrong index:%d vap_name %s\n", __func__, __LINE__, i, vap_names[i]);
            return webconfig_error_invalid_subdoc;
        }

        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Filling default values for %s\n", __func__, __LINE__, vap_names[i]);
        // Locate corresponding structure element in webconfig_ovsdb_data and update it with default values
        wifi_vap_info_t *t_vap_info = &webconfig_ovsdb_default_data.u.decoded.radios[radioIndx].vaps.vap_map.vap_array[vapArrayIndx];
        t_vap_info->vap_index = vapIndex;
        t_vap_info->radio_index = radioIndx;
        strcpy(t_vap_info->vap_name, vap_names[i]);
        t_vap_info->u.bss_info.wmm_enabled = true;
        t_vap_info->u.bss_info.isolation = 0;
        t_vap_info->u.bss_info.bssTransitionActivated = false;
        t_vap_info->u.bss_info.nbrReportActivated = false;
        t_vap_info->u.bss_info.rapidReconnThreshold = 180;
        t_vap_info->u.bss_info.mac_filter_enable = false;
        t_vap_info->u.bss_info.UAPSDEnabled = true;
        t_vap_info->u.bss_info.wmmNoAck = false;
        t_vap_info->u.bss_info.wepKeyLength = 128;
        t_vap_info->u.bss_info.security.encr = wifi_encryption_aes_tkip;
        t_vap_info->u.bss_info.bssHotspot = false;
        t_vap_info->u.bss_info.beaconRate = WIFI_BITRATE_6MBPS;
        strncpy(t_vap_info->u.bss_info.beaconRateCtl,"6Mbps",sizeof(t_vap_info->u.bss_info.beaconRateCtl)-1);
        t_vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
        t_vap_info->vap_mode = wifi_vap_mode_ap;
        t_vap_info->u.bss_info.enabled = false;
        t_vap_info->u.bss_info.bssMaxSta = 75;
        snprintf(t_vap_info->u.bss_info.interworking.interworking.hessid, sizeof(t_vap_info->u.bss_info.interworking.interworking.hessid), "11:22:33:44:55:66");


        if (is_vap_private(&hal_cap->wifi_prop, vapIndex) == TRUE) {
            t_vap_info->u.bss_info.network_initiated_greylist = false;
            t_vap_info->u.bss_info.vapStatsEnable = true;
            t_vap_info->u.bss_info.wpsPushButton = 0;
            t_vap_info->u.bss_info.wps.enable = true;
            t_vap_info->u.bss_info.rapidReconnectEnable = true;
            t_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            strcpy(t_vap_info->bridge_name, "brlan0");
            memset(ssid, 0, sizeof(ssid));
            strcpy(t_vap_info->u.bss_info.ssid, t_vap_info->vap_name);
            memset(password, 0, sizeof(password));
            //This is an example of password default if its not configured.
            strcpy(t_vap_info->u.bss_info.security.u.key.key, "123456789");
            memset(wps_pin, 0, sizeof(wps_pin));
            strcpy(t_vap_info->u.bss_info.wps.pin, "12345678");
            t_vap_info->u.bss_info.showSsid = true;

        } else if(is_vap_mesh_backhaul(&hal_cap->wifi_prop, vapIndex) == TRUE) {
            t_vap_info->u.bss_info.vapStatsEnable = false;
            t_vap_info->u.bss_info.rapidReconnectEnable = false;
            t_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_personal;
            t_vap_info->u.bss_info.showSsid = false;
            if (strcmp(t_vap_info->vap_name, "mesh_backhaul_2g") == 0) {
                strcpy(t_vap_info->bridge_name, "brlan112");
            } else if (strcmp(t_vap_info->vap_name, "mesh_backhaul_5g") == 0) {
                strcpy(t_vap_info->bridge_name, "brlan113");
            }
            memset(ssid, 0, sizeof(ssid));
            strcpy(t_vap_info->u.bss_info.ssid, "we.connect.yellowstone");
            memset(password, 0, sizeof(password));
            //This is an example of password default if its not configured.
            strcpy(t_vap_info->u.bss_info.security.u.key.key, "1234567890");
        } else if(is_vap_lnf_radius(&hal_cap->wifi_prop, vapIndex) == TRUE) {
            strcpy(t_vap_info->u.bss_info.security.u.radius.identity, "lnf_radius_identity");
            t_vap_info->u.bss_info.security.u.radius.port = 1812;
            strcpy((char *)t_vap_info->u.bss_info.security.u.radius.ip, "127.0.0.1");
            t_vap_info->u.bss_info.security.u.radius.s_port = 1812;
            strcpy((char *)t_vap_info->u.bss_info.security.u.radius.s_ip, "127.0.0.1");
            //This is an example of radius keys default if its not configured.
            strcpy(t_vap_info->u.bss_info.security.u.radius.key, "1234567890");
            strcpy(t_vap_info->u.bss_info.security.u.radius.s_key, "1234567890");

            strcpy(t_vap_info->u.bss_info.ssid, t_vap_info->vap_name);
            strcpy(t_vap_info->bridge_name, "brlan106");
            t_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
        }   else if(is_vap_lnf_psk(&hal_cap->wifi_prop, vapIndex) == TRUE) {
            t_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            strcpy(t_vap_info->bridge_name, "brlan106");
            memset(ssid, 0, sizeof(ssid));
            strcpy(t_vap_info->u.bss_info.ssid, t_vap_info->vap_name);
            memset(password, 0, sizeof(password));
            //This is an example of password default if its not configured.
            strcpy(t_vap_info->u.bss_info.security.u.key.key, "123456789");
            t_vap_info->u.bss_info.showSsid = false;
        }   else if(is_vap_xhs(&hal_cap->wifi_prop, vapIndex) == TRUE) {
            t_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            strcpy(t_vap_info->bridge_name, "brlan1");
            memset(ssid, 0, sizeof(ssid));
            strcpy(t_vap_info->u.bss_info.ssid, t_vap_info->vap_name);
            memset(password, 0, sizeof(password));
            //This is an example of password default if its not configured.
            strcpy(t_vap_info->u.bss_info.security.u.key.key, "123456789");
            t_vap_info->u.bss_info.showSsid = false;
        }
    }
    for (i= 0; i < decoded_params->num_radios; i++) {
        radioIndx = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        oper_param = &decoded_params->radios[radioIndx].oper;
        memcpy(&webconfig_ovsdb_default_data.u.decoded.radios[radioIndx].oper, oper_param, sizeof(wifi_radio_operationParam_t));
        strncpy(webconfig_ovsdb_default_data.u.decoded.radios[radioIndx].name, decoded_params->radios[radioIndx].name,  sizeof(webconfig_ovsdb_default_data.u.decoded.radios[radioIndx].name));
        webconfig_ovsdb_default_data.u.decoded.radios[radioIndx].vaps.vap_map.num_vaps = decoded_params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
    }

    webconfig_ovsdb_default_data.u.decoded.num_radios = decoded_params->num_radios;

    debug_external_protos(data, __func__, __LINE__);
    return webconfig_error_none;

}
webconfig_error_t webconfig_convert_ifname_to_subdoc_type(const char *ifname, webconfig_subdoc_type_t *type)
{
    wifi_platform_property_t *wifi_prop = &webconfig_ovsdb_default_data.u.decoded.hal_cap.wifi_prop;
    wifi_vap_name_t vapname;

    if (wifi_prop == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: wifi_prop is NULL!!!\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if ((ifname == NULL) || (type == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: input arguments are NULL!!!\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }


    if (convert_ifname_to_vapname(wifi_prop, (char *)ifname, vapname, sizeof(vapname)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed for : %s\n", __func__, __LINE__, ifname);
        return webconfig_error_translate_from_ovsdb;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d vap_name : %s\n", __func__, __LINE__, vapname);
    if (strncmp((char *)vapname, "private_ssid", strlen("private_ssid")) == 0) {
        *type =  webconfig_subdoc_type_private;
        return webconfig_error_none;
    } else if (strncmp((char *)vapname, "iot_ssid", strlen("iot_ssid")) == 0) {
        *type = webconfig_subdoc_type_home;
        return webconfig_error_none;
    } else if (strncmp((char *)vapname, "mesh_sta", strlen("mesh_sta")) == 0) {
        *type = webconfig_subdoc_type_mesh_sta;
        return webconfig_error_none;
    } else if (strncmp((char *)vapname, "mesh_backhaul", strlen("mesh_backhaul")) == 0) {
        *type = webconfig_subdoc_type_mesh_backhaul;
        return webconfig_error_none;
    } else if (strncmp((char *)vapname, "hotspot_", strlen("hotspot_")) == 0) {
        *type = webconfig_subdoc_type_xfinity;
        return webconfig_error_none;
    } else if (strncmp((char *)vapname, "lnf_", strlen("lnf_")) == 0) {
        *type = webconfig_subdoc_type_lnf;
        return webconfig_error_none;
    }
    *type = webconfig_subdoc_type_unknown;
    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d - No interface %s found\n", __FUNCTION__, __LINE__, ifname);

    return webconfig_error_translate_from_ovsdb;
}

webconfig_error_t webconfig_ovsdb_encode(webconfig_t *config,
        const webconfig_external_ovsdb_t *data,
        webconfig_subdoc_type_t type,
        char **str)
{

    wifi_util_info_print(WIFI_WEBCONFIG,"OVSM encode subdoc type %d\n", type);
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d\n", __func__, __LINE__);
    webconfig_ovsdb_data.u.decoded.external_protos = (webconfig_external_ovsdb_t *)data;
    webconfig_ovsdb_data.descriptor = webconfig_data_descriptor_translate_from_ovsdb;
    debug_external_protos(&webconfig_ovsdb_data, __func__, __LINE__);
    if (webconfig_encode(config, &webconfig_ovsdb_data, type) != webconfig_error_none) {
        *str = NULL;
        wifi_util_error_print(WIFI_WEBCONFIG,"OVSM encode failed\n");
        return webconfig_error_encode;
    }
    *str = webconfig_ovsdb_data.u.encoded.raw;
    return webconfig_error_none;
}

webconfig_error_t webconfig_ovsdb_decode(webconfig_t *config, const char *str,
        webconfig_external_ovsdb_t *data,
        webconfig_subdoc_type_t *type)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d\n", __func__, __LINE__);

    webconfig_ovsdb_data.u.decoded.external_protos = (webconfig_external_ovsdb_t *)data;
    webconfig_ovsdb_data.descriptor = webconfig_data_descriptor_translate_to_ovsdb;

    if (webconfig_decode(config, &webconfig_ovsdb_data, str) != webconfig_error_none) {
        //        *data = NULL;
        wifi_util_error_print(WIFI_WEBCONFIG,"OVSM decode failed\n");
        return webconfig_error_decode;

    }

    wifi_util_info_print(WIFI_WEBCONFIG,"OVSM decode subdoc type %d sucessfully\n", webconfig_ovsdb_data.type);
    *type = webconfig_ovsdb_data.type;
    debug_external_protos(&webconfig_ovsdb_data, __func__, __LINE__);
    return webconfig_error_none;
}

webconfig_error_t free_vap_object_assoc_client_entries(webconfig_subdoc_data_t *data)
{
    unsigned int i=0, j=0;
    rdk_wifi_radio_t *radio;
    rdk_wifi_vap_info_t *rdk_vap_info;
    webconfig_subdoc_decoded_data_t *decoded_params;
    assoc_dev_data_t *assoc_dev_data, *temp_assoc_dev_data;
    mac_addr_str_t mac_str;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            rdk_vap_info = &decoded_params->radios[i].vaps.rdk_vap_array[j];
            if (rdk_vap_info == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: rdk_vap_info is null", __func__, __LINE__);
                return webconfig_error_invalid_subdoc;
            }
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
                hash_map_destroy(rdk_vap_info->associated_devices_map);
                rdk_vap_info->associated_devices_map =  NULL;
            }
        }
    }
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            rdk_vap = &decoded_params->radios[i].vaps.rdk_vap_array[j];
            if (rdk_vap == NULL){
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: rdk_vap is null", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema is NULL\n", __func__, __LINE__);
        return NULL;
    }
    //convert if_name to vap_index
    if (convert_apindex_to_ifname(wifi_prop, vap_index, if_name, sizeof(if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid vap_index : %d\n", __func__, __LINE__, vap_index);
        return NULL;
    }

    for (i = 0; i<num_vaps; i++) {
        if (table[i] == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema is NULL\n", __func__, __LINE__);
            return NULL;
        }

        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: if_name:%s:table_if_name:%s\r\n", __func__, __LINE__, if_name, table[i]->if_name);
        if (!strcmp(if_name, table[i]->if_name))
        {
            return (struct schema_Wifi_VIF_Config *)table[i];
        }

    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: num_vaps:%d\r\n", __func__, __LINE__, num_vaps);
    return NULL;
}

webconfig_error_t translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(const rdk_wifi_vap_info_t *rdk_vap, struct schema_Wifi_VIF_Config *row)
{
    acl_entry_t *acl_entry;
    char mac_string[18] = {0};
    unsigned int count = 0;

    if ((rdk_vap == NULL) || (row == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if(rdk_vap->acl_map != NULL) {
        acl_entry = hash_map_get_first(rdk_vap->acl_map);
        while(acl_entry != NULL) {
            memset(&mac_string,0,18);
            snprintf(mac_string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", acl_entry->mac[0], acl_entry->mac[1],
                    acl_entry->mac[2], acl_entry->mac[3], acl_entry->mac[4], acl_entry->mac[5]);
            if (row->mac_list[count] == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: mac_list is NULL\n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if(rdk_vap->acl_map != NULL) {
        acl_entry = hash_map_get_first(rdk_vap->acl_map);
        while(acl_entry != NULL) {
            memset(&mac_string,0,18);
            snprintf(mac_string, 18, "%02x:%02x:%02x:%02x:%02x:%02x", acl_entry->mac[0], acl_entry->mac[1],
                    acl_entry->mac[2], acl_entry->mac[3], acl_entry->mac[4], acl_entry->mac[5]);
            if (row->mac_list[count] == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: mac_list is NULL\n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    rdk_vap->acl_map = hash_map_create();
    if (rdk_vap->acl_map == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: hash map create failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    for (i = 0; i < row->mac_list_len; i++) {
        mac_str = (char *)row->mac_list[i];
        if (mac_str == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: mac_str is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }
        str_to_mac_bytes(mac_str, mac);
        acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
        if (acl_entry == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer \n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (freq_band_conversion((wifi_freq_bands_t *)&oper_param->band, (char *)row->freq_band, sizeof(row->freq_band), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed. band 0x%x\n", __func__, __LINE__, oper_param->band);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_freq_band_to_radio_index(oper_param->band, &radio_index) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: frequency band to radio_index failed. band 0x%x\n", __func__, __LINE__, oper_param->band);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_radio_index_to_ifname(wifi_prop, radio_index, row->if_name, sizeof(row->if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: radio_index to ifname failed failed. radio_index %d\n", __func__, __LINE__, radio_index);
        return webconfig_error_translate_to_ovsdb;
    }

    if (country_code_conversion((wifi_countrycode_type_t *)&oper_param->countryCode, row->country, sizeof(row->country), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: country conversion failed. countryCode %d\n", __func__, __LINE__, oper_param->countryCode);
        return webconfig_error_translate_to_ovsdb;
    }


    if (hw_mode_conversion((wifi_ieee80211Variant_t *)&oper_param->variant, row->hw_mode, sizeof(row->hw_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Hw mode conversion failed. variant 0x%x\n", __func__, __LINE__, oper_param->variant);
        return webconfig_error_translate_to_ovsdb;
    }


    if (ht_mode_conversion((wifi_channelBandwidth_t *)&oper_param->channelWidth, row->ht_mode, sizeof(row->ht_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Ht mode conversion failed. channelWidth 0x%x\n", __func__, __LINE__, oper_param->channelWidth);
        return webconfig_error_translate_to_ovsdb;
    }

    if (channel_mode_conversion((BOOL *)&oper_param->autoChannelEnabled, row->channel_mode, sizeof(row->channel_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Channel mode conversion failed. autoChannelEnabled %d\n", __func__, __LINE__, oper_param->autoChannelEnabled);
        return webconfig_error_translate_to_ovsdb;
    }


    if (get_radio_if_hw_type(row->hw_type, sizeof(row->hw_type)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get hw type failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (get_allowed_channels(oper_param->band, &wifi_prop->radiocap[radio_index], row->allowed_channels, &row->allowed_channels_len) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get allowed channels failed\n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (freq_band_conversion((wifi_freq_bands_t *)&oper_param->band, (char *)row->freq_band, sizeof(row->freq_band), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed. band 0x%x\n", __func__, __LINE__, oper_param->band);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_freq_band_to_radio_index(oper_param->band, &radio_index) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: frequency band to radio_index failed. band 0x%x\n", __func__, __LINE__, oper_param->band);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_radio_index_to_ifname(wifi_prop, radio_index, row->if_name, sizeof(row->if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: radio_index to ifname failed failed. radio_index %d\n", __func__, __LINE__, radio_index);
        return webconfig_error_translate_to_ovsdb;
    }

    if (country_code_conversion((wifi_countrycode_type_t *)&oper_param->countryCode, row->country, sizeof(row->country), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: country conversion failed. countryCode %d\n", __func__, __LINE__, oper_param->countryCode);
        return webconfig_error_translate_to_ovsdb;
    }


    if (hw_mode_conversion((wifi_ieee80211Variant_t *)&oper_param->variant, row->hw_mode, sizeof(row->hw_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Hw mode conversion failed. variant 0x%x\n", __func__, __LINE__, oper_param->variant);
        return webconfig_error_translate_to_ovsdb;
    }


    if (ht_mode_conversion((wifi_channelBandwidth_t *)&oper_param->channelWidth, row->ht_mode, sizeof(row->ht_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Ht mode conversion failed. channelWidth 0x%x\n", __func__, __LINE__, oper_param->channelWidth);
        return webconfig_error_translate_to_ovsdb;
    }

    if (channel_mode_conversion((BOOL *)&oper_param->autoChannelEnabled, row->channel_mode, sizeof(row->channel_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: channel mode conversion failed. autoChannelEnabled %d\n", __func__, __LINE__, oper_param->autoChannelEnabled);
        return webconfig_error_translate_to_ovsdb;
    }

    if (get_radio_if_hw_type(row->hw_type, sizeof(row->hw_type)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get hw type failed\n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: radio config schema is NULL\n", __func__, __LINE__);
        return NULL;
    }

    for (i = 0; i<num_radios; i++) {
        if (table[i] == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: radio config schema is NULL\n", __func__, __LINE__);
            return NULL;
        }

        if (convert_ifname_to_radio_index(wifi_prop, (char *)table[i]->if_name, &schema_radio_index) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: radio if name to schema radio index failed for %s\n", __func__, __LINE__, table[i]->if_name);
            return NULL;
        }

        if (schema_radio_index == radio_index) {
            return (struct schema_Wifi_Radio_Config *)table[i];
        }

    }

    return NULL;
}

extern int wifi_hal_get_default_ssid(char *ssid, int vap_index);
extern int wifi_hal_get_default_keypassphrase(char *password, int vap_index);
extern int wifi_hal_get_default_wps_pin(char *pin);

webconfig_error_t   translate_radio_object_to_ovsdb_radio_config_for_mesh_sta(webconfig_subdoc_data_t *data)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Enter\n", __func__, __LINE__);

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
    wifi_hal_capability_t *hal_cap;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    table = proto->radio_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    for (i= 0; i < decoded_params->num_radios; i++) {

        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        if (radio_index == -1) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: invalid radio_index for  %s\n",
                    __func__, __LINE__, decoded_params->radios[i].name);
            return webconfig_error_translate_to_ovsdb;
        }

        oper_param = &decoded_params->radios[radio_index].oper;

        row = (struct schema_Wifi_Radio_Config *)table[radio_index];

        if (translate_radio_obj_to_ovsdb(oper_param, row, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate radio_obj to ovsdb %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_ovsdb;
        }
        presence_mask |= (1 << radio_index);

    }

    if (presence_mask != pow(2, decoded_params->num_radios) - 1) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_invalid_subdoc;
    }

    row_count = (unsigned int *)&proto->radio_config_row_count;
    *row_count = decoded_params->num_radios;

    hal_cap = &decoded_params->hal_cap;
    memcpy(&webconfig_ovsdb_data.u.decoded.hal_cap, hal_cap, sizeof(wifi_hal_capability_t));

    translator_ovsdb_init(data);

    for (i= 0; i < decoded_params->num_radios; i++) {
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        oper_param = &decoded_params->radios[radio_index].oper;
        memcpy(&webconfig_ovsdb_data.u.decoded.radios[radio_index].oper, oper_param, sizeof(wifi_radio_operationParam_t));
        strncpy(webconfig_ovsdb_data.u.decoded.radios[radio_index].name, decoded_params->radios[radio_index].name,  sizeof(webconfig_ovsdb_data.u.decoded.radios[radio_index].name));
        webconfig_ovsdb_data.u.decoded.radios[radio_index].vaps.vap_map.num_vaps = decoded_params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
    }

    return webconfig_error_none;
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
    wifi_hal_capability_t *hal_cap;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    table = proto->radio_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    for (i= 0; i < decoded_params->num_radios; i++) {

        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        if (radio_index == -1) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: invalid radio_index for  %s\n",
                    __func__, __LINE__, decoded_params->radios[i].name);
            return webconfig_error_translate_to_ovsdb;
        }

        oper_param = &decoded_params->radios[radio_index].oper;

        row = (struct schema_Wifi_Radio_Config *)table[radio_index];

        if (translate_radio_obj_to_ovsdb(oper_param, row, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate radio_obj to ovsdb %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_ovsdb;
        }
        presence_mask |= (1 << radio_index);

    }

    if (presence_mask != pow(2, decoded_params->num_radios) - 1) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_invalid_subdoc;
    }

    row_count = (unsigned int *)&proto->radio_config_row_count;
    *row_count = decoded_params->num_radios;

    hal_cap = &decoded_params->hal_cap;
    memcpy(&webconfig_ovsdb_data.u.decoded.hal_cap, hal_cap, sizeof(wifi_hal_capability_t));

     translator_ovsdb_init(data);

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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *)data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    table = proto->radio_state;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    if ((decoded_params->num_radios < MIN_NUM_RADIOS) || (decoded_params->num_radios > MAX_NUM_RADIOS )){
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    for (i= 0; i < decoded_params->num_radios; i++) {
        radio_index = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        if (radio_index == -1) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: invalid radio_index for  %s\n",
                    __func__, __LINE__, decoded_params->radios[i].name);
            return webconfig_error_translate_to_ovsdb;
        }

        oper_param = &decoded_params->radios[radio_index].oper;

        row = (struct schema_Wifi_Radio_State *)table[radio_index];

        if (translate_radio_obj_to_ovsdb_radio_state(oper_param, row, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate radio_obj to ovsdb state %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_ovsdb;
        }

        presence_mask |= (1 << radio_index);
    }

    if (presence_mask != pow(2, decoded_params->num_radios) - 1) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present : %x\n", __func__, __LINE__, presence_mask);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (macfilter_conversion(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), (wifi_vap_info_t *)vap, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Mac filter conversion failed. mac_filter_enable %d mac_filter_mode %d\n", __func__, __LINE__, vap->u.bss_info.mac_filter_enable, vap->u.bss_info.mac_filter_mode);
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
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. security mode 0x%x encr 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode, vap->u.bss_info.security.encr);
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
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: enterprise mode is not supported. security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
            return webconfig_error_translate_to_ovsdb;
        }
        vap_row->wpa_key_mgmt_len = 1;
        if ((key_mgmt_conversion((wifi_security_modes_t *)&vap->u.bss_info.security.mode, vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), ENUM_TO_STRING)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
            return webconfig_error_translate_to_ovsdb;
        }

        vap_row->wpa = true;

        if ((strlen(vap->u.bss_info.security.u.key.key) < MIN_PWD_LEN) || (strlen(vap->u.bss_info.security.u.key.key) > MAX_PWD_LEN)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length %d\n", __func__, __LINE__, strlen(vap->u.bss_info.security.u.key.key));
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    radius = (wifi_radius_settings_t *)&vap->u.bss_info.security.u.radius;

    if (radius == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: radius is NULL\n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (macfilter_conversion(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), (wifi_vap_info_t *)vap, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Mac filter conversion failed. mac_filter_enable %d mac_filter_mode %d\n", __func__, __LINE__, vap->u.bss_info.mac_filter_enable, vap->u.bss_info.mac_filter_mode);
        return webconfig_error_translate_to_ovsdb;
    }

    vap_row->group_rekey = vap->u.bss_info.security.rekey_interval;
    vap_row->wpa = true;

    if (translate_vap_info_to_ovsdb_radius_settings(vap, vap_row) !=  webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius settings from vap to ovsdb failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    int  index = 0;
    char str_mode[128] = {0};
    char str_encryp[128] = {0};

    memset(str_mode, 0, sizeof(str_mode));
    memset(str_encryp, 0, sizeof(str_encryp));
    if ((key_mgmt_conversion_legacy((wifi_security_modes_t *)&vap->u.bss_info.security.mode, (wifi_encryption_method_t *)&vap->u.bss_info.security.encr, str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp), ENUM_TO_STRING)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. security mode 0x%x encr 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode, vap->u.bss_info.security.encr);
        return webconfig_error_translate_to_ovsdb;
    }

    set_translator_config_security_key_value(vap_row, &index, "encryption", str_encryp);
    set_translator_config_security_key_value(vap_row, &index, "mode", str_mode);


#else
    if ((vap->u.bss_info.security.mode != wifi_security_mode_wpa2_enterprise) || (vap->u.bss_info.security.mode != wifi_security_mode_wpa3_enterprise)
            || (vap->u.bss_info.security.mode != wifi_security_mode_wpa_wpa2_enterprise) || (vap->u.bss_info.security.mode != wifi_security_mode_wpa_enterprise)){
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: enterprise mode is not supported. security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
        return webconfig_error_translate_to_ovsdb;
    }
    vap_row->wpa_key_mgmt_len = 1;
    if ((key_mgmt_conversion((wifi_security_modes_t *)&vap->u.bss_info.security.mode, vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), ENUM_TO_STRING)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
        return webconfig_error_translate_to_ovsdb;
    }

    vap_row->wpa = true;
#endif

    return webconfig_error_none;
}

webconfig_error_t translate_vap_info_to_ovsdb_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_ifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed. vap_index\n", __func__, __LINE__, vap->vap_index);
        return webconfig_error_translate_to_ovsdb;
    }


    if (ssid_broadcast_conversion(vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), (BOOL *)&vap->u.bss_info.showSsid, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: ssid broadbcast conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap_mode_conversion((wifi_vap_mode_t *)&vap->vap_mode, vap_row->mode, ARRAY_SIZE(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed. vap mode %d\n", __func__, __LINE__, vap->vap_mode);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_ifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed. vap_index\n", __func__, __LINE__, vap->vap_index);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap_mode_conversion((wifi_vap_mode_t *)&vap->vap_mode, vap_row->mode, ARRAY_SIZE(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed. vap mode %d\n", __func__, __LINE__, vap->vap_mode);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode is not station moode\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    snprintf(vap_row->parent, sizeof(vap_row->parent), "%02X:%02X:%02X:%02X:%02X:%02X",
                                                vap->u.sta_info.bssid[0], vap->u.sta_info.bssid[1],
                                                vap->u.sta_info.bssid[2], vap->u.sta_info.bssid[3],
                                                vap->u.sta_info.bssid[4], vap->u.sta_info.bssid[5]);

    snprintf(vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), "%s", "disabled");
    snprintf(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), "%s", "none");
    snprintf(vap_row->ssid, sizeof(vap_row->ssid), "%s", vap->u.sta_info.ssid);
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: ssid : %s Parent : %s\n", __func__, __LINE__, vap_row->ssid, vap_row->parent);

    strncpy(vap_row->bridge, vap->bridge_name, sizeof(vap_row->bridge));

    if (vap->u.sta_info.conn_status == wifi_connection_status_connected) {
        vap_row->enabled = true;
    } else {
        vap_row->enabled = false;
    }

    vap_row->vlan_id = iface_map->vlan_id;

    return webconfig_error_none;
}

webconfig_error_t translate_private_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_iot_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_hotspot_open_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_no_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for no security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_lnf_psk_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_secure_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_enterprise_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_lnf_radius_secure_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_enterprise_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_mesh_backhaul_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_sta_vap_info_to_ovsdb_config_personal_sec(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_Config *vap_row)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }
#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    int sec_index = 0;
    if (vap->u.sta_info.security.mode != wifi_security_mode_none) {
        char str_mode[128] = {0};
        char str_encryp[128] = {0};

        memset(str_mode, 0, sizeof(str_mode));
        memset(str_encryp, 0, sizeof(str_encryp));
        if ((key_mgmt_conversion_legacy((wifi_security_modes_t *)&vap->u.sta_info.security.mode, (wifi_encryption_method_t *)&vap->u.sta_info.security.encr, str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp), ENUM_TO_STRING)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. security mode 0x%x encr 0x%x\n", __func__, __LINE__, vap->u.sta_info.security.mode, vap->u.sta_info.security.encr);
            return webconfig_error_translate_to_ovsdb;
        }

        set_translator_config_security_key_value(vap_row, &sec_index, "encryption", str_encryp);
        set_translator_config_security_key_value(vap_row, &sec_index, "mode", str_mode);
        set_translator_config_security_key_value(vap_row, &sec_index, "key", vap->u.sta_info.security.u.key.key);
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: encr : %s mode : %s key : %s\n", __func__, __LINE__, str_encryp, str_mode, vap->u.sta_info.security.u.key.key);


    } else {
        set_translator_config_security_key_value(vap_row, &sec_index, "encryption", "OPEN");
    }
#else
    if (vap->u.sta_info.security.mode == wifi_security_mode_none) {
        vap_row->wpa = false;
    } else {
        if ((vap->u.sta_info.security.mode == wifi_security_mode_wpa2_enterprise) || (vap->u.sta_info.security.mode == wifi_security_mode_wpa3_enterprise)
                || (vap->u.sta_info.security.mode == wifi_security_mode_wpa_wpa2_enterprise) || (vap->u.sta_info.security.mode == wifi_security_mode_wpa_enterprise)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: enterprise mode is not supported. security mode 0x%x\n", __func__, __LINE__, vap->u.sta_info.security.mode);
            return webconfig_error_translate_to_ovsdb;
        }
        vap_row->wpa_key_mgmt_len = 1;
        if ((key_mgmt_conversion((wifi_security_modes_t *)&vap->u.sta_info.security.mode, vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), ENUM_TO_STRING)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. security mode 0x%x\n", __func__, __LINE__, vap->u.sta_info.security.mode);
            return webconfig_error_translate_to_ovsdb;
        }

        vap_row->wpa = true;

        if ((strlen(vap->u.sta_info.security.u.key.key) < MIN_PWD_LEN) || (strlen(vap->u.sta_info.security.u.key.key) > MAX_PWD_LEN)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length %d\n", __func__, __LINE__, strlen(vap->u.sta_info.security.u.key.key));
            return webconfig_error_translate_to_ovsdb;
        }

        snprintf(vap_row->wpa_psks[0], sizeof(vap_row->wpa_psks[0]), "%s", vap->u.sta_info.security.u.key.key);
        vap_row->wpa_psks_len = 1;
    }
#endif

    return webconfig_error_none;
}

webconfig_error_t translate_mesh_sta_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_sta_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_sta_vap_info_to_ovsdb_config_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for security\n", __func__, __LINE__);
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
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    //  struct schema_Wifi_Credential_Config **cred_table;
    //   struct schema_Wifi_Credential_Config  *cred_row;

    unsigned int presence_mask = 0;
    unsigned int *row_count = NULL;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    unsigned int dml_vap_mask = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    dml_vap_mask = create_vap_mask(wifi_prop, 8, VAP_PREFIX_PRIVATE, VAP_PREFIX_IOT, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE, \
                                                 VAP_PREFIX_MESH_BACKHAUL, VAP_PREFIX_MESH_STA, VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS);

    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    hal_cap = &decoded_params->hal_cap;
    memcpy(&webconfig_ovsdb_data.u.decoded.hal_cap, hal_cap, sizeof(wifi_hal_capability_t));

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
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[vap->vap_index];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_iot_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_hotspot_open(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_hotspot_open_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_lnf_psk_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_hotspot_secure(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_hotspot_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);

            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh backhaul to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: for %d\n", __func__, __LINE__, vap->vap_index);
                if (vap->u.sta_info.conn_status == wifi_connection_status_connected) {
                    if (translate_mesh_sta_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                        return webconfig_error_translate_to_ovsdb;
                    }
                } else {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: connection status is %d for vap_index %d\n", __func__, __LINE__, vap->u.sta_info.conn_status, vap->vap_index);
                }
                presence_mask |= (1 << vap->vap_index);
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if ((is_vap_mesh_sta(wifi_prop, vap->vap_index) != TRUE) && (is_vap_hotspot(wifi_prop, vap->vap_index) != TRUE) ) {
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
            }
        }
    }

    if (presence_mask != dml_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    row_count = (unsigned int *)&proto->vif_config_row_count;
    *row_count = get_list_of_vap_names(wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
            8, VAP_PREFIX_PRIVATE, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE, \
            VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS, VAP_PREFIX_MESH_BACKHAUL, \
            VAP_PREFIX_MESH_STA, VAP_PREFIX_IOT);;

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

const char* security_state_find_by_key(
        const struct  schema_Wifi_VIF_State *vstate,
        char *key)
{
    int  i;
    for (i = 0; i < vstate->security_len; i++) {
        if (!strcmp(vstate->security_keys[i], key)) {
            return vstate->security[i];
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_ifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed. vap index %d\n", __func__, __LINE__, vap->vap_index);
        return webconfig_error_translate_to_ovsdb;
    }


    if (ssid_broadcast_conversion(vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), (BOOL *)&vap->u.bss_info.showSsid, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: ssid broadbcast conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap_mode_conversion((wifi_vap_mode_t *)&vap->vap_mode, vap_row->mode, ARRAY_SIZE(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed. vap mode %d\n", __func__, __LINE__, vap->vap_mode);
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
    memset(vap_row->parent, 0, sizeof(vap_row->parent));

    if(min_hw_mode_conversion(vap->vap_index, "", vap_row->min_hw_mode, "STATE") != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: No min_hw_mode_conversion warning for %d\n", __func__, __LINE__, vap->vap_index);
    }
    if(vif_radio_idx_conversion(vap->vap_index, NULL, (int *)&vap_row->vif_radio_idx, "STATE") != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: No vif_radio_idx_conversion warning for %d\n", __func__, __LINE__, vap->vap_index);
    }
    return webconfig_error_none;
}

webconfig_error_t translate_vap_info_to_vif_state_radius_settings(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_State *vap_row)
{
    wifi_radius_settings_t *radius;
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    radius = (wifi_radius_settings_t *)&vap->u.bss_info.security.u.radius;

    if (radius == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: radius is NULL\n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (macfilter_conversion(vap_row->mac_list_type, sizeof(vap_row->mac_list_type), (wifi_vap_info_t *)vap, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Mac filter conversion failed\n", __func__, __LINE__);
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
#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    int  index = 0;
    char str_mode[128] = {0};
    char str_encryp[128] = {0};

    memset(str_mode, 0, sizeof(str_mode));
    memset(str_encryp, 0, sizeof(str_encryp));
    if ((key_mgmt_conversion_legacy((wifi_security_modes_t *)&vap->u.bss_info.security.mode, (wifi_encryption_method_t *)&vap->u.bss_info.security.encr, str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp), ENUM_TO_STRING)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    set_translator_state_security_key_value(vap_row, &index, "encryption", str_encryp);
    set_translator_state_security_key_value(vap_row, &index, "mode", str_mode);

#else
    if ((vap->u.bss_info.security.mode != wifi_security_mode_wpa2_enterprise) || (vap->u.bss_info.security.mode != wifi_security_mode_wpa3_enterprise)
            || (vap->u.bss_info.security.mode != wifi_security_mode_wpa_wpa2_enterprise) || (vap->u.bss_info.security.mode != wifi_security_mode_wpa_enterprise)){
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: enterprise mode is not Present\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }
    vap_row->wpa_key_mgmt_len = 1;
    if ((key_mgmt_conversion((wifi_security_modes_t *)&vap->u.bss_info.security.mode, vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), ENUM_TO_STRING)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

#endif

    return webconfig_error_none;
}

webconfig_error_t  translate_sta_vap_info_to_vif_state_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if ((vap == NULL) || (vap_row == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_ifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap_mode_conversion((wifi_vap_mode_t *)&vap->vap_mode, vap_row->mode, ARRAY_SIZE(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode is not station moode\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    strncpy(vap_row->ssid, vap->u.sta_info.ssid, sizeof(vap_row->ssid));
    strncpy(vap_row->bridge, vap->bridge_name, sizeof(vap_row->bridge));

    if (vap->u.sta_info.conn_status == wifi_connection_status_connected) {
        vap_row->enabled = true;
    } else {
        vap_row->enabled = false;
    }

    snprintf(vap_row->mac, sizeof(vap_row->mac), "%02X:%02X:%02X:%02X:%02X:%02X", vap->u.sta_info.mac[0], vap->u.sta_info.mac[1],
            vap->u.sta_info.mac[2], vap->u.sta_info.mac[3],
            vap->u.sta_info.mac[4], vap->u.sta_info.mac[5]);
    snprintf(vap_row->parent, sizeof(vap_row->parent), "%02X:%02X:%02X:%02X:%02X:%02X", vap->u.sta_info.bssid[0], vap->u.sta_info.bssid[1],
            vap->u.sta_info.bssid[2], vap->u.sta_info.bssid[3],
            vap->u.sta_info.bssid[4], vap->u.sta_info.bssid[5]);

    wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: vap_index : %d Parent : %s\n", __func__, __LINE__, vap->vap_index, vap_row->parent);

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


webconfig_error_t translate_sta_vap_info_to_ovsdb_state_personal_sec(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_State *vap_row)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }
#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    int sec_index = 0;
    if (vap->u.sta_info.security.mode != wifi_security_mode_none) {
        char str_mode[128] = {0};
        char str_encryp[128] = {0};

        memset(str_mode, 0, sizeof(str_mode));
        memset(str_encryp, 0, sizeof(str_encryp));
        if ((key_mgmt_conversion_legacy((wifi_security_modes_t *)&vap->u.sta_info.security.mode, (wifi_encryption_method_t *)&vap->u.sta_info.security.encr, 
                        str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp), ENUM_TO_STRING)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }

        set_translator_state_security_key_value(vap_row, &sec_index, "encryption", str_encryp);
        set_translator_state_security_key_value(vap_row, &sec_index, "mode", str_mode);
        set_translator_state_security_key_value(vap_row, &sec_index, "key", vap->u.sta_info.security.u.key.key);

    } else {
        set_translator_state_security_key_value(vap_row, &sec_index, "encryption", "OPEN");
    }
#else
    if (vap->u.sta_info.security.mode == wifi_security_mode_none) {
        vap_row->wpa = false;
    } else {
        if ((vap->u.sta_info.security.mode == wifi_security_mode_wpa2_enterprise) || (vap->u.sta_info.security.mode == wifi_security_mode_wpa3_enterprise)
                || (vap->u.sta_info.security.mode == wifi_security_mode_wpa_wpa2_enterprise) || (vap->u.sta_info.security.mode == wifi_security_mode_wpa_enterprise)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: enterprise mode is not supported\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }
        vap_row->wpa_key_mgmt_len = 1;
        if ((key_mgmt_conversion((wifi_security_modes_t *)&vap->u.sta_info.security.mode, vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), ENUM_TO_STRING)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }

        vap_row->wpa = true;

        if ((strlen(vap->u.sta_info.security.u.key.key) < MIN_PWD_LEN) || (strlen(vap->u.sta_info.security.u.key.key) > MAX_PWD_LEN)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length\n", __func__, __LINE__);
            return webconfig_error_translate_to_ovsdb;
        }

        snprintf(vap_row->wpa_psks[0], sizeof(vap_row->wpa_psks[0]), "%s", vap->u.sta_info.security.u.key.key);
        vap_row->wpa_psks_len = 1;
    }
#endif

    return webconfig_error_none;
}

webconfig_error_t translate_mesh_sta_vap_info_to_vif_state(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_sta_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_sta_vap_info_to_ovsdb_state_personal_sec(vap, vap_row) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }
    return webconfig_error_none;
}

webconfig_error_t translate_vap_object_to_ovsdb_associated_clients(const rdk_wifi_vap_info_t *rdk_vap_info, const struct schema_Wifi_Associated_Clients **clients_table, unsigned int *client_count, wifi_platform_property_t *wifi_prop)
{
    //	int count = 0, i = 0;
    assoc_dev_data_t *assoc_dev_data = NULL;
    struct schema_Wifi_Associated_Clients *client_row;
    unsigned int associated_client_count = 0;
    if ((rdk_vap_info == NULL) || (clients_table == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    associated_client_count = *client_count;
    if (rdk_vap_info->associated_devices_map != NULL) {
        assoc_dev_data = hash_map_get_first(rdk_vap_info->associated_devices_map);

        while (assoc_dev_data != NULL) {
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
            assoc_dev_data = hash_map_get_next(rdk_vap_info->associated_devices_map, assoc_dev_data);
        }
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
#if 0
    unsigned int assoc_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    assoc_vap_mask = create_vap_mask(wifi_prop, 8, VAP_PREFIX_PRIVATE, VAP_PREFIX_IOT, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE, \
                                                   VAP_PREFIX_MESH_BACKHAUL, VAP_PREFIX_MESH_STA, VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS);
#endif

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

#if 0
    //TBD
    if (presence_mask != assoc_vap_mask) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }
#endif
    row_count = (unsigned int *)&proto->assoc_clients_row_count;
    *row_count = client_count;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: client_count:%d \r\n", __func__, __LINE__, client_count);

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
    //  struct schema_Wifi_Credential_Config **cred_table;
    //   struct schema_Wifi_Credential_Config  *cred_row;

    unsigned int presence_mask = 0;
    unsigned int *row_count = NULL;
    unsigned int dml_vap_mask = 0;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO];
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    dml_vap_mask = create_vap_mask(wifi_prop, 8, VAP_PREFIX_PRIVATE, VAP_PREFIX_IOT, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE, \
                                                 VAP_PREFIX_MESH_BACKHAUL, VAP_PREFIX_MESH_STA, VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS);


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

    if (presence_mask != dml_vap_mask) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }
    row_count = (unsigned int *)&proto->vif_state_row_count;
    *row_count = get_list_of_vap_names(wifi_prop, vap_names, MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO, \
            8, VAP_PREFIX_PRIVATE, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE, \
            VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS, VAP_PREFIX_MESH_BACKHAUL, \
            VAP_PREFIX_MESH_STA, VAP_PREFIX_IOT);

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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Mac filter conversion failed. mac_filter_enable %d mac_filter_mode %d\n", __func__, __LINE__, vap->u.bss_info.mac_filter_enable, vap->u.bss_info.mac_filter_mode);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_radius_settings(vap_row, vap) !=  webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius settings from ovsdb to vap_info failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    const char *str_encryp;
    const char *str_mode;

    str_encryp = security_config_find_by_key(vap_row, "encryption");
    if (str_encryp == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: encryption is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    str_mode = security_config_find_by_key(vap_row, "mode");
    if (str_mode == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: mode is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if ((key_mgmt_conversion_legacy(&vap->u.bss_info.security.mode, &vap->u.bss_info.security.encr, (char *)str_mode, strlen(str_mode)+1, (char *)str_encryp, strlen(str_encryp)+1, STRING_TO_ENUM)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. str_mode '%s'\n", __func__, __LINE__, str_mode);
        return webconfig_error_translate_from_ovsdb;
    }

#else
    if (vap_row->wpa == false) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Open security is not supported\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    } else {
        if (vap_row->wpa_key_mgmt_len == 0)  {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: wpa_key_mgmt_len is 0\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((key_mgmt_conversion(&vap->u.bss_info.security.mode, (char *)vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), STRING_TO_ENUM)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__, (vap_row->wpa_key_mgmt[0]) ? vap_row->wpa_key_mgmt[0]: "NULL");
            return webconfig_error_translate_from_ovsdb;
        }

    }
#endif
    if ((vap->u.bss_info.security.mode != wifi_security_mode_wpa2_enterprise) && (vap->u.bss_info.security.mode != wifi_security_mode_wpa_wpa2_enterprise)
            && (vap->u.bss_info.security.mode != wifi_security_mode_wpa3_enterprise) && (vap->u.bss_info.security.mode != wifi_security_mode_wpa_enterprise)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Security mode is not enterprise. security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
        return webconfig_error_translate_from_ovsdb;
    }

    vap->u.bss_info.security.rekey_interval = vap_row->group_rekey;
    return webconfig_error_none;
}


webconfig_error_t translate_ovsdb_to_vap_info_no_sec(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    macfilter_conversion("none", strlen("none"), vap, STRING_TO_ENUM);

    if (vap_row->wpa == false) {
        vap->u.bss_info.security.mode = wifi_security_mode_none;
    } else {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid security mode\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    vap->u.bss_info.security.rekey_interval = vap_row->group_rekey;
    return webconfig_error_none;
}



webconfig_error_t translate_ovsdb_to_vap_info_common(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }


    if (vap_mode_conversion(&vap->vap_mode, (char *)vap_row->mode, ARRAY_SIZE(vap_row->mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed. mode '%s'\n", __func__, __LINE__, (vap_row->mode) ? vap_row->mode : "NULL");
        return webconfig_error_translate_from_ovsdb;
    }

    if (ssid_broadcast_conversion((char *)vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), &vap->u.bss_info.showSsid, STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: ssid broadcast conversion failed. ssid_broadcast '%s'\n", __func__, __LINE__, (vap_row->ssid_broadcast) ? vap_row->ssid_broadcast : "NULL");
        return webconfig_error_translate_from_ovsdb;
    }

    vap->u.bss_info.enabled = vap_row->enabled;

    if  (is_ssid_name_valid((char *)vap_row->ssid) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid ssid name. ssid '%s'\n", __func__, __LINE__, vap_row->ssid);
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
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vapIndex : %d min_hw_mode %s\n", __func__, __LINE__, vap->vap_index, vap_row->min_hw_mode);
    min_hw_mode_conversion(vap->vap_index, (char *)vap_row->min_hw_mode, "", "CONFIG");
    vif_radio_idx_conversion(vap->vap_index, (int *)&vap_row->vif_radio_idx, NULL, "CONFIG");

    return webconfig_error_none;
}

webconfig_error_t translate_private_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_personal_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_iot_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_personal_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_open_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_no_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for no security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_secure_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_enterprise_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_lnf_radius_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_enterprise_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_lnf_psk_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_personal_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_mesh_backhaul_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_personal_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_ovsdb_to_sta_vap_info_common(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (vap_mode_conversion(&vap->vap_mode, (char *)vap_row->mode, ARRAY_SIZE(vap_row->mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed. mode '%s'\n", __func__, __LINE__, (vap_row->mode) ? vap_row->mode : "NULL");
        return webconfig_error_translate_from_ovsdb;
    }

    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode is not station mode\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    vap->u.sta_info.enabled = vap_row->enabled;
    strncpy(vap->bridge_name, vap_row->bridge, sizeof(vap->bridge_name));
    str_to_mac_bytes((char *)vap_row->parent, vap->u.sta_info.bssid);
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Parent : %s bssid : %02x%02x%02x%02x%02x%02x\n", __func__, __LINE__, vap_row->parent,
            vap->u.sta_info.bssid[0], vap->u.sta_info.bssid[1],
            vap->u.sta_info.bssid[2], vap->u.sta_info.bssid[3],
            vap->u.sta_info.bssid[4], vap->u.sta_info.bssid[5]);


    return webconfig_error_none;
}


webconfig_error_t translate_ovsdb_config_to_vap_info_personal_sec(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

#ifdef CONFIG_RDK_LEGACY_SECURITY_SCHEMA
    const char *str_encryp;
    const char *str_mode;
    const char *val;

    str_encryp = security_config_find_by_key(vap_row, "encryption");
    if (str_encryp == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: encryption is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (!strcmp(str_encryp, "OPEN")) {
        vap->u.sta_info.security.mode = wifi_security_mode_none;
        vap->u.sta_info.security.encr = wifi_encryption_none;
    } else {
        str_mode = security_config_find_by_key(vap_row, "mode");
        if (str_mode == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: mode is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((key_mgmt_conversion_legacy(&vap->u.sta_info.security.mode, &vap->u.sta_info.security.encr, (char *)str_mode, strlen(str_mode)+1, (char *)str_encryp, strlen(str_encryp)+1, STRING_TO_ENUM)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. str_mode '%s'\n", __func__, __LINE__, str_mode);
            return webconfig_error_translate_from_ovsdb;
        }

        val = security_config_find_by_key(vap_row, "key");
        if (val == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: mode is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((strlen(val) < MIN_PWD_LEN) || (strlen(val) > MAX_PWD_LEN)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length %d\n", __func__, __LINE__, strlen(val));
            return webconfig_error_translate_from_ovsdb;
        }

        snprintf(vap->u.sta_info.security.u.key.key, sizeof(vap->u.sta_info.security.u.key.key), "%s", val);
    }

#else
    if (vap_row->wpa == false) {
        vap->u.sta_info.security.mode = wifi_security_mode_none;
    } else {
        if (vap_row->wpa_key_mgmt_len == 0)  {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: wpa_key_mgmt_len is 0\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((key_mgmt_conversion(&vap->u.sta_info.security.mode, (char *)vap_row->wpa_key_mgmt[0], sizeof(vap_row->wpa_key_mgmt[0]), STRING_TO_ENUM)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__, 
                (vap_row->wpa_key_mgmt[0]) ? vap_row->wpa_key_mgmt[0]: "NULL");
            return webconfig_error_translate_from_ovsdb;
        }

        if ((vap->u.sta_info.security.mode == wifi_security_mode_wpa2_enterprise) || (vap->u.sta_info.security.mode == wifi_security_mode_wpa3_enterprise) ||
                (vap->u.sta_info.security.mode == wifi_security_mode_wpa_wpa2_enterprise) || (vap->u.sta_info.security.mode == wifi_security_mode_wpa_enterprise)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: enterprise mode is not supported. security mode 0x%x\n", __func__, __LINE__, vap->u.sta_info.security.mode);
            return webconfig_error_translate_from_ovsdb;
        }

        if (vap_row->wpa_psks_len == 0)  {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: wpa_psks_len is 0\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if ((strlen(vap_row->wpa_psks[0]) < MIN_PWD_LEN) || (strlen(vap_row->wpa_psks[0]) > MAX_PWD_LEN)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length %d\n", __func__, __LINE__, vap_row->wpa_psks[0]);
            return webconfig_error_translate_from_ovsdb;
        }

        snprintf(vap->u.sta_info.security.u.key.key, sizeof(vap->u.sta_info.security.u.key.key), "%s", vap_row->wpa_psks[0]);

    }

#endif

    vap->u.sta_info.security.rekey_interval = vap_row->group_rekey;
    return webconfig_error_none;
}

webconfig_error_t translate_mesh_sta_vap_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    if (translate_ovsdb_to_sta_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_config_to_vap_info_personal_sec(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for security\n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;

    if (proto->vif_config_row_count < (MIN_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO) || proto->vif_config_row_count > (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: invalid vif config row count : %x\n", __func__, __LINE__, proto->vif_config_row_count);
        return webconfig_error_translate_to_ovsdb;
    }

    wifi_prop = &decoded_params->hal_cap.wifi_prop;
    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed, if_name '%s'\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n", __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        if (is_vap_private(wifi_prop, vap_index) == TRUE) {
            if (translate_private_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_xhs(wifi_prop, vap_index) == TRUE) {
            if (translate_iot_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_hotspot_open(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_open_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_lnf_psk(wifi_prop, vap_index) == TRUE) {
            if (translate_lnf_psk_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_hotspot_secure(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_secure_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_lnf_radius(wifi_prop, vap_index) == TRUE) {
            if (translate_lnf_radius_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf radius to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_backhaul(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_backhaul_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh backhaul failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_sta(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_sta_vap_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh sta failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }
    }

    if (presence_mask != (pow(2, proto->vif_config_row_count) - 1)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;

    if (proto->vif_config_row_count < (MIN_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO) || proto->vif_config_row_count > (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: invalid vif config row count : %x\n", __func__, __LINE__, proto->vif_config_row_count);
        return webconfig_error_translate_from_ovsdb;
    }

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed, if_name '%s'\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
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
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }
        //Update the Macfilter
        if ((is_vap_hotspot(wifi_prop, vap_index) != TRUE) && (is_vap_mesh_sta(wifi_prop, vap_index) != TRUE)) {
            if (translate_macfilter_from_ovsdb_to_rdk_vap(vap_row, &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index]) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
        }
    }

    if (presence_mask != (pow(2, proto->vif_config_row_count) - 1)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_radio_object_from_ovsdb(const struct schema_Wifi_Radio_Config *row, wifi_radio_operationParam_t *oper_param)
{
    if ((row == NULL) || (oper_param == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    //Update the values of oper_param
    if (freq_band_conversion(&oper_param->band, (char *)row->freq_band, sizeof(row->freq_band), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed. freq_band '%s'\n", __func__, __LINE__, row->freq_band);
        return webconfig_error_translate_from_ovsdb;
    }

    if (country_code_conversion(&oper_param->countryCode, (char *)row->country, sizeof(row->country), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: country conversion failed. country '%s'\n", __func__, __LINE__, row->country);
        return webconfig_error_translate_from_ovsdb;
    }

    //As part of southbound variant will not be updated
    /*
      if (hw_mode_conversion(&oper_param->variant, (char *)row->hw_mode, sizeof(row->hw_mode), STRING_TO_ENUM) != RETURN_OK) {
      wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Hw mode conversion failed\n", __func__, __LINE__);
      return webconfig_error_translate_from_ovsdb;
      }*/

    if (ht_mode_conversion(&oper_param->channelWidth, (char *)row->ht_mode, sizeof(row->ht_mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Ht mode conversion failed. ht_mode '%s'\n", __func__, __LINE__, row->ht_mode);
        return webconfig_error_translate_from_ovsdb;
    }

    if (channel_mode_conversion(&oper_param->autoChannelEnabled, (char *)row->channel_mode, sizeof(row->channel_mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: channel mode conversion failed. channel_mode '%s'\n", __func__, __LINE__, row->channel_mode);
        return webconfig_error_translate_from_ovsdb;
    }

    oper_param->enable = row->enabled;

    if (is_wifi_channel_valid(oper_param->band, row->channel) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d Radio Channel failed. band 0x%x channel %d\n", __func__, __LINE__, oper_param->band, row->channel);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->radio_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    presence_mask = 0;

    if (proto->radio_config_row_count > MAX_NUM_RADIOS || proto->radio_config_row_count < MIN_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    for (i= 0; i < proto->radio_config_row_count; i++) {

        row = (struct schema_Wifi_Radio_Config *)table[i];
        if (row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: row is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }

        //Convert the ifname to radioIndex
        if (convert_ifname_to_radio_index(&decoded_params->hal_cap.wifi_prop, row->if_name, &radio_index) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Conversion of if_name to radio_index failed for '%s'\n", __func__, __LINE__, row->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        oper_param = &decoded_params->radios[radio_index].oper;

        if (translate_radio_object_from_ovsdb(row, oper_param) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate ovsdb to radio_object for %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_from_ovsdb;

        }
        convert_radio_index_to_radio_name(radio_index, decoded_params->radios[radio_index].name);
        presence_mask |= (1 << radio_index);
    }

    if (presence_mask != pow(2, proto->radio_config_row_count) - 1) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present\n", __func__, __LINE__);
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
    unsigned int *row_count = 0;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Enter\n", __func__, __LINE__);

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    table = proto->radio_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    if (decoded_params->num_radios <  MIN_NUM_RADIOS || decoded_params->num_radios > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    row_count = (unsigned int *)&proto->radio_config_row_count;
    *row_count = decoded_params->num_radios;

    for (i= 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        radio_index = convert_radio_name_to_radio_index(radio->name);
        if (radio_index == -1) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: invalid radio_index for  %s\n",
                    __func__, __LINE__, decoded_params->radios[i].name);
            return webconfig_error_translate_to_ovsdb;
        }

        oper_param = &radio->oper;

        //row = get_radio_schema_from_radioindex(radio_index, table, proto->radio_config_row_count, &decoded_params->hal_cap.wifi_prop);
        row = (struct schema_Wifi_Radio_Config *)table[radio_index];

        if (translate_radio_obj_to_ovsdb(oper_param, row, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate radio_obj to ovsdb %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_to_ovsdb;
        }

        presence_mask |= (1 << radio_index);
    }
    if (presence_mask != pow(2, decoded_params->num_radios) - 1) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present %s\n", __func__, __LINE__, presence_mask);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->radio_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    presence_mask = 0;

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: radio_config_row_count %d\n", __func__, __LINE__, proto->radio_config_row_count);
    if (proto->radio_config_row_count <  MIN_NUM_RADIOS || proto->radio_config_row_count > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    for (i= 0; i < proto->radio_config_row_count; i++) {

        row = (struct schema_Wifi_Radio_Config *)table[i];
        if (row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: row is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }

        //Convert the ifname to radioIndex
        if (convert_ifname_to_radio_index(&decoded_params->hal_cap.wifi_prop, row->if_name, &radio_index) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Conversion of if_name to radio_index failed for  '%s'\n", __func__, __LINE__, row->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        radio = &decoded_params->radios[radio_index];

        oper_param = &radio->oper;

        convert_radio_index_to_radio_name(radio_index, radio->name);
        if (translate_radio_object_from_ovsdb(row, oper_param) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to translate ovsdb to radio_object for %d\n", __func__, __LINE__, radio_index);
            return webconfig_error_translate_from_ovsdb;

        }

        presence_mask |= (1 << radio_index);
    }
    if (presence_mask != pow(2, proto->radio_config_row_count) - 1) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present %x\n\n", __func__, __LINE__, presence_mask);
        return webconfig_error_invalid_subdoc;
    }

    return webconfig_error_none;
}

webconfig_error_t   translate_vap_object_to_ovsdb_vif_state(webconfig_subdoc_data_t *data, char *vap_name)
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
    unsigned char count = 0;

    unsigned int presence_mask = 0, private_vap_mask = 0;
    unsigned int *row_count = NULL;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_state;
    if (vif_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;

    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    hal_cap = &decoded_params->hal_cap;
    wifi_prop = &decoded_params->hal_cap.wifi_prop;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        if (radio->vaps.num_vaps !=  MAX_NUM_VAP_PER_RADIO) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of vaps: %x\n", __func__, __LINE__, radio->vaps.num_vaps);
            return webconfig_error_invalid_subdoc;
        }
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            if (strncmp(vap->vap_name, vap_name, strlen(vap_name)) != 0) {
                continue;
            }

            private_vap_mask |= (1 << vap->vap_index);

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            vap_row = (struct schema_Wifi_VIF_State *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: row count:%d ssid:%s\n", __func__, __LINE__, count, vap_row->ssid);
                count++;
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_iot_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_hotspot_open(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_hotspot_open_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_lnf_psk_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_hotspot_secure(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_hotspot_secure_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_secure_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh backhaul to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                count++;
                presence_mask |= (1 << vap->vap_index);
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if ((is_vap_mesh_sta(wifi_prop, vap->vap_index) != TRUE) && (is_vap_hotspot(wifi_prop, vap->vap_index) != TRUE) ) {
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_state(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
            }
        }
    }

    if (presence_mask != private_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }
    row_count = (unsigned int *)&proto->vif_state_row_count;
    *row_count = count;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: row count:%d\n", __func__, __LINE__, count);

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
    unsigned int *row_count = 0;
    unsigned char count = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    private_vap_mask = create_vap_mask(wifi_prop, 1, VAP_PREFIX_PRIVATE);

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s \r\n", __func__, __LINE__, vap->vap_name);
            if (strncmp(vap->vap_name, "private_ssid", strlen("private_ssid")) != 0) {
                continue;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s vap_index:%d\r\n", __func__, __LINE__, vap->vap_name, vap->vap_index);

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
           //vap_row = get_vif_schema_from_vapindex(vap->vap_index, vif_table, proto->vif_config_row_count, wifi_prop);
            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: row count:%d ssid:%s\n", __func__, __LINE__, count, vap_row->ssid);
                count++;
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

        }

    }
    if (presence_mask != private_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    row_count = (unsigned int *)&proto->vif_config_row_count;
    *row_count = count;

    return webconfig_error_none;
}

webconfig_error_t   translate_vap_object_to_ovsdb_vif_config_for_mesh_sta(webconfig_subdoc_data_t *data)
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
    unsigned int *row_count = 0;
    unsigned char count = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    /* create vap mask for mesh sta for all radios */
    mesh_vap_mask = create_vap_mask(wifi_prop, 1,  VAP_PREFIX_MESH_STA);

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            if (strncmp(vap->vap_name, "mesh_sta_", strlen("mesh_sta_")) != 0) {
                continue;
            }

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            //vap_row = get_vif_schema_from_vapindex(vap->vap_index, vif_table, proto->vif_config_row_count, wifi_prop);
            vap_row =  (struct schema_Wifi_VIF_Config *)vif_table[count];

            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta vap to ovsdb failed for %d\n",
                                                        __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                count++;
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: connection status is %d for vap_index %d\n", __func__, __LINE__, vap->u.sta_info.conn_status, vap->vap_index);
                presence_mask  |= (1 << vap->vap_index);
            }
            else {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

        }

    }
    if (presence_mask != mesh_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    row_count = (unsigned int *)&proto->vif_config_row_count;
    *row_count = count;
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: row count:%d\n", __func__, __LINE__, count);

    return webconfig_error_none;
}

webconfig_error_t   translate_vap_object_from_ovsdb_vif_config_for_mesh_sta(webconfig_subdoc_data_t *data)
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    /* create vap mask for mesh and sta */
    mesh_vap_mask = create_vap_mask(wifi_prop, 1, VAP_PREFIX_MESH_STA);

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed %s\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }
        if (is_vap_mesh_sta(wifi_prop, vap_index) == TRUE) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: conn_status:%d\n", __func__, __LINE__, vap->u.sta_info.conn_status);
            if( vap->u.sta_info.conn_status == wifi_connection_status_connected) {
                if (translate_mesh_sta_vap_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh sta failed\n", __func__, __LINE__);
                    return webconfig_error_translate_from_ovsdb;
                }
            }
            presence_mask  |= (1 << vap_index);
        } /*else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
            }*/
    }

    if (presence_mask != mesh_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t   translate_vap_object_to_ovsdb_vif_config_for_mesh_backhaul(webconfig_subdoc_data_t *data)
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
    unsigned int *row_count = 0;
    unsigned char count = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    /* create vap mask for mesh backhaul and mesh sta for all radios */
    mesh_vap_mask = create_vap_mask(wifi_prop, 1, VAP_PREFIX_MESH_BACKHAUL);

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];

            if (strncmp(vap->vap_name, "mesh_backhaul", strlen("mesh_backhaul")) != 0) {
                continue;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s vap_index:%d\r\n", __func__, __LINE__, vap->vap_name, vap->vap_index);

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh backhaul vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
                count++;
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

        }

    }
    if (presence_mask != mesh_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    row_count = (unsigned int *)&proto->vif_config_row_count;
    *row_count = count;

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
    unsigned int *row_count = 0;
    unsigned char count = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
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

            if ((strncmp(vap->vap_name, "mesh_backhaul", strlen("mesh_backhaul")) != 0) &&
                (strncmp(vap->vap_name, "mesh_sta", strlen("mesh_sta")) != 0)) {
                continue;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s vap_index:%d\r\n", __func__, __LINE__, vap->vap_name, vap->vap_index);

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            //vap_row = get_vif_schema_from_vapindex(vap->vap_index, vif_table, proto->vif_config_row_count, wifi_prop);
	    //vap_row = (struct schema_Wifi_VIF_Config *)vif_table[vap->vap_index];
	    vap_row = (struct schema_Wifi_VIF_Config *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh backhaul vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
                count++;
            } else if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (vap->u.sta_info.conn_status == wifi_connection_status_connected) {
                    if (translate_mesh_sta_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                        return webconfig_error_translate_to_ovsdb;
                    }
                    count++;
                } else {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: connection status is %d for vap_index %d\n", __func__, __LINE__, vap->u.sta_info.conn_status, vap->vap_index);
                }
                presence_mask  |= (1 << vap->vap_index);
            }
            else {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

        }

    }
    if (presence_mask != mesh_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    row_count = (unsigned int *)&proto->vif_config_row_count;
    *row_count = count;

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
    unsigned int *row_count = 0;
    unsigned char count = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    home_vap_mask = create_vap_mask(wifi_prop, 1, VAP_PREFIX_IOT);

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            if (strncmp(vap->vap_name, "iot_ssid", strlen("iot_ssid")) != 0) {
                continue;
            }

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            //vap_row = get_vif_schema_from_vapindex(vap->vap_index, vif_table, proto->vif_config_row_count, wifi_prop);
            //vap_row = (struct schema_Wifi_VIF_Config *)vif_table[vap->vap_index];
            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_iot_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
                count++;
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
        }

    }

    if (presence_mask != home_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }

    row_count = (unsigned int *)&proto->vif_config_row_count;
    *row_count = count;

    return webconfig_error_none;
}


webconfig_error_t   translate_vap_object_to_ovsdb_vif_config_for_lnf(webconfig_subdoc_data_t *data)
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
    unsigned int presence_mask = 0, lnf_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    unsigned int *row_count = 0;
    unsigned char count = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    lnf_vap_mask = create_vap_mask(wifi_prop, 2, VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS);

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            if ((strncmp(vap->vap_name, "lnf_psk", strlen("lnf_psk")) != 0) &&
                (strncmp(vap->vap_name, "lnf_radius", strlen("lnf_radius")) != 0)) {
                continue;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s vap_index:%d\r\n", __func__, __LINE__, vap->vap_name, vap->vap_index);

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_psk_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
                count++;
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
        }

    }
    if (presence_mask != lnf_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }
    row_count = (unsigned int *)&proto->vif_config_row_count;
    *row_count = count;

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
    unsigned int *row_count = 0;
    unsigned char count = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_table = proto->vif_config;
    if (vif_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    presence_mask = 0;
    home_vap_mask = create_vap_mask(wifi_prop, 2, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE);
    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            if ((strncmp(vap->vap_name, "hotspot_open", strlen("hotspot_open")) != 0) &&
                (strncmp(vap->vap_name, "hotspot_secure", strlen("hotspot_secure")) != 0)) {
                continue;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s vap_index:%d\r\n", __func__, __LINE__, vap->vap_name, vap->vap_index);

            iface_map = NULL;
            for (k = 0; k < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); k++) {
                if (hal_cap->wifi_prop.interface_map[k].index == vap->vap_index) {
                    iface_map = &(hal_cap->wifi_prop.interface_map[k]);
                    break;
                }
            }
            if (iface_map == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            //get the corresponding row
            //vap_row = get_vif_schema_from_vapindex(vap->vap_index, vif_table, proto->vif_config_row_count, wifi_prop);
            //vap_row = (struct schema_Wifi_VIF_Config *)vif_table[vap->vap_index];
            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (is_vap_hotspot_open(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_hotspot_open_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_hotspot_secure(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_hotspot_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_config(&decoded_params->radios[i].vaps.rdk_vap_array[j], vap_row) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
                count++;
            } else {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid vap_index %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
        }

    }
    if (presence_mask != home_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_to_ovsdb;
    }
    row_count = (unsigned int *)&proto->vif_config_row_count;
    *row_count = count;

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
    wifi_vap_info_t *tempVap;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    private_vap_mask = create_vap_mask(wifi_prop, 1, VAP_PREFIX_PRIVATE);

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: ifname  : %s\n", __func__, __LINE__, table[i]->if_name);
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap_index  : %d\n", __func__, __LINE__, vap_index);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }
        if (is_vap_private(wifi_prop, vap_index) == TRUE) {
            if (strlen(vap->vap_name) == 0) {
                tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
                memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
                wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Copied from defaults for vap_index : %d vap_name : %s\n", __func__, __LINE__, vap_index, vap->vap_name);
            }
            if (translate_private_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        }
    }

    if ((presence_mask != private_vap_mask)) {
        unsigned int missingVapIndexMask =0;
        unsigned int missingVapIndex = 0;
        uint8_t missingRadioIndex = 0, missingVapArrayIndex = 0;
        unsigned int rcount = 0;
        wifi_vap_info_t *tempVap;
        missingVapIndexMask = presence_mask ^ private_vap_mask;
        unsigned int missingVapIndexCount = 0;
        int missingVapIndexArr[MAX_NUM_VAP_PER_RADIO*MAX_NUM_RADIOS] = {0};
        while (missingVapIndexMask) {
            if ((missingVapIndexMask & 0x1) && ((is_vap_private(wifi_prop, missingVapIndex) == TRUE))) {
                missingVapIndexArr[missingVapIndexCount] = missingVapIndex;
                missingVapIndexCount++;
            }

            missingVapIndexMask = missingVapIndexMask>>1;
            if (missingVapIndexMask == 0) {
                break;
            }
            missingVapIndex++;
        }

        for (i = 0; i < missingVapIndexCount; i++) {
            missingVapIndex = missingVapIndexArr[i];
            if (get_vap_and_radio_index_from_vap_instance(wifi_prop, missingVapIndex, &missingRadioIndex, &missingVapArrayIndex) == RETURN_ERR) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_vap_and_radio_index_from_vap_instance failed for %d\n", __func__, __LINE__, missingVapIndex);
                return webconfig_error_translate_from_ovsdb;
            }

            vap = &decoded_params->radios[missingRadioIndex].vaps.vap_map.vap_array[missingVapArrayIndex];
            tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[missingRadioIndex].vaps.vap_map.vap_array[missingVapArrayIndex];

            memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
            for (rcount = 0; rcount < webconfig_ovsdb_default_data.u.decoded.num_radios; rcount++) {
                radio_index = convert_radio_name_to_radio_index(webconfig_ovsdb_default_data.u.decoded.radios[rcount].name);
                decoded_params->radios[radio_index].vaps.vap_map.num_vaps = webconfig_ovsdb_default_data.u.decoded.radios[rcount].vaps.vap_map.num_vaps;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: presence_mask : %x  missingVapIndex : %d missingRadioIndex : %d missingVapArrayIndex : %d vap->vap_index : %d\n",
                    __func__, __LINE__, presence_mask, missingVapIndex, missingRadioIndex, missingVapArrayIndex, vap->vap_index);

            presence_mask  |= (1 << missingVapIndex);
        }

    }

    if (presence_mask != private_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x supported mask : %x\n", __func__, __LINE__, presence_mask, private_vap_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t   translate_vap_object_from_ovsdb_vif_config_for_mesh_backhaul(webconfig_subdoc_data_t *data)
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
    wifi_vap_info_t *tempVap;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    /* create vap mask for mesh backhaul*/
    mesh_vap_mask = create_vap_mask(wifi_prop, 1, VAP_PREFIX_MESH_BACKHAUL);

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed %s\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        if (is_vap_mesh_backhaul(wifi_prop, vap_index) == TRUE) {
            if (strlen(vap->vap_name) == 0) {
                tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
                memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
                wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Copied from defaults for vap_index : %d vap_name : %s\n", __func__, __LINE__, vap_index, vap->vap_name);
            }
            if (translate_mesh_backhaul_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh backhaul failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }

            presence_mask  |= (1 << vap_index);
        } /*else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
            }*/
        if (translate_macfilter_from_ovsdb_to_rdk_vap(vap_row, &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index]) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap_index);
            return webconfig_error_translate_from_ovsdb;
        }
    }

    if ((presence_mask != mesh_vap_mask)) {
        unsigned int missingVapIndexMask =0;
        unsigned int missingVapIndex = 0;
        uint8_t missingRadioIndex = 0, missingVapArrayIndex = 0;
        unsigned int rcount = 0;
        wifi_vap_info_t *tempVap;
        missingVapIndexMask = presence_mask ^ mesh_vap_mask;
        unsigned int missingVapIndexCount = 0;
        int missingVapIndexArr[MAX_NUM_VAP_PER_RADIO*MAX_NUM_RADIOS] = {0};
        while (missingVapIndexMask) {
            if ((missingVapIndexMask & 0x1) && ((is_vap_mesh_backhaul(wifi_prop, missingVapIndex) == TRUE))) {
                missingVapIndexArr[missingVapIndexCount] = missingVapIndex;
                missingVapIndexCount++;
            }

            missingVapIndexMask = missingVapIndexMask>>1;
            if (missingVapIndexMask == 0) {
                break;
            }
            missingVapIndex++;
        }

        for (i = 0; i < missingVapIndexCount; i++) {
            missingVapIndex = missingVapIndexArr[i];
            if (get_vap_and_radio_index_from_vap_instance(wifi_prop, missingVapIndex, &missingRadioIndex, &missingVapArrayIndex) == RETURN_ERR) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_vap_and_radio_index_from_vap_instance failed for %d\n", __func__, __LINE__, missingVapIndex);
                return webconfig_error_translate_from_ovsdb;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: presence_mask : %x  missingVapIndex : %d missingRadioIndex : %d missingVapArrayIndex : %d\n",
                    __func__, __LINE__, presence_mask, missingVapIndex, missingRadioIndex, missingVapArrayIndex);

            vap = &decoded_params->radios[missingRadioIndex].vaps.vap_map.vap_array[missingVapArrayIndex];
            tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[missingRadioIndex].vaps.vap_map.vap_array[missingVapArrayIndex];

            memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
            for (rcount = 0; rcount < webconfig_ovsdb_default_data.u.decoded.num_radios; rcount++) {
                radio_index = convert_radio_name_to_radio_index(webconfig_ovsdb_default_data.u.decoded.radios[rcount].name);
                decoded_params->radios[radio_index].vaps.vap_map.num_vaps = webconfig_ovsdb_default_data.u.decoded.radios[rcount].vaps.vap_map.num_vaps;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: presence_mask : %x  missingVapIndex : %d missingRadioIndex : %d missingVapArrayIndex : %d vap->vap_index : %d\n",
                    __func__, __LINE__, presence_mask, missingVapIndex, missingRadioIndex, missingVapArrayIndex, vap->vap_index);

            presence_mask  |= (1 << missingVapIndex);
        }
    }

    if (presence_mask != mesh_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    mesh_vap_mask = create_vap_mask(wifi_prop, 2, VAP_PREFIX_MESH_STA, VAP_PREFIX_MESH_BACKHAUL);
    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed %s\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }
        if (is_vap_mesh_backhaul(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_backhaul_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh backhaul failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_sta(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_sta_vap_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh sta failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } /*else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
            }*/
        if (is_vap_mesh_sta(wifi_prop, vap_index) != TRUE) {
            if (translate_macfilter_from_ovsdb_to_rdk_vap(vap_row, &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index]) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
        }
    }

    if (presence_mask != mesh_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    home_vap_mask = create_vap_mask(wifi_prop, 1, VAP_PREFIX_IOT);

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }
        if (is_vap_xhs(wifi_prop, vap_index) == TRUE) {
            if (translate_iot_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }

            presence_mask  |= (1 << vap_index);
        }
    }

    if (presence_mask != home_vap_mask) {
        unsigned int missingVapIndexMask =0;
        unsigned int missingVapIndex = 0;
        uint8_t missingRadioIndex = 0, missingVapArrayIndex = 0;
        unsigned int rcount = 0;
        wifi_vap_info_t *tempVap;
        missingVapIndexMask = presence_mask ^ home_vap_mask;
        unsigned int missingVapIndexCount = 0;
        int missingVapIndexArr[MAX_NUM_VAP_PER_RADIO*MAX_NUM_RADIOS] = {0};
        while (missingVapIndexMask) {
            if ((missingVapIndexMask & 0x1) && ((is_vap_xhs(wifi_prop, missingVapIndex) == TRUE))) {
                missingVapIndexArr[missingVapIndexCount] = missingVapIndex;
                missingVapIndexCount++;
            }

            missingVapIndexMask = missingVapIndexMask>>1;
            if (missingVapIndexMask == 0) {
                break;
            }
            missingVapIndex++;
        }

        for (i = 0; i < missingVapIndexCount; i++) {
            missingVapIndex = missingVapIndexArr[i];
            if (get_vap_and_radio_index_from_vap_instance(wifi_prop, missingVapIndex, &missingRadioIndex, &missingVapArrayIndex) == RETURN_ERR) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_vap_and_radio_index_from_vap_instance failed for %d\n", __func__, __LINE__, missingVapIndex);
            return webconfig_error_translate_from_ovsdb;
        }

            vap = &decoded_params->radios[missingRadioIndex].vaps.vap_map.vap_array[missingVapArrayIndex];
            tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[missingRadioIndex].vaps.vap_map.vap_array[missingVapArrayIndex];

            memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
            for (rcount = 0; rcount < webconfig_ovsdb_default_data.u.decoded.num_radios; rcount++) {
                radio_index = convert_radio_name_to_radio_index(webconfig_ovsdb_default_data.u.decoded.radios[rcount].name);
                decoded_params->radios[radio_index].vaps.vap_map.num_vaps = webconfig_ovsdb_default_data.u.decoded.radios[rcount].vaps.vap_map.num_vaps;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: presence_mask : %x  missingVapIndex : %d missingRadioIndex : %d missingVapArrayIndex : %d vap->vap_index : %d\n",
                    __func__, __LINE__, presence_mask, missingVapIndex, missingRadioIndex, missingVapArrayIndex, vap->vap_index);

            presence_mask  |= (1 << missingVapIndex);
        }
    }

    if (presence_mask != home_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t   translate_vap_object_from_ovsdb_vif_config_for_lnf(webconfig_subdoc_data_t *data)
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
    unsigned int presence_mask = 0, lnf_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    wifi_vap_info_t *tempVap;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    lnf_vap_mask = create_vap_mask(wifi_prop, 2, VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS);

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        if (is_vap_lnf_psk(wifi_prop, vap_index) == TRUE) {
            if (strlen(vap->vap_name) == 0) {
                tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
                memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
                wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Copied from defaults for vap_index : %d vap_name : %s\n", __func__, __LINE__, vap_index, vap->vap_name);
            }
            if (translate_lnf_psk_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_lnf_radius(wifi_prop, vap_index) == TRUE) {
            if (strlen(vap->vap_name) == 0) {
                tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
                memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
                wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Copied from defaults for vap_index : %d vap_name : %s\n", __func__, __LINE__, vap_index, vap->vap_name);
            }
            if (translate_lnf_radius_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf radius to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        }
    }
    if (presence_mask != lnf_vap_mask) {
        unsigned int missingVapIndexMask =0;
        unsigned int missingVapIndex = 0;
        uint8_t missingRadioIndex = 0, missingVapArrayIndex = 0;
        unsigned int rcount = 0;
        wifi_vap_info_t *tempVap;
        missingVapIndexMask = presence_mask ^ lnf_vap_mask;
        unsigned int missingVapIndexCount = 0;
        int missingVapIndexArr[MAX_NUM_VAP_PER_RADIO*MAX_NUM_RADIOS] = {0};
        while (missingVapIndexMask) {
            if ((missingVapIndexMask & 0x1) && ((is_vap_lnf_psk(wifi_prop, missingVapIndex) == TRUE) || (is_vap_lnf_radius(wifi_prop, missingVapIndex) == TRUE))) {
                missingVapIndexArr[missingVapIndexCount] = missingVapIndex;
                missingVapIndexCount++;
            }

            missingVapIndexMask = missingVapIndexMask>>1;
            if (missingVapIndexMask == 0) {
                break;
            }
            missingVapIndex++;
        }

        for (i = 0; i < missingVapIndexCount; i++) {
            missingVapIndex = missingVapIndexArr[i];
            if (get_vap_and_radio_index_from_vap_instance(wifi_prop, missingVapIndex, &missingRadioIndex, &missingVapArrayIndex) == RETURN_ERR) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get_vap_and_radio_index_from_vap_instance failed for %d\n", __func__, __LINE__, missingVapIndex);
                return webconfig_error_translate_from_ovsdb;
            }

            vap = &decoded_params->radios[missingRadioIndex].vaps.vap_map.vap_array[missingVapArrayIndex];
            tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[missingRadioIndex].vaps.vap_map.vap_array[missingVapArrayIndex];

            memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
            for (rcount = 0; rcount < webconfig_ovsdb_default_data.u.decoded.num_radios; rcount++) {
                radio_index = convert_radio_name_to_radio_index(webconfig_ovsdb_default_data.u.decoded.radios[rcount].name);
                decoded_params->radios[radio_index].vaps.vap_map.num_vaps = webconfig_ovsdb_default_data.u.decoded.radios[rcount].vaps.vap_map.num_vaps;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: presence_mask : %x  missingVapIndex : %d missingRadioIndex : %d missingVapArrayIndex : %d vap->vap_index : %d\n",
                    __func__, __LINE__, presence_mask, missingVapIndex, missingRadioIndex, missingVapArrayIndex, vap->vap_index);

            presence_mask  |= (1 << missingVapIndex);
        }

    }

    if (presence_mask != lnf_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    presence_mask = 0;
    xfinity_vap_mask = create_vap_mask(wifi_prop, 2, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE);

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if (convert_ifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert ifname to vapname failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the radioindex
        radio_index = convert_vap_name_to_radio_array_index(wifi_prop, vapname);

        //get the vap_array_index
        vap_array_index =  convert_vap_name_to_array_index(wifi_prop, vapname);

        vap_index = convert_vap_name_to_index(wifi_prop, vapname);

        if ((vap_array_index == -1) || (radio_index == -1) || (vap_index == -1)) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid index radio_index %d vap_array_index  %d vap index: %d for vapname : %s\n",
                    __func__, __LINE__, radio_index, vap_array_index, vap_index, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        //get the vap
        vap = &decoded_params->radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        if (vap == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap is NULL for vapname : %s\n", __func__, __LINE__, vapname);
            return webconfig_error_translate_from_ovsdb;
        }

        if (is_vap_hotspot_open(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_open_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_hotspot_secure(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_secure_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }
    }

    if (presence_mask != xfinity_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t  translate_vap_object_from_ovsdb_config_for_null(webconfig_subdoc_data_t *data)
{
    //THIS is Dummy function
    return webconfig_error_none;
}



webconfig_error_t   translate_vap_object_to_ovsdb_vif_config_for_null(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_VIF_Config **vif_config_table;
    const struct schema_Wifi_VIF_State  **vif_state_table;
    const struct schema_Wifi_Associated_Clients **assoc_clients_table;
    //const struct schema_Wifi_Credential_Config **cred_table;
    struct schema_Wifi_VIF_Config *vif_config_row;
    struct schema_Wifi_VIF_State *vif_state_row;
    struct schema_Wifi_Associated_Clients  *assoc_client_row;
    unsigned int i;
    webconfig_subdoc_decoded_data_t *decoded_params;
    wifi_hal_capability_t *hal_cap;
    webconfig_external_ovsdb_t *proto;
    unsigned int vap_index = 0;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_config_table = proto->vif_config;
    if (vif_config_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: config table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vif_state_table = proto->vif_state;
    if (vif_state_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: state table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    assoc_clients_table = proto->assoc_clients;
    if (assoc_clients_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: assoc table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (decoded_params->num_radios > MAX_NUM_RADIOS || decoded_params->num_radios < MIN_NUM_RADIOS) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of radios : %x\n", __func__, __LINE__, decoded_params->num_radios);
        return webconfig_error_invalid_subdoc;
    }

    hal_cap = &decoded_params->hal_cap;
    if (hal_cap == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: hal capability is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    for (i = 0; i < (sizeof(hal_cap->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); i++) {
        vap_index = hal_cap->wifi_prop.interface_map[i].index;

        //get the corresponding config row
        vif_config_row = (struct schema_Wifi_VIF_Config *)vif_config_table[vap_index];
        if (vif_config_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap config schema row for %d\n", __func__, __LINE__, vap_index);
            return webconfig_error_translate_to_ovsdb;
        }

        memset(vif_config_row, 0, sizeof(struct schema_Wifi_VIF_Config));
        snprintf(vif_config_row->if_name, sizeof(vif_config_row->if_name), "%s", hal_cap->wifi_prop.interface_map[i].interface_name);

        //get the corresponding state row
        vif_state_row = (struct schema_Wifi_VIF_State *)vif_state_table[vap_index];
        if (vif_state_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap state schema row for %d\n", __func__, __LINE__, vap_index);
            return webconfig_error_translate_to_ovsdb;
        }

        memset(vif_state_row, 0, sizeof(struct schema_Wifi_VIF_State));
        snprintf(vif_state_row->if_name, sizeof(vif_state_row->if_name), "%s", hal_cap->wifi_prop.interface_map[i].interface_name);

        //get the corresponding associatedclients row
        assoc_client_row = (struct schema_Wifi_Associated_Clients *)assoc_clients_table[vap_index];
        if (assoc_client_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the assoc_clients row for %d\n", __func__, __LINE__, vap_index);
            return webconfig_error_translate_to_ovsdb;
        }

        memset(assoc_client_row, 0, sizeof(struct schema_Wifi_Associated_Clients));
    }
    return webconfig_error_none;
}


webconfig_error_t   translate_to_ovsdb_tables(webconfig_subdoc_type_t type, webconfig_subdoc_data_t *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Input data is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: subdoc_type:%d\n", __func__, __LINE__, type);
    switch (type) {
        case webconfig_subdoc_type_private:
            if (translate_vap_object_to_ovsdb_vif_state(data, "private_ssid") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_private vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_private(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_private vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_home:
            if (translate_vap_object_to_ovsdb_vif_state(data, "iot_ssid") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_home vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_home(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_home vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_xfinity:
            if (translate_vap_object_to_ovsdb_vif_state(data, "hotspot_") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_xfinity vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_xfinity(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_xfinity vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_lnf:
            if (translate_vap_object_to_ovsdb_vif_state(data, "lnf_") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_lnf vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_lnf(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_lnf vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_radio:
            if (translate_radio_object_to_ovsdb_radio_state_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_radio radio state translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_radio_object_to_ovsdb_radio_config_for_radio(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_radio radio_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_mesh:
            if (translate_vap_object_to_ovsdb_vif_state(data, "mesh_") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_mesh(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_mesh_backhaul:
            if (translate_vap_object_to_ovsdb_vif_state(data, "mesh_backhaul") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_backhaul vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_mesh_backhaul(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_backhaul vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_mesh_sta:
            if (translate_radio_object_to_ovsdb_radio_config_for_mesh_sta(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_sta radio_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_mesh_sta(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_sta vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_state(data, "mesh_sta_") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_sta vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_radio_object_to_ovsdb_radio_state_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_sta radio state translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_dml:
            // translate rif, vif tables for all rows
            if (translate_radio_object_to_ovsdb_radio_config_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml radio_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_radio_object_to_ovsdb_radio_state_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml radio state translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_state_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml vap state translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }


            if (free_vap_object_macfilter_entries(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml mac entries free failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

        break;

        case webconfig_subdoc_type_associated_clients:
            if (translate_vap_object_to_ovsdb_associated_clients_for_assoclist(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_associated_clients associated clients translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (free_vap_object_assoc_client_entries(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_associated_clients assoc clients free failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_null:
            if (translate_radio_object_to_ovsdb_radio_config_for_radio(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_null radio_object translation to ovsdb failed for null\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_null(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_null vap object translation to ovsdb failed for null\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
            break;

        default:
        break;

    }
    return webconfig_error_none;
}

webconfig_error_t   translate_from_ovsdb_tables(webconfig_subdoc_type_t type, webconfig_subdoc_data_t *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Input data is NULL\n", __func__, __LINE__);
        return webconfig_error_invalid_subdoc;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: subdoc_type:%d\n", __func__, __LINE__, type);
    switch (type) {
        case webconfig_subdoc_type_private:
            if (translate_vap_object_from_ovsdb_vif_config_for_private(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_private vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_home:
            if (translate_vap_object_from_ovsdb_vif_config_for_home(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_home vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_xfinity:
            if (translate_vap_object_from_ovsdb_vif_config_for_xfinity(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_xfinity vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_lnf:
            if (translate_vap_object_from_ovsdb_vif_config_for_lnf(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_lnf vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_radio:
            if (translate_radio_object_from_ovsdb_radio_config_for_radio(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_radio radio_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_mesh_sta:
            if (translate_vap_object_from_ovsdb_vif_config_for_mesh_sta(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_sta vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_mesh:
            if (translate_vap_object_from_ovsdb_vif_config_for_mesh(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_mesh_backhaul:
            if (translate_vap_object_from_ovsdb_vif_config_for_mesh_backhaul(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_backhaul vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_dml:
            // translate rif, vif tables for all rows
            if (translate_radio_object_from_ovsdb_radio_config_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml radio_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }

            if (translate_vap_object_from_ovsdb_vif_config_for_dml(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_dml vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_mac_filter:
            if (translate_vap_object_from_ovsdb_vif_config_for_macfilter(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mac_filter vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_null:
            if (translate_vap_object_from_ovsdb_config_for_null(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_null vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        default:
        break;

    }
    return webconfig_error_none;
}
