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

#define BLASTER_STATE_LEN    10

static webconfig_subdoc_data_t  webconfig_ovsdb_data;
/* global pointer to webconfig subdoc encoded data to avoid memory loss when passing data to OVSM */
static char *webconfig_ovsdb_raw_data_ptr = NULL;
static webconfig_subdoc_data_t  webconfig_ovsdb_default_data;
//static webconfig_external_ovsdb_t webconfig_ovsdb_external;
const char* security_state_find_by_key(const struct  schema_Wifi_VIF_State *vstate,
        char *key);
const char* security_config_find_by_key(const struct schema_Wifi_VIF_Config *vconf,
        char *key);
webconfig_error_t translate_ovsdb_to_vap_info_radius_settings(const struct
    schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap);

struct ovs_vapname_cloudvifname_map {
    char cloudvifname[64];
    char vapname[64];
};

#if defined (_PP203X_PRODUCT_REQ_) || defined (_XER5_PRODUCT_REQ_) || defined (_XB10_PRODUCT_REQ_) || defined (_SCER11BEL_PRODUCT_REQ_)
struct ovs_vapname_cloudvifname_map  cloud_vif_map[] = {
    {"bhaul-ap-24",  "mesh_backhaul_2g"},
    {"bhaul-ap-l50", "mesh_backhaul_5gl"},
    {"bhaul-ap-u50", "mesh_backhaul_5gh"},
    {"bhaul-ap-50",  "mesh_backhaul_5g"},
    {"bhaul-ap-60",  "mesh_backhaul_6g"},
    {"home-ap-24",   "private_ssid_2g"},
    {"home-ap-l50",  "private_ssid_5gl"},
    {"home-ap-u50",  "private_ssid_5gh"},
    {"home-ap-50",   "private_ssid_5g"},
    {"home-ap-60",   "private_ssid_6g"},
    {"bhaul-sta-24", "mesh_sta_2g"},   
    {"bhaul-sta-l50","mesh_sta_5gl"},
    {"bhaul-sta-u50","mesh_sta_5gh"},
    {"bhaul-sta-50", "mesh_sta_5g"},
    {"bhaul-sta-60", "mesh_sta_6g"},
    {"svc-d-ap-24",  "lnf_psk_2g"},
    {"svc-d-ap-l50", "lnf_psk_5gl"},
    {"svc-d-ap-u50", "lnf_psk_5gh"},
    {"svc-d-ap-50",  "lnf_psk_5g"},
    {"svc-d-ap-60",  "lnf_psk_6g"},    
    {"svc-e-ap-24",  "iot_ssid_2g"},
    {"svc-e-ap-l50", "iot_ssid_5gl"},
    {"svc-e-ap-u50", "iot_ssid_5gh"},
    {"svc-e-ap-50",  "iot_ssid_5g"},
    {"svc-e-ap-60",  "iot_ssid_6g"},
    {"svc-d-ap-s-24","lnf_radius_2g"},
    {"svc-d-ap-s-50","lnf_radius_5g"},
    {"svc-d-ap-s-60","lnf_radius_6gh"},
    {"svc-f-ap-24",  "hotspot_open_2g"},
    {"svc-f-ap-l50", "hotspot_open_5gl"},
    {"svc-f-ap-u50", "hotspot_open_5gh"},
    {"svc-f-ap-50",  "hotspot_open_5g"},
    {"svc-f-ap-60",  "hotspot_open_6g"},
    {"svc-g-ap-24",  "hotspot_secure_2g"},
    {"svc-g-ap-l50", "hotspot_secure_5gl"},
    {"svc-g-ap-u50", "hotspot_secure_5gh"},
    {"svc-g-ap-50",  "hotspot_secure_5g"},
    {"svc-g-ap-60",  "hotspot_secure_6g"},
}; 
#else
struct ovs_vapname_cloudvifname_map  cloud_vif_map[] = {
    {"wl0",   "mesh_sta_2g"},
    {"wl0.1", "private_ssid_2g"},
    {"wl0.2", "iot_ssid_2g"},
    {"wl0.3", "hotspot_open_2g"},
    {"wl0.4", "lnf_psk_2g"},
    {"wl0.5", "hotspot_secure_2g"},
    {"wl0.6", "lnf_radius_2g"},
    {"wl0.7", "mesh_backhaul_2g"},
    {"wl1",   "mesh_sta_5g"},
    {"wl1.1", "private_ssid_5g"},
    {"wl1.2", "iot_ssid_5g"},
    {"wl1.3", "hotspot_open_5g"},
    {"wl1.4", "lnf_psk_5g"},
    {"wl1.5", "hotspot_secure_5g"},
    {"wl1.6", "lnf_radius_5g"},
    {"wl1.7", "mesh_backhaul_5g"},
    {"wl2",   "mesh_sta_6g"},
    {"wl2.1", "private_ssid_6g"},
    {"wl2.2", "iot_ssid_6g"},
    {"wl2.3", "hotspot_open_6g"},
    {"wl2.4", "lnf_psk_6g"},
    {"wl2.5", "hotspot_secure_6g"},
    {"wl2.7", "mesh_backhaul_6g"},
    {"wl1",   "mesh_sta_5gl"},
    {"wl1.1", "private_ssid_5gl"},
    {"wl1.2", "iot_ssid_5gl"},
    {"wl1.3", "hotspot_open_5gl"},
    {"wl1.4", "lnf_psk_5gl"},
    {"wl1.5", "hotspot_secure_5gl"},
    {"wl1.6", "lnf_radius_5gl"},
    {"wl1.7", "mesh_backhaul_5gl"},
    {"wl2",   "mesh_sta_5gh"},
    {"wl2.1", "private_ssid_5gh"},
    {"wl2.2", "iot_ssid_5gh"},
    {"wl2.3", "hotspot_open_5gh"},
    {"wl2.4", "lnf_psk_5gh"},
    {"wl2.5", "hotspot_secure_5gh"},
    {"wl2.6", "lnf_radius_5gh"},
    {"wl2.7", "mesh_backhaul_5gh"}
};
#endif

struct ovs_radioname_cloudradioname_map {
    unsigned int radio_index;
    char cloudradioname[64];
};

#if defined (_PP203X_PRODUCT_REQ_) || defined (_XER5_PRODUCT_REQ_)
struct ovs_radioname_cloudradioname_map cloud_radio_map[] = {
    {0, "wifi0"},
    {1, "wifi1"},
    {2, "wifi2"},
};
#else
struct ovs_radioname_cloudradioname_map cloud_radio_map[] = {
    {0, "wl0"},
    {1, "wl1"},
    {2, "wl2"},
};
#endif

int convert_cloudifname_to_vapname(wifi_platform_property_t *wifi_prop, char *if_name, char *vap_name, int vapname_len)
{
    unsigned int i = 0;
    if ((if_name == NULL) || (vap_name == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: input_string parameter error!!! if_name : %p vap_name : %p\n", __FUNCTION__, __LINE__, if_name, vap_name);
        return RETURN_ERR;
    }

    for (i = 0; i < ARRAY_SIZE(cloud_vif_map); i++) {
        if ((strcmp(if_name, cloud_vif_map[i].cloudvifname) == 0) && (convert_vap_name_to_index(wifi_prop, cloud_vif_map[i].vapname) != RETURN_ERR))   {
            snprintf(vap_name, vapname_len, "%s", cloud_vif_map[i].vapname);
            return RETURN_OK;
        }
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: unable to find vapname for if_name : '%s'\n", __FUNCTION__, __LINE__, if_name);
    return RETURN_ERR;
}

int convert_vapname_to_cloudifname(char *vap_name, char *if_name, int ifname_len)
{
    unsigned int i = 0;
    if ((if_name == NULL) || (vap_name == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: input_string parameter error!!! if_name : %p vap_name : %p\n", __FUNCTION__, __LINE__, if_name, vap_name);
        return RETURN_ERR;
    }

    for (i = 0; i < ARRAY_SIZE(cloud_vif_map); i++) {
        if (strcmp(vap_name, cloud_vif_map[i].vapname) == 0) {
            snprintf(if_name, ifname_len, "%s", cloud_vif_map[i].cloudvifname);
            return RETURN_OK;
        }
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: unable to find if_name for vap_name : '%s'\n", __FUNCTION__, __LINE__, vap_name);
    return RETURN_ERR;
}

int convert_apindex_to_cloudifname(wifi_platform_property_t *wifi_prop, int idx, char *if_name, unsigned int len)
{
    char vapname[64] = {0};

    if (convert_vap_index_to_name(wifi_prop, idx, vapname) == RETURN_ERR) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: unable to find vapname for idx : '%d'\n", __FUNCTION__, __LINE__, idx);
        return RETURN_ERR;
    }

    if (convert_vapname_to_cloudifname(vapname, if_name, len) == RETURN_OK) {
        return RETURN_OK;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: unable to find if_name for idx : '%d'\n", __FUNCTION__, __LINE__, idx);
    return RETURN_ERR;
}

int convert_radio_index_to_cloudifname(unsigned int radio_index, char *if_name, int ifname_len)
{
    if ((if_name == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: input_string parameter error!!! if_name : %p\n", __FUNCTION__, __LINE__, if_name);
        return RETURN_ERR;
    }

    for (unsigned int index = 0; index < ARRAY_SIZE(cloud_radio_map); ++index) {
        if (radio_index == cloud_radio_map[index].radio_index) {
            snprintf(if_name, ifname_len, "%s", cloud_radio_map[index].cloudradioname);
            return RETURN_OK;
        }
    }

    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: unable to find ifname for radioIndex : %d!!!\n", __FUNCTION__, __LINE__, radio_index);
    return RETURN_ERR;
}

int convert_cloudifname_to_radio_index(char *if_name, unsigned int *radio_index)
{
    unsigned int i = 0;

    if (if_name == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"WIFI %s:%d input if_name is NULL \n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    for (i = 0; i < ARRAY_SIZE(cloud_radio_map); i++) {
        if (strcmp(if_name, cloud_radio_map[i].cloudradioname) == 0) {
            *radio_index = cloud_radio_map[i].radio_index;
            return RETURN_OK;
        }
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: unable to find radio_index for if_name : '%s'\n", __FUNCTION__, __LINE__, if_name);
    return RETURN_ERR;

}

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

void blaster_config_ovs_schema_dump(const struct schema_Wifi_Blaster_Config *blaster)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG,  " plan_id                  : %s\n",   blaster->plan_id);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " blast_packet_size         : %d\n",   blaster->blast_packet_size);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " blast_duration            : %d\n",   blaster->blast_duration);
    wifi_util_dbg_print(WIFI_WEBCONFIG, " blast_sample_count        : %d\n",   blaster->blast_sample_count);
}

void blaster_state_ovs_schema_dump(const struct schema_Wifi_Blaster_State *blaster)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, " plan id                   : %s\n",   blaster->plan_id);
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
    const struct schema_Wifi_Blaster_Config *blaster_config_row;
    const struct schema_Wifi_Blaster_State  *blaster_state_row;
    const struct schema_Wifi_VIF_Config *vif_config_row;
    const struct schema_Wifi_VIF_State *vif_state_row;
    unsigned int i;

    if (data == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Input data is NULL\n", __func__, __LINE__);
        return;
    }

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: proto is NULL\n", __func__, __LINE__);
        return;
    }
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: radio_config_row_count %d \n", __func__, proto->radio_config_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: vif_config_row_count %d\n", __func__, proto->vif_config_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: Blaster_config_row_count %d\n", __func__, proto->blaster_config_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: radio_state_row_count %d\n", __func__, proto->radio_state_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: vif_state_row_count %d\n", __func__, proto->vif_state_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: Blaster_state_row_count %d\n", __func__, proto->blaster_state_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: assoc_clients_row_count %d\n", __func__, proto->assoc_clients_row_count);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s: AWLAN_MQTT_Topic : %s\n", __func__, proto->awlan_mqtt_topic);

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

    for (i=0; i<proto->blaster_config_row_count; i++) {
        blaster_config_row = (struct schema_Wifi_Blaster_Config *)proto->blaster_config[i];
        if (blaster_config_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Blaster_config_row is NULL\n", __func__, __LINE__);
            return;
        }
        blaster_config_ovs_schema_dump(blaster_config_row);
    }

    for (i=0; i<proto->blaster_state_row_count; i++) {
        blaster_state_row = (struct schema_Wifi_Blaster_State *)proto->blaster_state[i];
        if (blaster_state_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Blaster_state_row is NULL\n", __func__, __LINE__);
            return;
        }
        blaster_state_ovs_schema_dump(blaster_state_row);
    }
}

int set_translator_config_wpa_psks(
        struct schema_Wifi_VIF_Config *vconfig,
        int *index,
        const char *key,
        const char *value)
{
    snprintf(vconfig->wpa_psks_keys[*index], sizeof(vconfig->wpa_psks_keys[*index]), "%s", key);
    snprintf(vconfig->wpa_psks[*index], sizeof(vconfig->wpa_psks[*index]), "%s", value);
    *index += 1;
    vconfig->wpa_psks_len = *index;
    return *index;
}

int set_translator_state_wpa_psks(
        struct schema_Wifi_VIF_State *vstate,
        int *index,
        const char *key,
        const char *value)
{
    snprintf(vstate->wpa_psks_keys[*index], sizeof(vstate->wpa_psks_keys[*index]), "%s", key);
    snprintf(vstate->wpa_psks[*index], sizeof(vstate->wpa_psks[*index]), "%s", value);
    *index += 1;
    vstate->wpa_psks_len = *index;
    return *index;
}

void set_translator_config_wpa_oftags(
        struct schema_Wifi_VIF_Config *vconfig,
        const char *oftag)
{
    for (int i = 0; i < vconfig->wpa_psks_len; i++) {
        snprintf(vconfig->wpa_oftags[i], sizeof(vconfig->wpa_oftags[i]), "%s", oftag);
    }
}

void get_translator_config_wpa_mfp(
        wifi_vap_info_t *vap)
{
    if (vap->u.bss_info.security.mode == wifi_security_mode_wpa3_personal || vap->u.bss_info.security.mode == wifi_security_mode_wpa3_enterprise) {
        vap->u.bss_info.security.mfp = wifi_mfp_cfg_required;
    } else if (vap->u.bss_info.security.mode == wifi_security_mode_wpa3_transition) {
        vap->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
    } else {
        vap->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
    }
}

void get_translator_config_wpa_psks(
        const struct schema_Wifi_VIF_Config *vconfig,
        wifi_vap_info_t *vap,
        int is_sta)
{
    for (int i = 0; i < vconfig->wpa_psks_len; i++) {
        if (strlen(vconfig->wpa_psks[i]) > 0) {
            if (is_sta)
                snprintf(vap->u.sta_info.security.u.key.key, sizeof(vap->u.sta_info.security.u.key.key), "%s", vconfig->wpa_psks[i]);
            else
                snprintf(vap->u.bss_info.security.u.key.key, sizeof(vap->u.bss_info.security.u.key.key), "%s", vconfig->wpa_psks[i]);
        }
    }
}

void get_translator_config_wpa_oftags(
        const struct schema_Wifi_VIF_Config *vconfig,
        wifi_vap_info_t *vap,
        int is_sta)
{
    for (int i = 0; i < vconfig->wpa_psks_len; i++) {
        if (strlen(vconfig->wpa_oftags[i]) > 0 ) {
            if (is_sta)
                snprintf(vap->u.sta_info.security.key_id, sizeof(vap->u.sta_info.security.key_id), "%s", vconfig->wpa_oftags[i]);
            else
                snprintf(vap->u.bss_info.security.key_id, sizeof(vap->u.bss_info.security.key_id), "%s", vconfig->wpa_oftags[i]);
        }
    }
}

webconfig_error_t translator_ovsdb_init(webconfig_subdoc_data_t *data)
{
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d\n", __func__, __LINE__);
    webconfig_subdoc_decoded_data_t *decoded_params, *default_decoded_params;
    wifi_hal_capability_t *hal_cap, *default_hal_cap;
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
    int band = 0;

    decoded_params = &data->u.decoded;
    default_decoded_params = &webconfig_ovsdb_default_data.u.decoded;

    hal_cap = &decoded_params->hal_cap;
    default_hal_cap = &default_decoded_params->hal_cap;
    memcpy(default_hal_cap, hal_cap, sizeof(wifi_hal_capability_t));

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
    /* get list of mesh sta */
    num_ssid += get_list_of_mesh_sta(&hal_cap->wifi_prop, MAX_NUM_RADIOS, &vap_names[num_ssid]);

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
        wifi_vap_info_t *default_vap_info =
            &default_decoded_params->radios[radioIndx].vaps.vap_map.vap_array[vapArrayIndx];
        wifi_vap_info_t *vap_info =
            &decoded_params->radios[radioIndx].vaps.vap_map.vap_array[vapArrayIndx];

        // set generic vap parameters
        default_vap_info->vap_index = vapIndex;
        default_vap_info->radio_index = radioIndx;
        strcpy(default_vap_info->vap_name, vap_names[i]);
        if (get_bridgename_from_vapname(&hal_cap->wifi_prop, (char *)default_vap_info->vap_name,
                default_vap_info->bridge_name,
                sizeof(default_vap_info->bridge_name)) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vapname to bridge name conversion failed\n",
                __func__, __LINE__);
        }

        // set sta parameters
        if (is_vap_mesh_sta(&hal_cap->wifi_prop, vapIndex)) {
            default_vap_info->vap_mode = wifi_vap_mode_sta;
            strncpy(default_vap_info->u.sta_info.ssid, vap_info->u.sta_info.ssid,
                sizeof(default_vap_info->u.sta_info.ssid) - 1);
            memset(default_vap_info->u.sta_info.bssid, 0,
                sizeof(default_vap_info->u.sta_info.bssid));
            default_vap_info->u.sta_info.enabled = true;
            default_vap_info->u.sta_info.conn_status = 0;
            memset(&default_vap_info->u.sta_info.scan_params, 0,
                sizeof(default_vap_info->u.sta_info.scan_params));
            memcpy(&default_vap_info->u.sta_info.security, &vap_info->u.sta_info.security,
                sizeof(default_vap_info->u.sta_info.security));
            memset(default_vap_info->u.sta_info.mac, 0, sizeof(default_vap_info->u.sta_info.mac));
            if (band == WIFI_FREQUENCY_6_BAND) {
                default_vap_info->u.sta_info.security.mode = wifi_security_mode_wpa3_personal;
                default_vap_info->u.sta_info.security.wpa3_transition_disable = true;
                default_vap_info->u.sta_info.security.encr = wifi_encryption_aes;
                default_vap_info->u.sta_info.security.mfp = wifi_mfp_cfg_required;
            }
            continue;
        }

        // set ap parameters
        default_vap_info->u.bss_info.wmm_enabled = true;
        default_vap_info->u.bss_info.isolation = 0;
        default_vap_info->u.bss_info.bssTransitionActivated = false;
        default_vap_info->u.bss_info.nbrReportActivated = false;
        default_vap_info->u.bss_info.rapidReconnThreshold = 180;
        default_vap_info->u.bss_info.mac_filter_enable = false;
        default_vap_info->u.bss_info.UAPSDEnabled = true;
        default_vap_info->u.bss_info.wmmNoAck = false;
        default_vap_info->u.bss_info.wepKeyLength = 128;
        default_vap_info->u.bss_info.security.encr = wifi_encryption_aes;
        default_vap_info->u.bss_info.bssHotspot = false;
        default_vap_info->u.bss_info.beaconRate = WIFI_BITRATE_6MBPS;
        strncpy(default_vap_info->u.bss_info.beaconRateCtl, "6Mbps",
            sizeof(default_vap_info->u.bss_info.beaconRateCtl) - 1);
        default_vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
        default_vap_info->vap_mode = wifi_vap_mode_ap;
        default_vap_info->u.bss_info.enabled = false;
        default_vap_info->u.bss_info.bssMaxSta = 75;
        snprintf(default_vap_info->u.bss_info.interworking.interworking.hessid,
            sizeof(default_vap_info->u.bss_info.interworking.interworking.hessid),
            "11:22:33:44:55:66");
        convert_radio_index_to_freq_band(&hal_cap->wifi_prop, radioIndx, &band);

        if (is_vap_private(&hal_cap->wifi_prop, vapIndex) == TRUE) {
            default_vap_info->u.bss_info.network_initiated_greylist = false;
            default_vap_info->u.bss_info.vapStatsEnable = true;
            default_vap_info->u.bss_info.wpsPushButton = 0;
            default_vap_info->u.bss_info.wps.enable = true;
            default_vap_info->u.bss_info.rapidReconnectEnable = true;
            if (band == WIFI_FREQUENCY_6_BAND) {
                default_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
                default_vap_info->u.bss_info.security.wpa3_transition_disable = true;
                default_vap_info->u.bss_info.security.encr = wifi_encryption_aes;
                default_vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_required;
            } else {
#if defined(_XB8_PRODUCT_REQ_)||defined(_PP203X_PRODUCT_REQ_)
                default_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_transition;
                default_vap_info->u.bss_info.security.wpa3_transition_disable = false;
                default_vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
                default_vap_info->u.bss_info.security.encr = wifi_encryption_aes;
#else
                default_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
#endif
            }
            memset(ssid, 0, sizeof(ssid));
            strcpy(default_vap_info->u.bss_info.ssid, default_vap_info->vap_name);
            memset(password, 0, sizeof(password));
            strcpy(default_vap_info->u.bss_info.security.u.key.key, INVALID_KEY);
            memset(wps_pin, 0, sizeof(wps_pin));
            strcpy(default_vap_info->u.bss_info.wps.pin, INVALID_KEY);
            default_vap_info->u.bss_info.showSsid = true;

        } else if(is_vap_mesh_backhaul(&hal_cap->wifi_prop, vapIndex) == TRUE) {
            default_vap_info->u.bss_info.vapStatsEnable = false;
            default_vap_info->u.bss_info.rapidReconnectEnable = false;
            default_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_personal;
            default_vap_info->u.bss_info.showSsid = false;
            memset(ssid, 0, sizeof(ssid));
            strcpy(default_vap_info->u.bss_info.ssid, "we.connect.yellowstone");
            memset(password, 0, sizeof(password));
            strcpy(default_vap_info->u.bss_info.security.u.key.key, INVALID_KEY);
            if (band == WIFI_FREQUENCY_6_BAND) {
                default_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
                default_vap_info->u.bss_info.security.wpa3_transition_disable = true;
                default_vap_info->u.bss_info.security.encr = wifi_encryption_aes;
                default_vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_required;
            }
        } else if(is_vap_lnf_radius(&hal_cap->wifi_prop, vapIndex) == TRUE) {
            strcpy(default_vap_info->u.bss_info.security.u.radius.identity, "lnf_radius_identity");
            default_vap_info->u.bss_info.security.u.radius.port = 1812;
            strcpy((char *)default_vap_info->u.bss_info.security.u.radius.ip, "127.0.0.1");
            default_vap_info->u.bss_info.security.u.radius.s_port = 1812;
            strcpy((char *)default_vap_info->u.bss_info.security.u.radius.s_ip, "127.0.0.1");
            strcpy(default_vap_info->u.bss_info.security.u.radius.key, INVALID_KEY);
            strcpy(default_vap_info->u.bss_info.security.u.radius.s_key, INVALID_KEY);

            strcpy(default_vap_info->u.bss_info.ssid, default_vap_info->vap_name);
            default_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
        }   else if(is_vap_lnf_psk(&hal_cap->wifi_prop, vapIndex) == TRUE) {
            default_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            memset(ssid, 0, sizeof(ssid));
            strcpy(default_vap_info->u.bss_info.ssid, default_vap_info->vap_name);
            memset(password, 0, sizeof(password));
            strcpy(default_vap_info->u.bss_info.security.u.key.key, INVALID_KEY);
            default_vap_info->u.bss_info.showSsid = false;
        }   else if(is_vap_xhs(&hal_cap->wifi_prop, vapIndex) == TRUE) {
            default_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            memset(ssid, 0, sizeof(ssid));
            strcpy(default_vap_info->u.bss_info.ssid, default_vap_info->vap_name);
            memset(password, 0, sizeof(password));
            strcpy(default_vap_info->u.bss_info.security.u.key.key, INVALID_KEY);
            default_vap_info->u.bss_info.showSsid = false;
            if (band == WIFI_FREQUENCY_6_BAND) {
                default_vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
                default_vap_info->u.bss_info.security.wpa3_transition_disable = true;
                default_vap_info->u.bss_info.security.encr = wifi_encryption_aes;
                default_vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_required;
            }
        }
    }
    for (i= 0; i < decoded_params->num_radios; i++) {
        radioIndx = convert_radio_name_to_radio_index(decoded_params->radios[i].name);
        if ((int)radioIndx < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid  radio_index\n", __func__, __LINE__);
            continue;
        }
        oper_param = &decoded_params->radios[radioIndx].oper;
        memcpy(&default_decoded_params->radios[radioIndx].oper, oper_param,
            sizeof(wifi_radio_operationParam_t));
        strncpy(default_decoded_params->radios[radioIndx].name,
            decoded_params->radios[radioIndx].name,
            sizeof(default_decoded_params->radios[radioIndx].name));
        default_decoded_params->radios[radioIndx].vaps.vap_map.num_vaps =
            decoded_params->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
    }

    default_decoded_params->num_radios = decoded_params->num_radios;

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


    if (convert_cloudifname_to_vapname(wifi_prop, (char *)ifname, vapname, sizeof(vapname)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert cloud ifname to vapname failed for : %s\n", __func__, __LINE__, ifname);
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
        *type = webconfig_subdoc_type_mesh_backhaul_sta;
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
    wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: OVSM encode subdoc type %d\n", __func__, __LINE__, type);

    webconfig_ovsdb_data.u.decoded.external_protos = (webconfig_external_ovsdb_t *)data;
    webconfig_ovsdb_data.descriptor = webconfig_data_descriptor_translate_from_ovsdb;
    debug_external_protos(&webconfig_ovsdb_data, __func__, __LINE__);

    if (webconfig_encode(config, &webconfig_ovsdb_data, type) != webconfig_error_none) {
        *str = NULL;
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: OVSM encode failed\n", __func__, __LINE__);
        return webconfig_error_encode;
    }

    if (webconfig_ovsdb_raw_data_ptr != NULL) {
        free(webconfig_ovsdb_raw_data_ptr);
        webconfig_ovsdb_raw_data_ptr = NULL;
    }
    webconfig_ovsdb_raw_data_ptr = webconfig_ovsdb_data.u.encoded.raw;

    *str = webconfig_ovsdb_raw_data_ptr;
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
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: OVSM decode failed\n", __func__, __LINE__);
        return webconfig_error_decode;
    }

    wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: OVSM decode subdoc type %d sucessfully\n", __func__, __LINE__, webconfig_ovsdb_data.type);
    *type = webconfig_ovsdb_data.type;
    debug_external_protos(&webconfig_ovsdb_data, __func__, __LINE__);
    webconfig_data_free(&webconfig_ovsdb_data);
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

webconfig_error_t free_vap_object_diff_assoc_client_entries(webconfig_subdoc_data_t *data)
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
            if (rdk_vap_info->associated_devices_diff_map != NULL) {
                assoc_dev_data = hash_map_get_first(rdk_vap_info->associated_devices_diff_map);
                while(assoc_dev_data != NULL) {
                    to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, mac_str);
                    assoc_dev_data = hash_map_get_next(rdk_vap_info->associated_devices_diff_map, assoc_dev_data);
                    temp_assoc_dev_data = hash_map_remove(rdk_vap_info->associated_devices_diff_map, mac_str);
                    if (temp_assoc_dev_data != NULL) {
                        free(temp_assoc_dev_data);
                    }
                }
                hash_map_destroy(rdk_vap_info->associated_devices_diff_map);
                rdk_vap_info->associated_devices_diff_map =  NULL;
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
    if (convert_apindex_to_cloudifname(wifi_prop, vap_index, if_name, sizeof(if_name)) != RETURN_OK) {
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

webconfig_error_t translate_macfilter_from_ovsdb_to_rdk_vap(const struct schema_Wifi_VIF_Config *row, rdk_wifi_vap_info_t *rdk_vap, wifi_platform_property_t *wifi_prop)
{
    int i = 0;
    mac_address_t mac;
    char *mac_str;
    mac_addr_str_t acl_str;
    acl_entry_t *acl_entry, *temp_acl_entry;

    if ((rdk_vap == NULL) || (row == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (rdk_vap->acl_map == NULL) {
        rdk_vap->acl_map = hash_map_create();
        if (rdk_vap->acl_map == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: hash map create failed\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }
    } else {
        wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: acl hash map already avaialble:%p for vap_index:%d\n", __func__, __LINE__, rdk_vap->acl_map, rdk_vap->vap_index);

        if (is_vap_mesh_backhaul(wifi_prop, rdk_vap->vap_index)) {
            wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: delete all the entries for vap_index:%d\n", __func__, __LINE__, rdk_vap->vap_index);
            acl_entry = hash_map_get_first(rdk_vap->acl_map);
            while(acl_entry != NULL) {
                to_mac_str(acl_entry->mac, acl_str);
                str_tolower(acl_str);
                acl_entry = hash_map_get_next(rdk_vap->acl_map, acl_entry);
                temp_acl_entry = hash_map_remove(rdk_vap->acl_map, acl_str);
                if (temp_acl_entry != NULL) {
                    free(temp_acl_entry);
                }
            }
        }
    }

    for (i = 0; i < row->mac_list_len; i++) {
        mac_str = (char *)row->mac_list[i];
        if (mac_str == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: mac_str is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }
        str_tolower(mac_str);
        acl_entry = hash_map_get(rdk_vap->acl_map, mac_str);
        if (acl_entry == NULL) {
            str_to_mac_bytes(mac_str, mac);
            acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
            if (acl_entry == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL Pointer \n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
            memset(acl_entry, 0, (sizeof(acl_entry_t)));

            memcpy(&acl_entry->mac, mac, sizeof(mac_address_t));
            hash_map_put(rdk_vap->acl_map, strdup(mac_str), acl_entry);
        } else {
            wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d:mac filter entry already avaialble for mac[%s] index:%d\n", __func__, __LINE__, mac_str, i);
        }
    }

    return webconfig_error_none;
}

static int get_channels(const wifi_channelMap_t *channel_map, wifi_radio_capabilities_t *radio_cap, struct schema_Wifi_Radio_State *row,
                        wifi_freq_bands_t band, bool dfs_enabled)
{
    bool remove_dfs_channels = FALSE;
    int chan_arr_index = 0;

    if (!channel_map || !radio_cap || !row) {
        return RETURN_ERR;
    }

    if ( ((band == WIFI_FREQUENCY_5_BAND)  ||
          (band == WIFI_FREQUENCY_5L_BAND) || (band == WIFI_FREQUENCY_5H_BAND)) &&
         (dfs_enabled == FALSE) ) {
         remove_dfs_channels = TRUE;
    }

    for (int i = 0; i < radio_cap->channel_list[0].num_channels; i++)
    {
        /* For 5G Radio, filter the channels 52 to 144 based on DFS flag */
        if ( (remove_dfs_channels == TRUE) &&
             ((channel_map[i].ch_number > 48) &&
              (channel_map[i].ch_number < 149)) ) {
            continue;
        }

        channel_state_enum_to_str(channel_map[i].ch_state, row->channels[chan_arr_index], ARRAY_SIZE(row->channels[chan_arr_index]) - 1);
        sprintf(row->channels_keys[chan_arr_index], "%d", channel_map[i].ch_number);
        chan_arr_index++;
    }
    row->channels_len = chan_arr_index;
    return RETURN_OK;
}

static int get_radar_detected(struct schema_Wifi_Radio_State *row,wifi_freq_bands_t band, int radio_index, bool dfs_enabled, radarInfo_t *radarInfo) {

    if(!row || !radarInfo) {
        return RETURN_ERR;
    }
    if((band == WIFI_FREQUENCY_5_BAND)  ||(band == WIFI_FREQUENCY_5L_BAND) || (band == WIFI_FREQUENCY_5H_BAND)) {
         if (dfs_enabled == FALSE)  {
             row->radar_len = 0;
             return RETURN_OK;
         }
         row->radar_len = 3;
         snprintf(row->radar_keys[0], sizeof(row->radar_keys[0]), "last_channel");
         snprintf(row->radar_keys[1], sizeof(row->radar_keys[1]), "num_detected");
         snprintf(row->radar_keys[2], sizeof(row->radar_keys[2]), "time");
         snprintf(row->radar[0], sizeof(row->radar[0]), "%d", radarInfo->last_channel);
         snprintf(row->radar[1], sizeof(row->radar[1]), "%d", radarInfo->num_detected);
         snprintf(row->radar[2], sizeof(row->radar[2]), "%lld", radarInfo->timestamp);
    }
    return RETURN_OK;
}
webconfig_error_t translate_radio_obj_to_ovsdb_radio_state(const wifi_radio_operationParam_t *oper_param, radarInfo_t *radarInfo, struct schema_Wifi_Radio_State *row, wifi_platform_property_t *wifi_prop)
{
    int radio_index = 0;
    wifi_freq_bands_t band_enum;
    wifi_countrycode_type_t country_code;
    wifi_ieee80211Variant_t hw_mode_enum;
    wifi_channelBandwidth_t ht_mode_enum;
    wifi_channelMap_t channel_map[MAX_CHANNELS];

    if ((oper_param == NULL) || (row == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    band_enum = oper_param->band;
    if (freq_band_conversion(&band_enum, (char *)row->freq_band, sizeof(row->freq_band), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed. band 0x%x\n", __func__, __LINE__, oper_param->band);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_freq_band_to_radio_index(oper_param->band, &radio_index) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: frequency band to radio_index failed. band 0x%x\n", __func__, __LINE__, oper_param->band);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_radio_index_to_cloudifname(radio_index, row->if_name, sizeof(row->if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: radio_index to ifname failed failed. radio_index %d\n", __func__, __LINE__, radio_index);
        return webconfig_error_translate_to_ovsdb;
    }

    country_code = oper_param->countryCode;
    if (country_code_conversion(&country_code, row->country, sizeof(row->country), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: country conversion failed. countryCode %d\n", __func__, __LINE__, oper_param->countryCode);
        return webconfig_error_translate_to_ovsdb;
    }

#if defined (_PP203X_PRODUCT_REQ_)
    char country_id[4] = {};

    if (country_id_conversion((wifi_countrycode_type_t *)&oper_param->countryCode, country_id, sizeof(country_id), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: country_id conversion failed. countryCode %d\n", __func__, __LINE__, oper_param->countryCode);
        return webconfig_error_translate_to_ovsdb;
    }

    row->hw_params_len = 0;
    STRSCPY(row->hw_params_keys[row->hw_params_len], "country_id");
    snprintf(row->hw_params[row->hw_params_len], sizeof(row->hw_params[row->hw_params_len]), "%s", country_id);
    row->hw_params_len++;

    STRSCPY(row->hw_params_keys[row->hw_params_len], "reg_domain");
    snprintf(row->hw_params[row->hw_params_len], sizeof(row->hw_params[row->hw_params_len]), "%u", oper_param->regDomain);
    row->hw_params_len++;
#endif

    hw_mode_enum = oper_param->variant;
    if (hw_mode_conversion(&hw_mode_enum, row->hw_mode, sizeof(row->hw_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Hw mode conversion failed. variant 0x%x\n", __func__, __LINE__, oper_param->variant);
        return webconfig_error_translate_to_ovsdb;
    }

    ht_mode_enum = oper_param->channelWidth;
    if (ht_mode_conversion(&ht_mode_enum, row->ht_mode, sizeof(row->ht_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Ht mode conversion failed. channelWidth 0x%x\n", __func__, __LINE__, oper_param->channelWidth);
        return webconfig_error_translate_to_ovsdb;
    }

    if (channel_mode_conversion((BOOL *)&oper_param->autoChannelEnabled, row->channel_mode, sizeof(row->channel_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Channel mode conversion failed. autoChannelEnabled %d\n", __func__, __LINE__, oper_param->autoChannelEnabled);
        return webconfig_error_translate_to_ovsdb;
    }


    if (get_radio_if_hw_type(radio_index, row->hw_type, sizeof(row->hw_type)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get hw type failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (get_allowed_channels(oper_param->band, &wifi_prop->radiocap[radio_index], row->allowed_channels, &row->allowed_channels_len, oper_param->DfsEnabled) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get allowed channels failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    (void)memcpy(channel_map, oper_param->channel_map, sizeof(channel_map));
    if (get_channels(channel_map, &wifi_prop->radiocap[radio_index], row, oper_param->band, oper_param->DfsEnabled) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get channels failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if(get_radar_detected(row, oper_param->band, radio_index, oper_param->DfsEnabled, radarInfo) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: get radar detected failed\n", __func__, __LINE__);
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
    wifi_freq_bands_t band_enum;
    wifi_countrycode_type_t country_code;
    wifi_ieee80211Variant_t hw_mode_enum;
    wifi_channelBandwidth_t ht_mode_enum;

    if ((oper_param == NULL) || (row == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    band_enum = oper_param->band;
    if (freq_band_conversion(&band_enum, (char *)row->freq_band, sizeof(row->freq_band), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed. band 0x%x\n", __func__, __LINE__, oper_param->band);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_freq_band_to_radio_index(oper_param->band, &radio_index) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: frequency band to radio_index failed. band 0x%x\n", __func__, __LINE__, oper_param->band);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_radio_index_to_cloudifname(radio_index, row->if_name, sizeof(row->if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: radio_index to ifname failed failed. radio_index %d\n", __func__, __LINE__, radio_index);
        return webconfig_error_translate_to_ovsdb;
    }

    country_code = oper_param->countryCode;
    if (country_code_conversion(&country_code, row->country, sizeof(row->country), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: country conversion failed. countryCode %d\n", __func__, __LINE__, oper_param->countryCode);
        return webconfig_error_translate_to_ovsdb;
    }

    hw_mode_enum = oper_param->variant;
    if (hw_mode_conversion(&hw_mode_enum, row->hw_mode, sizeof(row->hw_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Hw mode conversion failed. variant 0x%x\n", __func__, __LINE__, oper_param->variant);
        return webconfig_error_translate_to_ovsdb;
    }

    ht_mode_enum = oper_param->channelWidth;
    if (ht_mode_conversion(&ht_mode_enum, row->ht_mode, sizeof(row->ht_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Ht mode conversion failed. channelWidth 0x%x\n", __func__, __LINE__, oper_param->channelWidth);
        return webconfig_error_translate_to_ovsdb;
    }

    if (channel_mode_conversion((BOOL *)&oper_param->autoChannelEnabled, row->channel_mode, sizeof(row->channel_mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: channel mode conversion failed. autoChannelEnabled %d\n", __func__, __LINE__, oper_param->autoChannelEnabled);
        return webconfig_error_translate_to_ovsdb;
    }

    if (get_radio_if_hw_type(radio_index, row->hw_type, sizeof(row->hw_type)) != RETURN_OK) {
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

        if (convert_cloudifname_to_radio_index((char *)table[i]->if_name, &schema_radio_index) != RETURN_OK) {
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
        if ((int)radio_index < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid  radio_index\n", __func__, __LINE__);
            continue;
        }
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
        if ((int)radio_index < 0) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Invalid  radio_index\n", __func__, __LINE__);
            continue;
        }
        oper_param = &decoded_params->radios[radio_index].oper;
        memcpy(&webconfig_ovsdb_data.u.decoded.radios[radio_index].oper, oper_param, sizeof(wifi_radio_operationParam_t));
        strncpy(webconfig_ovsdb_data.u.decoded.radios[radio_index].name, decoded_params->radios[radio_index].name,  sizeof(webconfig_ovsdb_data.u.decoded.radios[radio_index].name));
        memcpy(&webconfig_ovsdb_default_data.u.decoded.radios[radio_index].vaps.vap_map, &decoded_params->radios[radio_index].vaps.vap_map , sizeof(wifi_vap_info_map_t));
        webconfig_ovsdb_default_data.u.decoded.radios[radio_index].vaps.num_vaps = decoded_params->radios[radio_index].vaps.num_vaps;
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
    radarInfo_t *radarInfo = NULL;
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
        radarInfo = &decoded_params->radios[radio_index].radarInfo;

        row = (struct schema_Wifi_Radio_State *)table[radio_index];

        if (translate_radio_obj_to_ovsdb_radio_state(oper_param, radarInfo, row, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
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

BOOL update_secmode_for_wpa3(wifi_vap_info_t *vap_info, char *mode_str, int mode_len, char *encrypt_str, int encrypt_len, bool to_ovsdb)
{
    int ret = false;
    if (vap_info ==  NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d NULL vap_info Pointer\n", __func__, __LINE__);
        return ret;
    }

    if (to_ovsdb) {
        if ((vap_info->u.bss_info.security.mode == wifi_security_mode_wpa3_transition) || (vap_info->u.bss_info.security.mode == wifi_security_mode_wpa3_personal)) {
            snprintf(mode_str, mode_len, "2");
            snprintf(encrypt_str, encrypt_len, "WPA-PSK");
            ret = true;
        }
        else if (vap_info->u.bss_info.security.mode == wifi_security_mode_wpa3_enterprise) {
            snprintf(mode_str, mode_len, "2");
            snprintf(encrypt_str, encrypt_len, "WPA-EAP");
            ret = true;
        }
        else if (vap_info->u.bss_info.security.mode == wifi_security_mode_enhanced_open) {
            snprintf(encrypt_str, encrypt_len, "OPEN");
            ret = true;
        }
    } else {
        if ((vap_info->u.bss_info.security.mode == wifi_security_mode_wpa3_transition) || (vap_info->u.bss_info.security.mode == wifi_security_mode_wpa3_personal)
        || (vap_info->u.bss_info.security.mode == wifi_security_mode_wpa3_enterprise) || (vap_info->u.bss_info.security.mode == wifi_security_mode_enhanced_open)) {
            ret = true;
        }
    }
    return ret;
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

static inline bool is_personal_sec(wifi_security_modes_t mode)
{
    return mode == wifi_security_mode_wpa_personal ||
        mode == wifi_security_mode_wpa2_personal ||
        mode == wifi_security_mode_wpa_wpa2_personal ||
        mode == wifi_security_mode_wpa3_personal ||
        mode == wifi_security_mode_wpa3_transition;
}

static inline bool is_enterprise_sec(wifi_security_modes_t mode)
{
    return mode == wifi_security_mode_wpa_enterprise ||
        mode == wifi_security_mode_wpa2_enterprise ||
        mode == wifi_security_mode_wpa_wpa2_enterprise ||
        mode == wifi_security_mode_wpa3_enterprise;
}

static webconfig_error_t translate_vap_info_to_ovsdb_sec_legacy(wifi_vap_info_t *vap,
    struct schema_Wifi_VIF_Config *vap_row)
{
    int index = 0;
    char str_mode[128] = {0};
    char str_encryp[128] = {0};

    if (vap->u.bss_info.security.mode == wifi_security_mode_none) {
        set_translator_config_security_key_value(vap_row, &index, "encryption", "OPEN");
        return webconfig_error_none;
    }

    if (!update_secmode_for_wpa3(vap, str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp),
        true)) {
        wifi_security_modes_t mode_enum = vap->u.bss_info.security.mode;
        wifi_encryption_method_t encryp_enum = vap->u.bss_info.security.encr;
        if (key_mgmt_conversion_legacy(&mode_enum,
            &encryp_enum, str_mode, sizeof(str_mode), str_encryp,
            sizeof(str_encryp), ENUM_TO_STRING) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert key mgmt: "
                "security mode 0x%x encr 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode,
                vap->u.bss_info.security.encr);
            return webconfig_error_translate_to_ovsdb;
        }
    }

    set_translator_config_security_key_value(vap_row, &index, "encryption", str_encryp);
    set_translator_config_security_key_value(vap_row, &index, "mode", str_mode);

    if (!is_personal_sec(vap->u.bss_info.security.mode)) {
        return webconfig_error_none;
    }

    set_translator_config_security_key_value(vap_row, &index, "key",
        vap->u.bss_info.security.u.key.key);

    if (strnlen(vap->u.bss_info.security.key_id, sizeof(vap->u.bss_info.security.key_id) - 1) > 0) {
        set_translator_config_security_key_value(vap_row, &index, "oftag",
            vap->u.bss_info.security.key_id);
    }

    return webconfig_error_none;
}

static webconfig_error_t translate_vap_info_to_ovsdb_sec_new(wifi_vap_info_t *vap,
    struct schema_Wifi_VIF_Config *vap_row)
{
    int wpa_psk_index = 0, len = 0;
    wifi_security_modes_t enum_sec;

    if (vap->u.bss_info.security.mode == wifi_security_mode_none) {
        vap_row->wpa = false;
        vap_row->wpa_key_mgmt_len = 0;
        return webconfig_error_none;
    }

    enum_sec = vap->u.bss_info.security.mode;
    if (key_mgmt_conversion(&enum_sec, vap_row->wpa_key_mgmt[0],
        vap_row->wpa_key_mgmt[1], sizeof(vap_row->wpa_key_mgmt[0]),
        sizeof(vap_row->wpa_key_mgmt[1]), ENUM_TO_STRING, &len) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
            "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
        return webconfig_error_translate_to_ovsdb;
    }

    vap_row->wpa = true;
    vap_row->wpa_key_mgmt_len = len;

    if (!is_personal_sec(vap->u.bss_info.security.mode)) {
        return webconfig_error_none;
    }

    if (strlen(vap->u.bss_info.security.u.key.key) < MIN_PWD_LEN ||
        strlen(vap->u.bss_info.security.u.key.key) > MAX_PWD_LEN) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert: "
            "invalid password length: %d\n", __func__, __LINE__,
            strlen(vap->u.bss_info.security.u.key.key));
        return webconfig_error_translate_to_ovsdb;
    }

    set_translator_config_wpa_psks(vap_row, &wpa_psk_index, "key--1",
        vap->u.bss_info.security.u.key.key);

    if (strnlen(vap->u.bss_info.security.key_id, sizeof(vap->u.bss_info.security.key_id) - 1) > 0) {
        set_translator_config_wpa_oftags(vap_row, vap->u.bss_info.security.key_id);
    }

    return webconfig_error_none;
}

static webconfig_error_t translate_vap_info_to_ovsdb_sec(wifi_vap_info_t *vap,
    struct schema_Wifi_VIF_Config *vap_row, bool sec_schema_is_legacy)
{
    webconfig_error_t ret;

    if (vap_row == NULL || vap == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert: input argument is NULL\n",
            __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (macfilter_conversion(vap_row->mac_list_type, sizeof(vap_row->mac_list_type),
        vap, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert MAC filter: "
            "mac_filter_enable: %d mac_filter_mode: %d\n", __func__, __LINE__,
            vap->u.bss_info.mac_filter_enable, vap->u.bss_info.mac_filter_mode);
        return webconfig_error_translate_to_ovsdb;
    }

    if (sec_schema_is_legacy) {
        if ((ret = translate_vap_info_to_ovsdb_sec_legacy(vap, vap_row)) != webconfig_error_none) {
            return ret;
        }
    } else {
        if ((ret = translate_vap_info_to_ovsdb_sec_new(vap, vap_row)) != webconfig_error_none) {
            return ret;
        }
    }

    if (vap->u.bss_info.security.rekey_interval) {
        vap_row->group_rekey = vap->u.bss_info.security.rekey_interval;
    } else {
        vap_row->group_rekey_exists = false;
    }

    if (!is_enterprise_sec(vap->u.bss_info.security.mode)) {
        return webconfig_error_none;
    }

    if (translate_vap_info_to_ovsdb_radius_settings(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to translate radius settings\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_vap_info_to_ovsdb_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    wifi_vap_mode_t vapmode_enum;

    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_cloudifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed. vap_index '%d'\n", __func__, __LINE__, vap->vap_index);
        return webconfig_error_translate_to_ovsdb;
    }


    if (ssid_broadcast_conversion(vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), (BOOL *)&vap->u.bss_info.showSsid, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: ssid broadbcast conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vapmode_enum = vap->vap_mode;
    if (vap_mode_conversion(&vapmode_enum, vap_row->mode, ARRAY_SIZE(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed. vap mode %d\n", __func__, __LINE__, vap->vap_mode);
        return webconfig_error_translate_to_ovsdb;
    }
    if (strlen(vap->repurposed_vap_name) == 0) {
        vap_row->enabled = vap->u.bss_info.enabled;
    } else {
        wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d vapname %s is repurposed as %s so disabled\n", __func__, __LINE__,vap->vap_name,vap->repurposed_vap_name);
        vap_row->enabled = false;
    }
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
    wifi_vap_mode_t vapmode_enum;

    if ((vap == NULL) || (vap_row == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_cloudifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed. vap_index '%d'\n", __func__, __LINE__, vap->vap_index);
        return webconfig_error_translate_to_ovsdb;
    }

    vapmode_enum = vap->vap_mode;
    if (vap_mode_conversion(&vapmode_enum, vap_row->mode, ARRAY_SIZE(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed. vap mode %d\n", __func__, __LINE__, vap->vap_mode);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode is not station moode\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (is_bssid_valid(vap->u.sta_info.bssid)) {
        snprintf(vap_row->parent, sizeof(vap_row->parent), "%02x:%02x:%02x:%02x:%02x:%02x",
                                                vap->u.sta_info.bssid[0], vap->u.sta_info.bssid[1],
                                                vap->u.sta_info.bssid[2], vap->u.sta_info.bssid[3],
                                                vap->u.sta_info.bssid[4], vap->u.sta_info.bssid[5]);
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap_row->parent=%s\n", __func__, __LINE__, vap_row->parent);
    }

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

webconfig_error_t translate_private_vap_info_to_vif_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_iot_vap_info_to_vif_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_hotspot_open_vap_info_to_vif_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_sec(vap, vap_row, false) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for no security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_lnf_psk_vap_info_to_vif_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_secure_vap_info_to_vif_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_lnf_radius_secure_vap_info_to_vif_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_mesh_backhaul_vap_info_to_vif_config(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_ovsdb_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_sta_vap_info_to_ovsdb_config_personal_sec(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_Config *vap_row, bool sec_schema_is_legacy)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }
    if (sec_schema_is_legacy == true) {
        int sec_index = 0;
        if (vap->u.sta_info.security.mode != wifi_security_mode_none) {
            char str_mode[128] = {0};
            char str_encryp[128] = {0};

            memset(str_mode, 0, sizeof(str_mode));
            memset(str_encryp, 0, sizeof(str_encryp));
            if (!update_secmode_for_wpa3((wifi_vap_info_t *)vap, str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp), true)) {
                wifi_security_modes_t mode_enum = vap->u.sta_info.security.mode;
                wifi_encryption_method_t encryp_enum = vap->u.sta_info.security.encr;
                if ((key_mgmt_conversion_legacy(&mode_enum, &encryp_enum, str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp), ENUM_TO_STRING)) != RETURN_OK) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. security mode 0x%x encr 0x%x\n", __func__, __LINE__, vap->u.sta_info.security.mode, vap->u.sta_info.security.encr);
                    return webconfig_error_translate_to_ovsdb;
                }
            }

            set_translator_config_security_key_value(vap_row, &sec_index, "encryption", str_encryp);
            set_translator_config_security_key_value(vap_row, &sec_index, "mode", str_mode);
            set_translator_config_security_key_value(vap_row, &sec_index, "key", vap->u.sta_info.security.u.key.key);
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: encr : %s mode : %s\n", __func__, __LINE__, str_encryp, str_mode);


        } else {
            set_translator_config_security_key_value(vap_row, &sec_index, "encryption", "OPEN");
        }
    } else {
        if (vap->u.sta_info.security.mode == wifi_security_mode_none) {
            vap_row->wpa = false;
        } else {
            int len = 0, wpa_psk_index = 0;
            wifi_security_modes_t enum_sec = vap->u.sta_info.security.mode;
            if ((key_mgmt_conversion(&enum_sec, vap_row->wpa_key_mgmt[0], vap_row->wpa_key_mgmt[1], sizeof(vap_row->wpa_key_mgmt[0]), sizeof(vap_row->wpa_key_mgmt[1]), ENUM_TO_STRING, &len)) != RETURN_OK) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. security mode 0x%x\n", __func__, __LINE__, vap->u.sta_info.security.mode);
                return webconfig_error_translate_to_ovsdb;
            }

            vap_row->wpa = true;
            vap_row->wpa_key_mgmt_len = len;

            if ((strlen(vap->u.sta_info.security.u.key.key) < MIN_PWD_LEN) || (strlen(vap->u.sta_info.security.u.key.key) > MAX_PWD_LEN)) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length %d\n", __func__, __LINE__, strlen(vap->u.sta_info.security.u.key.key));
                return webconfig_error_translate_to_ovsdb;
            }
            set_translator_config_wpa_psks(vap_row, &wpa_psk_index, "key--1", vap->u.sta_info.security.u.key.key);
        }
    }

    return webconfig_error_none;
}

webconfig_error_t translate_mesh_sta_vap_info_to_vif_config(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_Config *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_sta_vap_info_to_ovsdb_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_sta_vap_info_to_ovsdb_config_personal_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
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
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    bool sec_schema_is_legacy;

    unsigned int presence_mask = 0;
    unsigned int count = 0, *row_count = NULL;
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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
            rdk_vap = &radio->vaps.rdk_vap_array[j];

#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if (rdk_vap->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap->vap_index != 2 && vap->vap_index != 3) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                    rdk_vap->exists = true;
                }
#else
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                rdk_vap->exists = true;
#endif /*_SR213_PRODUCT_REQ_*/
            }
#endif /* !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)*/
            if (rdk_vap->exists == false) {
                presence_mask |= (1 << vap->vap_index);
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

            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_iot_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_hotspot_open(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_hotspot_open_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_lnf_psk_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_hotspot_secure(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_hotspot_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh backhaul to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: for %d\n", __func__, __LINE__, vap->vap_index);
                if (vap->u.sta_info.conn_status == wifi_connection_status_connected) {
                    if (translate_mesh_sta_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                        return webconfig_error_translate_to_ovsdb;
                    }
                } else {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: connection status is %d for vap_index %d\n", __func__, __LINE__, vap->u.sta_info.conn_status, vap->vap_index);
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
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
    *row_count = count;

    for (i = 0; i < decoded_params->num_radios; i++) {
        memcpy(&webconfig_ovsdb_data.u.decoded.radios[i].vaps, &decoded_params->radios[i].vaps, sizeof(rdk_wifi_vap_map_t));
    }

    return webconfig_error_none;
}

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

webconfig_error_t translate_vap_info_to_vif_state_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    wifi_vap_mode_t vapmode_enum;

    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_cloudifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed. vap index %d\n", __func__, __LINE__, vap->vap_index);
        return webconfig_error_translate_to_ovsdb;
    }


    if (ssid_broadcast_conversion(vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), (BOOL *)&vap->u.bss_info.showSsid, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: ssid broadbcast conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vapmode_enum = vap->vap_mode;
    if (vap_mode_conversion(&vapmode_enum, vap_row->mode, ARRAY_SIZE(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed. vap mode %d\n", __func__, __LINE__, vap->vap_mode);
        return webconfig_error_translate_to_ovsdb;
    }
    sprintf(vap_row->mac, "%02x:%02x:%02x:%02x:%02x:%02x", vap->u.bss_info.bssid[0], vap->u.bss_info.bssid[1],
                                                    vap->u.bss_info.bssid[2], vap->u.bss_info.bssid[3],
                                                    vap->u.bss_info.bssid[4], vap->u.bss_info.bssid[5]);
    if (strlen(vap->repurposed_vap_name) == 0) {
        vap_row->enabled = vap->u.bss_info.enabled;
    } else {
        wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d vapname %s is repurposed as %s so disabled\n", __func__, __LINE__,vap->vap_name,vap->repurposed_vap_name);
        vap_row->enabled = false;
    }
    strncpy(vap_row->ssid, vap->u.bss_info.ssid, sizeof(vap_row->ssid));
    if (strlen(vap->bridge_name) != 0) {
        strncpy(vap_row->bridge, vap->bridge_name, sizeof(vap_row->bridge));
    } else {
        vap_row->bridge_exists = false;
    }
    vap_row->uapsd_enable = vap->u.bss_info.UAPSDEnabled;
    vap_row->ap_bridge = vap->u.bss_info.isolation;
    if (vap->u.bss_info.bssTransitionActivated) {
        vap_row->btm = vap->u.bss_info.bssTransitionActivated;
        vap_row->btm_exists = true;
    } else {
        vap_row->btm_exists = false;
    }
    if (vap->u.bss_info.nbrReportActivated) {
        vap_row->rrm = vap->u.bss_info.nbrReportActivated;
        vap_row->rrm_exists = true;
    } else {
        vap_row->rrm_exists = false;
    }

    if (vap->u.bss_info.wps.enable) {
        vap_row->wps = vap->u.bss_info.wps.enable;
        vap_row->wps_exists = true;
    } else {
        vap_row->wps_exists=false;
    }

    if (strlen(vap->u.bss_info.wps.pin) != 0) {
        strncpy(vap_row->wps_pbc_key_id, vap->u.bss_info.wps.pin, sizeof(vap_row->wps_pbc_key_id));
        vap_row->wps_pbc_key_id_exists = true;
    } else {
        vap_row->wps_pbc_key_id_exists = false;
    }
    vap_row->vlan_id = iface_map->vlan_id;
    memset(vap_row->parent, 0, sizeof(vap_row->parent));

    if(min_hw_mode_conversion(vap->vap_index, "", vap_row->min_hw_mode, "STATE") != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: No min_hw_mode_conversion warning for %d\n", __func__, __LINE__, vap->vap_index);
    }
    if(vif_radio_idx_conversion(vap->vap_index, NULL, (int *)&vap_row->vif_radio_idx, "STATE") != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: No vif_radio_idx_conversion warning for %d\n", __func__, __LINE__, vap->vap_index);
    }

    // Unset all unused parameters
    vap_row->wds_exists = false;
    vap_row->ft_mobility_domain_exists=false;

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

    SCHEMA_SET_INT(vap_row->radius_srv_port, radius->port);
    SCHEMA_SET_STR(vap_row->radius_srv_secret, radius->key);

#ifndef WIFI_HAL_VERSION_3_PHASE2
    SCHEMA_SET_STR(vap_row->radius_srv_addr, (char *)radius->ip);
#else
    getIpStringFromAdrress(vap_row->radius_srv_addr, &(radius->ip));
    vap_row->radius_srv_addr_exists = 1;
#endif
    return webconfig_error_none;
}

static webconfig_error_t translate_vap_info_to_vif_state_sec_legacy(wifi_vap_info_t *vap,
    struct schema_Wifi_VIF_State *vap_row)
{
    int index = 0;
    char str_mode[128] = {0};
    char str_encryp[128] = {0};

    if (vap->u.bss_info.security.mode == wifi_security_mode_none) {
        set_translator_state_security_key_value(vap_row, &index, "encryption", "OPEN");
        return webconfig_error_none;
    }

    if (!update_secmode_for_wpa3(vap, str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp),
        true)) {
        wifi_security_modes_t mode_enum = vap->u.bss_info.security.mode;
        wifi_encryption_method_t encryp_enum = vap->u.bss_info.security.encr;
        if (key_mgmt_conversion_legacy(&mode_enum,
            &encryp_enum, str_mode, sizeof(str_mode), str_encryp,
            sizeof(str_encryp), ENUM_TO_STRING) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert key mgmt: "
                "security mode 0x%x encr 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode,
                vap->u.bss_info.security.encr);
            return webconfig_error_translate_to_ovsdb;
        }
    }

    set_translator_state_security_key_value(vap_row, &index, "encryption", str_encryp);
    set_translator_state_security_key_value(vap_row, &index, "mode", str_mode);

    if (is_personal_sec(vap->u.bss_info.security.mode) == false) {
        return webconfig_error_none;
    }

    set_translator_state_security_key_value(vap_row, &index, "key",
        vap->u.bss_info.security.u.key.key);

    if (strnlen(vap->u.bss_info.security.key_id, sizeof(vap->u.bss_info.security.key_id) - 1) > 0) {
        set_translator_state_security_key_value(vap_row, &index, "oftag",
            vap->u.bss_info.security.key_id);
    }

    return webconfig_error_none;
}

static webconfig_error_t translate_vap_info_to_vif_state_sec_new(wifi_vap_info_t *vap,
    struct schema_Wifi_VIF_State *vap_row)
{
    int len = 0, wpa_psk_index = 0;
    wifi_security_modes_t enum_sec;

    if (vap->u.bss_info.security.mode == wifi_security_mode_none) {
        vap_row->wpa = false;
        vap_row->wpa_key_mgmt_len = 0;
        return webconfig_error_none;
    }

    enum_sec = vap->u.bss_info.security.mode;
    if (key_mgmt_conversion(&enum_sec, vap_row->wpa_key_mgmt[0],
        vap_row->wpa_key_mgmt[1], sizeof(vap_row->wpa_key_mgmt[0]),
        sizeof(vap_row->wpa_key_mgmt[1]), ENUM_TO_STRING, &len) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed top convert key mgmt: "
            "security mode 0x%x\n", __func__, __LINE__, vap->u.bss_info.security.mode);
        return webconfig_error_translate_to_ovsdb;
    }

    vap_row->wpa = true;
    vap_row->wpa_key_mgmt_len = len;

    if (!is_personal_sec(vap->u.bss_info.security.mode)) {
        return webconfig_error_none;
    }

    if (strlen(vap->u.bss_info.security.u.key.key) < MIN_PWD_LEN ||
        strlen(vap->u.bss_info.security.u.key.key) > MAX_PWD_LEN) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert: "
            "invalid password length: %d\n", __func__, __LINE__,
            strlen(vap->u.bss_info.security.u.key.key));
        return webconfig_error_translate_to_ovsdb;
    }

    set_translator_state_wpa_psks(vap_row, &wpa_psk_index, "key--1",
        vap->u.bss_info.security.u.key.key);

    return webconfig_error_none;
}

static webconfig_error_t translate_vap_info_to_vif_state_sec(wifi_vap_info_t *vap,
    struct schema_Wifi_VIF_State *vap_row, bool sec_schema_is_legacy)
{
    webconfig_error_t ret;

    if (vap_row == NULL || vap == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert: input argument is NULL\n",
            __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (macfilter_conversion(vap_row->mac_list_type, sizeof(vap_row->mac_list_type),
        vap, ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert MAC filter: "
            "mac_filter_enable: %d mac_filter_mode: %d\n", __func__, __LINE__,
            vap->u.bss_info.mac_filter_enable, vap->u.bss_info.mac_filter_mode);
        return webconfig_error_translate_to_ovsdb;
    }

    if (sec_schema_is_legacy) {
        if ((ret = translate_vap_info_to_vif_state_sec_legacy(vap,
            vap_row)) != webconfig_error_none) {
            return ret;
        }
    } else {
        if ((ret = translate_vap_info_to_vif_state_sec_new(vap,
            vap_row)) != webconfig_error_none) {
            return ret;
        }
    }

    if (vap->u.bss_info.security.rekey_interval) {
        vap_row->group_rekey = vap->u.bss_info.security.rekey_interval;
    } else {
        vap_row->group_rekey_exists = false;
    }

    if (!is_enterprise_sec(vap->u.bss_info.security.mode)) {
        return webconfig_error_none;
    }

    if (translate_vap_info_to_vif_state_radius_settings(vap, vap_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to translate radius settings\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t  translate_sta_vap_info_to_vif_state_common(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    wifi_vap_mode_t vapmode_enum;

    if ((vap == NULL) || (vap_row == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (convert_apindex_to_cloudifname(wifi_prop, vap->vap_index, vap_row->if_name, sizeof(vap_row->if_name)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap_index to if_name conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    vapmode_enum = vap->vap_mode;
    if (vap_mode_conversion(&vapmode_enum, vap_row->mode, ARRAY_SIZE(vap_row->mode), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap mode is not station moode\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    strncpy(vap_row->ssid, vap->u.sta_info.ssid, sizeof(vap_row->ssid));
    strncpy(vap_row->bridge, vap->bridge_name, sizeof(vap_row->bridge));

    vap_row->enabled = vap->u.sta_info.enabled;

    snprintf(vap_row->mac, sizeof(vap_row->mac), "%02x:%02x:%02x:%02x:%02x:%02x", vap->u.sta_info.mac[0], vap->u.sta_info.mac[1],
                                                    vap->u.sta_info.mac[2], vap->u.sta_info.mac[3],
                                                    vap->u.sta_info.mac[4], vap->u.sta_info.mac[5]);

    if (is_bssid_valid(vap->u.sta_info.bssid)) {
        snprintf(vap_row->parent, sizeof(vap_row->parent), "%02x:%02x:%02x:%02x:%02x:%02x", vap->u.sta_info.bssid[0], vap->u.sta_info.bssid[1],
                                                    vap->u.sta_info.bssid[2], vap->u.sta_info.bssid[3],
                                                    vap->u.sta_info.bssid[4], vap->u.sta_info.bssid[5]);
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap_row->parent=%s\n", __func__, __LINE__, vap_row->parent);
    }

    vap_row->vlan_id = iface_map->vlan_id;

    return webconfig_error_none;
}

webconfig_error_t translate_private_vap_info_to_vif_state(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_open_vap_info_to_vif_state(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_sec(vap, vap_row, false) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for no security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_iot_vap_info_to_vif_state(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_lnf_psk_vap_info_to_vif_state(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_secure_vap_info_to_vif_state(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_lnf_radius_secure_vap_info_to_vif_state(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_mesh_backhaul_vap_info_to_vif_state(wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_vap_info_to_vif_state_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_sta_vap_info_to_ovsdb_state_personal_sec(const wifi_vap_info_t *vap, struct schema_Wifi_VIF_State *vap_row, bool sec_schema_is_legacy)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (sec_schema_is_legacy == true) {
        int sec_index = 0;
        if (vap->u.sta_info.security.mode != wifi_security_mode_none) {
            char str_mode[128] = {0};
            char str_encryp[128] = {0};

            memset(str_mode, 0, sizeof(str_mode));
            memset(str_encryp, 0, sizeof(str_encryp));
            if (!update_secmode_for_wpa3((wifi_vap_info_t *)vap, str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp), true)) {
                wifi_security_modes_t mode_enum = vap->u.sta_info.security.mode;
                wifi_encryption_method_t encryp_enum = vap->u.sta_info.security.encr;
                if ((key_mgmt_conversion_legacy(&mode_enum, &encryp_enum, 
                    str_mode, sizeof(str_mode), str_encryp, sizeof(str_encryp), ENUM_TO_STRING)) != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
                    return webconfig_error_translate_to_ovsdb;
                }
            }

            set_translator_state_security_key_value(vap_row, &sec_index, "encryption", str_encryp);
            set_translator_state_security_key_value(vap_row, &sec_index, "mode", str_mode);
            set_translator_state_security_key_value(vap_row, &sec_index, "key", vap->u.sta_info.security.u.key.key);

        } else {
            set_translator_state_security_key_value(vap_row, &sec_index, "encryption", "OPEN");
        }
    } else {
        if (vap->u.sta_info.security.mode == wifi_security_mode_none) {
            vap_row->wpa = false;
        } else {
            int len = 0, wpa_psk_index = 0;
            wifi_security_modes_t enum_sec = vap->u.sta_info.security.mode;
            if ((key_mgmt_conversion(&enum_sec, vap_row->wpa_key_mgmt[0], vap_row->wpa_key_mgmt[1], sizeof(vap_row->wpa_key_mgmt[0]), sizeof(vap_row->wpa_key_mgmt[1]), ENUM_TO_STRING, &len)) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            vap_row->wpa = true;
            vap_row->wpa_key_mgmt_len = len;

            if ((strlen(vap->u.sta_info.security.u.key.key) < MIN_PWD_LEN) || (strlen(vap->u.sta_info.security.u.key.key) > MAX_PWD_LEN)) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
            set_translator_state_wpa_psks(vap_row, &wpa_psk_index, "key--1", vap->u.sta_info.security.u.key.key);
        }
    }

    return webconfig_error_none;
}

webconfig_error_t translate_mesh_sta_vap_info_to_vif_state(const wifi_vap_info_t *vap, const wifi_interface_name_idex_map_t *iface_map, struct schema_Wifi_VIF_State *vap_row, wifi_platform_property_t *wifi_prop,
    bool sec_schema_is_legacy)
{
    if (translate_sta_vap_info_to_vif_state_common(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_sta_vap_info_to_ovsdb_state_personal_sec(vap, vap_row, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for security\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }
    return webconfig_error_none;
}

webconfig_error_t assoclist_update_assoc_map(rdk_wifi_vap_info_t *rdk_vap_info)
{
    hash_map_t *current_assoc_map = NULL, *diff_assoc_map = NULL;
    assoc_dev_data_t *diff_assoc_dev_data = NULL, *temp_assoc_dev_data = NULL;
    mac_addr_str_t diff_mac_str;

    current_assoc_map = rdk_vap_info->associated_devices_map;
    diff_assoc_map = rdk_vap_info->associated_devices_diff_map;

    if ((current_assoc_map == NULL) || (diff_assoc_map == NULL)) {
        return webconfig_error_none;
    }

    diff_assoc_dev_data = hash_map_get_first(diff_assoc_map);
    while (diff_assoc_dev_data != NULL) {
        to_mac_str(diff_assoc_dev_data->dev_stats.cli_MACAddress, diff_mac_str);
        str_tolower(diff_mac_str);
        if (diff_assoc_dev_data->client_state == client_state_disconnected) {
            //in disconnected state, remove diff_mac from current_assoc_map
            temp_assoc_dev_data = hash_map_remove(current_assoc_map, diff_mac_str);
            if (temp_assoc_dev_data != NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: diff mac : %s is removed from current assoc map for index : %d\n",
                        __func__, __LINE__, diff_mac_str, diff_assoc_dev_data->ap_index);
                free(temp_assoc_dev_data);
            } else {
                wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: diff mac : %s is not present in current assoc map for index : %d\n",
                        __func__, __LINE__, diff_mac_str, diff_assoc_dev_data->ap_index);
            }
        } else if (diff_assoc_dev_data->client_state == client_state_connected) {
            //in connected state, add diff_mac to current_assoc_map
            temp_assoc_dev_data = hash_map_get(current_assoc_map, diff_mac_str);
            if (temp_assoc_dev_data == NULL) {
                temp_assoc_dev_data = (assoc_dev_data_t *)malloc(sizeof(assoc_dev_data_t));
                if (temp_assoc_dev_data == NULL) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: allocate memory failed for diff mac : %s for index : %d\n",
                            __func__, __LINE__, diff_mac_str, diff_assoc_dev_data->ap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                memcpy(temp_assoc_dev_data, diff_assoc_dev_data, sizeof(assoc_dev_data_t));
                hash_map_put(current_assoc_map, strdup(diff_mac_str), temp_assoc_dev_data);
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: diff mac : %s is added to current assoc map for index : %d\n",
                        __func__, __LINE__, diff_mac_str, diff_assoc_dev_data->ap_index);
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: diff mac : %s is already present in current assoc map for index : %d, updating\n",
                        __func__, __LINE__, diff_mac_str, diff_assoc_dev_data->ap_index);
                memcpy(temp_assoc_dev_data, diff_assoc_dev_data, sizeof(assoc_dev_data_t));
            }
        }
        diff_assoc_dev_data = hash_map_get_next(diff_assoc_map, diff_assoc_dev_data);
    }

    return webconfig_error_none;
}

webconfig_error_t translate_vap_object_to_ovsdb_associated_clients(const rdk_wifi_vap_info_t *rdk_vap_info, const struct schema_Wifi_Associated_Clients **clients_table, unsigned int *client_count, wifi_platform_property_t *wifi_prop, assoclist_notifier_type_t assoclist_notifier_type)
{
    assoc_dev_data_t *assoc_dev_data = NULL;
    struct schema_Wifi_Associated_Clients *client_row;
    unsigned int associated_client_count = 0;
    assoc_dev_data_t *diff_assoc_dev_data;
    hash_map_t *diff_assoc_map = NULL;
    mac_addr_str_t diff_mac_str;

    if ((rdk_vap_info == NULL) || (clients_table == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Input arguments are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (assoclist_notifier_type == assoclist_notifier_diff) {
        if (assoclist_update_assoc_map((rdk_wifi_vap_info_t *)rdk_vap_info) != webconfig_error_none) {
            return webconfig_error_translate_to_ovsdb;
        }
        diff_assoc_map = rdk_vap_info->associated_devices_diff_map;
    }

    associated_client_count = *client_count;
    if (rdk_vap_info->associated_devices_map != NULL) {
        assoc_dev_data = hash_map_get_first(rdk_vap_info->associated_devices_map);

        while (assoc_dev_data != NULL) {

            if (associated_client_count >= WEBCONFIG_MAX_ASSOCIATED_CLIENTS) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Exceeded max number of associated clients %d, vap_name '%s'\n", __func__, __LINE__, WEBCONFIG_MAX_ASSOCIATED_CLIENTS, rdk_vap_info->vap_name);
                break;
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

            strncpy(client_row->wpa_key_mgmt, assoc_dev_data->conn_security.wpa_key_mgmt, sizeof(client_row->wpa_key_mgmt));
            strncpy(client_row->pairwise_cipher, assoc_dev_data->conn_security.pairwise_cipher, sizeof(client_row->pairwise_cipher));

            if ((strlen( assoc_dev_data->dev_stats.cli_OperatingStandard) != 0)) {
                snprintf(client_row->capabilities[0], sizeof(client_row->capabilities[0]), "11%s", assoc_dev_data->dev_stats.cli_OperatingStandard);
            } else {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Invalid Capabilities\n", __func__, __LINE__);
                //return webconfig_error_translate_to_ovsdb;
            }
            if (convert_vapname_to_cloudifname((char *)rdk_vap_info->vap_name, client_row->_uuid.uuid, sizeof(client_row->_uuid.uuid)) != RETURN_OK) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vapname to interface name conversion failed, vap_name '%s'\n", __func__, __LINE__, rdk_vap_info->vap_name);
                return webconfig_error_translate_to_ovsdb;
            }
            if (assoclist_notifier_type == assoclist_notifier_diff) {
                memset(diff_mac_str, 0, sizeof(diff_mac_str));
                to_mac_str(assoc_dev_data->dev_stats.cli_MACAddress, diff_mac_str);
                str_tolower(diff_mac_str);
                //As associated_devices_map connected has only connected client, check for the clients in diff_map and in diffmap its present then its reconnect
                if (diff_assoc_map != NULL)
                {
                    diff_assoc_dev_data = hash_map_get(diff_assoc_map, diff_mac_str);
                    if (diff_assoc_dev_data != NULL) {
                        strncpy(client_row->kick_keys[0], "state",sizeof(client_row->kick_keys[0]));
                        strncpy(client_row->kick[0], "reconnected",sizeof(client_row->kick[0]));
                        client_row->kick_len = 1;
                        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: client %s reconnected.\n", __func__, __LINE__, diff_mac_str);
                    }
                }
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

            if (translate_vap_object_to_ovsdb_associated_clients(&decoded_params->radios[i].vaps.rdk_vap_array[j], clients_table, &client_count, &decoded_params->hal_cap.wifi_prop, decoded_params->assoclist_notifier_type) != webconfig_error_none) {
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
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    //  struct schema_Wifi_Credential_Config **cred_table;
    //   struct schema_Wifi_Credential_Config  *cred_row;

    unsigned int presence_mask = 0;
    unsigned int count = 0, *row_count = NULL;
    unsigned int dml_vap_mask = 0;
    bool sec_schema_is_legacy;
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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
        if ((radio->vaps.num_vaps == 0) || (radio->vaps.num_vaps > MAX_NUM_VAP_PER_RADIO)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of vaps: %x\n", __func__, __LINE__, radio->vaps.num_vaps);
            return webconfig_error_invalid_subdoc;
        }
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            rdk_vap = &radio->vaps.rdk_vap_array[j];

            if (convert_vapname_to_cloudifname(rdk_vap->vap_name,
                    proto->vap_info[proto->num_vaps].if_name,
                    sizeof(proto->vap_info[proto->num_vaps].if_name)) != RETURN_OK) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap name to interface name "
                    "conversion failed for %s\n", __func__, __LINE__, rdk_vap->vap_name);
                return webconfig_error_translate_to_ovsdb;
            }
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if(rdk_vap->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap->vap_index != 2 && vap->vap_index != 3) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap->vap_index);
                    rdk_vap->exists = true;
                }
#else
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap->vap_index);
                rdk_vap->exists = true;
#endif /*_SR213_PRODUCT_REQ_*/
            }
#endif /*!defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)*/
            proto->vap_info[proto->num_vaps].exists = rdk_vap->exists;
            proto->num_vaps++;

            if (rdk_vap->exists == false) {
                presence_mask |= (1 << vap->vap_index);
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
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the interface map entry for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            vap_row = (struct schema_Wifi_VIF_State *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (radio->oper.channel) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Updating Channel %d to %s\n", __func__, __LINE__,radio->oper.channel, vap->vap_name);
                vap_row->channel = radio->oper.channel;
            }

            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_iot_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_hotspot_open(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_hotspot_open_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_lnf_psk_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_hotspot_secure(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_hotspot_secure_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_secure_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh backhaul to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh sta to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
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
    *row_count = count;

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

static webconfig_error_t translate_ovsdb_to_vap_info_sec_legacy(const struct
    schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    const char *str_encryp, *str_mode, *val;

    str_encryp = security_config_find_by_key(vap_row, "encryption");
    if (str_encryp == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert: encryption is NULL\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (!strcmp(str_encryp, "OPEN")) {
        vap->u.bss_info.security.mode = wifi_security_mode_none;
        return webconfig_error_none;
    }

    str_mode = security_config_find_by_key(vap_row, "mode");
    if (str_mode == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert: mode is NULL\n", __func__,
            __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (!update_secmode_for_wpa3(vap, (char *)str_mode, strlen(str_mode) + 1, (char *)str_encryp,
        strlen(str_encryp) + 1, false)) {
        wifi_security_modes_t mode_enum;
        wifi_encryption_method_t encryp_enum = vap->u.bss_info.security.encr;
        if (key_mgmt_conversion_legacy(&mode_enum,
            &encryp_enum, (char *)str_mode, strlen(str_mode) + 1,
            (char *)str_encryp, strlen(str_encryp) + 1, STRING_TO_ENUM) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert key mgmt: %s\n",
                __func__, __LINE__, str_mode);
            return webconfig_error_translate_from_ovsdb;
        }
        vap->u.bss_info.security.mode = mode_enum;
        vap->u.bss_info.security.encr = encryp_enum;
    }

    if (!is_personal_sec(vap->u.bss_info.security.mode)) {
        return webconfig_error_none;
    }

    val = security_config_find_by_key(vap_row, "key");
    if (val == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d failed to find key\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (strlen(val) < MIN_PWD_LEN || strlen(val) > MAX_PWD_LEN) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d failed to convert: "
            "invalid password length: %d\n", __func__, __LINE__, strlen(val));
        return webconfig_error_translate_from_ovsdb;
    }

    snprintf(vap->u.bss_info.security.u.key.key, sizeof(vap->u.bss_info.security.u.key.key), "%s",
        val);

    val = security_config_find_by_key(vap_row, "oftag");
    if (val != NULL) {
        snprintf(vap->u.bss_info.security.key_id, sizeof(vap->u.bss_info.security.key_id), "%s",
            val);
    }

    return webconfig_error_none;
}

static webconfig_error_t translate_ovsdb_to_vap_info_sec_new(const struct
    schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    int len = 0;
    wifi_security_modes_t enum_sec;

    if (vap_row->wpa == false) {
        vap->u.bss_info.security.mode = wifi_security_mode_none;
    } else {
        if (vap_row->wpa_key_mgmt_len == 0)  {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d wpa_key_mgmt_len is 0\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if (key_mgmt_conversion(&enum_sec, (char *)vap_row->wpa_key_mgmt[0],
            (char *)vap_row->wpa_key_mgmt[1], sizeof(vap_row->wpa_key_mgmt[0]),
            sizeof(vap_row->wpa_key_mgmt[1]), STRING_TO_ENUM, &len) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert key mgmt: %s\n",
                __func__, __LINE__, vap_row->wpa_key_mgmt[0] ? vap_row->wpa_key_mgmt[0] : "NULL");
            return webconfig_error_translate_from_ovsdb;
        }
        vap->u.bss_info.security.mode = enum_sec;
    }

    get_translator_config_wpa_mfp(vap);

    if (!is_personal_sec(vap->u.bss_info.security.mode)) {
        return webconfig_error_none;
    }

    if (vap_row->wpa_psks_len == 0)  {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d failed to convert: wpa_psks_len is 0\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (strlen(vap_row->wpa_psks[0]) < MIN_PWD_LEN || strlen(vap_row->wpa_psks[0]) > MAX_PWD_LEN) {
        wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d failed to convert: "
            "invalid password length: %d\n", __func__, __LINE__, strlen(vap_row->wpa_psks[0]));
        return webconfig_error_translate_from_ovsdb;
    }

    get_translator_config_wpa_psks(vap_row, vap, 0);
    get_translator_config_wpa_oftags(vap_row, vap, 0);

    return webconfig_error_none;
}

static webconfig_error_t translate_ovsdb_to_vap_info_sec(const struct
    schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap, bool sec_schema_is_legacy)
{
    webconfig_error_t ret;

    if (vap_row == NULL || vap == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (macfilter_conversion((char *)vap_row->mac_list_type, sizeof(vap_row->mac_list_type),
        vap, STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to convert MAC filter: "
            "mac_filter_enable: %d mac_filter_mode: %d\n", __func__, __LINE__,
            vap->u.bss_info.mac_filter_enable, vap->u.bss_info.mac_filter_mode);
        return webconfig_error_translate_from_ovsdb;
    }

    if (sec_schema_is_legacy) {
        if ((ret = translate_ovsdb_to_vap_info_sec_legacy(vap_row, vap)) != webconfig_error_none) {
            return ret;
        }
    } else {
        if ((ret = translate_ovsdb_to_vap_info_sec_new(vap_row, vap)) != webconfig_error_none) {
            return ret;
        }
    }

    vap->u.bss_info.security.rekey_interval = vap_row->group_rekey;

    if (!is_enterprise_sec(vap->u.bss_info.security.mode)) {
        return webconfig_error_none;
    }

    if (translate_ovsdb_to_vap_info_radius_settings(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d failed to translate radius settings\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


void remove_colon_from_mac(const char *mac_row, char *mac_wo_colon)
{
    int wo_colon_loop = 0;
    int with_colon_loop = 0;

    if ((mac_row == NULL) || (mac_wo_colon == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d Incoming Argument is NULL\n", __func__, __LINE__);
        return;
    }

    for (with_colon_loop = 0; with_colon_loop < 17; with_colon_loop++) {
        if ((*(mac_row + with_colon_loop)) != ':') {
            *(mac_wo_colon + wo_colon_loop) = *(mac_row + with_colon_loop);
        } else {
            continue;
        }
        wo_colon_loop++;
    }
    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d Incoming MAC : %s Outgoing MAC : %s\n", __func__, __LINE__, mac_row, mac_wo_colon);
}

webconfig_error_t translate_ovsdb_to_blaster_info_common(const struct schema_Wifi_Blaster_Config *blaster_row, const char *blaster_mqtt_topic, active_msmt_t *blaster_info)
{
    if ((blaster_row == NULL) || (blaster_info == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    unsigned int mqtt_len = 0;
    mqtt_len = strlen(blaster_mqtt_topic);
    memset(blaster_info, 0, sizeof(active_msmt_t));
    strncpy((char *)blaster_info->PlanId, blaster_row->plan_id, strlen(blaster_row->plan_id));
    blaster_info->PlanId[strlen((char *)blaster_info->PlanId)] = '\0';
    blaster_info->ActiveMsmtNumberOfSamples = blaster_row->blast_sample_count;
    blaster_info->ActiveMsmtSampleDuration = blaster_row->blast_duration;
    blaster_info->ActiveMsmtPktSize = blaster_row->blast_packet_size;

    for (int i = 0; i < blaster_row->step_id_and_dest_len; i++)
    {
        blaster_info->Step[i].StepId = atoi(blaster_row->step_id_and_dest_keys[i]);
        char mac_str_without_colon[MAC_ADDRESS_LENGTH] = {'\0'};
        remove_colon_from_mac(blaster_row->step_id_and_dest[i], mac_str_without_colon);
        strncpy((char *)blaster_info->Step[i].DestMac, mac_str_without_colon, MAC_ADDRESS_LENGTH);
        blaster_info->Step[i].DestMac[MAC_ADDRESS_LENGTH - 1] = '\0';
    }

    blaster_info->ActiveMsmtEnable = true;
    blaster_info->Status = blaster_state_new;

    if (blaster_mqtt_topic == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d:MQTT topic is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    else {
        if ((mqtt_len > 0) && (mqtt_len <= MAX_MQTT_TOPIC_LEN)) {
            strncpy((char *)blaster_info->blaster_mqtt_topic, blaster_mqtt_topic, mqtt_len);
            blaster_info->blaster_mqtt_topic[strlen((char *)blaster_info->blaster_mqtt_topic)] = '\0';
        }    
    }
    return webconfig_error_none;
}

webconfig_error_t translate_ovsdb_to_vap_info_common(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    wifi_vap_mode_t vapmode_enum;

    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    if (strlen(vap->repurposed_vap_name) != 0) {
       wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d vapname %s is repurposed as %s so disabled\n", __func__, __LINE__,vap->vap_name,vap->repurposed_vap_name);
       return webconfig_error_none;
    }


    if (vap_mode_conversion(&vapmode_enum, (char *)vap_row->mode, ARRAY_SIZE(vap_row->mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed. mode '%s'\n", __func__, __LINE__, (vap_row->mode) ? vap_row->mode : "NULL");
        return webconfig_error_translate_from_ovsdb;
    }
    vap->vap_mode = vapmode_enum;

    if (ssid_broadcast_conversion((char *)vap_row->ssid_broadcast, sizeof(vap_row->ssid_broadcast), &vap->u.bss_info.showSsid, STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: ssid broadcast conversion failed. ssid_broadcast '%s'\n", __func__, __LINE__, (vap_row->ssid_broadcast) ? vap_row->ssid_broadcast : "NULL");
        return webconfig_error_translate_from_ovsdb;
    }

    vap->u.bss_info.enabled = vap_row->enabled;

    if  (is_ssid_name_valid((char *)vap_row->ssid) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid ssid name. ssid '%s'\n", __func__, __LINE__, vap_row->ssid);
        return webconfig_error_translate_from_ovsdb;
    }
    snprintf(vap->u.bss_info.ssid,sizeof(vap->u.bss_info.ssid),"%s",vap_row->ssid);
    snprintf(vap->bridge_name,sizeof(vap->bridge_name),"%s",vap_row->bridge);
    vap->u.bss_info.UAPSDEnabled = vap_row->uapsd_enable;
    vap->u.bss_info.isolation = vap_row->ap_bridge;
    vap->u.bss_info.bssTransitionActivated = vap_row->btm;
    vap->u.bss_info.nbrReportActivated = vap_row->rrm;
    vap->u.bss_info.wps.enable = vap_row->wps;
    snprintf(vap->u.bss_info.wps.pin, sizeof(vap->u.bss_info.wps.pin),"%s",vap_row->wps_pbc_key_id);
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vapIndex : %d min_hw_mode %s\n", __func__, __LINE__, vap->vap_index, vap_row->min_hw_mode);
    min_hw_mode_conversion(vap->vap_index, (char *)vap_row->min_hw_mode, "", "CONFIG");
    vif_radio_idx_conversion(vap->vap_index, (int *)&vap_row->vif_radio_idx, NULL, "CONFIG");

    return webconfig_error_none;
}

webconfig_error_t translate_private_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap,
    bool sec_schema_is_legacy)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_sec(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_blaster_config_to_blast_info(const struct schema_Wifi_Blaster_Config *blaster_row, const char *blaster_mqtt_topic, active_msmt_t *blaster_info)
{
    if (translate_ovsdb_to_blaster_info_common(blaster_row, blaster_mqtt_topic, blaster_info) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_iot_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap, bool sec_schema_is_legacy)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_sec(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
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

    if (translate_ovsdb_to_vap_info_sec(vap_row, vap, false) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for no security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_hotspot_secure_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap,
    bool sec_schema_is_legacy)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_sec(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_lnf_radius_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap,
    bool sec_schema_is_legacy)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_sec(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for enterprise security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_lnf_psk_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap, bool sec_schema_is_legacy)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_sec(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_mesh_backhaul_vif_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap, bool sec_schema_is_legacy)
{
    if (translate_ovsdb_to_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_to_vap_info_sec(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for personal security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t translate_ovsdb_to_sta_vap_info_common(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap)
{
    wifi_vap_mode_t vapmode_enum;

    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (vap_mode_conversion(&vapmode_enum, (char *)vap_row->mode, ARRAY_SIZE(vap_row->mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode conversion failed. mode '%s'\n", __func__, __LINE__, (vap_row->mode) ? vap_row->mode : "NULL");
        return webconfig_error_translate_from_ovsdb;
    }
    vap->vap_mode = vapmode_enum;

    if (vap->vap_mode != wifi_vap_mode_sta) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vap mode is not station mode\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    vap->u.sta_info.enabled = vap_row->enabled;
    snprintf(vap->bridge_name,sizeof(vap->bridge_name),"%s",vap_row->bridge);
    str_to_mac_bytes((char *)vap_row->parent, vap->u.sta_info.bssid);
    snprintf(vap->u.sta_info.ssid, sizeof(vap->u.sta_info.ssid), "%s", vap_row->ssid);

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Parent : %s bssid : %02x%02x%02x%02x%02x%02x SSID: %s\n", __func__, __LINE__, vap_row->parent,
            vap->u.sta_info.bssid[0], vap->u.sta_info.bssid[1],
            vap->u.sta_info.bssid[2], vap->u.sta_info.bssid[3],
            vap->u.sta_info.bssid[4], vap->u.sta_info.bssid[5],
            vap->u.sta_info.ssid);

    return webconfig_error_none;
}


webconfig_error_t translate_ovsdb_config_to_vap_info_personal_sec(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap, bool sec_schema_is_legacy)
{
    if ((vap_row == NULL) || (vap == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input argument is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (sec_schema_is_legacy == true) {
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
        } else {
            str_mode = security_config_find_by_key(vap_row, "mode");
            if (str_mode == NULL) {
                // mode is optional for sta
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: mode is NULL, skipping\n", __func__, __LINE__);
            } else {
                if (!update_secmode_for_wpa3((wifi_vap_info_t *)vap, (char *)str_mode, strlen(str_mode)+1, (char *)str_encryp, strlen(str_encryp)+1, false)) {
                    wifi_security_modes_t mode_enum;
                    wifi_encryption_method_t encryp_enum = vap->u.sta_info.security.encr;
                    if ((key_mgmt_conversion_legacy(&mode_enum, &encryp_enum, (char *)str_mode, strlen(str_mode)+1, (char *)str_encryp, strlen(str_encryp)+1, STRING_TO_ENUM)) != RETURN_OK) {
                        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. str_mode '%s'\n", __func__, __LINE__, str_mode);
                        return webconfig_error_translate_from_ovsdb;
                    }
                    vap->u.sta_info.security.mode = mode_enum;
                    vap->u.sta_info.security.encr = encryp_enum;
                }
            }

            val = security_config_find_by_key(vap_row, "key");
            if (val == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key is NULL\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }

            if ((strlen(val) < MIN_PWD_LEN) || (strlen(val) > MAX_PWD_LEN)) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length %d\n", __func__, __LINE__, strlen(val));
                return webconfig_error_translate_from_ovsdb;
            }

            snprintf(vap->u.sta_info.security.u.key.key, sizeof(vap->u.sta_info.security.u.key.key), "%s", val);

            val = security_config_find_by_key(vap_row, "oftag");
            if (val == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d:  oftag is empty, Skiping..\n", __func__, __LINE__);
            } else {
                snprintf(vap->u.sta_info.security.key_id, sizeof(vap->u.sta_info.security.key_id), "%s", val);
            }
        }
    } else {
        if (vap_row->wpa == false) {
            vap->u.sta_info.security.mode = wifi_security_mode_none;
        } else {
            int len = 0;
            wifi_security_modes_t enum_sec;

            if (vap_row->wpa_key_mgmt_len == 0)  {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: wpa_key_mgmt_len is 0\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }

            if ((key_mgmt_conversion(&enum_sec, (char *)vap_row->wpa_key_mgmt[0], (char *)vap_row->wpa_key_mgmt[1], sizeof(vap_row->wpa_key_mgmt[0]), sizeof(vap_row->wpa_key_mgmt[1]), STRING_TO_ENUM, &len)) != RETURN_OK) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: key mgmt conversion failed. wpa_key_mgmt '%s'\n", __func__, __LINE__, 
                    (vap_row->wpa_key_mgmt[0]) ? vap_row->wpa_key_mgmt[0]: "NULL");
                return webconfig_error_translate_from_ovsdb;
            }
            vap->u.sta_info.security.mode = enum_sec;

            if (vap_row->wpa_psks_len == 0)  {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: wpa_psks_len is 0\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }

            if ((strlen(vap_row->wpa_psks[0]) < MIN_PWD_LEN) || (strlen(vap_row->wpa_psks[0]) > MAX_PWD_LEN)) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Invalid password length %d\n", __func__, __LINE__, strlen(vap_row->wpa_psks[0]));
                return webconfig_error_translate_from_ovsdb;
            }

            get_translator_config_wpa_psks(vap_row, vap, 1);
            get_translator_config_wpa_oftags(vap_row, vap, 1);

        }
    }

    vap->u.sta_info.security.rekey_interval = vap_row->group_rekey;
    return webconfig_error_none;
}

webconfig_error_t translate_mesh_sta_vap_config_to_vap_info(const struct schema_Wifi_VIF_Config *vap_row, wifi_vap_info_t *vap,
    bool sec_schema_is_legacy)
{
    if (translate_ovsdb_to_sta_vap_info_common(vap_row, vap) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for common\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (translate_ovsdb_config_to_vap_info_personal_sec(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation failed for security\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

static webconfig_error_t set_deleted_entries_to_default(webconfig_subdoc_data_t *data,
    unsigned int *presence_mask, unsigned int vap_mask)
{
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_vap_info_t *vap, *default_vap;
    rdk_wifi_radio_t *radio, *default_radio;
    uint8_t radio_index, vap_arr_index, missing_vap_index = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    webconfig_subdoc_decoded_data_t *decoded_params = &data->u.decoded;
    unsigned int missing_vap_index_map = *presence_mask ^ vap_mask;

    while (missing_vap_index_map) {
        if (missing_vap_index_map & 0x01) {
            if (get_vap_and_radio_index_from_vap_instance(wifi_prop, missing_vap_index,
                    &radio_index, &vap_arr_index) == RETURN_ERR) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: failed to get radio and vap array"
                    " index for vap index %u\n", __func__, __LINE__, missing_vap_index);
                return webconfig_error_translate_from_ovsdb;
            }

            radio = &decoded_params->radios[radio_index];
            default_radio = &webconfig_ovsdb_default_data.u.decoded.radios[radio_index];

            vap = &radio->vaps.vap_map.vap_array[vap_arr_index];
            default_vap = &default_radio->vaps.vap_map.vap_array[vap_arr_index];
            rdk_vap = &radio->vaps.rdk_vap_array[vap_arr_index];
            memcpy(vap, default_vap, sizeof(wifi_vap_info_t));

#ifndef CCSP_COMMON // If a VAP row is deleted POD interface MUST be disabled. 
            if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Setting STA VAP state to false [%s]\n", __func__, __LINE__,vap->vap_name);
                vap->u.sta_info.enabled = false;
            }
#endif
            radio->vaps.vap_map.num_vaps = default_radio->vaps.vap_map.num_vaps;
            rdk_vap->exists = false;
            *presence_mask  |= (1 << missing_vap_index);
        }

        missing_vap_index_map >>= 1;
        missing_vap_index += 1;
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
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int vap_mask, presence_mask;
    wifi_platform_property_t *wifi_prop;
    bool sec_schema_is_legacy;

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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

    presence_mask = 0;
    wifi_prop = &decoded_params->hal_cap.wifi_prop;
    vap_mask = create_vap_mask(wifi_prop, 8, VAP_PREFIX_PRIVATE, VAP_PREFIX_IOT,
        VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE, VAP_PREFIX_MESH_BACKHAUL,
        VAP_PREFIX_MESH_STA, VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS);

    if (proto->vif_config_row_count > (MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: invalid vif config row count : %x\n", __func__, __LINE__, proto->vif_config_row_count);
        return webconfig_error_translate_to_ovsdb;
    }

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_cloudifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert cloud ifname to vapname failed, if_name '%s'\n", __func__, __LINE__, table[i]->if_name);
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
        rdk_vap = &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap->exists = true;

        if (is_vap_private(wifi_prop, vap_index) == TRUE) {
            if (translate_private_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_xhs(wifi_prop, vap_index) == TRUE) {
            if (translate_iot_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
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
            if (translate_lnf_psk_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_hotspot_secure(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_secure_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_lnf_radius(wifi_prop, vap_index) == TRUE) {
            if (translate_lnf_radius_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf radius to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_backhaul(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_backhaul_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh backhaul failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_sta(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_sta_vap_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh sta failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }
    }

    if (set_deleted_entries_to_default(data, &presence_mask, vap_mask) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to set deleted entries to default\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (presence_mask != vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

int set_translator_stats_config_key_value(
        struct schema_Wifi_Stats_Config *config,
        int *index,
        const char *key,
        unsigned int value)
{
    strcpy(config->threshold_keys[*index], key);
    config->threshold[*index] = value;
 
    *index += 1;
    config->threshold_len = *index;

    return *index;
}

webconfig_error_t translate_statsconfig_from_rdk_to_ovsdb(struct schema_Wifi_Stats_Config *config_row,  const stats_config_t *stat_config)
{

    int i, index = 0;
    if ((config_row == NULL) || (stat_config == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguements are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (stats_type_conversion((stats_type_t *)&stat_config->stats_type, config_row->stats_type, sizeof(config_row->stats_type), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: stats_type_conversion failed for %s\n", __func__, __LINE__, config_row->stats_type);
        return webconfig_error_translate_to_ovsdb;
    }

    if (report_type_conversion((reporting_type_t *)&stat_config->report_type,config_row->report_type, sizeof(config_row->report_type), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: report_type_conversion failed for %s\n", __func__, __LINE__, config_row->report_type);
        return webconfig_error_translate_to_ovsdb;
    }

    if (survey_type_conversion((survey_type_t *)&stat_config->survey_type, config_row->survey_type, sizeof(config_row->survey_type), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: survey_type_conversion failed for %s\n", __func__, __LINE__, config_row->report_type);
        return webconfig_error_translate_to_ovsdb;
    }

    if (freq_band_conversion((wifi_freq_bands_t *)&stat_config->radio_type, config_row->radio_type, sizeof(config_row->radio_type), ENUM_TO_STRING) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    for (i = 0;i < stat_config->channels_list.num_channels; i++) {
        config_row->channel_list[i] = stat_config->channels_list.channels_list[i];
    }

    config_row->channel_list_len = stat_config->channels_list.num_channels;
    config_row->reporting_interval = stat_config->reporting_interval;
    config_row->reporting_count = stat_config->reporting_count;
    config_row->sampling_interval = stat_config->sampling_interval;
    config_row->survey_interval_ms = stat_config->survey_interval;
#ifdef _64BIT_ARCH_SUPPORT_
    set_translator_stats_config_key_value(config_row, &index, "util", ((long int)stat_config->threshold_util));
    set_translator_stats_config_key_value(config_row, &index, "max_delay", ((long int)stat_config->threshold_max_delay));
#else
    set_translator_stats_config_key_value(config_row, &index, "util", stat_config->threshold_util);
    set_translator_stats_config_key_value(config_row, &index, "max_delay", stat_config->threshold_max_delay);
#endif
    return webconfig_error_none;
}

webconfig_error_t  translate_config_to_ovsdb_for_stats_config(webconfig_subdoc_data_t *data)
{
    struct schema_Wifi_Stats_Config **table;
    webconfig_external_ovsdb_t *proto;
    stats_config_t *stat_config_entry;
    int count = 0;
    struct schema_Wifi_Stats_Config *stat_row;
    unsigned int *row_count = NULL;

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    table = (struct schema_Wifi_Stats_Config **)proto->stats_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: stats_config table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (data->u.decoded.stats_config_map != NULL) {
        stat_config_entry = hash_map_get_first(data->u.decoded.stats_config_map);
        while (stat_config_entry != NULL) {
            stat_row = (struct schema_Wifi_Stats_Config *)table[count];
            if (stat_row == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: stat_row is NULL\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_statsconfig_from_rdk_to_ovsdb(stat_row, stat_config_entry) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
            count++;
            stat_config_entry = hash_map_get_next(data->u.decoded.stats_config_map, stat_config_entry);
        }
    }
    row_count = (unsigned int *)&proto->stats_row_count;
    *row_count = count;
    return webconfig_error_none;
}


webconfig_error_t translate_statsconfig_from_ovsdb_to_rdk(const struct schema_Wifi_Stats_Config *config_row, stats_config_t *stat_config)
{
    int i = 0;
    char key[32] = {0};
    unsigned char id[32] = {0};
    if ((config_row == NULL) || (stat_config == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguements are NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (stats_type_conversion(&stat_config->stats_type, (char *)config_row->stats_type, sizeof(config_row->stats_type), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: stats_type_conversion failed for %s\n", __func__, __LINE__, config_row->stats_type);
        return webconfig_error_translate_from_ovsdb;
    }

    if (report_type_conversion(&stat_config->report_type,(char *) config_row->report_type, sizeof(config_row->report_type), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: report_type_conversion warning for %s\n", __func__, __LINE__, config_row->report_type);
        //return webconfig_error_translate_from_ovsdb;
    }

    if (survey_type_conversion(&stat_config->survey_type, (char *)config_row->survey_type, sizeof(config_row->survey_type), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: survey_type_conversion warning for %s\n", __func__, __LINE__, config_row->report_type);
        //return webconfig_error_translate_from_ovsdb;
    }

    if (freq_band_conversion(&stat_config->radio_type, (char *)config_row->radio_type, sizeof(config_row->radio_type), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    for (i = 0;i < config_row->channel_list_len; i++) {
        stat_config->channels_list.channels_list[i] = config_row->channel_list[i];
    }

    stat_config->channels_list.num_channels = config_row->channel_list_len;
    stat_config->reporting_interval = config_row->reporting_interval;
    stat_config->reporting_count = config_row->reporting_count;
    stat_config->sampling_interval = config_row->sampling_interval;
    stat_config->survey_interval = config_row->survey_interval_ms;

    for (i = 0; i < config_row->threshold_len; i++) {
        if (strcmp(config_row->threshold_keys[i], "util" ) == 0) {
            stat_config->threshold_util = config_row->threshold[i];
        } else if (strcmp(config_row->threshold_keys[i], "max_delay" ) == 0) {
            stat_config->threshold_max_delay = config_row->threshold[i];
        }
    }
    memset(key, 0, sizeof(key));
    memset(id, 0, sizeof(id));
    if (get_stats_cfg_id(key, sizeof(key), id, sizeof(id), stat_config->stats_type, stat_config->report_type,
                stat_config->radio_type, stat_config->survey_type) == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: get_stats_cfg_id failed for %d\n", __func__, __LINE__, i);
        return webconfig_error_translate_from_ovsdb;
    }
    snprintf(stat_config->stats_cfg_id, sizeof(stat_config->stats_cfg_id), "%s", key);

    return webconfig_error_none;
}

webconfig_error_t  translate_config_from_ovsdb_for_stats_config(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_Stats_Config **table;
    struct schema_Wifi_Stats_Config *config_row;
    webconfig_external_ovsdb_t *proto;
    stats_config_t    *stat_config_entry;
    stats_config_t    temp_stat_config_entry;
    unsigned int i = 0;

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->stats_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: stats table is NULL\n", __func__, __LINE__);
        return webconfig_error_none;
    }

    data->u.decoded.stats_config_map = hash_map_create();
    if (data->u.decoded.stats_config_map == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: stats_config_map is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: proto->stats_row_count : %d\n", __func__, __LINE__, proto->stats_row_count);
    for (i = 0; i < proto->stats_row_count; i++) {
        config_row = (struct schema_Wifi_Stats_Config *)table[i];
        if (config_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: config_row is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }
        memset(&temp_stat_config_entry, 0, sizeof(stats_config_t));
        if (translate_statsconfig_from_ovsdb_to_rdk(config_row, &temp_stat_config_entry) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: translation of stat_config failed for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }

        stat_config_entry = NULL;
        stat_config_entry = (stats_config_t *)malloc(sizeof(stats_config_t));
        if (stat_config_entry == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: stat_config is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }
        memset(stat_config_entry, 0, sizeof(stats_config_t));
        memcpy(stat_config_entry, &temp_stat_config_entry, sizeof(stats_config_t));
        hash_map_put(data->u.decoded.stats_config_map, strdup(temp_stat_config_entry.stats_cfg_id), stat_config_entry);
    }

    return webconfig_error_none;
}

webconfig_error_t translate_steerconfig_from_ovsdb_to_rdk(const struct schema_Band_Steering_Config *config_row, steering_config_t *st_cfg, wifi_platform_property_t *wifi_prop)
{
    char key[64] = {0};
    unsigned char id[64] = {0};
    int vap_name_list_len = 0;
    if ((config_row == NULL) || (st_cfg == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguement is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    st_cfg->chan_util_avg_count = config_row->chan_util_avg_count;
    st_cfg->chan_util_check_sec = config_row->chan_util_check_sec;
    st_cfg->chan_util_hwm = config_row->chan_util_hwm;
    st_cfg->chan_util_lwm = config_row->chan_util_lwm;
    st_cfg->dbg_2g_raw_chan_util = config_row->dbg_2g_raw_chan_util;
    st_cfg->dbg_2g_raw_rssi = config_row->dbg_2g_raw_rssi;
    st_cfg->dbg_5g_raw_chan_util = config_row->dbg_5g_raw_chan_util;
    st_cfg->dbg_5g_raw_rssi = config_row->dbg_5g_raw_rssi;
    st_cfg->debug_level = config_row->debug_level;
    st_cfg->def_rssi_inact_xing = config_row->def_rssi_inact_xing;
    st_cfg->def_rssi_low_xing = config_row->def_rssi_low_xing;
    st_cfg->gw_only = config_row->gw_only;
    st_cfg->inact_check_sec = config_row->inact_check_sec;
    st_cfg->inact_tmout_sec_normal = config_row->inact_tmout_sec_normal;
    st_cfg->inact_tmout_sec_overload = config_row->inact_tmout_sec_overload;
    st_cfg->kick_debounce_period = config_row->kick_debounce_period;
    st_cfg->kick_debounce_thresh = config_row->kick_debounce_thresh;
    st_cfg->stats_report_interval = config_row->stats_report_interval;
    st_cfg->success_threshold_secs = config_row->success_threshold_secs;

    if ((config_row->if_name_2g != NULL) && (strlen(config_row->if_name_2g) != 0)) {
        if (convert_ifname_to_vapname(wifi_prop, (char *)config_row->if_name_2g, (char *)st_cfg->vap_name_list[vap_name_list_len], sizeof(st_cfg->vap_name_list[vap_name_list_len])) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: convert_ifname_to_vapname failed %s\n", __func__, __LINE__, config_row->if_name_2g);
            return webconfig_error_translate_from_ovsdb;
        }
        vap_name_list_len++;
    }

    if ((config_row->if_name_5g != NULL) && (strlen(config_row->if_name_5g) != 0)) {
        if (convert_ifname_to_vapname(wifi_prop, (char *)config_row->if_name_5g, (char *)st_cfg->vap_name_list[vap_name_list_len], sizeof(st_cfg->vap_name_list[vap_name_list_len])) != RETURN_OK) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: convert_ifname_to_vapname failed %s\n", __func__, __LINE__, config_row->if_name_5g);
            return webconfig_error_translate_from_ovsdb;
        }
        vap_name_list_len++;
    }

    memset(key, 0, sizeof(key));
    memset(id, 0, sizeof(id));
    st_cfg->vap_name_list_len = vap_name_list_len;
    if (get_steering_cfg_id(key, sizeof(key), id, sizeof(id), st_cfg) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: get_steering_cfg_id failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    snprintf(st_cfg->steering_cfg_id, sizeof(st_cfg->steering_cfg_id), "%s", key);

    return webconfig_error_none;
}


webconfig_error_t  translate_config_from_ovsdb_for_steering_config(webconfig_subdoc_data_t *data)
{
    const struct schema_Band_Steering_Config **table;
    struct schema_Band_Steering_Config *config_row;
    webconfig_external_ovsdb_t *proto;
    steering_config_t *steer_config_entry;
    steering_config_t temp_steer_config;
    unsigned int i = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->band_steer_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: steer config table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (wifi_prop == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: wifi_prop is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    data->u.decoded.steering_config_map = hash_map_create();
    if (data->u.decoded.steering_config_map == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: stats_config_map is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    for (i = 0; i < proto->steer_row_count; i++) {
        config_row = (struct schema_Band_Steering_Config *)table[i];
        if (config_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: config_row is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }


        memset(&temp_steer_config, 0, sizeof(steering_config_t));
        if (translate_steerconfig_from_ovsdb_to_rdk(config_row, &temp_steer_config, wifi_prop) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: translation of steer_config failed for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }

        steer_config_entry = (steering_config_t *)malloc(sizeof(steering_config_t));
        if (steer_config_entry == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: steer_config is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }
        memset(steer_config_entry, 0, sizeof(steering_config_t));
        memcpy(steer_config_entry, &temp_steer_config, sizeof(steering_config_t));
        hash_map_put(data->u.decoded.steering_config_map, strdup(temp_steer_config.steering_cfg_id), steer_config_entry);
    }

    return webconfig_error_none;
}

webconfig_error_t translate_steerconfig_from_rdk_to_ovsdb(struct schema_Band_Steering_Config *config_row, const steering_config_t *st_cfg, wifi_platform_property_t *wifi_prop)
{
    if ((config_row == NULL) || (st_cfg == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguement is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    config_row->chan_util_avg_count = st_cfg->chan_util_avg_count;
    config_row->chan_util_check_sec = st_cfg->chan_util_check_sec;
    config_row->chan_util_hwm = st_cfg->chan_util_hwm;
    config_row->chan_util_lwm = st_cfg->chan_util_lwm;
    config_row->dbg_2g_raw_chan_util = st_cfg->dbg_2g_raw_chan_util;
    config_row->dbg_2g_raw_rssi = st_cfg->dbg_2g_raw_rssi;
    config_row->dbg_5g_raw_chan_util = st_cfg->dbg_5g_raw_chan_util;
    config_row->dbg_5g_raw_rssi = st_cfg->dbg_5g_raw_rssi;
    config_row->debug_level = st_cfg->debug_level;
    config_row->def_rssi_inact_xing = st_cfg->def_rssi_inact_xing;
    config_row->def_rssi_low_xing = st_cfg->def_rssi_low_xing;
    config_row->gw_only = st_cfg->gw_only;

    config_row->inact_check_sec = st_cfg->inact_check_sec;
    config_row->inact_tmout_sec_normal = st_cfg->inact_tmout_sec_normal;
    config_row->inact_tmout_sec_overload = st_cfg->inact_tmout_sec_overload;
    config_row->kick_debounce_period = st_cfg->kick_debounce_period;
    config_row->kick_debounce_thresh = st_cfg->kick_debounce_thresh;
    config_row->stats_report_interval = st_cfg->stats_report_interval;
    config_row->success_threshold_secs = st_cfg->success_threshold_secs;

    //Considering src as if_name_2g
    if (convert_vapname_to_ifname(wifi_prop, (char *)st_cfg->vap_name_list[0], config_row->if_name_2g, sizeof(config_row->if_name_2g)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: convert_vapname_to_ifname failed %s\n", __func__, __LINE__, st_cfg->vap_name_list[0]);
        return webconfig_error_translate_from_ovsdb;
    }

    //Considering tgt as if_name_5g
    if (convert_vapname_to_ifname(wifi_prop, (char *)st_cfg->vap_name_list[1], config_row->if_name_5g, sizeof(config_row->if_name_5g)) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: convert_vapname_to_ifname failed %s\n", __func__, __LINE__, st_cfg->vap_name_list[1]);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}


webconfig_error_t  translate_config_to_ovsdb_for_steering_config(webconfig_subdoc_data_t *data)
{
    struct schema_Band_Steering_Config **table;
    struct schema_Band_Steering_Config *config_row;
    webconfig_external_ovsdb_t *proto;
    steering_config_t *steer_config;
    int count = 0;
    unsigned int *row_count = NULL;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (wifi_prop == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: wifi_prop is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    table = (struct schema_Band_Steering_Config **)proto->band_steer_config;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: steering config table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    if (data->u.decoded.steering_config_map != NULL) {
        steer_config = hash_map_get_first(data->u.decoded.steering_config_map);
        while (steer_config != NULL) {
            config_row = (struct schema_Band_Steering_Config *)table[count];
            if (config_row == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: steer_row is NULL\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_steerconfig_from_rdk_to_ovsdb(config_row, steer_config, wifi_prop) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
            count++;
            steer_config = hash_map_get_next(data->u.decoded.steering_config_map, steer_config);
        }
    }
    row_count = (unsigned int *)&proto->steer_row_count;
    *row_count = count;

    return webconfig_error_none;
}

webconfig_error_t translate_steeringclients_from_rdk_to_ovsdb(struct schema_Band_Steering_Clients *client_row, const band_steering_clients_t *st_cfg)
{
    if ((client_row == NULL) || (st_cfg == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguement is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    return webconfig_error_none;
}


webconfig_error_t  translate_config_to_ovsdb_for_steering_clients(webconfig_subdoc_data_t *data)
{
    struct schema_Band_Steering_Clients **table;
    struct schema_Band_Steering_Clients *client_row;
    webconfig_external_ovsdb_t *proto;
    band_steering_clients_t *clients_config;
    int count = 0;
    unsigned int *row_count = NULL;

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    table = (struct schema_Band_Steering_Clients **)proto->band_steering_clients;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: steering clients table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }


    if (data->u.decoded.steering_client_map != NULL) {
        clients_config = hash_map_get_first(data->u.decoded.steering_client_map);
        while (clients_config != NULL) {
            client_row = (struct schema_Band_Steering_Clients *)table[count];
            if (client_row == NULL) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: client_row is NULL\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_steeringclients_from_rdk_to_ovsdb(client_row, clients_config) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Translation failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
            count++;
            clients_config = hash_map_get_next(data->u.decoded.steering_client_map, clients_config);
        }
    }
    row_count = (unsigned int *)&proto->steering_client_row_count;
    *row_count = count;

    return webconfig_error_none;
}

webconfig_error_t translate_steeringclients_from_ovsdb_to_rdk(const struct schema_Band_Steering_Clients *client_row, band_steering_clients_t *cli_cfg)
{
    char key[64] = {0};
    unsigned char id[64] = {0};
    int i = 0;
    unsigned int out_bytes = 0;
    if ((client_row == NULL) || (cli_cfg == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguement is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    cli_cfg->backoff_exp_base = client_row->backoff_exp_base;
    cli_cfg->backoff_secs = client_row->backoff_secs;
    cli_cfg->hwm  = client_row->hwm;
    cli_cfg->kick_debounce_period = client_row->kick_debounce_period;
    cli_cfg->kick_reason  = client_row->kick_reason;
    cli_cfg->kick_upon_idle  = client_row->kick_upon_idle;
    cli_cfg->lwm  = client_row->lwm;
    cli_cfg->max_rejects = client_row->max_rejects;
    cli_cfg->pre_assoc_auth_block = client_row->pre_assoc_auth_block;
    cli_cfg->rejects_tmout_secs  = client_row->rejects_tmout_secs;
    cli_cfg->sc_kick_debounce_period  = client_row->sc_kick_debounce_period;
    cli_cfg->sc_kick_reason  = client_row->sc_kick_reason;
    cli_cfg->steer_during_backoff  = client_row->steer_during_backoff;
    cli_cfg->steering_fail_cnt  = client_row->steering_fail_cnt;
    cli_cfg->steering_kick_cnt = client_row->steering_kick_cnt;
    cli_cfg->steering_success_cnt  = client_row->steering_success_cnt;
    cli_cfg->sticky_kick_cnt = client_row->sticky_kick_cnt;
    cli_cfg->sticky_kick_debounce_period = client_row->sticky_kick_debounce_period;
    cli_cfg->sticky_kick_reason = client_row->sticky_kick_reason;

    snprintf(cli_cfg->mac, sizeof(cli_cfg->mac), "%s", client_row->mac);

    if (cs_mode_type_conversion(&cli_cfg->cs_mode, (char *)client_row->cs_mode, sizeof(client_row->cs_mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Warning for cs_mode_type_conversion failed\n", __func__, __LINE__);
    }

    if (force_kick_type_conversion(&cli_cfg->force_kick, (char *)client_row->force_kick, sizeof(client_row->force_kick), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Warning for cs_state_type_conversion failed\n", __func__, __LINE__);
    }

    if (kick_type_conversion(&cli_cfg->kick_type, (char *)client_row->kick_type, sizeof(client_row->kick_type), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: kick_type_conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (pref_5g_conversion(&cli_cfg->pref_5g, (char *)client_row->pref_5g, sizeof(client_row->pref_5g), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: pref_5g_conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    if (reject_detection_conversion(&cli_cfg->reject_detection, (char *)client_row->reject_detection, sizeof(client_row->reject_detection), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: reject_detection_conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }
    if (sc_kick_type_conversion(&cli_cfg->sc_kick_type, (char *)client_row->sc_kick_type, sizeof(client_row->sc_kick_type), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Warning for sc_kick_conversion failed\n", __func__, __LINE__);
    }
    if (sticky_kick_type_conversion(&cli_cfg->sticky_kick_type, (char *)client_row->sticky_kick_type, sizeof(client_row->sticky_kick_type), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Warning for sticky_kick_conversion failed\n", __func__, __LINE__);
    }
    for (i = 0; i < client_row->cs_params_len; i++) {
        out_bytes = snprintf(cli_cfg->cs_params[i].key, sizeof(cli_cfg->cs_params[i].key), "%s", client_row->cs_params_keys[i]);
        if ((out_bytes < 0) || (out_bytes >= sizeof(cli_cfg->cs_params[i].key))) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error %d\n", __func__, __LINE__, out_bytes);
            return webconfig_error_translate_from_ovsdb;
        }
        out_bytes = snprintf(cli_cfg->cs_params[i].value, sizeof(cli_cfg->cs_params[i].value), "%s", client_row->cs_params[i]);
        if ((out_bytes < 0) || (out_bytes >= sizeof(cli_cfg->cs_params[i].value))) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error %d\n", __func__, __LINE__, out_bytes);
            return webconfig_error_translate_from_ovsdb;
        }
    }
    cli_cfg->cs_params_len  = client_row->cs_params_len;

    for (i = 0; i < client_row->rrm_bcn_rpt_params_len; i++) {
        out_bytes = snprintf(cli_cfg->rrm_bcn_rpt_params[i].key, sizeof(cli_cfg->rrm_bcn_rpt_params[i].key), "%s", client_row->rrm_bcn_rpt_params_keys[i]);
        if ((out_bytes < 0) || (out_bytes >= sizeof(cli_cfg->rrm_bcn_rpt_params[i].key))) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error %d\n", __func__, __LINE__, out_bytes);
            return webconfig_error_translate_from_ovsdb;
        }
        out_bytes = snprintf(cli_cfg->rrm_bcn_rpt_params[i].value, sizeof(cli_cfg->rrm_bcn_rpt_params[i].value), "%s", client_row->rrm_bcn_rpt_params[i]);
        if ((out_bytes < 0) || (out_bytes >= sizeof(cli_cfg->rrm_bcn_rpt_params[i].value))) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error %d\n", __func__, __LINE__, out_bytes);
            return webconfig_error_translate_from_ovsdb;
        }
    }
    cli_cfg->rrm_bcn_rpt_params_len  = client_row->rrm_bcn_rpt_params_len;

    for (i = 0; i < client_row->sc_btm_params_len; i++) {
        out_bytes = snprintf(cli_cfg->sc_btm_params[i].key, sizeof(cli_cfg->sc_btm_params[i].key), "%s", client_row->sc_btm_params_keys[i]);
        if ((out_bytes < 0) || (out_bytes >= sizeof(cli_cfg->sc_btm_params[i].key))) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error %d\n", __func__, __LINE__, out_bytes);
            return webconfig_error_translate_from_ovsdb;
        }
        out_bytes = snprintf(cli_cfg->sc_btm_params[i].value, sizeof(cli_cfg->sc_btm_params[i].value), "%s", client_row->sc_btm_params[i]);
        if ((out_bytes < 0) || (out_bytes >= sizeof(cli_cfg->sc_btm_params[i].value))) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error %d\n", __func__, __LINE__, out_bytes);
            return webconfig_error_translate_from_ovsdb;
        }
    }
    cli_cfg->sc_btm_params_len  = client_row->sc_btm_params_len;

    for (i = 0; i < client_row->steering_btm_params_len; i++) {
        out_bytes = snprintf(cli_cfg->steering_btm_params[i].key, sizeof(cli_cfg->steering_btm_params[i].key), "%s", client_row->steering_btm_params_keys[i]);
        if ((out_bytes < 0) || (out_bytes >= sizeof(cli_cfg->steering_btm_params[i].key))) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error %d\n", __func__, __LINE__, out_bytes);
            return webconfig_error_translate_from_ovsdb;
        }
        out_bytes = snprintf(cli_cfg->steering_btm_params[i].value, sizeof(cli_cfg->steering_btm_params[i].value), "%s", client_row->steering_btm_params[i]);
        if ((out_bytes < 0) || (out_bytes >= sizeof(cli_cfg->steering_btm_params[i].value))) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: snprintf error %d\n", __func__, __LINE__, out_bytes);
            return webconfig_error_translate_from_ovsdb;
        }
    }
    cli_cfg->steering_btm_params_len  = client_row->steering_btm_params_len;

    if (get_steering_clients_id(key, sizeof(key), id, sizeof(id), cli_cfg->mac) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: get_steering_cfg_id failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    snprintf(cli_cfg->steering_client_id, sizeof(cli_cfg->steering_client_id), "%s", key);

    return webconfig_error_none;
}


webconfig_error_t  translate_config_from_ovsdb_for_steering_clients(webconfig_subdoc_data_t *data)
{
    const struct schema_Band_Steering_Clients **table;
    struct schema_Band_Steering_Clients *client_row;
    webconfig_external_ovsdb_t *proto;
    band_steering_clients_t *steering_client_entry;
    band_steering_clients_t temp_steering_client;
    unsigned int i = 0;

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->band_steering_clients;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: steering client table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    data->u.decoded.steering_client_map = hash_map_create();
    if (data->u.decoded.steering_client_map == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: steering_client_map is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    for (i = 0; i < proto->steering_client_row_count; i++) {
        client_row = (struct schema_Band_Steering_Clients *)table[i];
        if (client_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: client_row is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }

        memset(&temp_steering_client, 0, sizeof(band_steering_clients_t));
        if (translate_steeringclients_from_ovsdb_to_rdk(client_row, &temp_steering_client) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: translation of steer_config failed for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }

        steering_client_entry = (band_steering_clients_t *)malloc(sizeof(band_steering_clients_t));
        if (steering_client_entry == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: steer_config is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }
        memset(steering_client_entry, 0, sizeof(band_steering_clients_t));
        memcpy(steering_client_entry, &temp_steering_client, sizeof(band_steering_clients_t));
        hash_map_put(data->u.decoded.steering_client_map, strdup(temp_steering_client.steering_client_id), steering_client_entry);
    }

    return webconfig_error_none;
}

webconfig_error_t translate_vif_neighbors_from_ovsdb_to_rdk(const struct schema_Wifi_VIF_Neighbors *neighbor_row, vif_neighbors_t *neighbor_cfg)
{
    char key[64] = {0};
    unsigned char id[64] = {0};
    if ((neighbor_row == NULL) || (neighbor_cfg == NULL)) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: input arguement is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    snprintf(neighbor_cfg->bssid, sizeof(neighbor_cfg->bssid), "%s", neighbor_row->bssid);
    snprintf(neighbor_cfg->if_name, sizeof(neighbor_cfg->if_name), "%s", neighbor_row->if_name);
    neighbor_cfg->channel = neighbor_row->channel;
    neighbor_cfg->priority = neighbor_row->priority;

    if (vif_neighbor_htmode_conversion(&neighbor_cfg->ht_mode, (char *)neighbor_row->ht_mode, sizeof(neighbor_row->ht_mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: ht_mode_conversion failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (get_vif_neighbor_id(key, sizeof(key), id, sizeof(id), neighbor_cfg->bssid) != RETURN_OK) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: get_vif_neighbor_id failed\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    snprintf(neighbor_cfg->neighbor_id, sizeof(neighbor_cfg->neighbor_id), "%s", key);

    return webconfig_error_none;
}


webconfig_error_t  translate_config_from_ovsdb_for_vif_neighbors(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_VIF_Neighbors **table;
    struct schema_Wifi_VIF_Neighbors *client_row;
    webconfig_external_ovsdb_t *proto;
    vif_neighbors_t *vif_neighbor_entry;
    vif_neighbors_t temp_vif_neighbor;
    unsigned int i = 0;

    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_neighbors;
    if (table == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif_neighbors table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    data->u.decoded.vif_neighbors_map = hash_map_create();
    if (data->u.decoded.vif_neighbors_map == NULL) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vif_neighbors_map is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    for (i = 0; i < proto->vif_neighbor_row_count; i++) {
        client_row = (struct schema_Wifi_VIF_Neighbors *)table[i];
        if (client_row == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: client_row is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }

        memset(&temp_vif_neighbor, 0, sizeof(vif_neighbors_t));
        if (translate_vif_neighbors_from_ovsdb_to_rdk(client_row, &temp_vif_neighbor) != webconfig_error_none) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: translation of vif_neighbor failed for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }

        vif_neighbor_entry = (vif_neighbors_t *)malloc(sizeof(vif_neighbors_t));
        if (vif_neighbor_entry == NULL) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: steer_config is NULL for %d\n", __func__, __LINE__, i);
            return webconfig_error_translate_from_ovsdb;
        }
        memset(vif_neighbor_entry, 0, sizeof(vif_neighbors_t));
        memcpy(vif_neighbor_entry, &temp_vif_neighbor, sizeof(vif_neighbors_t));
        hash_map_put(data->u.decoded.vif_neighbors_map, strdup(temp_vif_neighbor.neighbor_id), vif_neighbor_entry);
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
        if (convert_cloudifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert cloud ifname to vapname failed, if_name '%s'\n", __func__, __LINE__, table[i]->if_name);
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
            if (translate_macfilter_from_ovsdb_to_rdk_vap(vap_row, &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index], wifi_prop) != webconfig_error_none) {
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

webconfig_error_t translate_radio_object_from_ovsdb(const struct schema_Wifi_Radio_Config *row,
    wifi_radio_operationParam_t *oper_param, wifi_platform_property_t *wifi_prop)
{
    wifi_freq_bands_t band_enum;
    wifi_countrycode_type_t country_code;
    wifi_channelBandwidth_t ht_mode_enum;

    if ((row == NULL) || (oper_param == NULL)) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: input params is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    //Update the values of oper_param
    if (freq_band_conversion(&band_enum, (char *)row->freq_band, sizeof(row->freq_band), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: frequency band conversion failed. freq_band '%s'\n", __func__, __LINE__, row->freq_band);
        return webconfig_error_translate_from_ovsdb;
    }
    oper_param->band = band_enum;

    if (country_code_conversion(&country_code, (char *)row->country, sizeof(row->country), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: country conversion failed. country '%s'\n", __func__, __LINE__, row->country);
        return webconfig_error_translate_from_ovsdb;
    }
    oper_param->countryCode = country_code;

    //As part of southbound variant will not be updated
    /*
      if (hw_mode_conversion(&oper_param->variant, (char *)row->hw_mode, sizeof(row->hw_mode), STRING_TO_ENUM) != RETURN_OK) {
      wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Hw mode conversion failed\n", __func__, __LINE__);
      return webconfig_error_translate_from_ovsdb;
      }*/

    if (ht_mode_conversion(&ht_mode_enum, (char *)row->ht_mode, sizeof(row->ht_mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Ht mode conversion failed. ht_mode '%s'\n", __func__, __LINE__, row->ht_mode);
        return webconfig_error_translate_from_ovsdb;
    }
    oper_param->channelWidth = ht_mode_enum;

    if (channel_mode_conversion(&oper_param->autoChannelEnabled, (char *)row->channel_mode, sizeof(row->channel_mode), STRING_TO_ENUM) != RETURN_OK) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: channel mode conversion failed. channel_mode '%s'\n", __func__, __LINE__, row->channel_mode);
        return webconfig_error_translate_from_ovsdb;
    }

    oper_param->enable = row->enabled;

    if (is_wifi_channel_valid(wifi_prop, oper_param->band, row->channel) != RETURN_OK) {
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
        if (convert_cloudifname_to_radio_index(row->if_name, &radio_index) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Conversion of if_name to radio_index failed for '%s'\n", __func__, __LINE__, row->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        oper_param = &decoded_params->radios[radio_index].oper;

        if (translate_radio_object_from_ovsdb(row, oper_param, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
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
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Radio object not present : %d\n", __func__, __LINE__, decoded_params->num_radios);
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
        if (convert_cloudifname_to_radio_index(row->if_name, &radio_index) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Conversion of if_name to radio_index failed for  '%s'\n", __func__, __LINE__, row->if_name);
            return webconfig_error_translate_from_ovsdb;
        }

        radio = &decoded_params->radios[radio_index];

        oper_param = &radio->oper;

        convert_radio_index_to_radio_name(radio_index, radio->name);
        if (translate_radio_object_from_ovsdb(row, oper_param, &decoded_params->hal_cap.wifi_prop) != webconfig_error_none) {
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

webconfig_error_t translate_blaster_info_to_blaster_table(const active_msmt_t *blaster_info, struct schema_Wifi_Blaster_State *blaster_row)
{
    if ((blaster_info == NULL) || (blaster_row == NULL))  {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d Incoming Parameter is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    memset(blaster_row->plan_id, '\0', PLAN_ID_LENGTH);
    strncpy(blaster_row->plan_id, (char *)blaster_info->PlanId, strlen((char *)blaster_info->PlanId));
    blaster_row->plan_id[strlen(blaster_row->plan_id)] = '\0';

    memset(blaster_row->state, '\0', BLASTER_STATE_LEN);
    if (blaster_info->Status == blaster_state_new) {
        strncpy(blaster_row->state, "new", strlen("new"));
    } else if (blaster_info->Status == blaster_state_completed) {
        strncpy(blaster_row->state, "complete", strlen("complete"));
    }
    blaster_row->state[strlen(blaster_row->state)] = '\0';
    return webconfig_error_none;
}

webconfig_error_t   translate_blaster_config_to_ovsdb_for_blaster(webconfig_subdoc_data_t *data)
{
    const struct schema_Wifi_Blaster_State   **blaster_table = NULL;
    struct schema_Wifi_Blaster_State *blaster_row = NULL;
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;
    active_msmt_t *blaster_info = NULL;
    webconfig_external_ovsdb_t *proto = NULL;

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

    blaster_table = proto->blaster_state;
    if (blaster_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    int count = 0;
    blaster_row = (struct schema_Wifi_Blaster_State *)blaster_table[count];
    if (blaster_row == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the blaster schema ro\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    blaster_info = &decoded_params->blaster;

    if (translate_blaster_info_to_blaster_table(blaster_info, blaster_row) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of Blaster to ovsdb failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
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
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    wifi_platform_property_t *wifi_prop;
    unsigned char count = 0;

    unsigned int presence_mask = 0, private_vap_mask = 0;
    unsigned int *row_count = NULL;
    bool sec_schema_is_legacy;

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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
        if ((radio->vaps.num_vaps == 0) || (radio->vaps.num_vaps > MAX_NUM_VAP_PER_RADIO)) {
            wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Invalid number of vaps: %x\n", __func__, __LINE__, radio->vaps.num_vaps);
            return webconfig_error_invalid_subdoc;
        }
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            rdk_vap = &radio->vaps.rdk_vap_array[j];

            if (strncmp(vap->vap_name, vap_name, strlen(vap_name)) != 0) {
                continue;
            }

            private_vap_mask |= (1 << vap->vap_index);

            if (convert_vapname_to_cloudifname(rdk_vap->vap_name,
                    proto->vap_info[proto->num_vaps].if_name,
                    sizeof(proto->vap_info[proto->num_vaps].if_name)) != RETURN_OK) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vap name to interface name "
                    "conversion failed for %s\n", __func__, __LINE__, rdk_vap->vap_name);
                return webconfig_error_translate_to_ovsdb;
            }
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if(rdk_vap->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap->vap_index != 2 && vap->vap_index != 3) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_name=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap->vap_index);
                    rdk_vap->exists = true;
                }
#else
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_name=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,vap->vap_index);
                rdk_vap->exists = true;
#endif /*_SR213_PRODUCT_REQ_*/
            }
#endif /* !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) */
            proto->vap_info[proto->num_vaps].exists = rdk_vap->exists;
            proto->num_vaps++;

            if (rdk_vap->exists == false) {
                presence_mask |= (1 << vap->vap_index);
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
            vap_row = (struct schema_Wifi_VIF_State *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (radio->oper.channel) {
                wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Updating Channel %d to %s\n", __func__, __LINE__,radio->oper.channel, vap->vap_name);
                vap_row->channel = radio->oper.channel;
            } 

            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: row count:%d ssid:%s\n", __func__, __LINE__, count, vap_row->ssid);
                count++;
            } else  if (is_vap_xhs(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_iot_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
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

                if (translate_lnf_psk_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_hotspot_secure(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_hotspot_secure_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_secure_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of radius secure vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of mesh backhaul to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask |= (1 << vap->vap_index);
                count++;
            } else  if (is_vap_mesh_sta(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_sta_vap_info_to_vif_state(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
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
                if (translate_macfilter_from_rdk_vap_to_ovsdb_vif_state(rdk_vap, vap_row) != webconfig_error_none) {
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
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, private_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    unsigned int *row_count = 0;
    unsigned char count = 0;
    bool sec_schema_is_legacy;

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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
            rdk_vap = &radio->vaps.rdk_vap_array[j];

            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s \r\n", __func__, __LINE__, vap->vap_name);
            if (strncmp(vap->vap_name, "private_ssid", strlen("private_ssid")) != 0) {
                continue;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s vap_index:%d\r\n", __func__, __LINE__, vap->vap_name, vap->vap_index);

#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if (rdk_vap->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap->vap_index != 2 && vap->vap_index != 3) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                    rdk_vap->exists = true;
                }
#else
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                rdk_vap->exists = true;
#endif /* _SR213_PRODUCT_REQ_*/
            }
#endif /*!defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) */
            if (rdk_vap->exists == false) {
                presence_mask |= (1 << vap->vap_index);
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
            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            if (is_vap_private(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_private_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
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
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, mesh_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    unsigned int *row_count = 0;
    unsigned char count = 0;
    bool sec_schema_is_legacy;

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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
            rdk_vap = &radio->vaps.rdk_vap_array[j];

            if (strncmp(vap->vap_name, "mesh_sta_", strlen("mesh_sta_")) != 0) {
                continue;
            }

            if (rdk_vap->exists == false) {
                presence_mask |= (1 << vap->vap_index);
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
                if (translate_mesh_sta_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
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
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, mesh_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    bool sec_schema_is_legacy;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (proto->vif_config_row_count > 0 && table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
        if (convert_cloudifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert cloud ifname to vapname failed, if_name '%s'\n", __func__, __LINE__, table[i]->if_name);
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
        rdk_vap = &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap->exists = true;

        if (is_vap_mesh_sta(wifi_prop, vap_index) == TRUE) {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: conn_status:%d\n", __func__, __LINE__, vap->u.sta_info.conn_status);
            if (translate_mesh_sta_vap_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh sta failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } 
    }
    if (set_deleted_entries_to_default(data, &presence_mask, mesh_vap_mask) !=
            webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to set deleted entries to default\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
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
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, mesh_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    unsigned int *row_count = 0;
    unsigned char count = 0;
    bool sec_schema_is_legacy;

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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
            rdk_vap = &radio->vaps.rdk_vap_array[j];

            if (strncmp(vap->vap_name, "mesh_backhaul", strlen("mesh_backhaul")) != 0) {
                continue;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s vap_index:%d\r\n", __func__, __LINE__, vap->vap_name, vap->vap_index);

#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if (rdk_vap->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap->vap_index != 2 && vap->vap_index != 3) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                    rdk_vap->exists = true;
                }
#else
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                rdk_vap->exists = true;
#endif /* _SR213_PRODUCT_REQ_*/
            }
#endif /* !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) */
            if (rdk_vap->exists == false) {
                presence_mask |= (1 << vap->vap_index);
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
            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }
            if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
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
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, mesh_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    unsigned int *row_count = 0;
    unsigned char count = 0;
    bool sec_schema_is_legacy;

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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

    presence_mask = 0;
    mesh_vap_mask = create_vap_mask(wifi_prop, 2, VAP_PREFIX_MESH_STA, VAP_PREFIX_MESH_BACKHAUL);

    hal_cap = &decoded_params->hal_cap;

    //Get the number of radios
    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        vap_map = &radio->vaps.vap_map;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            //Get the corresponding vap
            vap = &vap_map->vap_array[j];
            rdk_vap = &radio->vaps.rdk_vap_array[j];

            if ((strncmp(vap->vap_name, "mesh_backhaul", strlen("mesh_backhaul")) != 0) &&
                (strncmp(vap->vap_name, "mesh_sta", strlen("mesh_sta")) != 0)) {
                continue;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s vap_index:%d\r\n", __func__, __LINE__, vap->vap_name, vap->vap_index);

#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if (rdk_vap->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap->vap_index != 2 && vap->vap_index != 3) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                    rdk_vap->exists = true;
                }
#else
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                rdk_vap->exists = true;
#endif /*_SR213_PRODUCT_REQ_*/
            }
#endif /*!defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) */
            if (rdk_vap->exists == false) {
                presence_mask |= (1 << vap->vap_index);
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
            if (is_vap_mesh_backhaul(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_mesh_backhaul_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
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
                    if (translate_mesh_sta_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
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
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, home_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    unsigned int *row_count = 0;
    unsigned char count = 0;
    bool sec_schema_is_legacy;

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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
            rdk_vap = &radio->vaps.rdk_vap_array[j];

            if (strncmp(vap->vap_name, "iot_ssid", strlen("iot_ssid")) != 0) {
                continue;
            }

#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if (rdk_vap->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap->vap_index != 2 && vap->vap_index != 3) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                    rdk_vap->exists = true;
                }
#else
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                rdk_vap->exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
            }
#endif /*!defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)*/
            if (rdk_vap->exists == false) {
                presence_mask |= (1 << vap->vap_index);
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
                if (translate_iot_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
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
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, lnf_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    unsigned int *row_count = 0;
    unsigned char count = 0;
    bool sec_schema_is_legacy;

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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
            rdk_vap = &radio->vaps.rdk_vap_array[j];

            if ((strncmp(vap->vap_name, "lnf_psk", strlen("lnf_psk")) != 0) &&
                (strncmp(vap->vap_name, "lnf_radius", strlen("lnf_radius")) != 0)) {
                continue;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s vap_index:%d\r\n", __func__, __LINE__, vap->vap_name, vap->vap_index);

#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if (rdk_vap->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap->vap_index != 2 && vap->vap_index != 3) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                    rdk_vap->exists = true;
                }
#else
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                rdk_vap->exists = true;
#endif /*_SR213_PRODUCT_REQ_*/
            }
#endif /*!defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)*/
            if (rdk_vap->exists == false) {
                presence_mask |= (1 << vap->vap_index);
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
            vap_row = (struct schema_Wifi_VIF_Config *)vif_table[count];
            if (vap_row == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the vap schema row for %d\n", __func__, __LINE__, vap->vap_index);
                return webconfig_error_translate_to_ovsdb;
            }

            if (is_vap_lnf_psk(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_psk_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf psk vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_lnf_radius(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_lnf_radius_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
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
    rdk_wifi_vap_info_t *rdk_vap;
    wifi_hal_capability_t *hal_cap;
    wifi_interface_name_idex_map_t *iface_map;
    webconfig_external_ovsdb_t *proto;
    unsigned int presence_mask = 0, home_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    unsigned int *row_count = 0;
    unsigned char count = 0;
    bool sec_schema_is_legacy;

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

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
            rdk_vap = &radio->vaps.rdk_vap_array[j];

            if ((strncmp(vap->vap_name, "hotspot_open", strlen("hotspot_open")) != 0) &&
                (strncmp(vap->vap_name, "hotspot_secure", strlen("hotspot_secure")) != 0)) {
                continue;
            }
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: vap->vap_name:%s vap_index:%d\r\n", __func__, __LINE__, vap->vap_name, vap->vap_index);

#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if (rdk_vap->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap->vap_index != 2 && vap->vap_index != 3) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                    rdk_vap->exists = true;
                }
#else
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d VAP_EXISTS_FALSE for vap_index=%d,Setting to true.\n",__FUNCTION__,__LINE__,vap->vap_index);
                rdk_vap->exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
            }
#endif /*defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) */
            if (rdk_vap->exists == false) {
                presence_mask |= (1 << vap->vap_index);
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

            if (is_vap_hotspot_open(wifi_prop, vap->vap_index) == TRUE) {

                if (translate_hotspot_open_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop) != webconfig_error_none) {
                    wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap->vap_index);
                    return webconfig_error_translate_to_ovsdb;
                }
                presence_mask  |= (1 << vap->vap_index);
                count++;

            } else  if (is_vap_hotspot_secure(wifi_prop, vap->vap_index) == TRUE) {
                if (translate_hotspot_secure_vap_info_to_vif_config(vap, iface_map, vap_row, wifi_prop, sec_schema_is_legacy) != webconfig_error_none) {
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
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, private_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    wifi_vap_info_t *tempVap;
    bool sec_schema_is_legacy;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (proto->vif_config_row_count > 0 && table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

    presence_mask = 0;
    private_vap_mask = create_vap_mask(wifi_prop, 1, VAP_PREFIX_PRIVATE);

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: ifname  : %s\n", __func__, __LINE__, table[i]->if_name);
        if (convert_cloudifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
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
        rdk_vap = &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap->exists = true;

        if (is_vap_private(wifi_prop, vap_index) == TRUE) {
            if (strlen(vap->vap_name) == 0) {
                tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
                memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
                wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Copied from defaults for vap_index : %d vap_name : %s\n", __func__, __LINE__, vap_index, vap->vap_name);
            }
            if (translate_private_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of private vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        }
    }

    if (set_deleted_entries_to_default(data, &presence_mask, private_vap_mask) !=
            webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to set deleted entries to default\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
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
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, mesh_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    wifi_vap_info_t *tempVap;
    bool sec_schema_is_legacy;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (proto->vif_config_row_count > 0 && table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

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
        if (convert_cloudifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert cloud ifname to vapname failed, if_name '%s'\n", __func__, __LINE__, table[i]->if_name);
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
        rdk_vap = &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap->exists = true;

        if (is_vap_mesh_backhaul(wifi_prop, vap_index) == TRUE) {
            if (strlen(vap->vap_name) == 0) {
                tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
                memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
                wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Copied from defaults for vap_index : %d vap_name : %s\n", __func__, __LINE__, vap_index, vap->vap_name);
            }
            if (translate_mesh_backhaul_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh backhaul failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }

            presence_mask  |= (1 << vap_index);
        } /*else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
            }*/
        if (translate_macfilter_from_ovsdb_to_rdk_vap(vap_row, &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index], wifi_prop) != webconfig_error_none) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap_index);
            return webconfig_error_translate_from_ovsdb;
        }
    }

    if (set_deleted_entries_to_default(data, &presence_mask, mesh_vap_mask) !=
            webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to set deleted entries to default\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
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
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, mesh_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    bool sec_schema_is_legacy;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (proto->vif_config_row_count > 0 && table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

    presence_mask = 0;
    mesh_vap_mask = create_vap_mask(wifi_prop, 2, VAP_PREFIX_MESH_STA, VAP_PREFIX_MESH_BACKHAUL);
    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_cloudifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert cloud ifname to vapname failed, if_name '%s'\n", __func__, __LINE__, table[i]->if_name);
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
        rdk_vap = &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap->exists = true;

        if (is_vap_mesh_backhaul(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_backhaul_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh backhaul failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_mesh_sta(wifi_prop, vap_index) == TRUE) {
            if (translate_mesh_sta_vap_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mesh sta failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } /*else {
            wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
            }*/
        if (is_vap_mesh_sta(wifi_prop, vap_index) != TRUE) {
            if (translate_macfilter_from_ovsdb_to_rdk_vap(vap_row, &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index], wifi_prop) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: update of mac filter failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
        }
    }

    if (set_deleted_entries_to_default(data, &presence_mask, mesh_vap_mask) !=
            webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to set deleted entries to default\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
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
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, home_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    wifi_vap_info_t *tempVap;
    bool sec_schema_is_legacy;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (proto->vif_config_row_count > 0 && table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

    presence_mask = 0;
    home_vap_mask = create_vap_mask(wifi_prop, 1, VAP_PREFIX_IOT);

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        //Ovsdb is only restricted to mesh related vaps
        if (convert_cloudifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert cloud ifname to vapname failed, if_name '%s'\n", __func__, __LINE__, table[i]->if_name);
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
        rdk_vap = &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap->exists = true;

        if (is_vap_xhs(wifi_prop, vap_index) == TRUE) {

            if (strlen(vap->vap_name) == 0) {
                tempVap = &webconfig_ovsdb_default_data.u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
                memcpy(vap, tempVap, sizeof(wifi_vap_info_t));
                wifi_util_info_print(WIFI_WEBCONFIG,"%s:%d: Copied from defaults for vap_index : %d vap_name : %s\n", __func__, __LINE__, vap_index, vap->vap_name);
            }

            if (translate_iot_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of iot vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }

            presence_mask  |= (1 << vap_index);
        }
    }

    if (set_deleted_entries_to_default(data, &presence_mask, home_vap_mask) !=
            webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to set deleted entries to default\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
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
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, lnf_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    wifi_vap_info_t *tempVap;
    bool sec_schema_is_legacy;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (proto->vif_config_row_count > 0 && table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

    presence_mask = 0;
    lnf_vap_mask = create_vap_mask(wifi_prop, 2, VAP_PREFIX_LNF_PSK, VAP_PREFIX_LNF_RADIUS);

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if (convert_cloudifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert cloud ifname to vapname failed, if_name '%s'\n", __func__, __LINE__, table[i]->if_name);
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
        rdk_vap = &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap->exists = true;

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
            if (translate_lnf_psk_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
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
            if (translate_lnf_radius_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of lnf radius to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        }
    }

    if (set_deleted_entries_to_default(data, &presence_mask, lnf_vap_mask) !=
            webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to set deleted entries to default\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
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
    rdk_wifi_vap_info_t *rdk_vap;
    webconfig_external_ovsdb_t *proto;
    int radio_index = 0, vap_array_index = 0;
    struct schema_Wifi_VIF_Config *vap_row;
    char vapname[32];
    int vap_index = 0;
    unsigned int presence_mask = 0, xfinity_vap_mask = 0;
    wifi_platform_property_t *wifi_prop = &data->u.decoded.hal_cap.wifi_prop;
    bool sec_schema_is_legacy;

    decoded_params = &data->u.decoded;
    proto = (webconfig_external_ovsdb_t *) data->u.decoded.external_protos;
    if (proto == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: external_protos is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    table = proto->vif_config;
    if (proto->vif_config_row_count > 0 && table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    sec_schema_is_legacy = proto->sec_schema_is_legacy;

    presence_mask = 0;
    xfinity_vap_mask = create_vap_mask(wifi_prop, 2, VAP_PREFIX_HOTSPOT_OPEN, VAP_PREFIX_HOTSPOT_SECURE);

    for (i = 0; i < proto->vif_config_row_count; i++) {
        vap_row = (struct schema_Wifi_VIF_Config *)table[i];
        if (vap_row == NULL) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: vif config schema row is NULL\n", __func__, __LINE__);
            return webconfig_error_translate_from_ovsdb;
        }

        if (convert_cloudifname_to_vapname(wifi_prop, (char *)&table[i]->if_name[0], vapname, sizeof(vapname)) != RETURN_OK) {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Convert cloud ifname to vapname failed, if_name '%s' \n", __func__, __LINE__, table[i]->if_name);
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
        rdk_vap = &decoded_params->radios[radio_index].vaps.rdk_vap_array[vap_array_index];
        rdk_vap->exists = true;

        if (is_vap_hotspot_open(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_open_vif_config_to_vap_info(vap_row, vap) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot open vap to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else if (is_vap_hotspot_secure(wifi_prop, vap_index) == TRUE) {
            if (translate_hotspot_secure_vif_config_to_vap_info(vap_row, vap, sec_schema_is_legacy) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of hotspot secure to ovsdb failed for %d\n", __func__, __LINE__, vap_index);
                return webconfig_error_translate_from_ovsdb;
            }
            presence_mask  |= (1 << vap_index);
        } else {
            wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: invalid ifname %s from ovsdb schema\n", __func__, __LINE__, table[i]->if_name);
            return webconfig_error_translate_from_ovsdb;
        }
    }

    if (set_deleted_entries_to_default(data, &presence_mask, xfinity_vap_mask) !=
            webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to set deleted entries to default\n",
            __func__, __LINE__);
        return webconfig_error_translate_from_ovsdb;
    }

    if (presence_mask != xfinity_vap_mask) {
        wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: vapindex conf missing presence_mask : %x\n", __func__, __LINE__, presence_mask);
        return webconfig_error_translate_from_ovsdb;
    }

    return webconfig_error_none;
}

webconfig_error_t translate_config_from_ovsdb_for_blaster_config(webconfig_subdoc_data_t *data)
{
    struct schema_Wifi_Blaster_Config *blaster_row = NULL;
    const struct schema_Wifi_Blaster_Config **blaster_table = NULL;
    const char blaster_mqtt_topic[MAX_MQTT_TOPIC_LEN] = {'\0'};
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;
    active_msmt_t *blaster_info =  NULL;
    webconfig_external_ovsdb_t *proto = NULL;
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

    blaster_table=proto->blaster_config;
    if (blaster_table == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: table is NULL\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    strncpy((char *)blaster_mqtt_topic, proto->awlan_mqtt_topic, strlen(proto->awlan_mqtt_topic));
    int count = 0;
    blaster_row = (struct schema_Wifi_Blaster_Config *)blaster_table[count];
    if (blaster_row == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Unable to find the blaster schema row\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    blaster_info = &decoded_params->blaster;
    if (blaster_info == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Allocation failed\n", __func__, __LINE__);
        return webconfig_error_translate_to_ovsdb;
    }

    if (translate_blaster_config_to_blast_info(blaster_row, blaster_mqtt_topic, blaster_info) != webconfig_error_none) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: Translation of Blaster to ovsdb failed\n", __func__, __LINE__);
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

        case webconfig_subdoc_type_mesh_backhaul_sta:
            if (translate_vap_object_to_ovsdb_vif_state(data, "mesh_sta") != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_backhaul_sta vap_object translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }

            if (translate_vap_object_to_ovsdb_vif_config_for_mesh_sta(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_backhaul_sta vap_object translation to ovsdb failed\n", __func__, __LINE__);
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

            if (free_vap_object_diff_assoc_client_entries(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_associated_clients diff assoc clients free failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_blaster:
            if (translate_blaster_config_to_ovsdb_for_blaster(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Blaster config translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;
        case webconfig_subdoc_type_stats_config:
            if (translate_config_to_ovsdb_for_stats_config(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: stats config translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;
        case webconfig_subdoc_type_steering_config:
            if (translate_config_to_ovsdb_for_steering_config(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: steering config translation to ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_to_ovsdb;
            }
        break;

        case webconfig_subdoc_type_steering_clients:
          if (translate_config_to_ovsdb_for_steering_clients(data) != webconfig_error_none) {
              wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: steering clients translation to ovsdb failed\n", __func__, __LINE__);
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

        case webconfig_subdoc_type_mesh_backhaul_sta:
            if (translate_vap_object_from_ovsdb_vif_config_for_mesh_sta(data) != webconfig_error_none) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: webconfig_subdoc_type_mesh_backhaul_sta vap_object translation from ovsdb failed\n", __func__, __LINE__);
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

        case webconfig_subdoc_type_blaster:
            if (translate_config_from_ovsdb_for_blaster_config(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: Blaster config translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;
        
        case webconfig_subdoc_type_stats_config:
            if (translate_config_from_ovsdb_for_stats_config(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_steering_config:
            if (translate_config_from_ovsdb_for_steering_config(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_steering_clients:
            if (translate_config_from_ovsdb_for_steering_clients(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation from ovsdb failed\n", __func__, __LINE__);
                return webconfig_error_translate_from_ovsdb;
            }
        break;

        case webconfig_subdoc_type_vif_neighbors:
            if (translate_config_from_ovsdb_for_vif_neighbors(data) != webconfig_error_none) {
                wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d: vap_object translation from ovsdb failed\n", __func__, __LINE__);
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
