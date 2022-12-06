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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "cJSON.h"
#include "wifi_hal.h"
#include "os.h"
#include "util.h"
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"
#include "schema.h"
#include "log.h"
#include "ds.h"
#include "json_util.h"
#include "target.h"
#include <ev.h>
#include <assert.h>
#include "collection.h"
#include "wifi_ovsdb.h"
#include "ccsp_base_api.h"
//This is a dummy string if the value is not passed.
#define INVALID_KEY "12345678"
int ovsdb_get_factory_reset_data(bool *data)
{
	return 0;
}

int ovsdb_set_factory_reset_data(bool data)
{
	return 0;
}

int ovsdb_del_interworking_entry()
{
    return 0;
}

int ovsdb_check_wmm_params()
{
    return 0;
}

int ovsdb_get_reset_hotspot_required(bool *req)
{
    return 0;
}

int ovsdb_set_reset_hotspot_required(bool req)
{
    return 0;
}

int ovsdb_get_radio_params(unsigned int radio_index, wifi_radio_operationParam_t *params)
{
    if (radio_index == 0) {
        params->band = WIFI_FREQUENCY_2_4_BAND;
        params->op_class = 12;
        params->channel = 3;
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_G;
    } else if (radio_index == 1) {
        params->band = WIFI_FREQUENCY_2_4_BAND;
        params->op_class = 12;
        params->channel = 3;
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_G;
    } else if (radio_index == 2) {
        params->band = WIFI_FREQUENCY_2_4_BAND;
        params->op_class = 12;
        params->channel = 3;
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_N;
    } else if (radio_index == 3) {
        params->band = WIFI_FREQUENCY_2_4_BAND;
        params->op_class = 12;
        params->channel = 3; 
        params->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
        params->variant = WIFI_80211_VARIANT_N;
    }
    
    params->autoChannelEnabled = false;
    params->csa_beacon_count = 0;
    params->countryCode = wifi_countrycode_US;
    params->beaconInterval = 100;
    params->dtimPeriod = 2;

    return 0;
}

int ovsdb_get_vap_info_map(unsigned int real_index, unsigned int index, wifi_vap_info_map_t *map)
{
    wifi_vap_info_t *params;

    params = &map->vap_array[index];
    memset((unsigned char *)params, 0, sizeof(wifi_vap_info_t));

    params->radio_index = real_index;

    if (index == 0) {
        map->num_vaps = 3;
        params->vap_index = 14;
        params->vap_mode = wifi_vap_mode_sta;
        strcpy(params->vap_name, "mesh_sta_2g");
        strcpy(params->u.sta_info.ssid, "wifi_test_private_2");
        params->u.sta_info.scan_params.period = 10;
        params->u.sta_info.security.mode = wifi_security_mode_wpa2_personal;
        params->u.sta_info.security.encr = wifi_encryption_aes;
        strcpy(params->u.sta_info.security.u.key.key, INVALID_KEY);
    } else if (index == 1) {
        map->num_vaps = 3;
        params->vap_index = 0;
        params->vap_mode = wifi_vap_mode_ap;
        strcpy(params->vap_name, "private_ssid_2g");
        strcpy(params->bridge_name, "brlan0");
        strcpy(params->u.bss_info.ssid, "private_ssid_2g");
        params->u.bss_info.enabled = true;
        params->u.bss_info.showSsid = true;
        params->u.bss_info.isolation = true;
        params->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
        params->u.bss_info.security.encr = wifi_encryption_aes;
        strcpy(params->u.bss_info.security.u.key.key, INVALID_KEY);
        params->u.bss_info.bssMaxSta = 20;
    } else if (index == 2) {
        map->num_vaps = 3;
        params->vap_index = 12;
        params->vap_mode = wifi_vap_mode_ap;
        strcpy(params->vap_name, "mesh_backhaul_2g");
        strcpy(params->bridge_name, "brlan112");
        strcpy(params->u.bss_info.ssid, "mesh_backhaul_2g");
        params->u.bss_info.enabled = true;
        params->u.bss_info.showSsid = true;
        params->u.bss_info.isolation = true;
        params->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
        params->u.bss_info.security.encr = wifi_encryption_aes;
        strcpy(params->u.bss_info.security.u.key.key, INVALID_KEY);
        params->u.bss_info.bssMaxSta = 20;
    }

    return 0;
}
