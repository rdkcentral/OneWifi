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
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include "vap_svc.h"
#include "wifi_ctrl.h"
#include "wifi_util.h"
#include "wifi_hal.h"

bool vap_svc_is_private(unsigned int vap_index)
{
    if (isVapPrivate(vap_index) || isVapXhs(vap_index) || isVapLnf(vap_index)) {
        return true;
    }

    return false;
}

int vap_svc_private_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    return vap_svc_start(svc, radio_index);
}

int vap_svc_private_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    return vap_svc_stop(svc, radio_index);
}

static int configure_lnf_psk_radius_from_hotspot(wifi_vap_info_t *vap_info)
{
  int band;
    wifi_vap_info_t *hotspot_vap_info = NULL;
    int rIdx = 0;
    if (!vap_info) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Invalid vap_info parameter\n", __FUNCTION__, __LINE__);
        return -1;
    }

    if (!isVapLnfPsk(vap_info->vap_index) || !vap_info->u.bss_info.mdu_enabled) {
        return 0;
    }
    wifi_platform_property_t *wifi_prop = get_wifi_hal_cap_prop();
    if (convert_radio_index_to_freq_band(wifi_prop, vap_info->radio_index, &band) != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get band for vap_index=%d\n", 
                             __FUNCTION__, __LINE__, vap_info->vap_index);
        return -1;
    }
    
    if (convert_freq_band_to_radio_index(WIFI_FREQUENCY_5_BAND, &rIdx) != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to convert freq to band\n", __FUNCTION__, __LINE__);
        return -1;
    }
    hotspot_vap_info = get_wifidb_vap_parameters(getApFromRadioIndex(rIdx, VAP_PREFIX_HOTSPOT_SECURE));

    if (hotspot_vap_info == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to get hotspot_vap_info for vap_index=%d\n", 
                             __FUNCTION__, __LINE__, vap_info->vap_index);
        return -1;
    }
    memcpy((unsigned char *)&vap_info->u.bss_info.security.repurposed_radius, (unsigned char *)&hotspot_vap_info->u.bss_info.security.u.radius, sizeof(vap_info->u.bss_info.security.repurposed_radius));
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d LNF RADIUS Config for vap name = %s - Primary IP: %s Port: %d, Secondary IP: %s Port: %d\n",
                       __func__, __LINE__, vap_info->vap_name,
                       vap_info->u.bss_info.security.repurposed_radius.ip,
                       vap_info->u.bss_info.security.repurposed_radius.port,
                       vap_info->u.bss_info.security.repurposed_radius.s_ip,
                       vap_info->u.bss_info.security.repurposed_radius.s_port);
    return 0;
}

int vap_svc_private_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map,
    rdk_wifi_vap_info_t *rdk_vap_info)
{
    bool enabled;
    unsigned int i;
    wifi_vap_info_map_t *p_tgt_vap_map = NULL;
    int ret;
    int band;
    wifi_platform_property_t *wifi_prop = get_wifi_hal_cap_prop();
    wifi_vap_info_t *vap = NULL;
    unsigned int vap_index = 0;

    p_tgt_vap_map = (wifi_vap_info_map_t *) malloc( sizeof(wifi_vap_info_map_t) );
    if (p_tgt_vap_map == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Failed to allocate memory.\n", __FUNCTION__,__LINE__);
        return -1;
    }
    for (i = 0; i < map->num_vaps; i++) {

        memset((unsigned char *)p_tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));
        memcpy((unsigned char *)&p_tgt_vap_map->vap_array[0], (unsigned char *)&map->vap_array[i],
                    sizeof(wifi_vap_info_t));
        p_tgt_vap_map->num_vaps = 1;

        // VAP is enabled in HAL if it is present in VIF_Config and enabled. Absent VAP entries are
        // saved to VAP_Config with exist flag set to 0 and default values.
        enabled = p_tgt_vap_map->vap_array[0].u.bss_info.enabled;
        if (configure_lnf_psk_radius_from_hotspot(&p_tgt_vap_map->vap_array[0]) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d configure_lnf_psk_radius_from_hotspot failed\n", __FUNCTION__, __LINE__);
            return -1;
        }

        vap = &p_tgt_vap_map->vap_array[0];
        vap_index = map->vap_array[i].vap_index;

        if (convert_radio_index_to_freq_band(wifi_prop, radio_index, &band) == RETURN_OK) {
            if (isVapPrivate(vap_index) && map->vap_array[i].u.bss_info.wps.enable) {
                if (band != WIFI_FREQUENCY_6_BAND) {
                    vap->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
                }
            }
            else if (isVapMeshBackhaul(vap_index)) {
                vap->u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
                vap->u.bss_info.security.wpa3_transition_disable = false;
                vap->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
                vap->u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
            }
        }

#if defined(_WNXL11BWL_PRODUCT_REQ_)
        if (rdk_vap_info[i].exists == false && isVapPrivate(map->vap_array[i].vap_index)) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE \n",__FUNCTION__,__LINE__,map->vap_array[i].vap_index);
            rdk_vap_info[i].exists = true;
        }
#elif !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_)
        if(rdk_vap_info[i].exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
            if(map->vap_array[i].vap_index != 2 && map->vap_array[i].vap_index != 3) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE \n",__FUNCTION__,__LINE__,map->vap_array[i].vap_index);
                rdk_vap_info[i].exists = true;
            }
#else
            wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE \n",__FUNCTION__,__LINE__,map->vap_array[i].vap_index);
            rdk_vap_info[i].exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
        }
#endif /* !defined(_PP203X_PRODUCT_REQ_) && !defined(_GREXT02ACTS_PRODUCT_REQ_) */
        p_tgt_vap_map->vap_array[0].u.bss_info.enabled &= rdk_vap_info[i].exists;

        // If WPS is enabled on private VAP, copy mesh backhaul credentials into multi_ap_backhaul structure
        if (map->vap_array[i].u.bss_info.wps.enable && isVapPrivate(map->vap_array[i].vap_index)) {
            wifi_platform_property_t *wifi_prop = get_wifi_hal_cap_prop();
            wifi_vap_name_t vap_names[MAX_NUM_RADIOS] = {0};
            unsigned int num_vaps = get_list_of_mesh_backhaul(wifi_prop, MAX_NUM_RADIOS, vap_names);
            wifi_vap_info_t *backhaul_vap_info = NULL;

            if (num_vaps > 0) {
                int backhaul_vap_index = convert_vap_name_to_index(wifi_prop, vap_names[0]);
                if (backhaul_vap_index >= 0) {
                    backhaul_vap_info = get_wifidb_vap_parameters(backhaul_vap_index);
                }
            }
            if (backhaul_vap_info != NULL &&
                strlen((char *)backhaul_vap_info->u.bss_info.ssid) > 0 &&
                strlen((char *)backhaul_vap_info->u.bss_info.security.u.key.key) > 0 &&
                strcmp((char *)backhaul_vap_info->u.bss_info.security.u.key.key, INVALID_KEY) != 0) {
                memset(p_tgt_vap_map->vap_array[0].u.bss_info.multi_ap_backhaul_ssid, 0,
                       sizeof(p_tgt_vap_map->vap_array[0].u.bss_info.multi_ap_backhaul_ssid));
                strncpy((char *)p_tgt_vap_map->vap_array[0].u.bss_info.multi_ap_backhaul_ssid,
                       (char *)backhaul_vap_info->u.bss_info.ssid,
                       sizeof(p_tgt_vap_map->vap_array[0].u.bss_info.multi_ap_backhaul_ssid) - 1);

                memset(p_tgt_vap_map->vap_array[0].u.bss_info.multi_ap_backhaul_network_key, 0,
                       sizeof(p_tgt_vap_map->vap_array[0].u.bss_info.multi_ap_backhaul_network_key));
                strncpy((char *)p_tgt_vap_map->vap_array[0].u.bss_info.multi_ap_backhaul_network_key,
                       (char *)backhaul_vap_info->u.bss_info.security.u.key.key,
                       sizeof(p_tgt_vap_map->vap_array[0].u.bss_info.multi_ap_backhaul_network_key) - 1);

                wifi_util_info_print(WIFI_CTRL, "%s:%d Copied mesh backhaul credentials to multi_ap_backhaul for private VAP %d\n",
                                   __FUNCTION__, __LINE__, map->vap_array[i].vap_index);
            } else {
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d Mesh backhaul credentials not found or invalid, WPS enabled without backhaul for VAP %d\n",
                                   __FUNCTION__, __LINE__, map->vap_array[i].vap_index);
            }
        }

        ret = wifi_hal_createVAP(radio_index, p_tgt_vap_map);
        if (ret != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s: wifi vap create failure: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
            free(p_tgt_vap_map);
            return ret;
        }

        p_tgt_vap_map->vap_array[0].u.bss_info.enabled = enabled;
        
        wifi_util_info_print(WIFI_CTRL,"%s: wifi vap create success: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
        get_wifidb_obj()->desc.print_fn("%s: wifi vap create success: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
        get_wifidb_obj()->desc.print_fn("%s:%d [Stop] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());
        if (isVapLnfPsk(p_tgt_vap_map->vap_array[0].vap_index)) {
            update_vap_hal_prop_bridge_name(svc, p_tgt_vap_map);
            // Since DB persistence not supported as of now for MDU LnF, copying it to here. To be moved in future.
            wifi_vap_info_t *lnf_vap_info = NULL;
            lnf_vap_info = (wifi_vap_info_t *)get_wifidb_vap_parameters(
                p_tgt_vap_map->vap_array[0].vap_index);
            if (lnf_vap_info == NULL) {
                wifi_util_error_print(WIFI_CTRL, "%s:%d LnF VAP info not found for vap_index=%d\n",
                    __FUNCTION__, __LINE__, map->vap_array[i].vap_index);
                return -1;
            }
            if (lnf_vap_info->u.bss_info.mdu_enabled) {
                memcpy((unsigned char *)&lnf_vap_info->u.bss_info.security.repurposed_radius,
                    (unsigned char *)&p_tgt_vap_map->vap_array[0]
                        .u.bss_info.security.repurposed_radius,
                    sizeof(lnf_vap_info->u.bss_info.security.repurposed_radius));
            } else {
                memset((unsigned char *)&lnf_vap_info->u.bss_info.security.repurposed_radius, 0,
                    sizeof(lnf_vap_info->u.bss_info.security.repurposed_radius));
            }
        }
        memcpy((unsigned char *)&map->vap_array[i], (unsigned char *)&p_tgt_vap_map->vap_array[0],
                    sizeof(wifi_vap_info_t));
        get_wifidb_obj()->desc.update_wifi_vap_info_fn(getVAPName(map->vap_array[i].vap_index), &map->vap_array[i],
            &rdk_vap_info[i]);
        get_wifidb_obj()->desc.update_wifi_interworking_cfg_fn(getVAPName(map->vap_array[i].vap_index),
                &map->vap_array[i].u.bss_info.interworking);
        get_wifidb_obj()->desc.update_wifi_security_config_fn(getVAPName(map->vap_array[i].vap_index),
                &map->vap_array[i].u.bss_info.security);

    }
    free(p_tgt_vap_map);

    return 0;
}

int vap_svc_private_event(vap_svc_t *svc, wifi_event_type_t type, wifi_event_subtype_t sub_type, vap_svc_event_t event, void *arg)
{
   return 0;
}
