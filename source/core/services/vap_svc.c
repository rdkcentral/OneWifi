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
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "vap_svc.h"

struct vap_svc *svc;

int svc_init(vap_svc_t *svc, vap_svc_type_t type)
{
    wifi_mgr_t *wifi_mgr_obj = get_wifimgr_obj();
    memset(svc, 0, sizeof(vap_svc_t));

    svc->ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    svc->prop = &wifi_mgr_obj->hal_cap.wifi_prop;

    svc->type = type;
    switch (type) {
        case vap_svc_type_private:
            svc->start_fn = vap_svc_private_start;
            svc->stop_fn = vap_svc_private_stop;
            svc->update_fn = vap_svc_private_update;
            svc->event_fn = vap_svc_private_event;
            svc->is_my_fn = vap_svc_is_private;
            break;

        case vap_svc_type_public:
            svc->start_fn = vap_svc_public_start;
            svc->stop_fn = vap_svc_public_stop;
            svc->update_fn = vap_svc_public_update;
            svc->event_fn = vap_svc_public_event;
            svc->is_my_fn = vap_svc_is_public;
            break;

        case vap_svc_type_mesh_gw:
            svc->start_fn = vap_svc_mesh_gw_start;
            svc->stop_fn = vap_svc_mesh_gw_stop;
            svc->update_fn = vap_svc_mesh_gw_update;
            svc->event_fn = vap_svc_mesh_gw_event;
            svc->is_my_fn = vap_svc_is_mesh_gw;
            break;

        case vap_svc_type_mesh_ext:
            svc->start_fn = vap_svc_mesh_ext_start;
            svc->stop_fn = vap_svc_mesh_ext_stop;
            svc->update_fn = vap_svc_mesh_ext_update;
            svc->event_fn = vap_svc_mesh_ext_event;
            svc->is_my_fn = vap_svc_is_mesh_ext;
            break;

        case vap_svc_type_max:
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d ctrl task service init event\n", __func__, __LINE__);
            break;
    }

    return 0;
}

int update_global_cache(wifi_vap_info_map_t *tgt_vap_map, rdk_wifi_vap_info_t *rdk_vap_info)
{
    uint8_t j = 0;
    rdk_wifi_vap_info_t *rdk_vaps;
    wifi_vap_info_map_t *vap_map = NULL;
    uint8_t i = 0, vap_index = 0;

    for (i = 0; i < tgt_vap_map->num_vaps; i++) {
        vap_index = tgt_vap_map->vap_array[i].vap_index;
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(tgt_vap_map->vap_array[i].radio_index);
        if (vap_map == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d global vap_map null radio_index:%d\n", __func__, __LINE__,
                tgt_vap_map->vap_array[i].radio_index);
            return RETURN_ERR;
        }
        rdk_vaps = get_wifidb_rdk_vaps(tgt_vap_map->vap_array[i].radio_index);
        if (rdk_vaps == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d failed to get rdk vaps for radio index: %d\n",
                __func__, __LINE__, tgt_vap_map->vap_array[i].radio_index);
            return RETURN_ERR;
        }
        for (j = 0; j < vap_map->num_vaps; j++) {
            if (vap_map->vap_array[j].vap_index == vap_index) {
                memcpy((unsigned char *)&vap_map->vap_array[j], (unsigned char *)&tgt_vap_map->vap_array[i],
                    sizeof(wifi_vap_info_t));
                memcpy(&rdk_vaps[j], &rdk_vap_info[i], sizeof(rdk_wifi_vap_info_t));
                break;
            }
        }
    }

    return RETURN_OK;
}

int update_acl_entries(wifi_vap_info_map_t *tgt_vap_map)
{
    rdk_wifi_vap_info_t *vap_info;
    mac_addr_str_t mac_str;
    mac_address_t acl_device_mac;
    acl_entry_t *acl_entry;
    uint8_t i = 0, vap_index = 0;

    for (i = 0; i < tgt_vap_map->num_vaps; i++) {
        vap_index = tgt_vap_map->vap_array[i].vap_index;
#ifdef NL80211_ACL
        wifi_hal_delApAclDevices(vap_index);
#else
        wifi_delApAclDevices(vap_index);
#endif
        vap_info = get_wifidb_rdk_vap_info(vap_index);

        if ((vap_info == NULL) || (vap_info->acl_map == NULL)) {
            return RETURN_ERR;
        }

        acl_entry = hash_map_get_first(vap_info->acl_map);
        while(acl_entry != NULL) {
            if (acl_entry->mac != NULL) {
                memcpy(&acl_device_mac,&acl_entry->mac,sizeof(mac_address_t));
                to_mac_str(acl_device_mac, mac_str);
                wifi_util_dbg_print(WIFI_CTRL, "%s:%d: calling wifi_addApAclDevice for mac %s vap_index %d\n", __func__, __LINE__, mac_str, vap_index);
#ifdef NL80211_ACL
                if (wifi_hal_addApAclDevice(vap_index, (CHAR *) mac_str) != RETURN_OK) {
#else
                if (wifi_addApAclDevice(vap_index, (CHAR *) mac_str) != RETURN_OK) {
#endif
                    wifi_util_error_print(WIFI_CTRL,"%s: wifi_addApAclDevice failed. vap_index:%d MAC:'%s'\n",__FUNCTION__, vap_index, mac_str);
                }
            }
            acl_entry = hash_map_get_next(vap_info->acl_map,acl_entry);
        }
        vap_info->is_mac_filter_initialized = true;
    }

    return RETURN_OK;
}

wifi_interface_name_idex_map_t *get_wifi_hal_capability_info(wifi_platform_property_t *wifi_prop, wifi_vap_info_t *old_vap_info)
{
    wifi_interface_name_idex_map_t *if_prop = NULL;
    UINT total_vaps = getTotalNumberVAPs();

    for (UINT i = 0; i < total_vaps; ++i) {
        if (!strcmp(old_vap_info->vap_name, wifi_prop->interface_map[i].vap_name)) {
            if_prop = &wifi_prop->interface_map[i];
            break;
        }
    }

    if (if_prop == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d: wifi interface not found for:%s\n", __func__, __LINE__, old_vap_info->vap_name);
    }

    return if_prop;
}

int update_lnf_psk_vap_hal_prop_bridge_name(vap_svc_t *svc, wifi_vap_info_map_t *vap_map)
{
    uint8_t j = 0;
    wifi_interface_name_idex_map_t *if_prop = NULL;

    for (j = 0; j < vap_map->num_vaps; j++) {
        if (isVapLnfPsk(vap_map->vap_array[j].vap_index)) {
            if_prop = get_wifi_hal_capability_info(svc->prop, &vap_map->vap_array[j]);
            if (if_prop == NULL) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d: Could not find wifi hal capability info for vap_name: %s\n", __func__, __LINE__, vap_map->vap_array[j].vap_name);
                return RETURN_ERR;
            } else {
                if (strncmp(if_prop->bridge_name, vap_map->vap_array[j].bridge_name, strlen(vap_map->vap_array[j].bridge_name)) != 0) {
                    wifi_util_info_print(WIFI_CTRL,"%s:%d: changed bridge name from :%s to %s\n", __func__, __LINE__, if_prop->bridge_name, vap_map->vap_array[j].bridge_name);
                    strncpy(if_prop->bridge_name, vap_map->vap_array[j].bridge_name, sizeof(vap_map->vap_array[j].bridge_name));
                }
            }
        }
    }

    return RETURN_OK;
}

int vap_svc_start_stop(vap_svc_t *svc, bool enable)
{
    uint8_t num_of_radios;
    uint8_t i, j;
    bool enabled[MAX_NUM_VAP_PER_RADIO];
    rdk_wifi_vap_info_t tgt_rdk_vaps[MAX_NUM_VAP_PER_RADIO], *rdk_vaps;
    wifi_vap_info_map_t *vap_map = NULL;
    wifi_vap_info_map_t *tgt_vap_map = (wifi_vap_info_map_t*)calloc(1, sizeof(wifi_vap_info_map_t));

    if (!tgt_vap_map)
    {
        wifi_util_error_print(WIFI_CTRL,"WIFI %s: calloc failure\n",__FUNCTION__);
        return -1;
    }

    if ((num_of_radios = getNumberRadios()) > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_CTRL,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        free(tgt_vap_map);
        return -1;
    }

    memset(tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));

    for (i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        rdk_vaps = get_wifidb_rdk_vaps(i);
        if (vap_map == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__, i);
            free(tgt_vap_map);
            return -1;
        }

        memset(tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));
        memset(tgt_rdk_vaps, 0, sizeof(tgt_rdk_vaps));
        for (j = 0; j < vap_map->num_vaps; j++) {
            if (svc->is_my_fn(vap_map->vap_array[j].vap_index) == false) {
                continue;
            }

            memcpy((unsigned char *)&tgt_vap_map->vap_array[tgt_vap_map->num_vaps], (unsigned char *)&vap_map->vap_array[j], sizeof(wifi_vap_info_t));
            memcpy(&tgt_rdk_vaps[tgt_vap_map->num_vaps], &rdk_vaps[j], sizeof(rdk_wifi_vap_info_t));
            if (tgt_vap_map->vap_array[tgt_vap_map->num_vaps].vap_mode == wifi_vap_mode_sta) {
                tgt_vap_map->vap_array[tgt_vap_map->num_vaps].u.sta_info.enabled = enable;
            } else {
                if(tgt_vap_map->vap_array[tgt_vap_map->num_vaps].u.bss_info.enabled) {
                    tgt_vap_map->vap_array[tgt_vap_map->num_vaps].u.bss_info.enabled = enable;
                }
                // VAP is enabled in HAL if it is present in VIF_Config and enabled. Absent VAP
                // entries are saved to VAP_Config with exist flag set to 0 and default values.
                enabled[tgt_vap_map->num_vaps] =
                    tgt_vap_map->vap_array[tgt_vap_map->num_vaps].u.bss_info.enabled;
                tgt_vap_map->vap_array[tgt_vap_map->num_vaps].u.bss_info.enabled &=
                    tgt_rdk_vaps[tgt_vap_map->num_vaps].exists;
            }
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
            if(tgt_rdk_vaps[tgt_vap_map->num_vaps].exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
                if(vap_map->vap_array[j].vap_index != 2 && vap_map->vap_array[j].vap_index != 3) {
                    wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE \n",__FUNCTION__,__LINE__,vap_map->vap_array[j].vap_index);
                    tgt_rdk_vaps[tgt_vap_map->num_vaps].exists = true;
                }
#else
                wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE \n",__FUNCTION__,__LINE__,vap_map->vap_array[j].vap_index);
                tgt_rdk_vaps[tgt_vap_map->num_vaps].exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
            }
#endif /* defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)*/

            tgt_vap_map->num_vaps++;
        }

        if (wifi_hal_createVAP(i, tgt_vap_map) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s: wifi vap create failure: radio_index:%d\n",__FUNCTION__, i);
            free(tgt_vap_map);
            return -1;
        }

        for (j = 0; j < tgt_vap_map->num_vaps; j++) {
            if (tgt_vap_map->vap_array[j].vap_mode != wifi_vap_mode_sta) {
                tgt_vap_map->vap_array[j].u.bss_info.enabled = enabled[j];
            }
        }

        wifi_util_info_print(WIFI_CTRL, "%s:%d wifi vaps create success for radio index: %d\n",
            __func__, __LINE__, i);
        update_global_cache(tgt_vap_map, tgt_rdk_vaps);
        update_acl_entries(tgt_vap_map);

        update_lnf_psk_vap_hal_prop_bridge_name(svc, tgt_vap_map);
    }

    free(tgt_vap_map);

    return 0;

}

int vap_svc_stop(vap_svc_t *svc)
{
    return vap_svc_start_stop(svc, false);
}

int vap_svc_start(vap_svc_t *svc)
{
    return vap_svc_start_stop(svc, true);
}

vap_svc_t *get_svc_by_type(wifi_ctrl_t *ct, vap_svc_type_t type)
{
    unsigned int i;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)ct;

    for (i = 0; i < vap_svc_type_max; i++) {
        if (ctrl->ctrl_svc[i].type == type) {
            return &ctrl->ctrl_svc[i];
        }
    }

    return NULL;
}

vap_svc_t *get_svc_by_name(wifi_ctrl_t *ct, char *vap_name)
{
    vap_svc_type_t type = vap_svc_type_max;

    if (strstr(vap_name, "private") != NULL) {
        type = vap_svc_type_private;
    } else if (strstr(vap_name, "iot") != NULL) {
        type = vap_svc_type_private;
    } else if (strstr(vap_name, "lnf") != NULL) {
        type = vap_svc_type_private;
    } else if (strstr(vap_name, "xfinity") != NULL) {
        type = vap_svc_type_public;
    } else if (strstr(vap_name, "hotspot") != NULL) {
        type = vap_svc_type_public;
    } else if (strncmp(vap_name, "mesh_sta", strlen("mesh_sta")) == 0) {
        type = vap_svc_type_mesh_ext;
    } else if (strncmp(vap_name, "mesh_backhaul", strlen("mesh_backhaul")) == 0) {
        type = vap_svc_type_mesh_gw;
    } else if (strncmp(vap_name, "mesh", strlen("mesh")) == 0) {
        type = vap_svc_type_mesh_gw;
    }

    if (type == vap_svc_type_max) {
        return NULL;
    }

    return get_svc_by_type(ct, type);
}

vap_svc_t *get_svc_by_vap_index(wifi_ctrl_t *ct, unsigned int vap_index)
{
    unsigned int i;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)ct;

    for (i = 0; i < vap_svc_type_max; i++) {
        if (ctrl->ctrl_svc[i].is_my_fn(vap_index) == true) {
            return &ctrl->ctrl_svc[i];
        }
    }

    return NULL;
}
