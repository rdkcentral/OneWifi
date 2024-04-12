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
#include "vap_svc.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"

bool vap_svc_is_public(unsigned int vap_index)
{
    return isVapHotspot(vap_index) ? true : false;
}

int vap_svc_public_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    // for public just create vaps
    if (radio_index == WIFI_ALL_RADIO_INDICES) {
        return vap_svc_start(svc);
    }

    return 0;
}

int vap_svc_public_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    if (radio_index == WIFI_ALL_RADIO_INDICES) {
        return vap_svc_stop(svc);
    }
    return 0;
}
void process_prefer_private_mac_filter(mac_address_t prefer_private_mac)
{
    unsigned int itr = 0, itrj = 0;
    int vap_index = 0;

    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    mac_address_t zero_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    acl_entry_t *acl_entry = NULL;
    acl_entry_t *temp_acl_entry = NULL;
    mac_address_t new_mac;
    mac_addr_str_t new_mac_str;
    char macfilterkey[128];
    wifi_vap_info_map_t *wifi_vap_map = NULL;
    int acl_count = 0;

    memset(macfilterkey, 0, sizeof(macfilterkey));

    memcpy(new_mac,prefer_private_mac, sizeof(mac_address_t));
    if (memcmp(new_mac, zero_mac, sizeof(mac_address_t)) == 0){
        wifi_util_dbg_print(WIFI_CTRL," new_mac is zero mac \n");
        return ;
    }

    to_mac_str(new_mac, new_mac_str);
    str_tolower(new_mac_str);
    wifi_util_dbg_print(WIFI_CTRL,"macstring to addi %s\n",new_mac_str);

    for (itr = 0; itr < getNumberRadios(); itr++) {
        wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(itr);
        for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {

            vap_index = wifi_vap_map->vap_array[itrj].vap_index;
            rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);

            if (rdk_vap_info == NULL) {
                 return;
            }

            if ((vap_svc_is_public(rdk_vap_info->vap_index) == false)) {
                continue;
            }

            if (rdk_vap_info->acl_map == NULL) {
                wifi_util_dbg_print(WIFI_CTRL,"PreferPrivate acl_map is NULL\n");
                rdk_vap_info->acl_map = hash_map_create();
            }
            acl_count = hash_map_count(rdk_vap_info->acl_map);
            wifi_util_dbg_print(WIFI_CTRL,"acl_count =%d \n",acl_count);

            if (acl_count >= MAX_ACL_COUNT) {
                wifi_util_info_print(WIFI_CTRL,"acl_count =%d greater than max acl entry\n",acl_count);
                continue;
            }
            temp_acl_entry = hash_map_get(rdk_vap_info->acl_map,new_mac_str);

            if (temp_acl_entry != NULL) {
                wifi_util_dbg_print(WIFI_CTRL,"Mac is already present in macfilter \n");
                return;
            }

            acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
            memcpy(acl_entry->mac, new_mac, sizeof(mac_address_t));
            to_mac_str(acl_entry->mac, new_mac_str);
            str_tolower(new_mac_str);
            strcpy(acl_entry->device_name,"");
            acl_entry->reason = PREFER_PRIVATE_RFC_REJECT;
            acl_entry->expiry_time = 0;

#ifdef NL80211_ACL
            if (wifi_hal_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
#else
            if (wifi_addApAclDevice(rdk_vap_info->vap_index, new_mac_str) != RETURN_OK) {
#endif
                wifi_util_info_print(WIFI_MGR, "%s:%d: wifi_addApAclDevice failed. vap_index %d, MAC %s \n",
                   __func__, __LINE__, rdk_vap_info->vap_index, new_mac_str);
            }

            hash_map_put(rdk_vap_info->acl_map, strdup(new_mac_str), acl_entry);
            snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", rdk_vap_info->vap_name, new_mac_str);
            wifidb_update_wifi_macfilter_config(macfilterkey, acl_entry, true);
            wifi_util_dbg_print(WIFI_CTRL,"add %s mac to %s\n",new_mac_str,rdk_vap_info->vap_name);
        }
    }
}

int vap_svc_public_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map,
    rdk_wifi_vap_info_t *rdk_vap_info)
{
    bool enabled;
    unsigned int i;
    wifi_vap_info_map_t *p_tgt_vap_map, *p_tgt_created_vap_map;
    bool greylist_rfc = false;
    bool rfc_passpoint_enable = false;
    p_tgt_vap_map = (wifi_vap_info_map_t *) malloc( sizeof(wifi_vap_info_map_t) );
    if (p_tgt_vap_map == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Failed to allocate memory.\n", __func__,__LINE__);
        return -1;
    }
    p_tgt_created_vap_map = (wifi_vap_info_map_t *) malloc( sizeof(wifi_vap_info_map_t) );
    if (p_tgt_created_vap_map == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Failed to allocate memory.\n", __func__,__LINE__);
        free(p_tgt_vap_map);
        return -1;
    }
    memset((unsigned char *)p_tgt_created_vap_map, 0, sizeof(wifi_vap_info_map_t));
    p_tgt_created_vap_map->num_vaps = 0;
    wifi_mgr_t *g_wifi_mgr = (wifi_mgr_t *)get_wifimgr_obj();
#if DML_SUPPORT
    wifi_rfc_dml_parameters_t *rfc_info = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
    if (rfc_info) {
        greylist_rfc = rfc_info->radiusgreylist_rfc;
        rfc_passpoint_enable = rfc_info->wifipasspoint_rfc;
    }
#endif // DML_SUPPORT
    wifi_global_param_t *pcfg = (wifi_global_param_t *) get_wifidb_wifi_global_param();
    for (i = 0; i < map->num_vaps; i++) {
        // Create xfinity secure vaps only if passpoint is enabled and update db and caches - just the way
        // it happens for other vaps - private, xH, etc,
        // The only expectation is that the first time creation of xfinity vaps will happen
        // through webconfig framework - this is because of the dependency on tunnels
        
        memset((unsigned char *)p_tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));
        memcpy((unsigned char *)&p_tgt_vap_map->vap_array[0], (unsigned char *)&map->vap_array[i],
                    sizeof(wifi_vap_info_t));
        p_tgt_vap_map->vap_array[0].u.bss_info.network_initiated_greylist = greylist_rfc;
        p_tgt_vap_map->num_vaps = 1;
        if (isVapHotspotSecure(map->vap_array[i].vap_index)) {
               if ((rfc_passpoint_enable == false) && (p_tgt_vap_map->vap_array[0].u.bss_info.interworking.passpoint.enable == true)) {
                    wifi_util_error_print(WIFI_CTRL,"%s:: radio_index:%d vap_index:%d Passpoint cannot be enabled when RFC is disabled RFC=%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index,rfc_passpoint_enable);
                    p_tgt_vap_map->vap_array[0].u.bss_info.interworking.passpoint.enable = false;
                }
        }
        // VAP is enabled in HAL if it is present in VIF_Config and enabled. Absent VAP entries are
        // saved to VAP_Config with exist flag set to 0 and default values.
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
        if(rdk_vap_info[i].exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
            if(map->vap_array[i].vap_index != 2 && map->vap_array[i].vap_index != 3) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,map->vap_array[i].vap_index);
                rdk_vap_info[i].exists = true;
            }
#else
            wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,map->vap_array[i].vap_index);
            rdk_vap_info[i].exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
        }
#endif /*defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)*/
        enabled = p_tgt_vap_map->vap_array[0].u.bss_info.enabled;
        p_tgt_vap_map->vap_array[0].u.bss_info.enabled &= rdk_vap_info[i].exists;
        if (is_6g_supported_device(&g_wifi_mgr->hal_cap.wifi_prop) && p_tgt_vap_map->vap_array[0].u.bss_info.enabled) {
            wifi_util_info_print(WIFI_CTRL, "%s:%d 6g supported device  %s is enabled  nbrReport is activated\n", __func__,__LINE__,p_tgt_vap_map->vap_array[0].vap_name);
            p_tgt_vap_map->vap_array[0].u.bss_info.nbrReportActivated = true;
        }
        if (wifi_hal_createVAP(radio_index, p_tgt_vap_map) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s: wifi vap create failure: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
            continue;
        }
        p_tgt_vap_map->vap_array[0].u.bss_info.enabled = enabled;
        if (greylist_rfc || ((pcfg != NULL && pcfg->prefer_private))) {
            wifi_setApMacAddressControlMode(p_tgt_vap_map->vap_array[0].vap_index, 2);
        }
        else {
            wifi_setApMacAddressControlMode(p_tgt_vap_map->vap_array[0].vap_index, 0);
        }
        wifi_util_info_print(WIFI_CTRL,"%s: wifi vap create success: radio_index:%d vap_index:%d greylist_rfc:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index,greylist_rfc);
        wifidb_print("%s: wifi vap create success: radio_index:%d vap_index:%d \n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
        wifidb_print("%s:%d [Stop] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());
        wifi_util_error_print(WIFI_CTRL,"%s: passpoint.enable %d\n", __FUNCTION__,map->vap_array[i].u.bss_info.interworking.passpoint.enable);
        //Storing the config of passpoint in DB as received from blob though RFC is disabled
        if (isVapHotspotSecure(map->vap_array[i].vap_index)) {
               if ((rfc_passpoint_enable == false) && (map->vap_array[i].u.bss_info.interworking.passpoint.enable == true)) {
                   p_tgt_vap_map->vap_array[0].u.bss_info.interworking.passpoint.enable = true;
                }
        }
        wifi_util_error_print(WIFI_CTRL,"%s: p_tgt_vap_map->passpoint.enable %d\n", __FUNCTION__,p_tgt_vap_map->vap_array[0].u.bss_info.interworking.passpoint.enable);
        memcpy((unsigned char *)&map->vap_array[i], (unsigned char *)&p_tgt_vap_map->vap_array[0],
                    sizeof(wifi_vap_info_t));
        memcpy((unsigned char *)&p_tgt_created_vap_map->vap_array[i], (unsigned char *)&p_tgt_vap_map->vap_array[0], sizeof(wifi_vap_info_t));
        wifidb_update_wifi_vap_info(map->vap_array[i].vap_name, &map->vap_array[i],
            &rdk_vap_info[i]);
        wifidb_update_wifi_interworking_config(map->vap_array[i].vap_name,
            &map->vap_array[i].u.bss_info.interworking);
        wifidb_update_wifi_security_config(map->vap_array[i].vap_name,
            &map->vap_array[i].u.bss_info.security);
        wifidb_update_wifi_passpoint_config(map->vap_array[i].vap_name,
            &map->vap_array[i].u.bss_info.interworking);
        wifidb_update_wifi_anqp_config(map->vap_array[i].vap_name,
             &map->vap_array[i].u.bss_info.interworking);
    }
     update_global_cache(p_tgt_created_vap_map, rdk_vap_info);
    //Load all the Acl entries related to the created public vaps
    update_xfinity_acl_entries(p_tgt_vap_map->vap_array[0].vap_name);
    free(p_tgt_vap_map);
    free(p_tgt_created_vap_map);
    return 0;
}
int update_xfinity_acl_entries(char* tgt_vap_name)
{
    mac_addr_str_t mac_str;
    mac_address_t acl_device_mac;
    acl_entry_t *acl_entry;
    uint8_t itr = 0,itrj = 0, vap_index = 0, acl_count= 0;

    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    wifi_vap_info_map_t *wifi_vap_map = NULL;

    wifi_util_dbg_print(WIFI_CTRL,"Enter %s tgt_vap_name=%s \n",__func__,tgt_vap_name);
    for (itr = 0; itr < getNumberRadios(); itr++) {
        wifi_vap_map =(wifi_vap_info_map_t *) get_wifidb_vap_map(itr);
        for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
            vap_index = wifi_vap_map->vap_array[itrj].vap_index;
            rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);

            if (rdk_vap_info == NULL) {
                 return -1;
            }

           if ((strcmp(rdk_vap_info->vap_name,tgt_vap_name) != 0 )) {
                continue;
            }
#ifdef NL80211_ACL
	   wifi_hal_delApAclDevices(vap_index);
#else
	   wifi_delApAclDevices(vap_index);
#endif

            acl_entry = hash_map_get_first(rdk_vap_info->acl_map);
            while(acl_entry != NULL && acl_count < MAX_ACL_COUNT ) {
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
                acl_entry = hash_map_get_next(rdk_vap_info->acl_map,acl_entry);
                acl_count++;
            }
            rdk_vap_info->is_mac_filter_initialized = true;
        }
    }
    return RETURN_OK;
}

void add_mac_mode_to_public_vaps(bool mac_mode)
{
    unsigned int itr = 0, itrj = 0;
    int vap_index = 0;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    wifi_vap_info_map_t *wifi_vap_map = NULL;

    for (itr = 0; itr < getNumberRadios(); itr++) {
        wifi_vap_map =(wifi_vap_info_map_t *) get_wifidb_vap_map(itr);
        for (itrj = 0; itrj < getMaxNumberVAPsPerRadio(itr); itrj++) {
            vap_index = wifi_vap_map->vap_array[itrj].vap_index;
            rdk_vap_info = get_wifidb_rdk_vap_info(vap_index);

            if (rdk_vap_info == NULL) {
                 return;
            }

            if ((vap_svc_is_public(rdk_vap_info->vap_index) == false)) {
                continue;
            }
            if (mac_mode) {
                wifi_setApMacAddressControlMode(rdk_vap_info->vap_index, 2);
            }
            else {
                wifi_setApMacAddressControlMode(rdk_vap_info->vap_index, 0);
            }
        }
    }
}

void process_prefer_private_rfc_event(vap_svc_event_t event, void *data)
{
    switch(event) {
        case add_prefer_private_acl_to_public:
            process_prefer_private_mac_filter(*(mac_address_t *)data);
            break;

        case add_macmode_to_public:
            add_mac_mode_to_public_vaps(*(bool *)data);
            break;

        default:
            break;

    }
}

void process_xfinity_enable(vap_svc_event_t event, void *data)
{
#if DML_SUPPORT
    public_vaps_data_t *public = ((public_vaps_data_t *)data);
    wifi_util_dbg_print(WIFI_CTRL,"WIFI Enter RFC Func %s: %d : vap_name:%s:bool %d\n",__FUNCTION__,__LINE__,public->vap_name,public->enabled);
    wifi_rfc_dml_parameters_t *rfc_param = (wifi_rfc_dml_parameters_t *) get_wifi_db_rfc_parameters();
    if (strcmp(public->vap_name,"hotspot_open_2g") == 0)
        rfc_param->hotspot_open_2g_last_enabled = public->enabled;
    else if (strcmp(public->vap_name,"hotspot_open_5g") == 0)
        rfc_param->hotspot_open_5g_last_enabled = public->enabled;
    else if(strcmp(public->vap_name,"hotspot_open_6g") == 0)
        rfc_param->hotspot_open_6g_last_enabled = public->enabled;
    else if(strcmp(public->vap_name,"hotspot_secure_2g") == 0)
        rfc_param->hotspot_secure_2g_last_enabled = public->enabled;
    else if (strcmp(public->vap_name,"hotspot_secure_5g") == 0)
        rfc_param->hotspot_secure_5g_last_enabled = public->enabled;
   else if (strcmp(public->vap_name,"hotspot_secure_6g") == 0)
        rfc_param->hotspot_secure_6g_last_enabled = public->enabled;

    wifidb_update_rfc_config(0, rfc_param);
#endif
}

void process_xfinity_rrm(vap_svc_event_t event)
{
    unsigned int secure_6g = 0, open_6g = 0;
    int hotspot_open_2g_index = 0,hotspot_open_5g_index = 0;
    int hotspot_sec_2g_index = 0,hotspot_sec_5g_index = 0;
    wifi_radio_operationParam_t *radio_params = NULL;
    bool radio6g_enabled = false;
    mac_address_t open_6g_mac,secure_6g_mac;
    uint8_t num_radios = getNumberRadios();

    wifi_util_info_print(WIFI_CTRL," %s LINE %d\n",__func__,__LINE__);

    for(int radio_indx = 0; radio_indx < num_radios; ++radio_indx) {
        radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(radio_indx);
        if (radio_params == NULL) {
            continue;
        }
        if (radio_params->band == WIFI_FREQUENCY_6_BAND && radio_params->enable == true)
            radio6g_enabled =  true;

        wifi_vap_info_map_t *wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(radio_indx);
        if( wifi_vap_map == NULL) {
            continue;
        }
        for(unsigned int j = 0; j < wifi_vap_map->num_vaps; ++j) {
            if(strstr(wifi_vap_map->vap_array[j].vap_name, "hotspot") == NULL) {
                continue;
            }
            if ((strcmp(wifi_vap_map->vap_array[j].vap_name,"hotspot_open_2g") == 0) &&
               wifi_vap_map->vap_array[j].u.bss_info.enabled) {
               hotspot_open_2g_index = wifi_vap_map->vap_array[j].vap_index;
            }
            if ((strcmp(wifi_vap_map->vap_array[j].vap_name,"hotspot_open_5g") == 0) &&
               wifi_vap_map->vap_array[j].u.bss_info.enabled) {
               hotspot_open_5g_index = wifi_vap_map->vap_array[j].vap_index;
            }
            if ((strcmp(wifi_vap_map->vap_array[j].vap_name,"hotspot_secure_2g") == 0) &&
               wifi_vap_map->vap_array[j].u.bss_info.enabled) {
               hotspot_sec_2g_index = wifi_vap_map->vap_array[j].vap_index;
            }
            if ((strcmp(wifi_vap_map->vap_array[j].vap_name,"hotspot_secure_5g") == 0) &&
               wifi_vap_map->vap_array[j].u.bss_info.enabled) {
               hotspot_sec_5g_index = wifi_vap_map->vap_array[j].vap_index;
            }
            if (strcmp(wifi_vap_map->vap_array[j].vap_name,"hotspot_open_6g") == 0) {
                memcpy(open_6g_mac,wifi_vap_map->vap_array[j].u.bss_info.bssid,sizeof(mac_address_t));
                if (wifi_vap_map->vap_array[j].u.bss_info.enabled && radio6g_enabled) {
                    open_6g = 1;
                }
            }
            if (strcmp(wifi_vap_map->vap_array[j].vap_name,"hotspot_secure_6g") == 0) {
                memcpy(secure_6g_mac,wifi_vap_map->vap_array[j].u.bss_info.bssid,sizeof(mac_address_t));
                if (wifi_vap_map->vap_array[j].u.bss_info.enabled && radio6g_enabled) {
                    secure_6g = 1;
                }
            }
        }
    }
    wifi_util_info_print(WIFI_CTRL,"%s open_6g=%d and secure_6g=%d\n",__func__,open_6g,secure_6g);
    if (hotspot_open_2g_index !=0 ) {
        wifi_hal_set_neighbor_report(hotspot_open_2g_index,open_6g,open_6g_mac);
    }
    if(hotspot_open_5g_index !=0 ) {
        wifi_hal_set_neighbor_report(hotspot_open_5g_index,open_6g,open_6g_mac);
    }

    if (hotspot_sec_2g_index !=0 ) {
        wifi_hal_set_neighbor_report(hotspot_sec_2g_index,secure_6g,secure_6g_mac);
    }
    if(hotspot_sec_5g_index !=0 ) {
        wifi_hal_set_neighbor_report(hotspot_sec_5g_index,secure_6g,secure_6g_mac);
    }
}

void process_public_service_command(vap_svc_event_t event,wifi_event_subtype_t sub_type,void *data)
{

     switch(sub_type) {

        case wifi_event_type_prefer_private_rfc:
            process_prefer_private_rfc_event(event, data);
            break;
        case wifi_event_type_xfinity_enable:
            process_xfinity_enable(event, data);
            break;

        case wifi_event_type_xfinity_rrm:
            process_xfinity_rrm(event);
            break;

        default:
            break;
    }
}

int vap_svc_public_event(vap_svc_t *svc, wifi_event_type_t type, wifi_event_subtype_t sub_type, vap_svc_event_t event, void *arg)
{

    switch(type) {
        case wifi_event_type_command:
            process_public_service_command(event, sub_type, arg);
            break;

        default:
            break;
    }
    return 0;
}
