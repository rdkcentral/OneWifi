#include <stdio.h>
#include <stdbool.h>
#include "ansc_platform.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "webconfig_framework.h"
#include "scheduler.h"
#include <unistd.h>
#include <pthread.h>
#include <rbus.h>
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
#include "wifi_webconfig_consumer.h"
#endif

int webconfig_blaster_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int i = 0;

    active_msmt_t *cfg = &data->blaster;

    SetActiveMsmtPktSize(cfg->ActiveMsmtPktSize);
    SetActiveMsmtSampleDuration(cfg->ActiveMsmtSampleDuration);
    SetActiveMsmtNumberOfSamples(cfg->ActiveMsmtNumberOfSamples);
    SetActiveMsmtPlanID((char *)cfg->PlanId);

    for (i = 0; i < MAX_STEP_COUNT; i++) {
        if(strlen((char *) cfg->Step[i].DestMac) != 0) {
            SetActiveMsmtStepID(cfg->Step[i].StepId, i);
            SetActiveMsmtStepDstMac((char *)cfg->Step[i].DestMac, i);
            SetActiveMsmtStepSrcMac((char *)cfg->Step[i].SrcMac, i);
        }
    }
    SetActiveMsmtEnable(cfg->ActiveMsmtEnable);

    return RETURN_OK;
}

int webconfig_send_wifi_config_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&mgr->global_config, sizeof(wifi_global_config_t));

    if (webconfig_encode(&ctrl->webconfig, &data,
                webconfig_subdoc_type_wifi_config) == webconfig_error_none) {
        ctrl->webconfig_state = ctrl_webconfig_state_none;
    }
    return RETURN_OK;

}

int webconfig_send_radio_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&mgr->global_config, sizeof(wifi_global_config_t));
    data.u.decoded.num_radios = getNumberRadios();

    if (webconfig_encode(&ctrl->webconfig, &data,
                webconfig_subdoc_type_dml) == webconfig_error_none) {
        ctrl->webconfig_state = ctrl_webconfig_state_none;
    }

    return RETURN_OK;
}

int webconfig_send_vap_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&mgr->global_config, sizeof(wifi_global_config_t));
    data.u.decoded.num_radios = getNumberRadios();

    if (webconfig_encode(&ctrl->webconfig, &data,
                webconfig_subdoc_type_dml) == webconfig_error_none) {
        ctrl->webconfig_state = ctrl_webconfig_state_none;
    }

    return RETURN_OK;
}

int webconfig_analyze_pending_states(wifi_ctrl_t *ctrl)
{
    // this may move to scheduler task
    switch (ctrl->webconfig_state) {
        case ctrl_webconfig_state_radio_cfg_rsp_pending:
            webconfig_send_radio_status(ctrl);
        ctrl->webconfig_state = ctrl_webconfig_state_none;
            break;
        case ctrl_webconfig_state_vap_cfg_rsp_pending:
            webconfig_send_vap_status(ctrl);
        ctrl->webconfig_state = ctrl_webconfig_state_none;
            break;
        case ctrl_webconfig_state_wifi_config_cfg_rsp_pending:
            webconfig_send_wifi_config_status(ctrl);
            ctrl->webconfig_state = ctrl_webconfig_state_none;
            break;

        default:
            //wifi_util_dbg_print(WIFI_CTRL,"[%s]:WIFI webconfig analyze pending states event not supported: [%d]\r\n",__FUNCTION__, ctrl->webconfig_state);
            break;
    }

    return RETURN_OK;
}

int webconfig_hal_vap_apply_by_name(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data, char **vap_names, unsigned int size)
{
    unsigned int i, j, k;
    int tgt_radio_idx, tgt_vap_index;
    wifi_vap_info_t *mgr_vap_info, *vap_info;
    wifi_vap_info_map_t *mgr_vap_map, tgt_vap_map;
    bool found_target = false;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (i = 0; i < size; i++) {

        if ((tgt_radio_idx = convert_vap_name_to_radio_array_index(vap_names[i])) == -1) {
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: Could not find radio index for vap name:%s\n",
                        __func__, __LINE__, vap_names[i]);
            continue;
        }

        if ((tgt_vap_index = convert_vap_name_to_index(vap_names[i])) == -1) {
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: Could not find vap index for vap name:%s\n",
                        __func__, __LINE__, vap_names[i]);
            continue;
        }

        for (j = 0; j < getNumberRadios(); j++) {
            if (mgr->radio_config[j].vaps.radio_index == (unsigned int)tgt_radio_idx) {
                mgr_vap_map = &mgr->radio_config[j].vaps.vap_map;
                found_target = true;
                break;
            }
        }

        if (found_target == false) {
            continue;
        }

        found_target = false;

        for (j = 0; j < mgr_vap_map->num_vaps; j++) {
            if (mgr_vap_map->vap_array[j].vap_index == (unsigned int)tgt_vap_index) {
                mgr_vap_info = &mgr_vap_map->vap_array[j];
                found_target = true;
                break;
            }
        }

        if (found_target == false) {
            continue;
        }

        found_target = false;

        for (j = 0; j < getNumberRadios(); j++) {
            for (k = 0; k < getMaxNumberVAPsPerRadio(j); k++) {
                if (strcmp(data->radios[j].vaps.vap_map.vap_array[k].vap_name, vap_names[i]) == 0) {
                    vap_info = &data->radios[j].vaps.vap_map.vap_array[k];
                    found_target = true;
                    break;
                }
            }

            if (found_target == true) {
                break;
            }
        }

        if (found_target == false) {
            continue;
        }

        found_target = false;
        printf("%s:%d: Found vap map source and target for vap name: %s\n", __func__, __LINE__, vap_info->vap_name);

        if (memcmp(mgr_vap_info, vap_info, sizeof(wifi_vap_info_t)) != 0) {
            // radio data changed apply
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: Change detected in received vap config, applying new configuration for vap: %s\n",
                                __func__, __LINE__, vap_names[i]);
            memset(&tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));
            tgt_vap_map.num_vaps = 1;
            memcpy(&tgt_vap_map.vap_array[0], vap_info, sizeof(wifi_vap_info_t));
            if (wifi_hal_createVAP(tgt_radio_idx, &tgt_vap_map) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_MGR, "%s:%d: failed to apply\n", __func__, __LINE__);
        ctrl->webconfig_state = ctrl_webconfig_state_vap_cfg_rsp_pending;
                return RETURN_ERR;
            }

            // write the value to database
#ifndef LINUX_VM_PORT
            wifidb_update_wifi_vap_info(vap_names[i], vap_info);
            if (isVapSTAMesh(tgt_vap_index)) {
                wifidb_update_wifi_security_config(vap_names[i],&vap_info->u.sta_info.security);
            } else {
                wifidb_update_wifi_interworking_config(vap_names[i],&vap_info->u.bss_info.interworking);
                wifidb_update_wifi_security_config(vap_names[i],&vap_info->u.bss_info.security);
            }
#endif
            ctrl->webconfig_state = ctrl_webconfig_state_vap_cfg_rsp_pending;
        } else {
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: Received vap config is same for %s, not applying\n",
                        __func__, __LINE__, vap_names[i]);
        }
    }

    return RETURN_OK;
}

bool isgasConfigChanged(wifi_global_config_t *data_config)
{
    wifi_global_config_t  *mgr_global_config;
    mgr_global_config = get_wifidb_wifi_global_config();
    wifi_GASConfiguration_t mgr_gasconfig, data_gasconfig;
    mgr_gasconfig = mgr_global_config->gas_config;
    data_gasconfig = data_config->gas_config;

    if (memcmp(&mgr_gasconfig,&data_gasconfig,sizeof(wifi_GASConfiguration_t)) != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"GasConfig param changed\n");
        return true;
    }
    return false;
}

bool isglobalParamChanged(wifi_global_config_t *data_config)
{
    wifi_global_config_t  *mgr_global_config;
    mgr_global_config = get_wifidb_wifi_global_config();
    wifi_global_param_t mgr_param, data_param;
    mgr_param = mgr_global_config->global_parameters;
    data_param = data_config->global_parameters;

    if (memcmp(&mgr_param,&data_param, sizeof(wifi_global_param_t)) != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"Global param changed\n");
        return true;
    }
    return false;
}

int webconfig_global_config_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    wifi_util_dbg_print(WIFI_CTRL,"Inside webconfig_global_config_apply\n");
    wifi_global_config_t *data_global_config;
    data_global_config = &data->config;
    bool global_param_changed = false;
    bool gas_config_changed = false;
    global_param_changed = isglobalParamChanged(data_global_config);
    gas_config_changed = isgasConfigChanged(data_global_config);

   /* If neither GasConfig nor Global params are modified */
    if(!global_param_changed && !gas_config_changed) {
        wifi_util_dbg_print(WIFI_CTRL,"Neither Gasconfig nor globalparams are modified");
        ctrl->webconfig_state = ctrl_webconfig_state_radio_cfg_rsp_pending;
        return RETURN_ERR;
    }

    if (global_param_changed) {
        wifi_util_dbg_print(WIFI_CTRL,"Global config value is changed hence update the global config in DB\n");
        if(update_wifi_global_config(&data_global_config->global_parameters) == -1) {
            wifi_util_dbg_print(WIFI_CTRL,"Global config value is not updated in DB\n");
            ctrl->webconfig_state = ctrl_webconfig_state_radio_cfg_rsp_pending;
            return RETURN_ERR;
        }
    }

   if (gas_config_changed) {
        wifi_util_dbg_print(WIFI_CTRL,"Gas config value is changed hence update the gas config in DB\n");
        if(update_wifi_gas_config(data_global_config->gas_config.AdvertisementID,&data_global_config->gas_config) == -1) {
            wifi_util_dbg_print(WIFI_CTRL,"Gas config value is not updated in DB\n");
            ctrl->webconfig_state = ctrl_webconfig_state_radio_cfg_rsp_pending;
            return RETURN_ERR;
        }
    }

    ctrl->webconfig_state = ctrl_webconfig_state_radio_cfg_rsp_pending;
    return RETURN_OK;
}


int webconfig_hal_private_vap_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int ap_index;
    unsigned int num_vaps = 0;
    char *vap_name;
    char *vap_names[MAX_VAP];

    for (ap_index = 0; ap_index < getTotalNumberVAPs(); ap_index++){
        if(isVapPrivate(ap_index)){
            vap_name = getVAPName(ap_index);
            vap_names[num_vaps] = vap_name;
            num_vaps++;
        }
    }
    return webconfig_hal_vap_apply_by_name(ctrl, data, vap_names, num_vaps);
}

int webconfig_hal_home_vap_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int ap_index;
    unsigned int num_vaps = 0;
    char *vap_name;
    char *vap_names[MAX_VAP];

    for (ap_index = 0; ap_index < getTotalNumberVAPs(); ap_index++){
        if(isVapXhs(ap_index)){
            vap_name = getVAPName(ap_index);
            vap_names[num_vaps] = vap_name;
            num_vaps++;
        }
    }
    return webconfig_hal_vap_apply_by_name(ctrl, data, vap_names, num_vaps);
}

int webconfig_hal_xfinity_vap_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int ap_index;
    unsigned int num_vaps = 0;
    char *vap_name;
    char *vap_names[MAX_VAP];

    for (ap_index = 0; ap_index < getTotalNumberVAPs(); ap_index++){
        if(isVapHotspot(ap_index)){
            vap_name = getVAPName(ap_index);
            vap_names[num_vaps] = vap_name;
            num_vaps++;
        }
    }
    return webconfig_hal_vap_apply_by_name(ctrl, data, vap_names, num_vaps);
}

int webconfig_hal_mesh_vap_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int ap_index;
    unsigned int num_vaps = 0;
    char *vap_name;
    char *vap_names[MAX_VAP];

    for (ap_index = 0; ap_index < getTotalNumberVAPs(); ap_index++){
        if(isVapMesh(ap_index)){
            vap_name = getVAPName(ap_index);
            vap_names[num_vaps] = vap_name;
            num_vaps++;
        }
    }
    return webconfig_hal_vap_apply_by_name(ctrl, data, vap_names, num_vaps);
}

static char *to_mac_str    (mac_address_t mac, mac_addr_str_t key) {
    snprintf(key, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return (char *)key;
}

int webconfig_hal_mac_filter_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int radio_index, vap_index;
    rdk_wifi_vap_info_t *new_config = NULL, *current_config = NULL;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    acl_entry_t *new_acl_entry, *temp_acl_entry;
    mac_addr_str_t new_mac_str;
    int ret = RETURN_OK;
    char macfilterkey[128];

    memset(macfilterkey, 0, sizeof(macfilterkey));

    //Apply the MacFilter Data
    for(radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        for (vap_index = 0; vap_index < getMaxNumberVAPsPerRadio(radio_index); vap_index++) {
            new_config = &data->radios[radio_index].vaps.rdk_vap_array[vap_index];
            current_config = &mgr->radio_config[radio_index].vaps.rdk_vap_array[vap_index];

            if (new_config == NULL || current_config == NULL) {
                wifi_util_dbg_print(WIFI_MGR,"%s %d NULL pointer \n", __func__, __LINE__);
                return RETURN_ERR;
            }

            if (new_config->acl_map == current_config->acl_map) {
                wifi_util_dbg_print(WIFI_MGR,"%s %d Same data returning \n", __func__, __LINE__);
                return RETURN_OK;
            }

            if (new_config->acl_map != NULL) {
                new_acl_entry = hash_map_get_first(new_config->acl_map);
                while (new_acl_entry != NULL) {
                    to_mac_str(new_acl_entry->mac,new_mac_str);
                    if (new_acl_entry->acl_action_type == acl_action_add) {
                        temp_acl_entry = hash_map_get(current_config->acl_map, new_mac_str);
                        if (temp_acl_entry != NULL) {
                            wifi_util_dbg_print(WIFI_MGR,"%s %d. Error trying to add existing MAC (%s)\n", __func__, __LINE__, new_mac_str);
                            ret = RETURN_ERR;
                            goto free_data;
                        } else {

                            if (wifi_addApAclDevice(current_config->vap_index, new_mac_str) != RETURN_OK) {
                                wifi_util_dbg_print(WIFI_MGR, "%s:%d: wifi_addApAclDevice failed. vap_index %d, MAC %s \n",
                                        __func__, __LINE__, vap_index, new_mac_str);
                                ret = RETURN_ERR;
                                goto free_data;
                            }
                            temp_acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
                            memset(temp_acl_entry, 0, (sizeof(acl_entry_t)));
                            memcpy(temp_acl_entry, new_acl_entry, sizeof(acl_entry_t));
                            temp_acl_entry->acl_action_type = acl_action_none;

                            hash_map_put(current_config->acl_map,strdup(new_mac_str),temp_acl_entry);
                            snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", current_config->vap_name, new_mac_str);

                            wifidb_update_wifi_macfilter_config(macfilterkey, temp_acl_entry, new_acl_entry->acl_action_type);
                        }
                    }
                    if (new_acl_entry->acl_action_type == acl_action_del) {
                        temp_acl_entry = hash_map_get(current_config->acl_map, new_mac_str);
                        if (temp_acl_entry == NULL) {
                            wifi_util_dbg_print(WIFI_MGR,"%s %d. Error trying to delete MAC (%s) not in the macfilter list\n", __func__, __LINE__, new_mac_str);
                            ret = RETURN_ERR;
                            goto free_data;
                        } else {

                            if (wifi_delApAclDevice(current_config->vap_index, new_mac_str) != RETURN_OK) {
                                wifi_util_dbg_print(WIFI_MGR, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
                                        __func__, __LINE__, vap_index, new_mac_str);
                                ret = RETURN_ERR;
                                goto free_data;
                            }
                            temp_acl_entry = hash_map_remove(current_config->acl_map,new_mac_str);
                            if (temp_acl_entry != NULL) {
                                snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", current_config->vap_name, new_mac_str);

                                wifidb_update_wifi_macfilter_config(macfilterkey, temp_acl_entry, new_acl_entry->acl_action_type);
                                free(temp_acl_entry);
                            }
                        }
                    }
                    new_acl_entry = hash_map_get_next(new_config->acl_map,new_acl_entry);
                }
            }
        }
    }
free_data:
    if ((new_config != NULL) && (new_config->acl_map != NULL)) {
        new_acl_entry = hash_map_get_first(new_config->acl_map);
        while (new_acl_entry != NULL) {
            to_mac_str(new_acl_entry->mac,new_mac_str);
            new_acl_entry = hash_map_get_next(new_config->acl_map,new_acl_entry);
            temp_acl_entry = hash_map_remove(new_config->acl_map, new_mac_str);
            if (temp_acl_entry != NULL) {
                free(temp_acl_entry);
            }
        }
        hash_map_destroy(new_config->acl_map);
    }
    return ret;
}

int webconfig_hal_radio_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int i, j;
    rdk_wifi_radio_t *radio_data, *mgr_radio_data;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    bool found_radio_index = false;

    // apply the radio and vap data
    for (i = 0; i < getNumberRadios(); i++) {
        radio_data = &data->radios[i];

        for (j = 0; j < getNumberRadios(); j++) {
            mgr_radio_data = &mgr->radio_config[j];
            if (mgr_radio_data->vaps.radio_index == radio_data->vaps.radio_index) {
                found_radio_index = true;
                break;
            }
        }

        if (found_radio_index == false) {
            continue;
        }

        found_radio_index = false;
        if (memcmp(&mgr_radio_data->oper, &radio_data->oper, sizeof(wifi_radio_operationParam_t)) != 0) {

            // radio data changed apply
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: Change detected in received radio config, applying new configuration for radio: %s\n",
                            __func__, __LINE__, radio_data->name);
            if (wifi_hal_setRadioOperatingParameters(mgr_radio_data->vaps.radio_index, &radio_data->oper) != RETURN_OK) {
                wifi_util_dbg_print(WIFI_MGR, "%s:%d: failed to apply\n", __func__, __LINE__);
        ctrl->webconfig_state = ctrl_webconfig_state_radio_cfg_rsp_pending;
                return RETURN_ERR;
            }

            // write the value to database
#ifndef LINUX_VM_PORT
            wifidb_update_wifi_radio_config(mgr_radio_data->vaps.radio_index, &radio_data->oper);
#endif
            ctrl->webconfig_state = ctrl_webconfig_state_radio_cfg_rsp_pending;
        } else {
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: Received radio config is same, not applying\n", __func__, __LINE__);
        }
    }

    return RETURN_OK;
}

int webconfig_harvester_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    instant_measurement_config_t *ptr;
    mac_address_t sta_mac;

    ptr = &data->harvester;
    wifi_util_dbg_print(WIFI_CTRL,"[%s]:WIFI webconfig harver apply Reporting period=%d default reporting period=%d default override=%d macaddress=%s enabled=%d\n",__FUNCTION__,ptr->u_inst_client_reporting_period,ptr->u_inst_client_def_reporting_period,ptr->u_inst_client_def_override_ttl,ptr->mac_address,ptr->b_inst_client_enabled);
    instant_msmt_reporting_period(ptr->u_inst_client_reporting_period);
    instant_msmt_def_period(ptr->u_inst_client_def_reporting_period);
    instant_msmt_ttl(ptr->u_inst_client_def_override_ttl);
    instant_msmt_macAddr(ptr->mac_address);
    str_to_mac_bytes(ptr->mac_address,sta_mac);
    monitor_enable_instant_msmt(&sta_mac, ptr->b_inst_client_enabled);
    return RETURN_OK;
}

webconfig_error_t webconfig_ctrl_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data)
{
    int ret = RETURN_OK;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    switch (doc->type) {
        case webconfig_subdoc_type_unknown:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: Unknown webconfig subdoc\n", __func__, __LINE__);
            break;

        case webconfig_subdoc_type_private:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: private webconfig subdoc\n", __func__, __LINE__);
            ret = webconfig_hal_private_vap_apply(ctrl, &data->u.decoded);
            //This is for captive_portal_check for private SSID when defaults modified
            captive_portal_check();
            break;

        case webconfig_subdoc_type_home:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: home webconfig subdoc\n", __func__, __LINE__);
            ret = webconfig_hal_home_vap_apply(ctrl, &data->u.decoded);
            break;

        case webconfig_subdoc_type_xfinity:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: xfinity webconfig subdoc\n", __func__, __LINE__);
            ret = webconfig_hal_xfinity_vap_apply(ctrl, &data->u.decoded);
            break;

        case webconfig_subdoc_type_radio:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: radio webconfig subdoc\n", __func__, __LINE__);
            ret = webconfig_hal_radio_apply(ctrl, &data->u.decoded);
            break;

        case webconfig_subdoc_type_mesh:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: mesh webconfig subdoc\n", __func__, __LINE__);
            ret = webconfig_hal_mesh_vap_apply(ctrl, &data->u.decoded);
            break;

        case webconfig_subdoc_type_mac_filter:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: mac_filter webconfig subdoc\n", __func__, __LINE__);
            ret = webconfig_hal_mac_filter_apply(ctrl, &data->u.decoded);
            break;
        case webconfig_subdoc_type_blaster:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: blaster webconfig subdoc\n", __func__, __LINE__);
            ret = webconfig_blaster_apply(ctrl, &data->u.decoded);
        break;

        case webconfig_subdoc_type_harvester:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: havester webconfig subdoc\n", __func__, __LINE__);
            ret = webconfig_harvester_apply(ctrl, &data->u.decoded);
            break;
        case webconfig_subdoc_type_wifi_config:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: global webconfig subdoc\n", __func__, __LINE__);
            ret = webconfig_global_config_apply(ctrl, &data->u.decoded);
            break;

        case webconfig_subdoc_type_dml:
        case webconfig_subdoc_type_vap_status:
        case webconfig_subdoc_type_radio_status:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: sending subdoc:%s\n", __func__, __LINE__, doc->name);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
            push_data_to_consumer_queue((unsigned char *)data->u.encoded.raw, strlen(data->u.encoded.raw), consumer_event_type_webconfig, consumer_event_webconfig_set_data);
#else
            ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
#endif
            break;

            wifi_util_dbg_print(WIFI_MGR, "%s:%d: vap status webconfig subdoc\n", __func__, __LINE__);
            ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
            break;

        default:
            break;
    }

    return ((ret == RETURN_OK) ? webconfig_error_none:webconfig_error_apply);
}


