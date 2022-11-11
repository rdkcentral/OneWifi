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
#include "const.h"
#define  WBCFG_MULTI_COMP_SUPPORT 1
#include "webconfig_framework.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "msgpack.h"
#include "cJSON.h"
#include "scheduler.h"
#include "base64.h"
#include <unistd.h>
#include <pthread.h>
#include <rbus.h>
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
#include "wifi_webconfig_consumer.h"
#endif

void print_wifi_hal_radio_data(wifi_dbg_type_t log_file_type, char *prefix, unsigned int radio_index, wifi_radio_operationParam_t *radio_config)
{
    wifi_util_info_print(log_file_type, "%s:%d: [%s] Wifi_Radio[%d]_Config data: enable = %d\n band = %d\n autoChannelEnabled = %d\n op_class = %d\n channel = %d\n numSecondaryChannels = %d\n channelSecondary = %s\n channelWidth = %d\n variant = %d\n csa_beacon_count = %d\n countryCode = %d\n DCSEnabled = %d\n dtimPeriod = %d\n beaconInterval = %d\n operatingClass = %d\n basicDataTransmitRates = %d\n operationalDataTransmitRates = %d\n fragmentationThreshold = %d\n guardInterval = %d\n transmitPower = %d\n rtsThreshold = %d\n factoryResetSsid = %d\n radioStatsMeasuringRate = %d\n radioStatsMeasuringInterval = %d\n ctsProtection = %d\n obssCoex = %d\n stbcEnable = %d\n greenFieldEnable = %d\n userControl = %d\n adminControl = %d\n chanUtilThreshold = %d\n chanUtilSelfHealEnable = %d\r\n", __func__, __LINE__, prefix, radio_index, radio_config->enable, radio_config->band, radio_config->autoChannelEnabled, radio_config->op_class, radio_config->channel, radio_config->numSecondaryChannels, radio_config->channelSecondary, radio_config->channelWidth, radio_config->variant, radio_config->csa_beacon_count, radio_config->countryCode, radio_config->DCSEnabled, radio_config->dtimPeriod, radio_config->beaconInterval, radio_config->operatingClass, radio_config->basicDataTransmitRates, radio_config->operationalDataTransmitRates, radio_config->fragmentationThreshold, radio_config->guardInterval, radio_config->transmitPower, radio_config->rtsThreshold, radio_config->factoryResetSsid, radio_config->radioStatsMeasuringRate, radio_config->radioStatsMeasuringInterval, radio_config->ctsProtection, radio_config->obssCoex, radio_config->stbcEnable, radio_config->greenFieldEnable, radio_config->userControl, radio_config->adminControl, radio_config->chanUtilThreshold, radio_config->chanUtilSelfHealEnable);
}

void print_wifi_hal_bss_vap_data(wifi_dbg_type_t log_file_type, char *prefix, unsigned int vap_index, wifi_vap_info_t *l_vap_info)
{
    wifi_front_haul_bss_t    *l_bss_info = &l_vap_info->u.bss_info;
    wifi_back_haul_sta_t     *l_sta_info = &l_vap_info->u.sta_info;
    char mac_str[32] = {0};
    char l_bssid_str[32] = {0};

    if (isVapSTAMesh(vap_index)) {
        to_mac_str(l_sta_info->bssid, l_bssid_str);
        to_mac_str(l_sta_info->mac, mac_str);
        wifi_util_info_print(log_file_type, "%s:%d: [%s] Mesh VAP Config Data: radioindex=%d\n vap_name=%s\n vap_index=%d\n ssid=%s\n bssid:%s\n enabled=%d\n conn_status=%d\n scan_period=%d\n scan_channel=%d\n scan_band =%d\n mac=%s\r\n",__func__, __LINE__, prefix, l_vap_info->radio_index, l_vap_info->vap_name, l_vap_info->vap_index, l_sta_info->ssid, l_bssid_str, l_sta_info->enabled, l_sta_info->conn_status, l_sta_info->scan_params.period, l_sta_info->scan_params.channel.channel, l_sta_info->scan_params.channel.band, mac_str);
    } else {
        to_mac_str(l_bss_info->bssid, l_bssid_str);
        wifi_util_info_print(log_file_type, "%s:%d: [%s] VAP Config Data: radioindex=%d\n vap_name=%s\n vap_index=%d\n ssid=%s\n enabled=%d\n ssid_advertisement_enable=%d\n isolation_enabled=%d\n mgmt_power_control=%d\n bss_max_sta =%d\n bss_transition_activated=%d\n nbr_report_activated=%d\n rapid_connect_enabled=%d\n rapid_connect_threshold=%d\n vap_stats_enable=%d\n mac_filter_enabled =%d\n mac_filter_mode=%d\n wmm_enabled=%d\n uapsd_enabled =%d\n beacon_rate=%d\n bridge_name=%s\n mac=%s\n wmm_noack = %d\n wep_key_length = %d\n bss_hotspot = %d\n wps_push_button = %d\n beacon_rate_ctl =%s\n network_initiated_greylist=%d\n mcast2ucast=%d\r\n",__func__, __LINE__, prefix, l_vap_info->radio_index, l_vap_info->vap_name, l_vap_info->vap_index, l_bss_info->ssid, l_bss_info->enabled, l_bss_info->showSsid, l_bss_info->isolation, l_bss_info->mgmtPowerControl, l_bss_info->bssMaxSta, l_bss_info->bssTransitionActivated, l_bss_info->nbrReportActivated, l_bss_info->rapidReconnectEnable, l_bss_info->rapidReconnThreshold, l_bss_info->vapStatsEnable, l_bss_info->mac_filter_enable, l_bss_info->mac_filter_mode, l_bss_info->wmm_enabled, l_bss_info->UAPSDEnabled, l_bss_info->beaconRate, l_vap_info->bridge_name, l_bssid_str, l_bss_info->wmmNoAck, l_bss_info->wepKeyLength, l_bss_info->bssHotspot, l_bss_info->wpsPushButton, l_bss_info->beaconRateCtl, l_bss_info->network_initiated_greylist, l_bss_info->mcast2ucast);
    }
}

void print_wifi_hal_vap_security_param(wifi_dbg_type_t log_file_type, char *prefix, unsigned int vap_index, wifi_vap_security_t *l_security)
{
    char   address[64] = {0};

    wifi_util_info_print(log_file_type,"%s:%d: [%s] Wifi_Security_Config table vap_index=%d\n Sec_mode=%d\n enc_mode=%d\n mfg_config=%d\n rekey_interval=%d\n strict_rekey=%d\n eapol_key_timeout=%d\n eapol_key_retries=%d\n eap_identity_req_timeout=%d\n eap_identity_req_retries=%d\n eap_req_timeout=%d\n eap_req_retries=%d\n disable_pmksa_caching = %d \r\n", __func__, __LINE__, prefix, vap_index, l_security->mode,l_security->encr,l_security->mfp,l_security->rekey_interval,l_security->strict_rekey,l_security->eapol_key_timeout,l_security->eapol_key_retries,l_security->eap_identity_req_timeout,l_security->eap_identity_req_retries,l_security->eap_req_timeout,l_security->eap_req_retries,l_security->disable_pmksa_caching);

    if ((l_security->mode == wifi_security_mode_wpa_enterprise) || (l_security->mode == wifi_security_mode_wpa2_enterprise ) ||
          (l_security->mode == wifi_security_mode_wpa3_enterprise) || (l_security->mode == wifi_security_mode_wpa_wpa2_enterprise)) {
        getIpStringFromAdrress(address, &l_security->u.radius.dasip);
        wifi_util_info_print(log_file_type,"%s:%d: [%s] Wifi_Security_Config table radius server ip=%s\n port=%d\n sec key=%s\n Secondary radius server ip=%s\n port=%d\n key=%s\n max_auth_attempts=%d\n blacklist_table_timeout=%d\n identity_req_retry_interval=%d\n server_retries=%d\n das_ip=%s\n das_port=%d\n das_key=%s\r\n",__func__, __LINE__, prefix, l_security->u.radius.ip,l_security->u.radius.port,l_security->u.radius.key,l_security->u.radius.s_ip,l_security->u.radius.s_port,l_security->u.radius.s_key,l_security->u.radius.max_auth_attempts,l_security->u.radius.blacklist_table_timeout,l_security->u.radius.identity_req_retry_interval,l_security->u.radius.server_retries,address,l_security->u.radius.dasport,l_security->u.radius.daskey);
    } else {
        wifi_util_info_print(log_file_type,"%s:%d: [%s] Wifi_Security_Config table sec type=%d\n sec key=%s\r\n",__func__, __LINE__, prefix, l_security->u.key.type, l_security->u.key.key);
    }
}

void print_wifi_hal_vap_wps_data(wifi_dbg_type_t log_file_type, char *prefix, unsigned int vap_index, wifi_wps_t *l_wifi_wps)
{
    wifi_util_info_print(log_file_type,"%s:%d: [%s] Wifi_wps_Config vap_index=%d\n enable:%d\n methods:%d\n pin:%s\r\n", __func__, __LINE__, prefix, vap_index, l_wifi_wps->enable, l_wifi_wps->methods, l_wifi_wps->pin);
}

#define WEBCONFIG_DML_SUBDOC_STATES (ctrl_webconfig_state_vap_all_cfg_rsp_pending| \
                                     ctrl_webconfig_state_macfilter_cfg_rsp_pending| \
                                     ctrl_webconfig_state_factoryreset_cfg_rsp_pending)

#if DML_SUPPORT
int webconfig_blaster_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int i = 0;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    if ((mgr == NULL) || (data == NULL)) {
        wifi_util_error_print(WIFI_CTRL,"%s %d Mgr or Data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    mgr->blaster_config_global = data->blaster;

    /* If Device operating in POD mode, Send the blaster status as new to the cloud */
    if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        /* MQTT Topic is required to publish data to QM */
	if (strcmp((char *)mgr->blaster_config_global.blaster_mqtt_topic, "") == 0) {
            wifi_util_error_print(WIFI_CTRL, "%s %d MQTT topic seems empty\n", __func__, __LINE__);
            return RETURN_ERR;
        }
        wifi_util_info_print(WIFI_CTRL, "%s %d POD MOde Activated. Sending Blaster status to cloud\n", __func__, __LINE__);
        mgr->ctrl.webconfig_state |= ctrl_webconfig_state_blaster_cfg_init_rsp_pending;
        webconfig_send_blaster_status(ctrl);
    }
    else if (ctrl->network_mode == rdk_dev_mode_type_gw) {
            wifi_util_info_print(WIFI_CTRL, "GW doesnot dependant on MQTT topic\n");
    }

    active_msmt_t *cfg = &data->blaster;

    SetActiveMsmtPktSize(cfg->ActiveMsmtPktSize);
    SetActiveMsmtSampleDuration(cfg->ActiveMsmtSampleDuration);
    SetActiveMsmtNumberOfSamples(cfg->ActiveMsmtNumberOfSamples);
    SetActiveMsmtPlanID((char *)cfg->PlanId);
    SetBlasterMqttTopic((char *)cfg->blaster_mqtt_topic);

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
#endif // DML_SUPPORT

static void webconfig_init_subdoc_data(webconfig_subdoc_data_t *data)
{
    wifi_mgr_t *mgr = get_wifimgr_obj();

    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data->u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data->u.decoded.config, (unsigned char *)&mgr->global_config, sizeof(wifi_global_config_t));
    memcpy((unsigned char *)&data->u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));
    data->u.decoded.num_radios = getNumberRadios();
}

int webconfig_send_wifi_config_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    memset(&data,0,sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&mgr->global_config, sizeof(wifi_global_config_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));

    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_wifi_config) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
     }

    return RETURN_OK;

}

int webconfig_send_radio_subdoc_status(wifi_ctrl_t *ctrl, webconfig_subdoc_type_t type)
{
    webconfig_subdoc_data_t data;

    webconfig_init_subdoc_data(&data);

    if (webconfig_encode(&ctrl->webconfig, &data, type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    }

    return RETURN_OK;
}

int webconfig_send_vap_subdoc_status(wifi_ctrl_t *ctrl, webconfig_subdoc_type_t type)
{
    webconfig_subdoc_data_t data;

    webconfig_init_subdoc_data(&data);

    if (webconfig_encode(&ctrl->webconfig, &data, type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    }

    return RETURN_OK;
}

int webconfig_send_dml_subdoc_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;
    
    webconfig_init_subdoc_data(&data);
    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_dml) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    }
    return RETURN_OK;
}

int webconfig_send_csi_status(wifi_ctrl_t *ctrl)
{
#if DML_SUPPORT
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    memset(&data,0,sizeof(webconfig_subdoc_data_t));
    data.u.decoded.csi_data_queue = mgr->csi_data_queue;
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));

    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_csi) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    }
#endif // DML_SUPPORT

    return RETURN_OK;
}

int webconfig_send_associate_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;

    webconfig_init_subdoc_data(&data);
    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_associated_clients) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    }
    return RETURN_OK;
}

/* This function is responsible for encoding the data and trigger rbus call */
int webconfig_send_blaster_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    if ((mgr == NULL) || (ctrl == NULL)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Mgr or ctrl is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(&data,0,sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.blaster, (unsigned char *)&mgr->blaster_config_global, sizeof(active_msmt_t));

    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_blaster) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    }
    return RETURN_OK;
}

int webconfig_analyze_pending_states(wifi_ctrl_t *ctrl)
{
    static int pending_state = ctrl_webconfig_state_max;
    webconfig_subdoc_type_t type = webconfig_subdoc_type_unknown;
#if CCSP_COMMON
    wifi_apps_t *analytics = NULL;

    analytics = get_app_by_type(ctrl, wifi_apps_type_analytics);
#endif // CCSP_COMMON

    wifi_mgr_t *mgr = get_wifimgr_obj();
    if ((ctrl->webconfig_state & CTRL_WEBCONFIG_STATE_MASK) == 0) {
        return RETURN_OK;
    }

    do {
        pending_state <<= 1;
        if (pending_state >= ctrl_webconfig_state_max) {
            pending_state = 0x0001;
        }
    } while ((ctrl->webconfig_state & pending_state) == 0);

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d - pending subdoc status:0x%x pending_state:0x%x\r\n", __func__,
                                                        __LINE__, ctrl->webconfig_state, pending_state);
    // this may move to scheduler task
    switch ((ctrl->webconfig_state & pending_state)) {
        case ctrl_webconfig_state_radio_cfg_rsp_pending:
            if (check_wifi_csa_sched_timeout_active_status(ctrl) == false) {
                type = webconfig_subdoc_type_radio;
                webconfig_send_radio_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
            break;
        case ctrl_webconfig_state_vap_private_cfg_rsp_pending:
            type = webconfig_subdoc_type_private;
            webconfig_send_vap_subdoc_status(ctrl, type);
            break;
        case ctrl_webconfig_state_vap_home_cfg_rsp_pending:
            type = webconfig_subdoc_type_home;
            webconfig_send_vap_subdoc_status(ctrl, type);
            break;
        case ctrl_webconfig_state_vap_xfinity_cfg_rsp_pending:
            type = webconfig_subdoc_type_xfinity;
            webconfig_send_vap_subdoc_status(ctrl, type);
            break;
        case ctrl_webconfig_state_vap_lnf_cfg_rsp_pending:
            type = webconfig_subdoc_type_lnf;
            webconfig_send_vap_subdoc_status(ctrl, type);
            break;
        case ctrl_webconfig_state_vap_mesh_cfg_rsp_pending:
            type = webconfig_subdoc_type_mesh;
            webconfig_send_vap_subdoc_status(ctrl, type);
        break;
        case ctrl_webconfig_state_sta_conn_status_rsp_pending:
        case ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending:
            type = webconfig_subdoc_type_mesh_sta;
            webconfig_send_vap_subdoc_status(ctrl, type);
        break;
        case ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending:
            type = webconfig_subdoc_type_mesh_backhaul;
            webconfig_send_vap_subdoc_status(ctrl, type);
        break;
        case ctrl_webconfig_state_macfilter_cfg_rsp_pending:
            type = webconfig_subdoc_type_mac_filter;
            webconfig_send_vap_subdoc_status(ctrl, webconfig_subdoc_type_mac_filter);
        break;
        case ctrl_webconfig_state_vap_all_cfg_rsp_pending:
            type = webconfig_subdoc_type_dml;
            webconfig_send_dml_subdoc_status(ctrl);
            break;
        case ctrl_webconfig_state_factoryreset_cfg_rsp_pending:
            if(ctrl->network_mode == rdk_dev_mode_type_gw) {
                type = webconfig_subdoc_type_dml;
                webconfig_send_dml_subdoc_status(ctrl);
            } else  if(ctrl->network_mode == rdk_dev_mode_type_ext) {
                type = webconfig_subdoc_type_mesh_sta;
                webconfig_send_vap_subdoc_status(ctrl, type);
            }
        break;
        case ctrl_webconfig_state_wifi_config_cfg_rsp_pending:
            type = webconfig_subdoc_type_wifi_config;
            webconfig_send_wifi_config_status(ctrl);
            break;
        case ctrl_webconfig_state_associated_clients_cfg_rsp_pending:
            type = webconfig_subdoc_type_associated_clients;
            webconfig_send_associate_status(ctrl);
            break;
        case ctrl_webconfig_state_csi_cfg_rsp_pending:
            type = webconfig_subdoc_type_csi;
            webconfig_send_csi_status(ctrl);
            break;
        case ctrl_webconfig_state_blaster_cfg_complete_rsp_pending:
                /* Once the blaster triggered successfully, update the status as completed and pass it to OVSM */
                mgr->blaster_config_global.Status = blaster_state_completed;
                webconfig_send_blaster_status(ctrl);
            break;
        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d - default pending subdoc status:0x%x\r\n", __func__, __LINE__, (ctrl->webconfig_state & CTRL_WEBCONFIG_STATE_MASK));
            break;
    }

#if CCSP_COMMON
    if (analytics->event_fn != NULL) {
        analytics->event_fn(analytics, ctrl_event_type_webconfig, ctrl_event_webconfig_set_status, &type);
    }
#endif // CCSP_COMMON

    return RETURN_OK;
}

int webconfig_hal_vap_apply_by_name(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data, char **vap_names, unsigned int size)
{
    unsigned int i, j, k;
    int tgt_radio_idx, tgt_vap_index;
    wifi_vap_info_t *mgr_vap_info, *vap_info;
    vap_svc_t *svc;
    wifi_vap_info_map_t *mgr_vap_map, tgt_vap_map;
    bool found_target = false;
    wifi_mgr_t *mgr = get_wifimgr_obj();
#if CCSP_COMMON
    int ret = 0;
    wifi_apps_t         *analytics = NULL;
    char update_status[128];
#endif // CCSP_COMMON

    for (i = 0; i < size; i++) {

        if ((svc = get_svc_by_name(ctrl, vap_names[i])) == NULL) {
            continue;
        }

        if ((tgt_radio_idx = convert_vap_name_to_radio_array_index(&mgr->hal_cap.wifi_prop, vap_names[i])) == -1) {
            wifi_util_error_print(WIFI_MGR, "%s:%d: Could not find radio index for vap name:%s\n",
                        __func__, __LINE__, vap_names[i]);
            continue;
        }

        tgt_vap_index = convert_vap_name_to_index(&mgr->hal_cap.wifi_prop, vap_names[i]);
        if (tgt_vap_index == -1) {
            wifi_util_error_print(WIFI_MGR, "%s:%d: Could not find vap index for vap name:%s\n",
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
            for (k = 0; k < getNumberVAPsPerRadio(j); k++) {
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
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s:%d: Found vap map source and target for vap name: %s\n", __func__, __LINE__, vap_info->vap_name);

        if (memcmp(mgr_vap_info, vap_info, sizeof(wifi_vap_info_t)) != 0) {
            // radio data changed apply
            wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: Change detected in received vap config, applying new configuration for vap: %s\n",
                                __func__, __LINE__, vap_names[i]);

            print_wifi_hal_bss_vap_data(WIFI_WEBCONFIG, "Old", tgt_vap_index, mgr_vap_info);
            print_wifi_hal_bss_vap_data(WIFI_WEBCONFIG, "New", tgt_vap_index, vap_info);

            if (isVapSTAMesh(tgt_vap_index)) {
                if (memcmp(&mgr_vap_info->u.sta_info.security, &vap_info->u.sta_info.security, sizeof(wifi_vap_security_t))) {
                    print_wifi_hal_vap_security_param(WIFI_WEBCONFIG, "Old", tgt_vap_index, &mgr_vap_info->u.sta_info.security);
                    print_wifi_hal_vap_security_param(WIFI_WEBCONFIG, "New", tgt_vap_index, &vap_info->u.sta_info.security);
                }
            } else {
                if (memcmp(&mgr_vap_info->u.bss_info.security, &vap_info->u.bss_info.security, sizeof(wifi_vap_security_t))) {
                    print_wifi_hal_vap_security_param(WIFI_WEBCONFIG, "Old", tgt_vap_index, &mgr_vap_info->u.bss_info.security);
                    print_wifi_hal_vap_security_param(WIFI_WEBCONFIG, "New", tgt_vap_index, &vap_info->u.bss_info.security);
                }
                if (memcmp(&mgr_vap_info->u.bss_info.wps, &vap_info->u.bss_info.wps, sizeof(wifi_wps_t))) {
                    print_wifi_hal_vap_wps_data(WIFI_WEBCONFIG, "Old", tgt_vap_index, &mgr_vap_info->u.bss_info.wps);
                    print_wifi_hal_vap_wps_data(WIFI_WEBCONFIG, "New", tgt_vap_index, &vap_info->u.bss_info.wps);
                }
            }

            memset(&tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));
            tgt_vap_map.num_vaps = 1;
            memcpy(&tgt_vap_map.vap_array[0], vap_info, sizeof(wifi_vap_info_t));

            if (svc->update_fn(svc, tgt_radio_idx, &tgt_vap_map) != 0) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: failed to apply\n", __func__, __LINE__);
                return RETURN_ERR;
            }

#if CCSP_COMMON
            analytics = get_app_by_type(ctrl, wifi_apps_type_analytics);
            if (analytics->event_fn != NULL) {
                memset(update_status, 0, sizeof(update_status));
                snprintf(update_status, sizeof(update_status), "%s %s", vap_names[i], (ret == RETURN_OK)?"success":"fail");
                analytics->event_fn(analytics, ctrl_event_type_webconfig, ctrl_event_webconfig_hal_result, update_status);
            }

            if (strcmp(vap_info->vap_name,"hotspot_open_2g") == 0) {
                process_xfinity_open_2g_enabled(vap_info->u.bss_info.enabled);
                wifi_util_dbg_print(WIFI_CTRL,"vapname is %s and %d \n",vap_info->vap_name,vap_info->u.bss_info.enabled);
            }
            else if (strcmp(vap_info->vap_name,"hotspot_open_5g") == 0) {
                wifi_util_dbg_print(WIFI_CTRL,"vapname is %s and %d\n",vap_info->vap_name,vap_info->u.bss_info.enabled);
                process_xfinity_open_5g_enabled(vap_info->u.bss_info.enabled);
            }
            else if (strcmp(vap_info->vap_name,"hotspot_secure_2g") == 0) {
                wifi_util_dbg_print(WIFI_CTRL,"vapname is %s and %d \n",vap_info->vap_name,vap_info->u.bss_info.enabled);
                process_xfinity_sec_2g_enabled(vap_info->u.bss_info.enabled);
            }
            else if (strcmp(vap_info->vap_name,"hotspot_secure_5g") == 0) {
                wifi_util_dbg_print(WIFI_CTRL,"vapname is %s and %d \n",vap_info->vap_name,vap_info->u.bss_info.enabled);
                process_xfinity_sec_5g_enabled(vap_info->u.bss_info.enabled);
            }
#endif // CCSP_COMMON
            memcpy(mgr_vap_info, &tgt_vap_map.vap_array[0], sizeof(wifi_vap_info_t));

            if (vap_info->vap_mode == wifi_vap_mode_ap) {
                if (wifi_setApManagementFramePowerControl(vap_info->vap_index,vap_info->u.bss_info.mgmtPowerControl) == RETURN_OK) {
                    wifi_util_dbg_print(WIFI_WEBCONFIG, "%s:%d:ManagementFrame Power control set for vapindex =%d Successful \n",__func__, __LINE__,vap_info->vap_index);
                } else {
                    wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d:ManagementFrame Power control set failed in  \n",__func__, __LINE__);
                }
            }
        } else {
            wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: Received vap config is same for %s, not applying\n",
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
        return RETURN_ERR;
    }

    if (global_param_changed) {
        wifi_util_dbg_print(WIFI_CTRL,"Global config value is changed hence update the global config in DB\n");
        if(update_wifi_global_config(&data_global_config->global_parameters) == -1) {
            wifi_util_dbg_print(WIFI_CTRL,"Global config value is not updated in DB\n");
            return RETURN_ERR;
        }
    }

   if (gas_config_changed) {
        wifi_util_dbg_print(WIFI_CTRL,"Gas config value is changed hence update the gas config in DB\n");
        if(update_wifi_gas_config(data_global_config->gas_config.AdvertisementID,&data_global_config->gas_config) == -1) {
            wifi_util_dbg_print(WIFI_CTRL,"Gas config value is not updated in DB\n");
            return RETURN_ERR;
        }
    }
    return RETURN_OK;
}


int webconfig_hal_private_vap_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int ap_index;
    unsigned int num_vaps = 0;
    char *vap_name;
    char *vap_names[MAX_VAP];
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (UINT index = 0; index < getTotalNumberVAPs(); index++){
        ap_index = VAP_INDEX(mgr->hal_cap, index);
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
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (UINT index = 0; index < getTotalNumberVAPs(); index++){
        ap_index = VAP_INDEX(mgr->hal_cap, index);
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
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (UINT index = 0; index < getTotalNumberVAPs(); index++){
        ap_index = VAP_INDEX(mgr->hal_cap, index);
        if(isVapHotspot(ap_index)){
            vap_name = getVAPName(ap_index);
            vap_names[num_vaps] = vap_name;
            num_vaps++;
        }
    }
    return webconfig_hal_vap_apply_by_name(ctrl, data, vap_names, num_vaps);
}

int webconfig_hal_lnf_vap_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int ap_index;
    unsigned int num_vaps = 0;
    char *vap_name;
    char *vap_names[MAX_VAP];

    for (ap_index = 0; ap_index < getTotalNumberVAPs(); ap_index++){
        if(isVapLnf(ap_index)){
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
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (UINT index = 0; index < getTotalNumberVAPs(); index++){
        ap_index = VAP_INDEX(mgr->hal_cap, index);
        if(isVapMesh(ap_index)){
            vap_name = getVAPName(ap_index);
            vap_names[num_vaps] = vap_name;
            num_vaps++;
        }
    }
    return webconfig_hal_vap_apply_by_name(ctrl, data, vap_names, num_vaps);
}

int webconfig_hal_mesh_sta_vap_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int num_vaps = 0;
    unsigned int ap_index;
    char *vap_name;
    char *vap_names[MAX_VAP];
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (UINT index = 0; index < getTotalNumberVAPs(); index++){
        ap_index = VAP_INDEX(mgr->hal_cap, index);
        if(isVapSTAMesh(ap_index)){
            vap_name = getVAPName(ap_index);
            vap_names[num_vaps] = vap_name;
            num_vaps++;
        }
    }
    return webconfig_hal_vap_apply_by_name(ctrl, data, vap_names, num_vaps);
}

int webconfig_hal_mesh_backhaul_vap_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int num_vaps = 0;
    char *vap_name;
    char *vap_names[MAX_VAP];

    for (UINT index = 0; index < getTotalNumberVAPs(); index++){
        if(isVapMeshBackhaul(index)){
            vap_name = getVAPName(index);
            vap_names[num_vaps] = vap_name;
            num_vaps++;
        }
    }
    return webconfig_hal_vap_apply_by_name(ctrl, data, vap_names, num_vaps);
}

int webconfig_hal_csi_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
#if DML_SUPPORT
    wifi_mgr_t *mgr = get_wifimgr_obj();
    queue_t *new_config, *current_config;
    new_config = data->csi_data_queue;
    char tmp_cli_list[128];
    unsigned int itr, i, current_config_count, new_config_count, itrj, num_unique_mac=0;
    csi_data_t *current_csi_data = NULL, *new_csi_data;
    bool found = false, data_change = false;
    mac_addr_str_t mac_str;
    mac_address_t unique_mac_list[MAX_NUM_CSI_CLIENTS];
    current_config = mgr->csi_data_queue;

    if (current_config == NULL) {
        wifi_util_error_print(WIFI_MGR,"%s %d NULL pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    //check new configuration did not exceed the max number of csi clients 
    if(new_config != NULL) {
        new_config_count = queue_count(new_config);
        for (itr=0; itr<new_config_count; itr++) {
            new_csi_data = (csi_data_t *)queue_peek(new_config, itr);
            if ((new_csi_data != NULL) && (new_csi_data->enabled)) {
                for (itrj=0; itrj<new_csi_data->csi_client_count; itrj ++) {
                    found  = false;
                    for (i=0; i<num_unique_mac; i++) {
                        if (memcmp(new_csi_data->csi_client_list[itrj], unique_mac_list[i], sizeof(mac_address_t)) == 0) {
                            found  = true;
                            break;
                        }
                    }
                    if (!found) {
                        num_unique_mac++;
                        if (num_unique_mac > MAX_NUM_CSI_CLIENTS) {
                            wifi_util_error_print(WIFI_MGR,"%s %d MAX_NUM_CSI_CLIENTS reached\n", __func__, __LINE__);
                            goto free_csi_data;
                        } else {
                            memcpy(unique_mac_list[num_unique_mac-1], new_csi_data->csi_client_list[itrj], sizeof(mac_address_t));
                        }
                    }
                }
            }
        }
    }

    current_config_count = queue_count(current_config);
    for (itr=0; itr<current_config_count; itr++) {
        current_csi_data = (csi_data_t *)queue_peek(current_config, itr);
        found = false;
        if(new_config != NULL) {
            new_config_count = queue_count(new_config);
            for (itrj=0; itrj<new_config_count; itrj++) {
                new_csi_data = (csi_data_t *)queue_peek(new_config, itrj);
                if (new_csi_data != NULL) {
                    if (new_csi_data->csi_session_num == current_csi_data->csi_session_num) {
                        found = true;
                    }
               } 
            }
        }
        if (!found) {
            csi_del_session(current_csi_data->csi_session_num);
            current_csi_data = (csi_data_t *)queue_remove(current_config, itr);
            if (current_csi_data != NULL) {
                free(current_csi_data);
            }
            current_config_count = queue_count(current_config);
        }
    }


    if (new_config != NULL) {
        new_config_count = queue_count(new_config);
        for (itr=0; itr<new_config_count; itr++) {
            new_csi_data = (csi_data_t *)queue_peek(new_config, itr);
            memset(tmp_cli_list, 0, sizeof(tmp_cli_list));
            found = false;
            data_change = false;
            if (current_config != NULL) {
                current_config_count = queue_count(current_config);
                for (itrj=0; itrj<current_config_count; itrj++) {
                    current_csi_data = (csi_data_t *)queue_peek(current_config, itrj);
                    if (current_csi_data != NULL) {
                        if (new_csi_data->csi_session_num == current_csi_data->csi_session_num) {
                            found = true;
                            if (memcmp(new_csi_data, current_csi_data, sizeof(csi_data_t)) != 0) {
                                data_change = true;
                            }
                            break;
                        }
                    }
                }
            }

            //Change client macarray to comma seperarted string.
            for (i=0; i<new_csi_data->csi_client_count; i++) {
                to_mac_str(new_csi_data->csi_client_list[i], mac_str);
                strcat(tmp_cli_list, mac_str);
                strcat(tmp_cli_list, ",");
            }
            int len  = strlen(tmp_cli_list);
            if (len > 0) {
                tmp_cli_list[len-1] = '\0';
            }

            if (!found) {
                csi_create_session(new_csi_data->csi_session_num);
                csi_data_t *to_queue = (csi_data_t *)malloc(sizeof(csi_data_t));
                memcpy(to_queue, new_csi_data, sizeof(csi_data_t));
                queue_push(current_config, to_queue);
                csi_enable_session(new_csi_data->enabled, new_csi_data->csi_session_num);
                csi_set_client_mac(tmp_cli_list, new_csi_data->csi_session_num);
            }

            if(found && data_change) {
                csi_enable_session(new_csi_data->enabled, new_csi_data->csi_session_num);
                csi_set_client_mac(tmp_cli_list, new_csi_data->csi_session_num);
                memcpy(current_csi_data, new_csi_data, sizeof(csi_data_t));
            }
        }
    }

free_csi_data:
    if (new_config != NULL) {
        queue_destroy(new_config);
    }
#endif // DML_SUPPORT

    return RETURN_OK;
}

int webconfig_hal_mac_filter_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data, webconfig_subdoc_type_t subdoc_type)
{
    unsigned int radio_index, vap_index;
    rdk_wifi_vap_info_t *new_config = NULL, *current_config = NULL;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    acl_entry_t *new_acl_entry, *temp_acl_entry, *current_acl_entry;
    mac_addr_str_t current_mac_str;

    mac_addr_str_t new_mac_str;
    int ret = RETURN_OK;
    char macfilterkey[128];

    memset(macfilterkey, 0, sizeof(macfilterkey));

    //Apply the MacFilter Data
    for(radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        for (vap_index = 0; vap_index < getNumberVAPsPerRadio(radio_index); vap_index++) {
            new_config = &data->radios[radio_index].vaps.rdk_vap_array[vap_index];
            current_config = &mgr->radio_config[radio_index].vaps.rdk_vap_array[vap_index];

            if (new_config == NULL || current_config == NULL) {
                wifi_util_error_print(WIFI_MGR,"%s %d NULL pointer \n", __func__, __LINE__);
                return RETURN_ERR;
            }

            if (new_config->acl_map == current_config->acl_map) {
                wifi_util_dbg_print(WIFI_MGR,"%s %d Same data returning \n", __func__, __LINE__);
                return RETURN_OK;
            }

            if ((subdoc_type == webconfig_subdoc_type_mesh) && (isVapMeshBackhaul(data->radios[radio_index].vaps.rdk_vap_array[vap_index].vap_index)) == FALSE) {
                continue;
            }

            if(current_config->is_mac_filter_initialized == true)  {
                if (current_config->acl_map != NULL) {
                    current_acl_entry = hash_map_get_first(current_config->acl_map);
                    while (current_acl_entry != NULL) {
                        to_mac_str(current_acl_entry->mac, current_mac_str);
                        str_tolower(current_mac_str);
                        if ((new_config->acl_map == NULL) || (hash_map_get(new_config->acl_map, current_mac_str) == NULL)) {
                            wifi_util_info_print(WIFI_MGR, "%s:%d: calling wifi_delApAclDevice for mac %s vap_index %d\n", __func__, __LINE__, current_mac_str, current_config->vap_index);
                            if (wifi_delApAclDevice(current_config->vap_index, current_mac_str) != RETURN_OK) {
                                wifi_util_error_print(WIFI_MGR, "%s:%d: wifi_delApAclDevice failed. vap_index %d, mac %s \n",
                                        __func__, __LINE__, vap_index, current_mac_str);
                                ret = RETURN_ERR;
                                goto free_data;
                            }
                            current_acl_entry = hash_map_get_next(current_config->acl_map, current_acl_entry);
                            temp_acl_entry = hash_map_remove(current_config->acl_map, current_mac_str);
                            if (temp_acl_entry != NULL) {
                                snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", current_config->vap_name, current_mac_str);

                                wifidb_update_wifi_macfilter_config(macfilterkey, temp_acl_entry, false);
                                free(temp_acl_entry);
                            }
                        } else {
                            current_acl_entry = hash_map_get_next(current_config->acl_map, current_acl_entry);
                        }
                    }
                }
            } else {
                wifi_delApAclDevices(vap_index);
                current_config->is_mac_filter_initialized = true;
            }

            if (new_config->acl_map != NULL) {
                new_acl_entry = hash_map_get_first(new_config->acl_map);
                while (new_acl_entry != NULL) {
                    to_mac_str(new_acl_entry->mac, new_mac_str);
                    str_tolower(new_mac_str);
                    acl_entry_t *check_acl_entry = hash_map_get(current_config->acl_map, new_mac_str);
                    if (check_acl_entry == NULL) { //mac is in new_config but not in running config need to update HAL
                        wifi_util_info_print(WIFI_MGR, "%s:%d: calling wifi_addApAclDevice for mac %s vap_index %d\n", __func__, __LINE__, new_mac_str, current_config->vap_index);
                        if (wifi_addApAclDevice(current_config->vap_index, new_mac_str) != RETURN_OK) {
                            wifi_util_error_print(WIFI_MGR, "%s:%d: wifi_addApAclDevice failed. vap_index %d, MAC %s \n",
                                    __func__, __LINE__, vap_index, new_mac_str);
                            ret = RETURN_ERR;
                            goto free_data;
                        }

                        temp_acl_entry = (acl_entry_t *)malloc(sizeof(acl_entry_t));
                        memset(temp_acl_entry, 0, (sizeof(acl_entry_t)));
                        memcpy(temp_acl_entry, new_acl_entry, sizeof(acl_entry_t));

                        hash_map_put(current_config->acl_map,strdup(new_mac_str),temp_acl_entry);
                        snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", current_config->vap_name, new_mac_str);

                        wifidb_update_wifi_macfilter_config(macfilterkey, temp_acl_entry, true);
                    } else {
                        if (strncmp(check_acl_entry->device_name, new_acl_entry->device_name, sizeof(check_acl_entry->device_name)-1) != 0) {
                            strncpy(check_acl_entry->device_name, new_acl_entry->device_name, sizeof(check_acl_entry->device_name)-1);
                            snprintf(macfilterkey, sizeof(macfilterkey), "%s-%s", current_config->vap_name, new_mac_str);

                            wifidb_update_wifi_macfilter_config(macfilterkey, check_acl_entry, true);
                        }
                    }
                    new_acl_entry = hash_map_get_next(new_config->acl_map, new_acl_entry);
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

bool is_csa_sched_timer_trigger(wifi_radio_operationParam_t old_radio_cfg, wifi_radio_operationParam_t new_radio_cfg)
{
    if (new_radio_cfg.enable && ((old_radio_cfg.channel != new_radio_cfg.channel) ||
            (old_radio_cfg.channelWidth != new_radio_cfg.channelWidth))) {
        return true;
    }
    return false;
}

bool is_radio_param_config_changed(wifi_radio_operationParam_t *current_radio_cfg, wifi_radio_operationParam_t *new_radio_cfg)
{
    new_radio_cfg->op_class = current_radio_cfg->op_class;

    if (memcmp(current_radio_cfg, new_radio_cfg, sizeof(wifi_radio_operationParam_t)) != 0) {
        return true;
    }

    return false;
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

        if (is_radio_param_config_changed(&mgr_radio_data->oper, &radio_data->oper) == true) {

            // radio data changed apply
            wifi_util_info_print(WIFI_MGR, "%s:%d: Change detected in received radio config, applying new configuration for radio: %s\n",
                            __func__, __LINE__, radio_data->name);

            print_wifi_hal_radio_data(WIFI_WEBCONFIG, "old", i, &mgr_radio_data->oper);
            print_wifi_hal_radio_data(WIFI_WEBCONFIG, "New", i, &radio_data->oper);

            if (ctrl->network_mode == rdk_dev_mode_type_ext) {
                vap_svc_t *ext_svc;
                ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
                if (ext_svc != NULL) {
                    vap_svc_ext_t *ext;
                    ext = &ext_svc->u.ext;
                    unsigned int connected_radio_index = 0;
                    connected_radio_index = get_radio_index_for_vap_index(ext_svc->prop, ext->connected_vap_index);
                    if ((ext->conn_state == connection_state_connected) && (connected_radio_index == mgr_radio_data->vaps.radio_index) && (mgr_radio_data->oper.channel != radio_data->oper.channel)) {
                        ext_svc->event_fn(ext_svc, ctrl_event_type_webconfig, ctrl_event_webconfig_set_data, vap_svc_event_none, &radio_data->oper);
                    }
                }
            }

            if (wifi_hal_setRadioOperatingParameters(mgr_radio_data->vaps.radio_index, &radio_data->oper) != RETURN_OK) {
                wifi_util_error_print(WIFI_MGR, "%s:%d: failed to apply\n", __func__, __LINE__);
                ctrl->webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
                return RETURN_ERR;
            }

            if (is_csa_sched_timer_trigger(mgr_radio_data->oper, radio_data->oper) == true) {
                start_wifi_csa_sched_timer(&mgr_radio_data->vaps.radio_index, ctrl);
            }

            // write the value to database
#ifndef LINUX_VM_PORT
            wifidb_update_wifi_radio_config(mgr_radio_data->vaps.radio_index, &radio_data->oper);
#endif
        } else {
            wifi_util_info_print(WIFI_MGR, "%s:%d: Received radio config is same, not applying\n", __func__, __LINE__);
        }
    }

    return RETURN_OK;
}

int webconfig_harvester_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
#if DML_SUPPORT
    instant_measurement_config_t *ptr;
    mac_address_t sta_mac;

    ptr = &data->harvester;
    wifi_util_info_print(WIFI_CTRL,"[%s]:WIFI webconfig harver apply Reporting period=%d default reporting period=%d default override=%d macaddress=%s enabled=%d\n",__FUNCTION__,ptr->u_inst_client_reporting_period,ptr->u_inst_client_def_reporting_period,ptr->u_inst_client_def_override_ttl,ptr->mac_address,ptr->b_inst_client_enabled);
    instant_msmt_reporting_period(ptr->u_inst_client_reporting_period);
    instant_msmt_def_period(ptr->u_inst_client_def_reporting_period);
    instant_msmt_ttl(ptr->u_inst_client_def_override_ttl);
    instant_msmt_macAddr(ptr->mac_address);
    str_to_mac_bytes(ptr->mac_address,sta_mac);
    monitor_enable_instant_msmt(&sta_mac, ptr->b_inst_client_enabled);
#endif // DML_SUPPORT
    return RETURN_OK;
}

webconfig_error_t webconfig_ctrl_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data)
{
    int ret = RETURN_OK;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: webconfig_state:%02x doc_type:%d doc_name:%s\n", 
                                        __func__, __LINE__, ctrl->webconfig_state, doc->type, doc->name);

    switch (doc->type) {
        case webconfig_subdoc_type_unknown:
            wifi_util_error_print(WIFI_MGR, "%s:%d: Unknown webconfig subdoc\n", __func__, __LINE__);
            break;

        case webconfig_subdoc_type_radio:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_radio_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_radio_cfg_rsp_pending;
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
                ret = webconfig_hal_radio_apply(ctrl, &data->u.decoded);
            }
            break;

        case webconfig_subdoc_type_private:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_private_cfg_rsp_pending) {
                    ctrl->webconfig_state  &= ~ctrl_webconfig_state_vap_private_cfg_rsp_pending;
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_vap_private_cfg_rsp_pending;
                ret = webconfig_hal_private_vap_apply(ctrl, &data->u.decoded);
            }
            //This is for captive_portal_check for private SSID when defaults modified
            captive_portal_check();
            break;

        case webconfig_subdoc_type_home:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_home_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_home_cfg_rsp_pending;
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_vap_home_cfg_rsp_pending;
                ret = webconfig_hal_home_vap_apply(ctrl, &data->u.decoded);
            }
            break;

        case webconfig_subdoc_type_xfinity:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_xfinity_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_xfinity_cfg_rsp_pending;
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_vap_xfinity_cfg_rsp_pending;
                ret = webconfig_hal_xfinity_vap_apply(ctrl, &data->u.decoded);
            }
            break;

        case webconfig_subdoc_type_lnf:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_lnf_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_lnf_cfg_rsp_pending;
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_vap_lnf_cfg_rsp_pending;
                ret = webconfig_hal_lnf_vap_apply(ctrl, &data->u.decoded);
            }
        break;

        case webconfig_subdoc_type_mesh:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_mesh_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_mesh_cfg_rsp_pending;
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_cfg_rsp_pending;
                ret = webconfig_hal_mesh_vap_apply(ctrl, &data->u.decoded);
                if (ret != RETURN_OK) {
                    wifi_util_error_print(WIFI_MGR, "%s:%d: mesh webconfig subdoc failed\n", __func__, __LINE__);
                    return webconfig_error_apply;
                }
                ret = webconfig_hal_mac_filter_apply(ctrl, &data->u.decoded, doc->type);
                if (ret != RETURN_OK) {
                    wifi_util_error_print(WIFI_MGR, "%s:%d: macfilter for mesh webconfig subdoc failed\n", __func__, __LINE__);
                    return webconfig_error_apply;
                }
            }
            break;

        case webconfig_subdoc_type_mesh_sta:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & (ctrl_webconfig_state_factoryreset_cfg_rsp_pending |
                                                ctrl_webconfig_state_sta_conn_status_rsp_pending |
                                                ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending)) {
                    ctrl->webconfig_state &= ~(ctrl_webconfig_state_factoryreset_cfg_rsp_pending |
                                                ctrl_webconfig_state_sta_conn_status_rsp_pending |
                                                ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending);
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending;
                ret = webconfig_hal_mesh_sta_vap_apply(ctrl, &data->u.decoded);
            }
            break;


        case webconfig_subdoc_type_mesh_backhaul:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending;
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending;
                ret = webconfig_hal_mesh_backhaul_vap_apply(ctrl, &data->u.decoded);
                if (ret != RETURN_OK) {
                    wifi_util_error_print(WIFI_MGR, "%s:%d: mesh webconfig subdoc failed\n", __func__, __LINE__);
                    return webconfig_error_apply;
                }
                ret = webconfig_hal_mac_filter_apply(ctrl, &data->u.decoded, doc->type);
                if (ret != RETURN_OK) {
                    wifi_util_error_print(WIFI_MGR, "%s:%d: macfilter for mesh webconfig subdoc failed\n", __func__, __LINE__);
                    return webconfig_error_apply;
                }
            }
            break;

        case webconfig_subdoc_type_mac_filter:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_macfilter_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_macfilter_cfg_rsp_pending;
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_macfilter_cfg_rsp_pending;
                ret = webconfig_hal_mac_filter_apply(ctrl, &data->u.decoded, doc->type);
                if (ret != RETURN_OK) {
                    wifi_util_error_print(WIFI_MGR, "%s:%d: macfilter subdoc failed\n", __func__, __LINE__);
                    return webconfig_error_apply;
                }
            }
            break;
#if DML_SUPPORT
        case webconfig_subdoc_type_blaster:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                /* If Device is operating in POD Mode, send the status to cloud */
                if (ctrl->network_mode == rdk_dev_mode_type_ext) {
                    if (ctrl->webconfig_state & ctrl_webconfig_state_blaster_cfg_init_rsp_pending) {
                        wifi_util_info_print(WIFI_CTRL, "%s:%d: Blaster Status updated as new\n", __func__, __LINE__);
                        ctrl->webconfig_state &= ~ctrl_webconfig_state_blaster_cfg_init_rsp_pending;
                        ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                    } else if (ctrl->webconfig_state & ctrl_webconfig_state_blaster_cfg_complete_rsp_pending) {
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Blaster Status updated as complete\n", __func__, __LINE__);
                        ctrl->webconfig_state &= ~ctrl_webconfig_state_blaster_cfg_complete_rsp_pending;
                        ret = webconfig_rbus_apply(ctrl, &data->u.encoded);

                    }
                } else if (ctrl->network_mode == rdk_dev_mode_type_gw) {
                    wifi_util_error_print(WIFI_CTRL, "%s:%d: Device is in GW Mode. No need to send blaster status\n", __func__, __LINE__);
                }
            } else {
                ret = webconfig_blaster_apply(ctrl, &data->u.decoded);
            }
            break;
#endif // DML_SUPPORT

        case webconfig_subdoc_type_csi:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: csi webconfig subdoc\n", __func__, __LINE__);
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_csi_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_csi_cfg_rsp_pending;
                    wifi_util_dbg_print(WIFI_MGR, "%s:%d: going for notify\n", __func__, __LINE__);
                    ret = webconfig_csi_notify_apply(ctrl, &data->u.encoded);
                }
            } else {
                wifi_util_dbg_print(WIFI_MGR, "%s:%d: going for apply\n", __func__, __LINE__);
                ctrl->webconfig_state |= ctrl_webconfig_state_csi_cfg_rsp_pending;
                ret = webconfig_hal_csi_apply(ctrl, &data->u.decoded);
            }
            break;

        case webconfig_subdoc_type_harvester:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: havester webconfig subdoc\n", __func__, __LINE__);
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                wifi_util_error_print(WIFI_MGR, "%s:%d: Not expected publish of havester webconfig subdoc\n", __func__, __LINE__);
            } else {
                ret = webconfig_harvester_apply(ctrl, &data->u.decoded);
            }
            break;
        case webconfig_subdoc_type_wifi_config:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: global webconfig subdoc\n", __func__, __LINE__);
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                ctrl->webconfig_state &= ~ctrl_webconfig_state_wifi_config_cfg_rsp_pending;
                wifi_util_error_print(WIFI_MGR, "%s:%d: Not expected publish of global wifi webconfig subdoc\n", __func__, __LINE__);
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_wifi_config_cfg_rsp_pending;
                ret = webconfig_global_config_apply(ctrl, &data->u.decoded);
            }
            break;

        case webconfig_subdoc_type_associated_clients:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: associated clients webconfig subdoc\n", __func__, __LINE__);
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_associated_clients_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_associated_clients_cfg_rsp_pending;
                    ret = webconfig_client_notify_apply(ctrl, &data->u.encoded);
                }
            } else {
                wifi_util_error_print(WIFI_MGR, "%s:%d: Not expected apply to associated clients webconfig subdoc\n", __func__, __LINE__);
            }
            break;

        case webconfig_subdoc_type_null: 
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: null webconfig subdoc\n", __func__, __LINE__);
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                ret = webconfig_null_subdoc_notify_apply(ctrl, &data->u.encoded);
            } else {
                wifi_util_error_print(WIFI_MGR, "%s:%d: Not expected apply to null webconfig subdoc\n", __func__, __LINE__);
            }
            break;

        case webconfig_subdoc_type_dml:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: sending subdoc:%s\n", __func__, __LINE__, doc->name);
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
            push_data_to_consumer_queue((unsigned char *)data->u.encoded.raw, strlen(data->u.encoded.raw), consumer_event_type_webconfig, consumer_event_webconfig_set_data);
#else
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & WEBCONFIG_DML_SUBDOC_STATES) {
                    ctrl->webconfig_state &= ~WEBCONFIG_DML_SUBDOC_STATES;
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
            } else {
                wifi_util_error_print(WIFI_MGR, "%s:%d: Not expected apply to dml webconfig subdoc\n", __func__, __LINE__);
            }
#endif
            break;

        default:
            break;
    }

    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: new webconfig_state:%02x\n", 
                                        __func__, __LINE__, ctrl->webconfig_state);

    return ((ret == RETURN_OK) ? webconfig_error_none:webconfig_error_apply);
}

uint32_t get_wifi_blob_version(char* subdoc)
{
    // TODO: implementation
    return 0;
}

int set_wifi_blob_version(char* subdoc,uint32_t version)
{
    // TODO: implementation
    return 0;
}

static size_t webconf_timeout_handler(size_t numOfEntries)
{
    return (numOfEntries * 90);
}

static void webconf_free_resources(void *arg)
{
    wifi_util_dbg_print(WIFI_CTRL, "%s: Enter\n", __func__);
    if(arg == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null Input Data\n", __func__);
        return;
    }

    execData *blob_exec_data  = (execData*) arg;
    char *blob_data = (char*)blob_exec_data->user_data;
    if(blob_data != NULL) {
        free(blob_data);
        blob_data = NULL;
    }

    free(blob_exec_data);
}

static int webconf_rollback_handler(void)
{
    //TODO: what should rollback handler do in the context of OneWifi

    wifi_util_dbg_print(WIFI_CTRL, "%s: Enter\n", __func__);
    return RETURN_OK;
}

pErr webconf_config_handler(void *blob)
{
    pErr exec_ret_val = NULL;

    if(blob == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        return exec_ret_val;
    }

    exec_ret_val = (pErr ) malloc (sizeof(Err));
    if (exec_ret_val == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return exec_ret_val;
    }

    memset(exec_ret_val,0,(sizeof(Err)));
    exec_ret_val->ErrorCode = BLOB_EXEC_SUCCESS;

    // push blob to ctrl queue
    push_data_to_ctrl_queue(blob, strlen(blob), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_webconfig);

    wifi_util_dbg_print(WIFI_CTRL, "%s: return success\n", __func__);
    return exec_ret_val;
}

pErr private_home_exec_common_handler(void *data, bool priv_sd)
{
    pErr execRetVal = NULL;

    if(data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        return execRetVal;
    }

    execRetVal = (pErr)malloc(sizeof(Err));
    if (execRetVal == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return execRetVal;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s, data:\n%s\n", __func__, data);
    memset(execRetVal,0,(sizeof(Err)));
    execRetVal->ErrorCode = VALIDATION_FALIED;

    cJSON *root = cJSON_Parse((char*)data);
    if(root == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        return execRetVal;
    }

    const char* p2g_vap = priv_sd ? "private_ssid_2g" : "home_ssid_2g";
    const char* p5g_vap = priv_sd ? "private_ssid_5g" : "home_ssid_5g";
    const char* p2g_vap_sec = priv_sd ? "private_security_2g" : "home_security_2g";
    const char* p5g_vap_sec = priv_sd ? "private_security_5g" : "home_security_5g";

    const char* p2g_vap_name = priv_sd ? "private_ssid_2g" : "iot_ssid_2g";
    const char* p5g_vap_name = priv_sd ? "private_ssid_5g" : "iot_ssid_5g";

    cJSON *p2g = cJSON_GetObjectItem(root, p2g_vap);
    if(p2g == NULL) {
        cJSON_Delete(root);
        wifi_util_dbg_print(WIFI_CTRL, "%s: Failed to get 2g VapName\n", __func__);
        return execRetVal;
    }

    cJSON *p2g_sec = cJSON_GetObjectItem(root, p2g_vap_sec);
    if(p2g_sec == NULL) {
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to get 2g Security\n", __func__);
        return execRetVal;
    }

    cJSON *p5g = cJSON_GetObjectItem(root, p5g_vap);
    if(p5g == NULL) {
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to get 5g VapName\n", __func__);
        return execRetVal;
    }

    cJSON *p5g_sec = cJSON_GetObjectItem(root, p5g_vap_sec);
    if(p5g_sec == NULL) {
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to get 5g Security\n", __func__);
        return execRetVal;
    }

    cJSON *p2g_ssid = cJSON_GetObjectItem(p2g, "SSID");
    if(p2g_ssid == NULL) {
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to get 2g SSID\n", __func__);
        return execRetVal;
    }

    cJSON *p5g_ssid = cJSON_GetObjectItem(p5g, "SSID");
    if(p5g_ssid == NULL) {
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to get 5g SSID\n", __func__);
        return execRetVal;
    }

    cJSON *p2g_pass = cJSON_GetObjectItem(p2g_sec, "Passphrase");
    cJSON *p2g_enc = cJSON_GetObjectItem(p2g_sec, "EncryptionMethod");
    cJSON *p2g_mod = cJSON_GetObjectItem(p2g_sec, "ModeEnabled");

    if((p2g_pass == NULL) || (p2g_enc == NULL) || (p2g_mod == NULL)) {
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to get 2g Security Info\n", __func__);
        return execRetVal;
    }

    cJSON *p5g_pass = cJSON_GetObjectItem(p5g_sec, "Passphrase");
    cJSON *p5g_enc = cJSON_GetObjectItem(p5g_sec, "EncryptionMethod");
    cJSON *p5g_mod = cJSON_GetObjectItem(p5g_sec, "ModeEnabled");

    if((p5g_pass == NULL) || (p5g_enc == NULL) || (p5g_mod == NULL)) {
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to get 5g Security Info\n", __func__);
        return execRetVal;
    }

    cJSON *vap_blob = cJSON_DetachItemFromObject(root, "WifiVapConfig");
    if(vap_blob == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s,no WifiVapConfig, so create one\n", __func__);

        vap_blob = cJSON_CreateArray();
        if(vap_blob == NULL) {
            cJSON_Delete(root);
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to create WifiVapConfig array\n", __func__);
            return execRetVal;
        }

        // Mandatory elements like SSID, Passphrase, etc. are always filled with equivalent elements
        // from 1.0 blob that's delivered through webcfg framework. These have to be present in the
        // webcfg blob(aka 1.0 blob)
        cJSON *a_itm1 = cJSON_CreateObject();
        cJSON_AddItemToObject(a_itm1, "VapName", cJSON_CreateString(p2g_vap_name));
        cJSON_AddItemToArray(vap_blob, a_itm1);
        cJSON_AddItemToObject(a_itm1, "SSID", cJSON_CreateString(cJSON_GetStringValue(p2g_ssid)));
        bool p2g_enabled_b = false;
        cJSON *p2g_enabled = cJSON_GetObjectItem(p2g, "Enable");
        if(p2g_enabled != NULL) {
            if(cJSON_IsBool(p2g_enabled)) {
                p2g_enabled_b = cJSON_IsTrue(p2g_enabled) ? true : false;
            }
        }
        cJSON_AddBoolToObject(a_itm1, "Enabled", p2g_enabled_b);
        bool p2g_ad_b = false;
        cJSON *p2g_ad = cJSON_GetObjectItem(p2g, "SSIDAdvertisementEnabled");
        if(p2g_ad != NULL) {
            if(cJSON_IsBool(p2g_ad)) {
                p2g_ad_b = cJSON_IsTrue(p2g_ad) ? true : false;
            }
        }
        cJSON_AddBoolToObject(a_itm1, "SSIDAdvertisementEnabled", p2g_ad_b);

        cJSON *a_itm1_sec = cJSON_CreateObject();
        cJSON_AddItemToObject(a_itm1_sec, "Mode", cJSON_CreateString(cJSON_GetStringValue(p2g_mod)));
        cJSON_AddItemToObject(a_itm1_sec, "EncryptionMethod", cJSON_CreateString(cJSON_GetStringValue(p2g_enc)));
        cJSON_AddItemToObject(a_itm1_sec, "Passphrase", cJSON_CreateString(cJSON_GetStringValue(p2g_pass)));
        cJSON_AddItemToObject(a_itm1, "Security", a_itm1_sec);

        cJSON *a_itm2 = cJSON_CreateObject();
        cJSON_AddItemToObject(a_itm2, "VapName", cJSON_CreateString(p5g_vap_name));
        cJSON_AddItemToArray(vap_blob, a_itm2);
        cJSON_AddItemToObject(a_itm2, "SSID", cJSON_CreateString(cJSON_GetStringValue(p5g_ssid)));
        bool p5g_enabled_b = false;
        cJSON *p5g_enabled = cJSON_GetObjectItem(p5g, "Enable");
        if(p5g_enabled != NULL) {
            if(cJSON_IsBool(p5g_enabled)) {
                p5g_enabled_b = cJSON_IsTrue(p5g_enabled) ? true : false;
            }
        }
        cJSON_AddBoolToObject(a_itm2, "Enabled", p5g_enabled_b);
        bool p5g_ad_b = false;
        cJSON *p5g_ad = cJSON_GetObjectItem(p5g, "SSIDAdvertisementEnabled");
        if(p5g_ad != NULL) {
            if(cJSON_IsBool(p5g_ad)) {
                p5g_ad_b = cJSON_IsTrue(p5g_ad) ? true : false;
            }
        }
        cJSON_AddBoolToObject(a_itm2, "SSIDAdvertisementEnabled", p5g_ad_b);

        cJSON *a_itm2_sec = cJSON_CreateObject();
        cJSON_AddItemToObject(a_itm2_sec, "Mode", cJSON_CreateString(cJSON_GetStringValue(p5g_mod)));
        cJSON_AddItemToObject(a_itm2_sec, "EncryptionMethod", cJSON_CreateString(cJSON_GetStringValue(p5g_enc)));
        cJSON_AddItemToObject(a_itm2_sec, "Passphrase", cJSON_CreateString(cJSON_GetStringValue(p5g_pass)));
        cJSON_AddItemToObject(a_itm2, "Security", a_itm2_sec);
    }

    wifi_mgr_t *mgr = get_wifimgr_obj();
    cJSON *vb_entry = NULL;

    cJSON_ArrayForEach(vb_entry, vap_blob) {
        cJSON *nm_o = cJSON_GetObjectItem(vb_entry, "VapName");
        if((nm_o == NULL) || (cJSON_IsString(nm_o) == false)) {
            wifi_util_error_print(WIFI_CTRL, "%s: Missing VapName\n", __func__);
            continue;
        }
        char *nm_s = cJSON_GetStringValue(nm_o);

        int rindx = convert_vap_name_to_radio_array_index(&mgr->hal_cap.wifi_prop, nm_s);
        if(rindx == -1) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get radio_index for %s\n", __func__, nm_s);
            continue;
        }
        unsigned int vindx;
        if(getVAPIndexFromName(nm_s, &vindx) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get vap_index for %s\n", __func__, nm_s);
            continue;
        }
        int array_index;
        if ((array_index = convert_vap_name_to_array_index(&mgr->hal_cap.wifi_prop, nm_s)) == -1) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get array index for %s\n", __func__, nm_s);
            continue;
        }
        char br_name[32];
        memset(br_name, 0, sizeof(br_name));
        if(get_vap_interface_bridge_name(vindx, br_name) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get bridge name for vap_index %d\n", __func__, vindx);
            continue;
        }

        wifi_vap_info_map_t *wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(rindx);
        if(wifi_vap_map == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get vap map for radio_index %d\n", __func__, rindx);
            continue;
        }

        cJSON *pg = NULL;
        if(rindx == 0) { pg = p2g; }
        else
        if(rindx == 1) { pg = p5g; }
        if(pg == NULL) {
            // TODO - extend for the 6g case
            wifi_util_error_print(WIFI_CTRL, "%s: Invalid radio_index %d\n", __func__, rindx);
            continue;
        }

        cJSON_AddNumberToObject(vb_entry, "RadioIndex", rindx);
        cJSON_AddNumberToObject(vb_entry, "VapMode", 0);
        cJSON_AddItemToObject(vb_entry, "BridgeName", cJSON_CreateString(br_name));
        cJSON_AddItemToObject(vb_entry, "BSSID", cJSON_CreateString("11:22:33:44:55:66"));

        // Elements like IsolationEnable, BssMaxNumSta use values from the cache unless
        // overridden by equivalent elements in the webcfg blob(aka 1.0 blob)
        bool iso_en_b = wifi_vap_map->vap_array[array_index].u.bss_info.isolation;
        cJSON *iso_en = cJSON_GetObjectItem(pg, "IsolationEnable");
        if(iso_en != NULL) {
            if(cJSON_IsBool(iso_en)) {
                iso_en_b = cJSON_IsTrue(iso_en) ? true : false;
            }
        }
        int m_frm_c_n = wifi_vap_map->vap_array[array_index].u.bss_info.mgmtPowerControl;
        cJSON *m_frm_c = cJSON_GetObjectItem(pg, "ManagementFramePowerControl");
        if(m_frm_c != NULL) {
            m_frm_c_n = cJSON_GetNumberValue(m_frm_c);
        }
        UINT bss_max_n = wifi_vap_map->vap_array[array_index].u.bss_info.bssMaxSta;
        cJSON *bss_max = cJSON_GetObjectItem(pg, "BssMaxNumSta");
        if(bss_max != NULL) {
            bss_max_n = cJSON_GetNumberValue(bss_max);
        }
        bss_max_n = (bss_max_n == 0) ? 75 : bss_max_n;

        bool bss_trans_b = wifi_vap_map->vap_array[array_index].u.bss_info.bssTransitionActivated;
        cJSON *bss_trans = cJSON_GetObjectItem(pg, "BSSTransitionActivated");
        if(bss_trans != NULL) {
            if(cJSON_IsBool(bss_trans)) {
                bss_trans_b = cJSON_IsTrue(bss_trans) ? true : false;
            }
        }
        bool neigh_b = wifi_vap_map->vap_array[array_index].u.bss_info.nbrReportActivated;
        cJSON *neigh = cJSON_GetObjectItem(pg, "NeighborReportActivated");
        if(neigh != NULL) {
            if(cJSON_IsBool(neigh)) {
                neigh_b = cJSON_IsTrue(neigh) ? true : false;
            }
        }
        bool rrc_en_b = wifi_vap_map->vap_array[array_index].u.bss_info.rapidReconnectEnable;
        cJSON *rrc_en = cJSON_GetObjectItem(pg, "RapidReconnCountEnable");
        if(rrc_en != NULL) {
            if(cJSON_IsBool(rrc_en)) {
                rrc_en_b = cJSON_IsTrue(rrc_en) ? true : false;
            }
        }
        UINT rrt_n = wifi_vap_map->vap_array[array_index].u.bss_info.rapidReconnThreshold;
        cJSON *rrt = cJSON_GetObjectItem(pg, "RapidReconnThreshold");
        if(rrt != NULL) {
            rrt_n = cJSON_GetNumberValue(rrt);
        }
        bool vs_en_b = wifi_vap_map->vap_array[array_index].u.bss_info.vapStatsEnable;
        cJSON *vs_en = cJSON_GetObjectItem(pg, "VapStatsEnable");
        if(vs_en != NULL) {
            if(cJSON_IsBool(vs_en)) {
                vs_en_b = cJSON_IsTrue(vs_en) ? true : false;
            }
        }
        bool mac_fil_en_b = wifi_vap_map->vap_array[array_index].u.bss_info.mac_filter_enable;
        cJSON *mac_fil_en = cJSON_GetObjectItem(pg, "MacFilterEnable");
        if(mac_fil_en != NULL) {
            if(cJSON_IsBool(mac_fil_en)) {
                mac_fil_en_b = cJSON_IsTrue(mac_fil_en) ? true : false;
            }
        }
        UINT mac_fil_mode_n = (UINT)(wifi_vap_map->vap_array[array_index].u.bss_info.mac_filter_mode);
        cJSON *mac_fil_mode = cJSON_GetObjectItem(pg, "MacFilterMode");
        if(mac_fil_mode != NULL) {
            mac_fil_mode_n = cJSON_GetNumberValue(mac_fil_mode);
        }
        bool wnm_en_b = wifi_vap_map->vap_array[array_index].u.bss_info.wmm_enabled;
        cJSON *wnm_en = cJSON_GetObjectItem(pg, "WmmEnabled");
        if(wnm_en != NULL) {
            if(cJSON_IsBool(wnm_en)) {
                wnm_en_b = cJSON_IsTrue(wnm_en) ? true : false;
            }
        }
        bool uapsd_en_b = wifi_vap_map->vap_array[array_index].u.bss_info.UAPSDEnabled;
        cJSON *uapsd_en = cJSON_GetObjectItem(pg, "UapsdEnabled");
        if(uapsd_en != NULL) {
            if(cJSON_IsBool(uapsd_en)) {
                uapsd_en_b = cJSON_IsTrue(uapsd_en) ? true : false;
            }
        }
        UINT beacon_rate_n = wifi_vap_map->vap_array[array_index].u.bss_info.beaconRate;
        cJSON *beacon_rate = cJSON_GetObjectItem(pg, "BeaconRate");
        if(beacon_rate != NULL) {
            beacon_rate_n = cJSON_GetNumberValue(beacon_rate);
        }
        UINT wmm_noack_n = wifi_vap_map->vap_array[array_index].u.bss_info.wmmNoAck;
        cJSON *wmm_noack = cJSON_GetObjectItem(pg, "WmmNoAck");
        if(wmm_noack != NULL) {
            wmm_noack_n = cJSON_GetNumberValue(wmm_noack);
        }
        UINT wep_key_n = wifi_vap_map->vap_array[array_index].u.bss_info.wepKeyLength;
        cJSON *wep_key = cJSON_GetObjectItem(pg, "WepKeyLength");
        if(wep_key != NULL) {
            wep_key_n = cJSON_GetNumberValue(wep_key);
        }
        UINT wps_push_n = wifi_vap_map->vap_array[array_index].u.bss_info.wpsPushButton;
        cJSON *wps_push = cJSON_GetObjectItem(pg, "WpsPushButton");
        if(wps_push != NULL) {
            wps_push_n = cJSON_GetNumberValue(wps_push);
        }
        cJSON *beacon_rate_ctrl = cJSON_GetObjectItem(pg, "BeaconRateCtl");
        if(strstr(p2g_vap_name, "private") != NULL){
            UINT wps_cfg_en_b =  wifi_vap_map->vap_array[array_index].u.bss_info.wps.methods;
            cJSON *wps_methods = cJSON_GetObjectItem(pg, "WpsConfigMethodsEnabled");
            if(wps_methods != NULL) {
                wps_cfg_en_b = cJSON_GetNumberValue(wps_methods);
            }
            cJSON_AddNumberToObject(vb_entry, "WpsConfigMethodsEnabled", wps_cfg_en_b);
        }
        cJSON_AddBoolToObject(vb_entry, "IsolationEnable", iso_en_b);
        cJSON_AddNumberToObject(vb_entry, "ManagementFramePowerControl", m_frm_c_n);
        cJSON_AddNumberToObject(vb_entry, "BssMaxNumSta", bss_max_n);
        cJSON_AddBoolToObject(vb_entry, "BSSTransitionActivated", bss_trans_b);
        cJSON_AddBoolToObject(vb_entry, "NeighborReportActivated", neigh_b);
        cJSON_AddBoolToObject(vb_entry, "RapidReconnCountEnable", rrc_en_b);
        cJSON_AddNumberToObject(vb_entry, "RapidReconnThreshold", rrt_n);
        cJSON_AddBoolToObject(vb_entry, "VapStatsEnable", vs_en_b);

        cJSON_AddBoolToObject(vb_entry, "MacFilterEnable", mac_fil_en_b);
        cJSON_AddNumberToObject(vb_entry, "MacFilterMode", mac_fil_mode_n);
        cJSON_AddBoolToObject(vb_entry, "WmmEnabled", wnm_en_b);
        cJSON_AddBoolToObject(vb_entry, "UapsdEnabled", uapsd_en_b);
        cJSON_AddNumberToObject(vb_entry, "BeaconRate", beacon_rate_n);
        cJSON_AddNumberToObject(vb_entry, "WmmNoAck", wmm_noack_n);
        cJSON_AddNumberToObject(vb_entry, "WepKeyLength", wep_key_n);
        cJSON_AddBoolToObject(vb_entry, "BssHotspot", false);
        cJSON_AddNumberToObject(vb_entry, "WpsPushButton", wps_push_n);
        cJSON_AddBoolToObject(vb_entry, "WpsEnable", true);

        if(beacon_rate_ctrl != NULL) {
            cJSON_AddStringToObject(vb_entry, "BeaconRateCtl", cJSON_GetStringValue(beacon_rate_ctrl));
        }
        else {
            cJSON_AddStringToObject(vb_entry, "BeaconRateCtl", "6Mbps");
        }

        cJSON *sec = cJSON_GetObjectItem(vb_entry, "Security");
        if(sec != NULL) {
            char *mfpc = "Optional";
            if(wifi_vap_map->vap_array[array_index].u.bss_info.security.mfp == wifi_mfp_cfg_disabled) {
                mfpc = "Disabled";
            }
            else
            if(wifi_vap_map->vap_array[array_index].u.bss_info.security.mfp == wifi_mfp_cfg_required) {
                mfpc = "Required";
            }
            cJSON_AddItemToObject(sec, "MFPConfig", cJSON_CreateString(mfpc));
        }

        cJSON *inter = cJSON_GetObjectItem(vb_entry, "Interworking");
        if(inter == NULL) {
            inter = cJSON_CreateObject();
            cJSON_AddBoolToObject(inter, "InterworkingEnable", wifi_vap_map->vap_array[array_index].u.bss_info.interworking.interworking.interworkingEnabled);
            cJSON_AddNumberToObject(inter, "AccessNetworkType", wifi_vap_map->vap_array[array_index].u.bss_info.interworking.interworking.accessNetworkType);
            cJSON_AddBoolToObject(inter, "Internet", wifi_vap_map->vap_array[array_index].u.bss_info.interworking.interworking.internetAvailable);
            cJSON_AddBoolToObject(inter, "ASRA", wifi_vap_map->vap_array[array_index].u.bss_info.interworking.interworking.asra);
            cJSON_AddBoolToObject(inter, "ESR", wifi_vap_map->vap_array[array_index].u.bss_info.interworking.interworking.esr);
            cJSON_AddBoolToObject(inter, "UESA", wifi_vap_map->vap_array[array_index].u.bss_info.interworking.interworking.uesa);
            cJSON_AddBoolToObject(inter, "HESSOptionPresent", wifi_vap_map->vap_array[array_index].u.bss_info.interworking.interworking.hessOptionPresent);
            if(wifi_vap_map->vap_array[vindx].u.bss_info.interworking.interworking.hessid[0] != 0) {
                cJSON_AddItemToObject(inter, "HESSID", cJSON_CreateString(wifi_vap_map->vap_array[array_index].u.bss_info.interworking.interworking.hessid));
            }
            else {
                cJSON_AddItemToObject(inter, "HESSID", cJSON_CreateString("11:22:33:44:55:66"));
            }
            cJSON *ven = cJSON_CreateObject();
            cJSON_AddNumberToObject(ven, "VenueType", wifi_vap_map->vap_array[array_index].u.bss_info.interworking.interworking.venueType);
            cJSON_AddNumberToObject(ven, "VenueGroup", wifi_vap_map->vap_array[array_index].u.bss_info.interworking.interworking.venueGroup);
            cJSON_AddItemToObject(inter, "Venue", ven);
            cJSON_AddItemToObject(vb_entry, "Interworking", inter);
      }
    }

    cJSON *n_blob = cJSON_CreateObject();
    cJSON_AddItemToObject(n_blob, "Version", cJSON_CreateString("1.0"));
    const char *sd_name = priv_sd ? "private" : "home";
    cJSON_AddItemToObject(n_blob, "SubDocName", cJSON_CreateString(sd_name));
    cJSON_AddItemToObject(n_blob, "WifiVapConfig", vap_blob);

    char *vap_blob_str = cJSON_Print(n_blob);
    wifi_util_dbg_print(WIFI_CTRL, "%s, vap_blob:\n%s\n", __func__, vap_blob_str);

    // push blob to ctrl queue
    push_data_to_ctrl_queue(vap_blob_str, strlen(vap_blob_str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_webconfig);

    cJSON_free(vap_blob_str);
    cJSON_Delete(n_blob);
    cJSON_Delete(root);

    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    return execRetVal;
}

pErr wifi_private_vap_exec_handler(void *data)
{
    return private_home_exec_common_handler(data, true);
}

pErr wifi_home_vap_exec_handler(void *data)
{
    return private_home_exec_common_handler(data, false);
}

#define MAX_JSON_BUFSIZE 10240

char *unpackDecode(const char* enb)
{
    unsigned long msg_size = 0L;
    unsigned char *msg = NULL;

    msg_size = b64_get_decoded_buffer_size(strlen((char *)enb));
    msg = (unsigned char *) calloc(1,sizeof(unsigned char *) * msg_size);
    if (!msg) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to allocate memory.\n",__FUNCTION__);
        return NULL;
    }

    msg_size = 0;
    msg_size = b64_decode((unsigned char *)enb, strlen((char *)enb),msg );

    if (msg_size == 0) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed in Decoding multicomp blob\n",__FUNCTION__);
        free(msg);
        return NULL;
    }

    msgpack_zone msg_z;
    msgpack_object msg_obj;

    msgpack_zone_init(&msg_z, MAX_JSON_BUFSIZE);
    msgpack_zone_init(&msg_z, MAX_JSON_BUFSIZE);
    if(msgpack_unpack((const char*)msg, (size_t)msg_size, NULL, &msg_z, &msg_obj) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_zone_destroy(&msg_z);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to unpack blob\n", __func__);
        return NULL;
    }

    char *dej = (char*)malloc(MAX_JSON_BUFSIZE);
    if(dej == NULL) {
        msgpack_zone_destroy(&msg_z);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return NULL;
    }

    memset(dej, 0, MAX_JSON_BUFSIZE);
    int json_len = msgpack_object_print_jsonstr(dej, MAX_JSON_BUFSIZE, msg_obj);
    if(json_len <= 0) {
        msgpack_zone_destroy(&msg_z);
        free(dej);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: json conversion failure\n", __func__);
        return NULL;
    }

    msgpack_zone_destroy(&msg_z);
    wifi_util_dbg_print(WIFI_CTRL, "%s, blob\n%s\n", __func__, dej);
    return dej; // decoded, unpacked json - caller should free memory
}

bool webconf_ver_txn(const char* bb, uint32_t *ver, uint16_t *txn)
{
    cJSON *root = cJSON_Parse(bb);
    if(root == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        return false;
    }

    cJSON *c_ver = cJSON_GetObjectItemCaseSensitive(root, "version");
    if(c_ver == NULL) {
       cJSON_Delete(root);
       wifi_util_error_print(WIFI_CTRL, "%s, Failed to get version\n", __func__ );
       return false;
    }
    cJSON *c_txn = cJSON_GetObjectItem(root, "transaction_id");
    if(c_txn == NULL) {
       cJSON_Delete(root);
       wifi_util_error_print(WIFI_CTRL, "%s, Failed to get transaction_id\n", __func__ );
       return false;
    }

    *ver = (uint32_t)c_ver->valuedouble;
    *txn = (uint16_t)c_txn->valuedouble;
    wifi_util_dbg_print(WIFI_CTRL, "%s, ver: %u, txn: %u\n", __func__, *ver, *txn);

    cJSON_Delete(root);

    return true;
}

void webconf_process_private_vap(const char* enb)
{
    char *blob_buf = unpackDecode(enb);
    if(blob_buf == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s, Invalid Json\n", __func__ );
        return;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s, blob\n%s\n", __func__, blob_buf);

    uint32_t t_version = 0;
    uint16_t tx_id = 0;
    if(!webconf_ver_txn(blob_buf, &t_version, &tx_id)) {
        free(blob_buf);
        wifi_util_error_print(WIFI_CTRL, "%s, Invalid json, no version or transaction Id\n", __func__ );
        return;
    }

    execData *execDataPf = (execData*) malloc (sizeof(execData));
    if (execDataPf != NULL) {
        memset(execDataPf, 0, sizeof(execData));
        execDataPf->txid = tx_id;
        execDataPf->version = t_version;
        execDataPf->numOfEntries = 1;
        strncpy(execDataPf->subdoc_name, "privatessid", sizeof(execDataPf->subdoc_name)-1);
        execDataPf->user_data = (void*) blob_buf;
        execDataPf->calcTimeout = webconf_timeout_handler;
        execDataPf->executeBlobRequest = wifi_private_vap_exec_handler;
        execDataPf->rollbackFunc = webconf_rollback_handler;
        execDataPf->freeResources = webconf_free_resources;
        PushBlobRequest(execDataPf);
        wifi_util_info_print(WIFI_CTRL, "%s:%d: PushBlobRequest Complete\n", __func__, __LINE__ );
    }
}

void webconf_process_home_vap(const char* enb)
{
    char *blob_buf = unpackDecode(enb);
    if(blob_buf == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s, Invalid Json\n", __func__ );
        return;
    }

    uint32_t t_version = 0;
    uint16_t tx_id = 0;
    if(!webconf_ver_txn(blob_buf, &t_version, &tx_id)) {
        free(blob_buf);
        wifi_util_error_print(WIFI_CTRL, "%s, Invalid json, no version or transaction Id\n", __func__ );
        return;
    }

    execData *execDataPf = (execData*) malloc (sizeof(execData));
    if (execDataPf != NULL) {
        memset(execDataPf, 0, sizeof(execData));
        execDataPf->txid = tx_id;
        execDataPf->version = t_version;
        execDataPf->numOfEntries = 1;
        strncpy(execDataPf->subdoc_name, "home", sizeof(execDataPf->subdoc_name)-1);
        execDataPf->user_data = (void*) blob_buf;
        execDataPf->calcTimeout = webconf_timeout_handler;
        execDataPf->executeBlobRequest = wifi_home_vap_exec_handler;
        execDataPf->rollbackFunc = webconf_rollback_handler;
        execDataPf->freeResources = webconf_free_resources;
        PushBlobRequest(execDataPf);
        wifi_util_info_print(WIFI_CTRL, "%s:%d: PushBlobRequest Complete\n", __func__, __LINE__ );
    }
}

pErr wifi_vap_cfg_subdoc_handler(void *data)
{
    pErr execRetVal = NULL;

    if(data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        return execRetVal;
    }

    unsigned long msg_size = 0L;
    unsigned char *msg = NULL;

    msg_size = b64_get_decoded_buffer_size(strlen((char *)data));
    msg = (unsigned char *) calloc(1,sizeof(unsigned char *) * msg_size);
    if (!msg) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to allocate memory.\n",__FUNCTION__);
        return NULL;
    }

    msg_size = 0;
    msg_size = b64_decode((unsigned char *)data, strlen((char *)data), msg );
    if (msg_size == 0) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed in Decoding multicomp blob\n",__FUNCTION__);
        free(msg);
        return NULL;
    } 

    wifidb_print("%s:%d [Start] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());
    execRetVal = (pErr)malloc(sizeof(Err));
    if (execRetVal == NULL ) {
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return execRetVal;
    }
    memset(execRetVal,0,(sizeof(Err)));

    msgpack_zone msg_z;
    msgpack_object msg_obj;

    msgpack_zone_init(&msg_z, MAX_JSON_BUFSIZE);
    if(msgpack_unpack((const char*)msg, (size_t)msg_size, NULL, &msg_z, &msg_obj) != MSGPACK_UNPACK_SUCCESS) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "Msg unpack failed", sizeof(execRetVal->ErrorMsg)-1);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to unpack blob\n", __func__);
        return execRetVal;
    }

    char *blob_buf = (char*)malloc(MAX_JSON_BUFSIZE);
    if(blob_buf == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "blob mem alloc failure", sizeof(execRetVal->ErrorMsg)-1);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return execRetVal;
    }
    memset(blob_buf, 0, MAX_JSON_BUFSIZE);
    int json_len = msgpack_object_print_jsonstr(blob_buf, MAX_JSON_BUFSIZE, msg_obj);
    if(json_len <= 0) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "json conversion failure", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: json conversion failure\n", __func__);
        return execRetVal;
    }

    //wifi_util_dbg_print(WIFI_CTRL, "%s, blob\n%s\n", __func__, blob_buf);

    cJSON *root = cJSON_Parse(blob_buf);
    if(root == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "json parse failure", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        return execRetVal;
    }

    cJSON *vap_blob = cJSON_DetachItemFromObject(root, "WifiVapConfig");
    if(vap_blob == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "Failed to detach WifiVapConfig", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to detach WifiVapConfig\n", __func__);
        return execRetVal;
    }

    cJSON_Delete(root); // don't need this anymore

    // wifi_util_dbg_print(WIFI_CTRL, "%s, vap_blob arr sz: %d\n", __func__, cJSON_GetArraySize(vap_blob));
    wifi_mgr_t *mgr = get_wifimgr_obj();

    cJSON *vb_entry = NULL;
    cJSON_ArrayForEach(vb_entry, vap_blob) {
        cJSON *nm_o = cJSON_GetObjectItem(vb_entry, "VapName");
        if((nm_o == NULL) || (cJSON_IsString(nm_o) == false)) {
            wifi_util_error_print(WIFI_CTRL, "%s: Missing VapName\n", __func__);
            continue;
        }
        char *nm_s = cJSON_GetStringValue(nm_o);

        int rindx = convert_vap_name_to_radio_array_index(&mgr->hal_cap.wifi_prop, nm_s);
        if(rindx == -1) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get radio_index for %s\n", __func__, nm_s);
            continue;
        }
        unsigned int vindx;
        int vapArrayIndex = 0;
        if(getVAPIndexFromName(nm_s, &vindx) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get vap_index for %s\n", __func__, nm_s);
            continue;
        }
        vapArrayIndex = convert_vap_name_to_array_index(&mgr->hal_cap.wifi_prop, nm_s);
        if (vapArrayIndex == -1) {
            wifi_util_dbg_print(WIFI_CTRL, "%s: Failed to get vap_array_index for %s\n", __func__, nm_s);
            continue;
        }
        char br_name[32];
        memset(br_name, 0, sizeof(br_name));
        if(get_vap_interface_bridge_name(vindx, br_name) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get bridge name for vap_index %d\n", __func__, vindx);
            continue;
        }
        wifi_vap_info_map_t *wifi_vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(rindx);
        if(wifi_vap_map == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get vap map for radio_index %d\n", __func__, rindx);
            continue;
        }

        cJSON_AddNumberToObject(vb_entry, "RadioIndex", rindx);
        cJSON_AddNumberToObject(vb_entry, "VapMode", 0);
        cJSON_AddItemToObject(vb_entry, "BridgeName", cJSON_CreateString(br_name));
        cJSON_AddItemToObject(vb_entry, "BSSID", cJSON_CreateString("00:00:00:00:00:00"));

        cJSON_AddBoolToObject(vb_entry, "MacFilterEnable", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.mac_filter_enable);
        cJSON_AddNumberToObject(vb_entry, "MacFilterMode", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.mac_filter_mode);
        cJSON_AddBoolToObject(vb_entry, "WmmEnabled", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.wmm_enabled);
        cJSON_AddBoolToObject(vb_entry, "UapsdEnabled", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.UAPSDEnabled);
        cJSON_AddNumberToObject(vb_entry, "BeaconRate", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.beaconRate);
        cJSON_AddNumberToObject(vb_entry, "WmmNoAck", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.wmmNoAck);
        cJSON_AddNumberToObject(vb_entry, "WepKeyLength", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.wepKeyLength);
        cJSON_AddBoolToObject(vb_entry, "BssHotspot", true);
        cJSON_AddNumberToObject(vb_entry, "WpsPushButton", 0);
        cJSON_AddBoolToObject(vb_entry, "WpsEnable", false);
        if(strstr(nm_s, "private") != NULL) {
            cJSON_AddNumberToObject(vb_entry, "WpsConfigMethodsEnabled", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.wps.methods);
        }
        if(wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.beaconRateCtl[0] != 0) {
            cJSON_AddStringToObject(vb_entry, "BeaconRateCtl", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.beaconRateCtl);
        }
        else {
            cJSON_AddStringToObject(vb_entry, "BeaconRateCtl", "6Mbps");
        }

        if(strstr(nm_s, "hotspot_secure") == NULL) { continue; }

        cJSON *sec_o = cJSON_GetObjectItem(vb_entry, "Security");
        if(sec_o == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get Security obj for %s\n", __func__, nm_s);
            continue;
        }

        cJSON_AddBoolToObject(sec_o, "Wpa3_transition_disable", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.wpa3_transition_disable);
        cJSON_AddNumberToObject(sec_o, "RekeyInterval", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.rekey_interval);
        cJSON_AddBoolToObject(sec_o, "StrictRekey", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.strict_rekey);
        cJSON_AddNumberToObject(sec_o, "EapolKeyTimeout", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eapol_key_timeout);
        cJSON_AddNumberToObject(sec_o, "EapolKeyRetries", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eapol_key_retries);
        cJSON_AddNumberToObject(sec_o, "EapIdentityReqTimeout", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eap_identity_req_timeout);
        cJSON_AddNumberToObject(sec_o, "EapIdentityReqRetries", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eap_identity_req_retries);
        cJSON_AddNumberToObject(sec_o, "EapReqTimeout", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eap_req_timeout);
        cJSON_AddNumberToObject(sec_o, "EapReqRetries", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.eap_req_retries);
        cJSON_AddBoolToObject(sec_o, "DisablePmksaCaching", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.disable_pmksa_caching);

        cJSON *rad_o = cJSON_GetObjectItem(sec_o, "RadiusSettings");
        if(rad_o == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get RadiusSettings obj for %s\n", __func__, nm_s);
            continue;
        }
        char dasIpAddr[32];
        memset(dasIpAddr, 0, sizeof(dasIpAddr));
        int das_ip_r = getIpStringFromAdrress(dasIpAddr, &wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.dasip);
        if(das_ip_r == 1) {
            cJSON_AddItemToObject(rad_o, "DasServerIPAddr", cJSON_CreateString(dasIpAddr));
        }
        else {
            cJSON_AddItemToObject(rad_o, "DasServerIPAddr", cJSON_CreateString("0.0.0.0"));
        }
        cJSON_AddNumberToObject(rad_o, "DasServerPort", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.dasport);
        if(wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.daskey[0] != 0) {
            cJSON_AddStringToObject(rad_o, "DasSecret", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.daskey);
        }
        else {
            cJSON_AddStringToObject(rad_o, "DasSecret", INVALID_KEY);
        }
        cJSON_AddNumberToObject(rad_o, "MaxAuthAttempts", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.max_auth_attempts);
        cJSON_AddNumberToObject(rad_o, "BlacklistTableTimeout", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.blacklist_table_timeout);
        cJSON_AddNumberToObject(rad_o, "IdentityReqRetryInterval", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.identity_req_retry_interval);
        cJSON_AddNumberToObject(rad_o, "ServerRetries", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.security.u.radius.server_retries);
    }

    cJSON *n_blob = cJSON_CreateObject();
    cJSON_AddItemToObject(n_blob, "Version", cJSON_CreateString("1.0"));
    cJSON_AddItemToObject(n_blob, "SubDocName", cJSON_CreateString("xfinity"));
    cJSON_AddItemToObject(n_blob, "WifiVapConfig", vap_blob);

    char *vap_blob_str = cJSON_Print(n_blob);
    wifi_util_dbg_print(WIFI_CTRL, "%s, vap_blob:\n%s\n", __func__, vap_blob_str);

    // push blob to ctrl queue
    push_data_to_ctrl_queue(vap_blob_str, strlen(vap_blob_str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_tunnel);

    cJSON_free(vap_blob_str);
    cJSON_Delete(n_blob);

    free(blob_buf);
    msgpack_zone_destroy(&msg_z);
    free(msg);

    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    return execRetVal;
}

size_t wifi_vap_cfg_timeout_handler()
{
    wifi_util_info_print(WIFI_CTRL, "%s: Enter\n", __func__);
#if defined(_XB6_PRODUCT_REQ_) && !defined (_XB7_PRODUCT_REQ_)
    // return (2 * XB6_DEFAULT_TIMEOUT);
#else
    // return (2 * SSID_DEFAULT_TIMEOUT);
#endif
    return 100;
}

int wifi_vap_cfg_rollback_handler()
{
    wifi_util_info_print(WIFI_CTRL, "%s: Enter\n", __func__);
    return RETURN_OK;
}

int register_multicomp_subdocs()
{
    int multi_subdoc_count = 1;
    int m_sz = multi_subdoc_count * sizeof(multiCompSubDocReg);

    multiCompSubDocReg *subdoc_data = (multiCompSubDocReg *)malloc(m_sz);
    if(subdoc_data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to allocate memory\n", __func__);
        return RETURN_ERR;
    }
    memset(subdoc_data, 0 , m_sz);

    // PAM delivers xfinity blob as hotspot - so OneWifi will register for hotspot blob
    char *sd[] = {"hotspot", (char *) 0 };
    for(int j = 0; j < multi_subdoc_count; ++j) {
        strncpy(subdoc_data->multi_comp_subdoc, sd[j], sizeof(subdoc_data->multi_comp_subdoc)-1);
        subdoc_data->executeBlobRequest = wifi_vap_cfg_subdoc_handler;
        subdoc_data->calcTimeout = wifi_vap_cfg_timeout_handler;
        subdoc_data->rollbackFunc = wifi_vap_cfg_rollback_handler;
    }

    register_MultiComp_subdoc_handler(subdoc_data, multi_subdoc_count);

    return RETURN_OK;
}

// static char *sub_docs[] = { "privatessid", "home", "xfinity", (char *) 0 };
static char *sub_docs[] = { "privatessid", "home", (char *)0 };

// register subdocs with webconfig_framework
int register_with_webconfig_framework()
{
    int sd_sz = sizeof(sub_docs)/sizeof(char*) - 1; // not counting 0 in array

    blobRegInfo *blob_data = (blobRegInfo*) malloc(sd_sz * sizeof(blobRegInfo));
    if (blob_data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Malloc error\n", __func__);
        return RETURN_ERR;
    }
    memset(blob_data, 0, sd_sz * sizeof(blobRegInfo));

    blobRegInfo *blob_data_pointer = blob_data;
    for (int i=0 ;i < sd_sz; i++)
    {
        strncpy(blob_data_pointer->subdoc_name, sub_docs[i], sizeof(blob_data_pointer->subdoc_name)-1);
        blob_data_pointer++;
    }
    blob_data_pointer = blob_data;

    getVersion version_get = get_wifi_blob_version;
    setVersion version_set = set_wifi_blob_version;

    register_sub_docs(blob_data, sd_sz, version_get, version_set);

    if(register_multicomp_subdocs() != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to register multicomp subdocs with framework\n", __func__);
        return RETURN_ERR;
    }

    wifi_util_info_print(WIFI_CTRL, "%s: Done Registering\n", __func__);
    return RETURN_OK;
}

