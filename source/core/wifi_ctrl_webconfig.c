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
#include <string.h> /* strdup() */
#include <stdlib.h>
#include "const.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_stubs.h"
#include "wifi_util.h"
#include <cjson/cJSON.h>
#include "scheduler.h"
#include "base64.h"
#include <unistd.h>
#include <pthread.h>
#ifdef WEBCONFIG_TESTS_OVER_QUEUE
#include "wifi_webconfig_consumer.h"
#endif
#define OW_CONF_BARRIER_TIMEOUT_MSEC (60 * 1000)

struct ow_conf_vif_config_cb_arg
{
    rdk_wifi_vap_info_t *rdk_vap_info;
    wifi_vap_info_t *vap_info;
};

void print_wifi_hal_radio_data(wifi_dbg_type_t log_file_type, char *prefix, unsigned int radio_index, wifi_radio_operationParam_t *radio_config)
{
    wifi_util_info_print(log_file_type, "%s:%d: [%s] Wifi_Radio[%d]_Config data: enable = %d\n band = %d\n autoChannelEnabled = %d\n channel = %d\n numSecondaryChannels = %d\n channelSecondary = %s\n channelWidth = %d\n variant = %d\n csa_beacon_count = %d\n countryCode = %d\n DCSEnabled = %d\n dtimPeriod = %d\n beaconInterval = %d\n operatingClass = %d\n basicDataTransmitRates = %d\n operationalDataTransmitRates = %d\n fragmentationThreshold = %d\n guardInterval = %d\n transmitPower = %d\n rtsThreshold = %d\n factoryResetSsid = %d\n radioStatsMeasuringRate = %d\n radioStatsMeasuringInterval = %d\n ctsProtection = %d\n obssCoex = %d\n stbcEnable = %d\n greenFieldEnable = %d\n userControl = %d\n adminControl = %d\n chanUtilThreshold = %d\n chanUtilSelfHealEnable = %d\n EcoPowerDown = %d DFSTimer:%d \r\n", __func__, __LINE__, prefix, radio_index, radio_config->enable, radio_config->band, radio_config->autoChannelEnabled, radio_config->channel, radio_config->numSecondaryChannels, radio_config->channelSecondary, radio_config->channelWidth, radio_config->variant, radio_config->csa_beacon_count, radio_config->countryCode, radio_config->DCSEnabled, radio_config->dtimPeriod, radio_config->beaconInterval, radio_config->operatingClass, radio_config->basicDataTransmitRates, radio_config->operationalDataTransmitRates, radio_config->fragmentationThreshold, radio_config->guardInterval, radio_config->transmitPower, radio_config->rtsThreshold, radio_config->factoryResetSsid, radio_config->radioStatsMeasuringRate, radio_config->radioStatsMeasuringInterval, radio_config->ctsProtection, radio_config->obssCoex, radio_config->stbcEnable, radio_config->greenFieldEnable, radio_config->userControl, radio_config->adminControl, radio_config->chanUtilThreshold, radio_config->chanUtilSelfHealEnable, radio_config->EcoPowerDown, radio_config->DFSTimer);
}

void print_wifi_hal_bss_vap_data(wifi_dbg_type_t log_file_type, char *prefix,
    unsigned int vap_index, wifi_vap_info_t *l_vap_info, rdk_wifi_vap_info_t *l_rdk_vap_info)
{
    wifi_front_haul_bss_t    *l_bss_info = &l_vap_info->u.bss_info;
    wifi_back_haul_sta_t     *l_sta_info = &l_vap_info->u.sta_info;
    char mac_str[32] = {0};
    char l_bssid_str[32] = {0};

    if (isVapSTAMesh(vap_index)) {
        to_mac_str(l_sta_info->bssid, l_bssid_str);
        to_mac_str(l_sta_info->mac, mac_str);
        wifi_util_info_print(log_file_type,
            "%s:%d: [%s] Mesh VAP Config Data:\n radioindex=%d\n vap_name=%s\n vap_index=%d\n "
            "ssid=%s\n bssid=%s\n enabled=%d\n conn_status=%d\n scan_period=%d\n scan_channel=%d\n "
            "scan_band=%d\n mac=%s\n exists=%d\n",
            __func__, __LINE__, prefix, l_vap_info->radio_index, l_vap_info->vap_name,
            l_vap_info->vap_index, l_sta_info->ssid, l_bssid_str, l_sta_info->enabled,
            l_sta_info->conn_status, l_sta_info->scan_params.period,
            l_sta_info->scan_params.channel.channel, l_sta_info->scan_params.channel.band, mac_str,
            l_rdk_vap_info->exists);
    } else {
        to_mac_str(l_bss_info->bssid, l_bssid_str);
        wifi_util_info_print(log_file_type,
            "%s:%d: [%s] VAP Config Data:\n radioindex=%d\n vap_name=%s\n vap_index=%d\n ssid=%s\n "
            "enabled=%d\n ssid_advertisement_enable=%d\n isolation_enabled=%d\n "
            "mgmt_power_control=%d\n bss_max_sta=%d\n bss_transition_activated=%d\n "
            "nbr_report_activated=%d\n rapid_connect_enabled=%d\n rapid_connect_threshold=%d\n "
            "vap_stats_enable=%d\n mac_filter_enabled=%d\n mac_filter_mode=%d\n wmm_enabled=%d\n "
            "uapsd_enabled=%d\n beacon_rate=%d\n bridge_name=%s\n mac=%s\n wmm_noack=%d\n "
            "wep_key_length=%d\n bss_hotspot=%d\n wps_push_button=%d\n beacon_rate_ctl=%s\n "
            "network_initiated_greylist=%d\n mcast2ucast=%d\n exists=%d\n "
            "hostap_mgt_frame_ctrl=%d\n mbo_enabled=%d\n",
            __func__, __LINE__, prefix, l_vap_info->radio_index, l_vap_info->vap_name,
            l_vap_info->vap_index, l_bss_info->ssid, l_bss_info->enabled, l_bss_info->showSsid,
            l_bss_info->isolation, l_bss_info->mgmtPowerControl, l_bss_info->bssMaxSta,
            l_bss_info->bssTransitionActivated, l_bss_info->nbrReportActivated,
            l_bss_info->rapidReconnectEnable, l_bss_info->rapidReconnThreshold,
            l_bss_info->vapStatsEnable, l_bss_info->mac_filter_enable, l_bss_info->mac_filter_mode,
            l_bss_info->wmm_enabled, l_bss_info->UAPSDEnabled, l_bss_info->beaconRate,
            l_vap_info->bridge_name, l_bssid_str, l_bss_info->wmmNoAck, l_bss_info->wepKeyLength,
            l_bss_info->bssHotspot, l_bss_info->wpsPushButton, l_bss_info->beaconRateCtl,
            l_bss_info->network_initiated_greylist, l_bss_info->mcast2ucast, l_rdk_vap_info->exists,
            l_bss_info->hostap_mgt_frame_ctrl, l_bss_info->mbo_enabled);
    }
}

void print_wifi_hal_vap_security_param(wifi_dbg_type_t log_file_type, char *prefix, unsigned int vap_index, wifi_vap_security_t *l_security)
{
    char   address[64] = {0};

    wifi_util_info_print(log_file_type,"%s:%d: [%s] Wifi_Security_Config table vap_index=%d\n Sec_mode=%d\n enc_mode=%d\n mfg_config=%d\n rekey_interval=%d\n strict_rekey=%d\n eapol_key_timeout=%d\n eapol_key_retries=%d\n eap_identity_req_timeout=%d\n eap_identity_req_retries=%d\n eap_req_timeout=%d\n eap_req_retries=%d\n disable_pmksa_caching = %d\n wpa3_transition_disable=%d\r\n", __func__, __LINE__, prefix, vap_index, l_security->mode,l_security->encr,l_security->mfp,l_security->rekey_interval,l_security->strict_rekey,l_security->eapol_key_timeout,l_security->eapol_key_retries,l_security->eap_identity_req_timeout,l_security->eap_identity_req_retries,l_security->eap_req_timeout,l_security->eap_req_retries,l_security->disable_pmksa_caching,l_security->wpa3_transition_disable);

    if ( security_mode_support_radius(l_security->mode) ) {
        getIpStringFromAdrress(address, &l_security->u.radius.dasip);
        wifi_util_info_print(log_file_type,"%s:%d: [%s] Wifi_Security_Config table radius server ip=%s\n port=%d\n Secondary radius server ip=%s\n port=%d\n max_auth_attempts=%d\n blacklist_table_timeout=%d\n identity_req_retry_interval=%d\n server_retries=%d\n das_ip=%s\n das_port=%d\r\n",__func__, __LINE__, prefix, l_security->u.radius.ip,l_security->u.radius.port,l_security->u.radius.s_ip,l_security->u.radius.s_port,l_security->u.radius.max_auth_attempts,l_security->u.radius.blacklist_table_timeout,l_security->u.radius.identity_req_retry_interval,l_security->u.radius.server_retries,address,l_security->u.radius.dasport);
    } else {
        wifi_util_info_print(log_file_type,"%s:%d: [%s] Wifi_Security_Config table sec type=%d\r\n",__func__, __LINE__, prefix, l_security->u.key.type);
    }
}

void print_wifi_hal_vap_wps_data(wifi_dbg_type_t log_file_type, char *prefix, unsigned int vap_index, wifi_wps_t *l_wifi_wps)
{
#ifdef FEATURE_SUPPORT_WPS
    wifi_util_info_print(log_file_type,"%s:%d: [%s] Wifi_wps_Config vap_index=%d\n enable:%d\n methods:%d\r\n", __func__, __LINE__, prefix, vap_index, l_wifi_wps->enable, l_wifi_wps->methods);
#endif
}

#define WEBCONFIG_DML_SUBDOC_STATES                         \
    (ctrl_webconfig_state_vap_all_cfg_rsp_pending |         \
        ctrl_webconfig_state_macfilter_cfg_rsp_pending |    \
        ctrl_webconfig_state_factoryreset_cfg_rsp_pending | \
        ctrl_webconfig_state_sta_conn_status_rsp_pending |  \
        ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending)

int webconfig_blaster_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    wifi_mgr_t *mgr = get_wifimgr_obj();

    if ((mgr == NULL) || (data == NULL)) {
        wifi_util_error_print(WIFI_CTRL,"%s %d Mgr or Data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    mgr->blaster_config_global = data->blaster;

    /* If Device operating in POD mode, Send the blaster status as new to the cloud */
    if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        wifi_util_info_print(WIFI_CTRL, "%s %d POD MOde Activated. Sending Blaster status to cloud\n", __func__, __LINE__);
        mgr->ctrl.webconfig_state |= ctrl_webconfig_state_blaster_cfg_init_rsp_pending;
        webconfig_send_blaster_status(ctrl);
    }
    else if (ctrl->network_mode == rdk_dev_mode_type_gw) {
            wifi_util_info_print(WIFI_CTRL, "GW doesnot dependant on MQTT topic\n");
    }

    return RETURN_OK;
}

void webconfig_init_subdoc_data(webconfig_subdoc_data_t *data)
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
    } else {
        webconfig_data_free(&data);
    }

    return RETURN_OK;
}

int webconfig_send_radio_subdoc_status(wifi_ctrl_t *ctrl, webconfig_subdoc_type_t type)
{
    webconfig_subdoc_data_t data;

    webconfig_init_subdoc_data(&data);

    if (webconfig_encode(&ctrl->webconfig, &data, type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    } else {
        webconfig_data_free(&data);
    }

    return RETURN_OK;
}

int webconfig_send_vap_subdoc_status(wifi_ctrl_t *ctrl, webconfig_subdoc_type_t type)
{
    webconfig_subdoc_data_t data;

    webconfig_init_subdoc_data(&data);

    if (webconfig_encode(&ctrl->webconfig, &data, type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    } else {
        webconfig_data_free(&data);
    }

    return RETURN_OK;
}

int webconfig_send_dml_subdoc_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;

    webconfig_init_subdoc_data(&data);
    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_dml) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    } else {
        webconfig_data_free(&data);
    }

    return RETURN_OK;
}

int  webconfig_free_vap_object_diff_assoc_client_entries(webconfig_subdoc_data_t *data)
{
    unsigned int i=0, j=0;
    rdk_wifi_radio_t *radio;
    rdk_wifi_vap_info_t *rdk_vap_info, *tmp_rdk_vap_info;
    webconfig_subdoc_decoded_data_t *decoded_params;
    assoc_dev_data_t *assoc_dev_data, *temp_assoc_dev_data;
    mac_addr_str_t mac_str;

    decoded_params = &data->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s:%d: decoded_params is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    for (i = 0; i < decoded_params->num_radios; i++) {
        radio = &decoded_params->radios[i];
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            rdk_vap_info = &decoded_params->radios[i].vaps.rdk_vap_array[j];
            if (rdk_vap_info == NULL) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: rdk_vap_info is null", __func__, __LINE__);
                return RETURN_ERR;
            }
            pthread_mutex_lock(rdk_vap_info->associated_devices_lock);
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
            //Clearing the global memory
            tmp_rdk_vap_info = get_wifidb_rdk_vap_info(decoded_params->radios[i].vaps.rdk_vap_array[j].vap_index);
            if (tmp_rdk_vap_info == NULL) {
                pthread_mutex_unlock(rdk_vap_info->associated_devices_lock);
                wifi_util_error_print(WIFI_CTRL,"%s:%d NULL rdk_vap_info pointer\n", __func__, __LINE__);
                return RETURN_ERR;
            }
            tmp_rdk_vap_info->associated_devices_diff_map = NULL;
            pthread_mutex_unlock(tmp_rdk_vap_info->associated_devices_lock);
        }
    }
    return RETURN_OK;
}

int webconfig_send_associate_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;
    webconfig_init_subdoc_data(&data);
    data.u.decoded.assoclist_notifier_type = assoclist_notifier_diff;
    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_associated_clients) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    }
    webconfig_free_vap_object_diff_assoc_client_entries(&data);
    webconfig_data_free(&data);

    return RETURN_OK;
}

int webconfig_send_full_associate_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;
    webconfig_init_subdoc_data(&data);
    data.u.decoded.assoclist_notifier_type = assoclist_notifier_full;
    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_associated_clients) !=
        webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__,
            __LINE__);
    }
    webconfig_data_free(&data);

    return RETURN_OK;
}

/* This function is responsible for encoding the data and trigger bus call */
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
    } else {
        webconfig_data_free(&data);
    }

    return RETURN_OK;
}

int webconfig_send_steering_clients_status(wifi_ctrl_t *ctrl)
{
    webconfig_subdoc_data_t data;
    webconfig_init_subdoc_data(&data);

    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_steering_clients) != webconfig_error_none) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__, __LINE__);
    } else {
        webconfig_data_free(&data);
    }

    return RETURN_OK;
}

int webconfig_send_multivap_subdoc_status(wifi_ctrl_t *ctrl, webconfig_subdoc_type_t type)
{
    webconfig_subdoc_data_t data;

    webconfig_init_subdoc_data(&data);

    if (webconfig_encode(&ctrl->webconfig, &data, type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode\n", __FUNCTION__,
            __LINE__);
    } else {
        webconfig_data_free(&data);
    }
    return RETURN_OK;
}

int webconfig_analyze_pending_states(wifi_ctrl_t *ctrl)
{
    static int pending_state = ctrl_webconfig_state_max;
    webconfig_subdoc_type_t type = webconfig_subdoc_type_unknown;
    int radio_index = -1;
    int state;

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
            if (check_wifi_radio_sched_timeout_active_status(ctrl) == false &&
                check_wifi_csa_sched_timeout_active_status(ctrl) == false) {
                type = webconfig_subdoc_type_radio;
                webconfig_send_radio_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
            break;
        case ctrl_webconfig_state_vap_private_cfg_rsp_pending:
            if (check_wifi_vap_sched_timeout_active_status(ctrl, isVapPrivate) == false) {
                type = webconfig_subdoc_type_private;
                webconfig_send_vap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
            break;
        case ctrl_webconfig_state_vap_home_cfg_rsp_pending:
            if (check_wifi_vap_sched_timeout_active_status(ctrl, isVapXhs) == false) {
                type = webconfig_subdoc_type_home;
                webconfig_send_vap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
            break;
        case ctrl_webconfig_state_vap_xfinity_cfg_rsp_pending:
            if (check_wifi_vap_sched_timeout_active_status(ctrl, isVapHotspot) == false) {
                type = webconfig_subdoc_type_xfinity;
                webconfig_send_vap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
            break;
        case ctrl_webconfig_state_vap_lnf_cfg_rsp_pending:
            if (check_wifi_vap_sched_timeout_active_status(ctrl, isVapLnf) == false) {
                type = webconfig_subdoc_type_lnf;
                webconfig_send_vap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
            break;
        case ctrl_webconfig_state_vap_mesh_cfg_rsp_pending:
            if (check_wifi_vap_sched_timeout_active_status(ctrl, isVapMesh) == false) {
                type = webconfig_subdoc_type_mesh;
                webconfig_send_vap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
        break;
        case ctrl_webconfig_state_sta_conn_status_rsp_pending:
            type = webconfig_subdoc_type_dml;
            webconfig_send_vap_subdoc_status(ctrl, type);
        break;
        case ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending:
            if (check_wifi_vap_sched_timeout_active_status(ctrl, isVapSTAMesh) == false) {
                type = webconfig_subdoc_type_dml;
                webconfig_send_vap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
        break;
        case ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending:
            if (check_wifi_vap_sched_timeout_active_status(ctrl, isVapMeshBackhaul) == false) {
                type = webconfig_subdoc_type_mesh_backhaul;
                webconfig_send_vap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
        break;
        case ctrl_webconfig_state_vap_mesh_backhaul_sta_cfg_rsp_pending:
            if (check_wifi_vap_sched_timeout_active_status(ctrl, isVapSTAMesh) == false) {
                type = webconfig_subdoc_type_mesh_backhaul_sta;
                webconfig_send_vap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
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
            type = webconfig_subdoc_type_dml;
            webconfig_send_dml_subdoc_status(ctrl);
        break;
        case ctrl_webconfig_state_wifi_config_cfg_rsp_pending:
            type = webconfig_subdoc_type_wifi_config;
            webconfig_send_wifi_config_status(ctrl);
            break;
        case ctrl_webconfig_state_associated_clients_cfg_rsp_pending:
            type = webconfig_subdoc_type_associated_clients;
            webconfig_send_associate_status(ctrl);
            break;

        case ctrl_webconfig_state_associated_clients_full_cfg_rsp_pending:
            type = webconfig_subdoc_type_associated_clients;
            webconfig_send_full_associate_status(ctrl);
            break;

        case ctrl_webconfig_state_blaster_cfg_complete_rsp_pending:
                /* Once the blaster triggered successfully, update the status as completed and pass it to OVSM */
                type = webconfig_subdoc_type_blaster;
                mgr->blaster_config_global.Status = blaster_state_completed;
                webconfig_send_blaster_status(ctrl);
            break;
        case ctrl_webconfig_state_steering_clients_rsp_pending:
            type = webconfig_subdoc_type_steering_clients;
            webconfig_send_steering_clients_status(ctrl);
            break;
        case ctrl_webconfig_state_trigger_dml_thread_data_update_pending:
            type = webconfig_subdoc_type_dml;
            webconfig_send_dml_subdoc_status(ctrl);
            break;
        case ctrl_webconfig_state_vap_24G_cfg_rsp_pending:
            if (check_wifi_multivap_sched_timeout_active_status(ctrl, 0) == false) {
                type = webconfig_subdoc_type_vap_24G;
                webconfig_send_multivap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
            break;
        case ctrl_webconfig_state_vap_5G_cfg_rsp_pending:
            if (check_wifi_multivap_sched_timeout_active_status(ctrl, 1) == false) {
                type = webconfig_subdoc_type_vap_5G;
                webconfig_send_multivap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
            break;
        case ctrl_webconfig_state_vap_6G_cfg_rsp_pending:
            if (check_wifi_multivap_sched_timeout_active_status(ctrl, 2) == false) {
                type = webconfig_subdoc_type_vap_6G;
                webconfig_send_multivap_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
            break;
        case ctrl_webconfig_state_radio_24G_rsp_pending:
        case ctrl_webconfig_state_radio_5G_rsp_pending:
        case ctrl_webconfig_state_radio_6G_rsp_pending:
            state = (ctrl->webconfig_state & pending_state);
            if (state == ctrl_webconfig_state_radio_24G_rsp_pending) {
                radio_index = 0;
                type = webconfig_subdoc_type_radio_24G;
            } else if (state == ctrl_webconfig_state_radio_5G_rsp_pending) {
                radio_index = 1;
                type = webconfig_subdoc_type_radio_5G;
            } else {
                radio_index = 2;
                type = webconfig_subdoc_type_radio_6G;
            }
            if (check_wifi_radio_sched_timeout_active_status_of_radio_index(ctrl, radio_index) ==
                    false &&
                check_wifi_csa_sched_timeout_active_status_of_radio_index(ctrl, radio_index) ==
                    false) {
                webconfig_send_radio_subdoc_status(ctrl, type);
            } else {
                return RETURN_OK;
            }
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d - default pending subdoc status:0x%x\r\n", __func__, __LINE__, (ctrl->webconfig_state & CTRL_WEBCONFIG_STATE_MASK));
            break;
    }
    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_set_status, &type);
    return RETURN_OK;
}

static bool is_preassoc_cac_config_changed(wifi_vap_info_t *old, wifi_vap_info_t *new)
{
    if ((IS_STR_CHANGED(old->u.bss_info.preassoc.rssi_up_threshold, new->u.bss_info.preassoc.rssi_up_threshold, sizeof(old->u.bss_info.preassoc.rssi_up_threshold)))
        || (IS_STR_CHANGED(old->u.bss_info.preassoc.snr_threshold, new->u.bss_info.preassoc.snr_threshold, sizeof(old->u.bss_info.preassoc.snr_threshold)))
        || (IS_STR_CHANGED(old->u.bss_info.preassoc.cu_threshold, new->u.bss_info.preassoc.cu_threshold, sizeof(old->u.bss_info.preassoc.cu_threshold)))
        || (IS_STR_CHANGED(old->u.bss_info.preassoc.basic_data_transmit_rates, new->u.bss_info.preassoc.basic_data_transmit_rates, sizeof(old->u.bss_info.preassoc.basic_data_transmit_rates)))
        || (IS_STR_CHANGED(old->u.bss_info.preassoc.operational_data_transmit_rates, new->u.bss_info.preassoc.operational_data_transmit_rates, sizeof(old->u.bss_info.preassoc.operational_data_transmit_rates)))
        || (IS_STR_CHANGED(old->u.bss_info.preassoc.supported_data_transmit_rates, new->u.bss_info.preassoc.supported_data_transmit_rates, sizeof(old->u.bss_info.preassoc.supported_data_transmit_rates)))
        || (IS_STR_CHANGED(old->u.bss_info.preassoc.minimum_advertised_mcs, new->u.bss_info.preassoc.minimum_advertised_mcs, sizeof(old->u.bss_info.preassoc.minimum_advertised_mcs)))
        || (IS_STR_CHANGED(old->u.bss_info.preassoc.sixGOpInfoMinRate, new->u.bss_info.preassoc.sixGOpInfoMinRate, sizeof(old->u.bss_info.preassoc.sixGOpInfoMinRate)))
        || (IS_CHANGED(old->u.bss_info.preassoc.time_ms, new->u.bss_info.preassoc.time_ms))
        || (IS_CHANGED(old->u.bss_info.preassoc.min_num_mgmt_frames, new->u.bss_info.preassoc.min_num_mgmt_frames))
        || (IS_STR_CHANGED(old->u.bss_info.preassoc.tcm_exp_weightage, new->u.bss_info.preassoc.tcm_exp_weightage, sizeof(old->u.bss_info.preassoc.tcm_exp_weightage)))
        || (IS_STR_CHANGED(old->u.bss_info.preassoc.tcm_gradient_threshold, new->u.bss_info.preassoc.tcm_gradient_threshold, sizeof(old->u.bss_info.preassoc.tcm_gradient_threshold)))) {
        return true;
    } else {
        return false;
    }
}

static bool is_postassoc_cac_config_changed(wifi_vap_info_t *old, wifi_vap_info_t *new)
{
    if ((IS_STR_CHANGED(old->u.bss_info.postassoc.rssi_up_threshold, new->u.bss_info.postassoc.rssi_up_threshold, sizeof(old->u.bss_info.postassoc.rssi_up_threshold)))
        || (IS_STR_CHANGED(old->u.bss_info.postassoc.sampling_interval, new->u.bss_info.postassoc.sampling_interval, sizeof(old->u.bss_info.postassoc.sampling_interval)))
        || (IS_STR_CHANGED(old->u.bss_info.postassoc.snr_threshold, new->u.bss_info.postassoc.snr_threshold, sizeof(old->u.bss_info.postassoc.snr_threshold)))
        || (IS_STR_CHANGED(old->u.bss_info.postassoc.sampling_count, new->u.bss_info.postassoc.sampling_count, sizeof(old->u.bss_info.postassoc.sampling_count)))
        || (IS_STR_CHANGED(old->u.bss_info.postassoc.cu_threshold, new->u.bss_info.postassoc.cu_threshold, sizeof(old->u.bss_info.postassoc.cu_threshold)))) {
        return true;
    } else {
        return false;
    }
}


void vap_param_config_changed_event_logging(wifi_vap_info_t *old, wifi_vap_info_t *new,char name[16],wifi_radio_operationParam_t *radio)
{
    if (radio->enable) {
        OneWifiEventTrace(("RDK_LOG_NOTICE,  WiFi radio %s is set to UP\n",name));
        if (new->u.bss_info.enabled) {
            if (IS_CHANGED(old->u.bss_info.enabled, new->u.bss_info.enabled)) {
                OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi VAP Changed to UP\n"));
            }
            if (IS_STR_CHANGED(old->u.bss_info.ssid, new->u.bss_info.ssid,sizeof(old->u.bss_info.ssid))) {
                OneWifiEventTrace(("RDK_LOG_NOTICE, SSID Changed \n"));
            }
            if (IS_STR_CHANGED(old->u.bss_info.security.u.key.key, new->u.bss_info.security.u.key.key,sizeof(old->u.bss_info.security.u.key.key))) {
                OneWifiEventTrace(("RDK_LOG_NOTICE, KeyPassphrase Changed \n "));
            }
            if (IS_CHANGED(old->u.bss_info.security.mode, new->u.bss_info.security.mode)) {
                switch (new->u.bss_info.security.mode) {
                    case wifi_security_mode_none:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode None is enabled\n"));
                        break;
                    case wifi_security_mode_wep_64:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WEP-64 is enabled\n"));
                        break;
                    case wifi_security_mode_wep_128:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WEP-128 is enabled\n"));
                        break;
                    case wifi_security_mode_wpa_personal:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA-Personal is enabled\n"));
                        break;
                    case wifi_security_mode_wpa2_personal:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA2-Personal is enabled\n"));
                        break;
                    case wifi_security_mode_wpa_wpa2_personal:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA-WPA2-Personal is enabled\n"));
                        break;
                    case wifi_security_mode_wpa_enterprise:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA-Enterprise is enabled\n"));
                        break;
                    case wifi_security_mode_wpa2_enterprise:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA2-Enterprise is enabled\n"));
                        break;
                    case wifi_security_mode_wpa_wpa2_enterprise:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA-WPA2-Enterprise is enabled\n"));
                        break;
                    case wifi_security_mode_wpa3_personal:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA3-Personal is enabled\n"));
                        break;
                    case wifi_security_mode_wpa3_transition:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA3-Transition is enabled\n"));
                        break;
                    case wifi_security_mode_wpa3_enterprise:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA3-Enterprise is enabled\n"));
                        break;
                    case wifi_security_mode_enhanced_open:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode Open is enabled\n"));
                        break;
                    default:
                        OneWifiEventTrace(("RDK_LOG_NOTICE, Incorrect Wifi Security mode %d is enabled.\n",new->u.bss_info.security.mode));
                        break;
                }
            }
        } else {
              OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi VAP is set to down\n"));
        }
    } else {
          OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi radio %s is set to DOWN\n",name));
    }
    return;
}

static void webconfig_send_sta_bssid_change_event(wifi_ctrl_t *ctrl, wifi_vap_info_t *old,
    wifi_vap_info_t *new)
{
    vap_svc_t *ext_svc;
    char old_bssid_str[32], new_bssid_str[32];

    if (ctrl->network_mode != rdk_dev_mode_type_ext ||
            !isVapSTAMesh(new->vap_index) ||
            memcmp(old->u.sta_info.bssid, new->u.sta_info.bssid, sizeof(bssid_t)) == 0) {
        return;
    }

    uint8_mac_to_string_mac(old->u.sta_info.bssid, old_bssid_str);
    uint8_mac_to_string_mac(new->u.sta_info.bssid, new_bssid_str);
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: mesh sta bssid changed %s -> %s\n", __func__,
        __LINE__, old_bssid_str, new_bssid_str);

    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    if (ext_svc == NULL) {
        return;
    }

    ext_svc->event_fn(ext_svc, wifi_event_type_webconfig, wifi_event_webconfig_set_data_sta_bssid,
        vap_svc_event_none, new);
}

//We need to know that config applied due to force apply
bool is_force_apply_true(rdk_wifi_vap_info_t *rdk_vap_info) {
    if (rdk_vap_info == NULL) {
        return false;
    }

    if (rdk_vap_info->force_apply == true) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: SubDoc Force Apply is True, clearing it\n", __func__, __LINE__);
        //before returning make it to false
        rdk_vap_info->force_apply = false;
        return true;
    }
    return false;
}

int webconfig_hal_vap_apply_by_name(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data, char **vap_names, unsigned int size)
{
    unsigned int i, j, k;
    int tgt_radio_idx, tgt_vap_index;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_t *mgr_vap_info, *vap_info;
    vap_svc_t *svc;
    wifi_vap_info_map_t *mgr_vap_map, *p_tgt_vap_map = NULL;
    bool found_target = false;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    char update_status[128];
    public_vaps_data_t pub;
    rdk_wifi_vap_info_t *mgr_rdk_vap_info, *rdk_vap_info;
    rdk_wifi_vap_info_t tgt_rdk_vap_info;
    int ret = 0;

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
            radio = &mgr->radio_config[j];
            if (radio->vaps.radio_index == (unsigned int)tgt_radio_idx) {
                mgr_vap_map = &radio->vaps.vap_map;
                found_target = true;
                break;
            }
        }

        if (found_target == false) {
            wifi_util_error_print(WIFI_MGR,
                "%s:%d: Could not find tgt_radio_idx:%d for vap name:%s\n", __func__, __LINE__,
                tgt_radio_idx, vap_names[i]);
            continue;
        }

        found_target = false;

        for (j = 0; j < mgr_vap_map->num_vaps; j++) {
            if (mgr_vap_map->vap_array[j].vap_index == (unsigned int)tgt_vap_index) {
                mgr_vap_info = &mgr_vap_map->vap_array[j];
                mgr_rdk_vap_info = &radio->vaps.rdk_vap_array[j];
                found_target = true;
                break;
            }
        }

        if (found_target == false) {
            wifi_util_error_print(WIFI_MGR,
                "%s:%d: Could not find tgt_vap_index:%d for vap name:%s\n", __func__, __LINE__,
                tgt_vap_index, vap_names[i]);
            continue;
        }

        found_target = false;

        for (j = 0; j < getNumberRadios(); j++) {
            for (k = 0; k < getNumberVAPsPerRadio(j); k++) {
                if (strcmp(data->radios[j].vaps.vap_map.vap_array[k].vap_name, vap_names[i]) == 0) {
                    vap_info = &data->radios[j].vaps.vap_map.vap_array[k];
                    rdk_vap_info = &data->radios[j].vaps.rdk_vap_array[k];
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
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Found vap map source and target for vap name: %s\n", __func__, __LINE__, vap_info->vap_name);
        // STA BSSID change is handled by event to avoid disconnection.
        webconfig_send_sta_bssid_change_event(ctrl, mgr_vap_info, vap_info);

        // Ignore exists flag change because STA interfaces always enabled in HAL. This allows to
        // avoid redundant reconfiguration with STA disconnection.
        // For pods, STA is just like any other AP interface, deletion is allowed.
        if (ctrl->network_mode == rdk_dev_mode_type_ext && isVapSTAMesh(tgt_vap_index)) {
            mgr_rdk_vap_info->exists = rdk_vap_info->exists;
        }

        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Comparing VAP [%s] with [%s]. \n",__func__, __LINE__,mgr_vap_info->vap_name,vap_info->vap_name);
        if (is_vap_param_config_changed(mgr_vap_info, vap_info, mgr_rdk_vap_info, rdk_vap_info,
                isVapSTAMesh(tgt_vap_index)) || is_force_apply_true(rdk_vap_info)) {
            // radio data changed apply
            wifi_util_info_print(WIFI_CTRL, "%s:%d: Change detected in received vap config, applying new configuration for vap: %s\n",
                                __func__, __LINE__, vap_names[i]);
            vap_param_config_changed_event_logging(mgr_vap_info,vap_info,radio->name,&radio->oper);
            print_wifi_hal_bss_vap_data(WIFI_WEBCONFIG, "Old", tgt_vap_index, mgr_vap_info,
                mgr_rdk_vap_info);
            print_wifi_hal_bss_vap_data(WIFI_WEBCONFIG, "New", tgt_vap_index, vap_info,
                rdk_vap_info);

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
#ifdef FEATURE_SUPPORT_WPS
                if (memcmp(&mgr_vap_info->u.bss_info.wps, &vap_info->u.bss_info.wps, sizeof(wifi_wps_t))) {
                    print_wifi_hal_vap_wps_data(WIFI_WEBCONFIG, "Old", tgt_vap_index, &mgr_vap_info->u.bss_info.wps);
                    print_wifi_hal_vap_wps_data(WIFI_WEBCONFIG, "New", tgt_vap_index, &vap_info->u.bss_info.wps);
                }
#endif
            } 

            p_tgt_vap_map = (wifi_vap_info_map_t *) malloc(sizeof(wifi_vap_info_map_t));
            if(p_tgt_vap_map == NULL ) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: Failed to allocate memory.\n", __func__, __LINE__);
                return RETURN_ERR;
            }
            memset(p_tgt_vap_map, 0, sizeof(wifi_vap_info_map_t));
            p_tgt_vap_map->num_vaps = 1;

            memcpy(&p_tgt_vap_map->vap_array[0], vap_info, sizeof(wifi_vap_info_t));
            memset(&tgt_rdk_vap_info, 0, sizeof(rdk_wifi_vap_info_t));
            memcpy(&tgt_rdk_vap_info, rdk_vap_info, sizeof(rdk_wifi_vap_info_t));

            start_wifi_sched_timer(vap_info->vap_index, ctrl, wifi_vap_sched);

            if (svc->update_fn(svc, tgt_radio_idx, p_tgt_vap_map, &tgt_rdk_vap_info) != RETURN_OK) {
                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d: failed to apply\n", __func__, __LINE__);
                memset(update_status, 0, sizeof(update_status));
                snprintf(update_status, sizeof(update_status), "%s %s", vap_names[i], "fail");
                apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_hal_result, update_status);
                free(p_tgt_vap_map);
                p_tgt_vap_map = NULL;
                return RETURN_ERR;
            }

            memset(update_status, 0, sizeof(update_status));
            snprintf(update_status, sizeof(update_status), "%s %s", vap_names[i], (ret == RETURN_OK)?"success":"fail");
            apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_hal_result, update_status);
            if (vap_svc_is_public(tgt_vap_index)) {
                wifi_util_dbg_print(WIFI_CTRL,"vapname is %s and %d \n",vap_info->vap_name,vap_info->u.bss_info.enabled);
                if (svc->event_fn != NULL) {
                    snprintf(pub.vap_name,sizeof(pub.vap_name),"%s",vap_info->vap_name);
                    pub.enabled = vap_info->u.bss_info.enabled;
                    svc->event_fn(svc, wifi_event_type_command, wifi_event_type_xfinity_enable,
                       vap_svc_event_none, &pub);
                }
            }
            /* XXX: This memcpy should be deleted later. Mgr's cache should be
             * updated only from WifiDb callbacks (see update_fn).
             *
             * Problems:
             * 1. memcpy would be executed even if wifi_hal_createVAP/webconfig_set_ow_core_vif_config failed
             * 2. MAC is updated by ow_core_update_vap_mac for XE2. Currently, schema_Wifi_VAP_Config doesn't have mac field
             * So, it won't be updated within update_fn -> wifidb_update_wifi_vap_info. Thats the reason why I leaved memcpy here. 
             */
            memcpy(mgr_vap_info, &p_tgt_vap_map->vap_array[0], sizeof(wifi_vap_info_t));

            // This block of code is only used for updating VAP mac.
            //if (vap_info->vap_mode == wifi_vap_mode_ap && is_bssid_valid(p_tgt_vap_map->vap_array[0].u.bss_info.bssid)) {
            //    memcpy(vap_info->u.bss_info.bssid, p_tgt_vap_map->vap_array[0].u.bss_info.bssid, sizeof(mac_address_t));
            //}
            //else if (vap_info->vap_mode == wifi_vap_mode_sta && is_bssid_valid(p_tgt_vap_map->vap_array[0].u.sta_info.mac)){
            //    memcpy(vap_info->u.sta_info.mac, p_tgt_vap_map->vap_array[0].u.sta_info.mac, sizeof(mac_address_t));
           // }
            free(p_tgt_vap_map);

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

int webconfig_stats_config_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    wifi_mgr_t *mgr = get_wifimgr_obj();
    stats_config_t  *mgr_stats_config, *dec_stats_config, *temp_stats_config;
    hash_map_t *mgr_cfg_map, *dec_cfg_map;
    int ret = RETURN_OK;
    char key[64] = {0};

    wifi_util_dbg_print(WIFI_CTRL,"%s %d \n", __func__, __LINE__);

    mgr_cfg_map = mgr->stats_config_map;
    dec_cfg_map = data->stats_config_map;

    if (dec_cfg_map == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s %d NULL pointer \n", __func__, __LINE__);
        ret = RETURN_ERR;
        goto free_data;
    }

    if (mgr_cfg_map == dec_cfg_map) {
        wifi_util_dbg_print(WIFI_CTRL,"%s %d Same data returning \n", __func__, __LINE__);
        ret = RETURN_OK;
        goto free_data;
    }

    if (mgr_cfg_map != NULL) {
        mgr_stats_config = hash_map_get_first(mgr_cfg_map);
        while (mgr_stats_config != NULL) {
            if (hash_map_get(dec_cfg_map, mgr_stats_config->stats_cfg_id) == NULL) {
                //Notification for delete
                //notify_observer(mgr_stats_config);
                memset(key, 0, sizeof(key));
                snprintf(key, sizeof(key), "%s",  mgr_stats_config->stats_cfg_id);
                mgr_stats_config = hash_map_get_next(mgr_cfg_map, mgr_stats_config);
                temp_stats_config = hash_map_remove(mgr_cfg_map, key);
                if (temp_stats_config != NULL) {
                    free(temp_stats_config);
                }
            } else {
                mgr_stats_config = hash_map_get_next(mgr_cfg_map, mgr_stats_config);
            }
        }
    }

    if (dec_cfg_map != NULL) {
        dec_stats_config = hash_map_get_first(dec_cfg_map);
        while (dec_stats_config != NULL) {
            mgr_stats_config = hash_map_get(mgr_cfg_map, dec_stats_config->stats_cfg_id);
            if (mgr_stats_config == NULL) {
                mgr_stats_config = (stats_config_t *)malloc(sizeof(stats_config_t));
                if (mgr_stats_config == NULL) {
                    wifi_util_dbg_print(WIFI_CTRL,"%s %d NULL pointer \n", __func__, __LINE__);
                    ret = RETURN_ERR;
                    goto free_data;
                }
                memset(mgr_stats_config, 0, sizeof(stats_config_t));
                memcpy(mgr_stats_config, dec_stats_config, sizeof(stats_config_t));
                hash_map_put(mgr_cfg_map, strdup(mgr_stats_config->stats_cfg_id), mgr_stats_config);
                //Notification for new entry
                //notify_observer(mgr_stats_config);
            } else {
                memcpy(mgr_stats_config, dec_stats_config, sizeof(stats_config_t));
                //Notification for update
                //notify_observer(mgr_stats_config);
            }
            dec_stats_config = hash_map_get_next(dec_cfg_map, dec_stats_config);
        }
    }

  free_data:
    if ((data != NULL) && (dec_cfg_map != NULL)) {
        wifi_util_dbg_print(WIFI_CTRL,"%s %d Freeing Decoded Data \n", __func__, __LINE__);
        dec_stats_config = hash_map_get_first(dec_cfg_map);
        while (dec_stats_config != NULL) {
            memset(key, 0, sizeof(key));
            snprintf(key, sizeof(key), "%s",  dec_stats_config->stats_cfg_id);
            dec_stats_config = hash_map_get_next(dec_cfg_map, dec_stats_config);
            temp_stats_config = hash_map_remove(dec_cfg_map, key);
            if (temp_stats_config != NULL) {
                free(temp_stats_config);
            }
        }
        hash_map_destroy(dec_cfg_map);
        dec_cfg_map = NULL;
    }

    return ret;
}


int webconfig_steering_clients_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    wifi_mgr_t *mgr = get_wifimgr_obj();
    band_steering_clients_t  *mgr_steering_client, *dec_steering_client, *temp_steering_client;
    hash_map_t *mgr_cfg_map, *dec_cfg_map;
    int ret = RETURN_OK;
    char key[64] = {0};

    wifi_util_dbg_print(WIFI_MGR,"%s %d \n", __func__, __LINE__);

    mgr_cfg_map = mgr->steering_client_map;
    dec_cfg_map = data->steering_client_map;

    if (dec_cfg_map == NULL) {
        wifi_util_dbg_print(WIFI_MGR,"%s %d NULL pointer \n", __func__, __LINE__);
        ret = RETURN_ERR;
        goto free_data;
    }

    if (mgr_cfg_map == dec_cfg_map) {
        wifi_util_dbg_print(WIFI_MGR,"%s %d Same data returning \n", __func__, __LINE__);
        ret = RETURN_OK;
        goto free_data;
    }

    if (mgr_cfg_map != NULL) {
        mgr_steering_client = hash_map_get_first(mgr_cfg_map);
        while (mgr_steering_client != NULL) {
            if (hash_map_get(dec_cfg_map, mgr_steering_client->steering_client_id) == NULL) {
                //Notification for delete
                //notify_observer(mgr_steering_client);
                memset(key, 0, sizeof(key));
                snprintf(key, sizeof(key), "%s",  mgr_steering_client->steering_client_id);
                mgr_steering_client = hash_map_get_next(mgr_cfg_map, mgr_steering_client);
                temp_steering_client = hash_map_remove(mgr_cfg_map, key);
                if (temp_steering_client != NULL) {
                    free(temp_steering_client);
                }
            } else {
                mgr_steering_client = hash_map_get_next(mgr_cfg_map, mgr_steering_client);
            }
        }
    }

    if (dec_cfg_map != NULL) {
        dec_steering_client = hash_map_get_first(dec_cfg_map);
        while (dec_steering_client != NULL) {
            mgr_steering_client = hash_map_get(mgr_cfg_map, dec_steering_client->steering_client_id);
            if (mgr_steering_client == NULL) {
                mgr_steering_client = (band_steering_clients_t *)malloc(sizeof(band_steering_clients_t));
                if (mgr_steering_client == NULL) {
                    wifi_util_dbg_print(WIFI_MGR,"%s %d NULL pointer \n", __func__, __LINE__);
                    ret = RETURN_ERR;
                    goto free_data;
                }
                memset(mgr_steering_client, 0, sizeof(band_steering_clients_t));
                memcpy(mgr_steering_client, dec_steering_client, sizeof(band_steering_clients_t));
                hash_map_put(mgr_cfg_map, strdup(mgr_steering_client->steering_client_id), mgr_steering_client);
                //notify_observer(mgr_steering_client);
            } else {
                memcpy(mgr_steering_client, dec_steering_client, sizeof(band_steering_clients_t));
                //notify_observer(mgr_steering_client);
            }
            dec_steering_client = hash_map_get_next(dec_cfg_map, dec_steering_client);
        }
    }

  free_data:
    if ((data != NULL) && (dec_cfg_map != NULL)) {
        wifi_util_dbg_print(WIFI_MGR,"%s %d Freeing Decoded Data \n", __func__, __LINE__);
        dec_steering_client = hash_map_get_first(dec_cfg_map);
        while (dec_steering_client != NULL) {
            memset(key, 0, sizeof(key));
            snprintf(key, sizeof(key), "%s",  dec_steering_client->steering_client_id);
            dec_steering_client = hash_map_get_next(dec_cfg_map, dec_steering_client);
            temp_steering_client = hash_map_remove(dec_cfg_map, key);
            if (temp_steering_client != NULL) {
                free(temp_steering_client);
            }
        }
        hash_map_destroy(dec_cfg_map);
        dec_cfg_map = NULL;
    }

    return ret;
}


int webconfig_steering_config_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{

    wifi_mgr_t *mgr = get_wifimgr_obj();
    steering_config_t *mgr_steer_config, *dec_steer_config, *temp_steer_config;
    hash_map_t *mgr_cfg_map, *dec_cfg_map;
    int ret = RETURN_OK;
    char key[64] = {0};

    wifi_util_dbg_print(WIFI_MGR,"%s %d \n", __func__, __LINE__);

    mgr_cfg_map = mgr->steering_config_map;
    dec_cfg_map = data->steering_config_map;

    if (dec_cfg_map == NULL) {
        wifi_util_dbg_print(WIFI_MGR,"%s %d NULL pointer \n", __func__, __LINE__);
        ret = RETURN_ERR;
        goto free_data;
    }

    if (mgr_cfg_map == dec_cfg_map) {
        wifi_util_dbg_print(WIFI_MGR,"%s %d Same data returning \n", __func__, __LINE__);
        ret = RETURN_OK;
        goto free_data;
    }

    if (mgr_cfg_map != NULL) {
        mgr_steer_config = hash_map_get_first(mgr_cfg_map);
        while (mgr_steer_config != NULL) {
            if (hash_map_get(dec_cfg_map, mgr_steer_config->steering_cfg_id) == NULL) {
                //Notification for delete
                //notify_observer(mgr_steer_config);
                memset(key, 0, sizeof(key));
                snprintf(key, sizeof(key), "%s",  mgr_steer_config->steering_cfg_id);
                mgr_steer_config = hash_map_get_next(mgr_cfg_map, mgr_steer_config);
                temp_steer_config = hash_map_remove(mgr_cfg_map, key);
                if (temp_steer_config != NULL) {
                    free(temp_steer_config);
                }
            } else {
                mgr_steer_config = hash_map_get_next(mgr_cfg_map, mgr_steer_config);
            }
        }
    }

    if (dec_cfg_map != NULL) {
        dec_steer_config = hash_map_get_first(dec_cfg_map);
        while (dec_steer_config != NULL) {
            mgr_steer_config = hash_map_get(mgr_cfg_map, dec_steer_config->steering_cfg_id);
            if (mgr_steer_config == NULL) {
                mgr_steer_config = (steering_config_t *)malloc(sizeof(steering_config_t));
                if (mgr_steer_config == NULL) {
                    wifi_util_dbg_print(WIFI_MGR,"%s %d NULL pointer \n", __func__, __LINE__);
                    ret = RETURN_ERR;
                    goto free_data;
                }
                memset(mgr_steer_config, 0, sizeof(steering_config_t));
                memcpy(mgr_steer_config, dec_steer_config, sizeof(steering_config_t));
                hash_map_put(mgr_cfg_map, strdup(mgr_steer_config->steering_cfg_id), mgr_steer_config);
                //notify_observer(mgr_steer_config);
            } else {
                memcpy(mgr_steer_config, dec_steer_config, sizeof(steering_config_t));
                //notify_observer(mgr_steer_config);
            }
            dec_steer_config = hash_map_get_next(dec_cfg_map, dec_steer_config);
        }
    }
  free_data:
    if ((data != NULL) && (dec_cfg_map != NULL)) {
        wifi_util_dbg_print(WIFI_MGR,"%s %d Freeing Decoded Data \n", __func__, __LINE__);
        dec_steer_config = hash_map_get_first(dec_cfg_map);
        while (dec_steer_config != NULL) {
            memset(key, 0, sizeof(key));
            snprintf(key, sizeof(key), "%s", dec_steer_config->steering_cfg_id);
            dec_steer_config = hash_map_get_next(dec_cfg_map, dec_steer_config);
            temp_steer_config = hash_map_remove(dec_cfg_map, key);
            if (temp_steer_config != NULL) {
                free(temp_steer_config);
            }
        }
        hash_map_destroy(dec_cfg_map);
        dec_cfg_map = NULL;
    }

    return ret;
}

int webconfig_vif_neighbors_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{

    wifi_mgr_t *mgr = get_wifimgr_obj();
    vif_neighbors_t *mgr_vif_neighbors, *dec_vif_neighbors, *temp_vif_neighbors;
    hash_map_t *mgr_cfg_map, *dec_cfg_map;
    int ret = RETURN_OK;
    char key[64] = {0};

    wifi_util_dbg_print(WIFI_MGR,"%s %d \n", __func__, __LINE__);

    mgr_cfg_map = mgr->vif_neighbors_map;
    dec_cfg_map = data->vif_neighbors_map;

    if (dec_cfg_map == NULL) {
        wifi_util_dbg_print(WIFI_MGR,"%s %d NULL pointer \n", __func__, __LINE__);
        ret = RETURN_ERR;
        goto free_data;
    }

    if (mgr_cfg_map == dec_cfg_map) {
        wifi_util_dbg_print(WIFI_MGR,"%s %d Same data returning \n", __func__, __LINE__);
        ret = RETURN_OK;
        goto free_data;
    }

    if (mgr_cfg_map != NULL) {
        mgr_vif_neighbors = hash_map_get_first(mgr_cfg_map);
        while (mgr_vif_neighbors != NULL) {
            if (hash_map_get(dec_cfg_map, mgr_vif_neighbors->neighbor_id) == NULL) {
                //Notification for delete
                //notify_observer(mgr_vif_neighbors);
                memset(key, 0, sizeof(key));
                snprintf(key, sizeof(key), "%s",  mgr_vif_neighbors->neighbor_id);
                mgr_vif_neighbors = hash_map_get_next(mgr_cfg_map, mgr_vif_neighbors);
                temp_vif_neighbors = hash_map_remove(mgr_cfg_map, key);
                if (temp_vif_neighbors != NULL) {
                    free(temp_vif_neighbors);
                }
            } else {
                mgr_vif_neighbors = hash_map_get_next(mgr_cfg_map, mgr_vif_neighbors);
            }
        }
    }

    if (dec_cfg_map != NULL) {
        dec_vif_neighbors = hash_map_get_first(dec_cfg_map);
        while (dec_vif_neighbors != NULL) {
            mgr_vif_neighbors = hash_map_get(mgr_cfg_map, dec_vif_neighbors->neighbor_id);
            if (mgr_vif_neighbors == NULL) {
                mgr_vif_neighbors = (vif_neighbors_t *)malloc(sizeof(vif_neighbors_t));
                if (mgr_vif_neighbors == NULL) {
                    wifi_util_dbg_print(WIFI_MGR,"%s %d NULL pointer \n", __func__, __LINE__);
                    ret = RETURN_ERR;
                    goto free_data;
                }
                memset(mgr_vif_neighbors, 0, sizeof(vif_neighbors_t));
                memcpy(mgr_vif_neighbors, dec_vif_neighbors, sizeof(vif_neighbors_t));
                hash_map_put(mgr_cfg_map, strdup(mgr_vif_neighbors->neighbor_id), mgr_vif_neighbors);
                //notify_observer(mgr_vif_neighbors);
            } else {
                memcpy(mgr_vif_neighbors, dec_vif_neighbors, sizeof(vif_neighbors_t));
                //notify_observer(mgr_vif_neighbors);
            }
            dec_vif_neighbors = hash_map_get_next(dec_cfg_map, dec_vif_neighbors);
        }
    }
  free_data:
    if ((data != NULL) && (dec_cfg_map != NULL)) {
        wifi_util_dbg_print(WIFI_MGR,"%s %d Freeing Decoded Data \n", __func__, __LINE__);
        dec_vif_neighbors = hash_map_get_first(dec_cfg_map);
        while (dec_vif_neighbors != NULL) {
            memset(key, 0, sizeof(key));
            snprintf(key, sizeof(key), "%s", dec_vif_neighbors->neighbor_id);
            dec_vif_neighbors = hash_map_get_next(dec_cfg_map, dec_vif_neighbors);
            temp_vif_neighbors = hash_map_remove(dec_cfg_map, key);
            if (temp_vif_neighbors != NULL) {
                free(temp_vif_neighbors);
            }
        }
        hash_map_destroy(dec_cfg_map);
        dec_cfg_map = NULL;
    }

    return ret;
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

int webconfig_cac_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    wifi_util_dbg_print(WIFI_CTRL,"Inside webconfig_cac_apply\n");
    unsigned int vap_index;
    unsigned int radio_index;
    wifi_vap_info_map_t *l_vap_maps;

    //Apply the CAC Data
    for(radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        l_vap_maps = get_wifidb_vap_map(radio_index);
        for (vap_index = 0; vap_index < getNumberVAPsPerRadio(radio_index); vap_index++) {
            wifi_util_dbg_print(WIFI_CTRL,"Comparing cac config\n");

            if (is_preassoc_cac_config_changed(&l_vap_maps->vap_array[vap_index], &data->radios[radio_index].vaps.vap_map.vap_array[vap_index])
                || is_postassoc_cac_config_changed(&l_vap_maps->vap_array[vap_index], &data->radios[radio_index].vaps.vap_map.vap_array[vap_index])) {
                // cac or tcm data changed apply
                wifi_util_info_print(WIFI_CTRL, "%s:%d: Change detected in received cac config, applying new configuration for vap: %d\n",
                                    __func__, __LINE__, vap_index);
                wifidb_update_wifi_cac_config(&data->radios[radio_index].vaps.vap_map);
            } else {
                wifi_util_info_print(WIFI_CTRL, "%s:%d: Received vap config is same for %d, not applying\n",
                            __func__, __LINE__, vap_index);
            }
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
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (UINT index = 0; index < getTotalNumberVAPs(); index++){
        ap_index = VAP_INDEX(mgr->hal_cap, index);
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
    char *vap_name = NULL;
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
    unsigned int ap_index;
    char *vap_name;
    char *vap_names[MAX_VAP];
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (UINT index = 0; index < getTotalNumberVAPs(); index++){
        ap_index = VAP_INDEX(mgr->hal_cap, index);
        if(isVapMeshBackhaul(ap_index)){
            vap_name = getVAPName(ap_index);
            vap_names[num_vaps] = vap_name;
            num_vaps++;
        }
    }
    return webconfig_hal_vap_apply_by_name(ctrl, data, vap_names, num_vaps);
}

int webconfig_hal_multivap_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data,
    webconfig_subdoc_type_t doc_type)
{
    unsigned int num_vaps = 0;
    char *vap_names[MAX_NUM_VAP_PER_RADIO];
    wifi_mgr_t *mgr = get_wifimgr_obj();
    rdk_wifi_vap_map_t *mgr_vap_map = NULL;
    int radio_index = -1;

    switch (doc_type) {
    case webconfig_subdoc_type_vap_24G:
        radio_index = 0;
        break;
    case webconfig_subdoc_type_vap_5G:
        radio_index = 1;
        break;
    case webconfig_subdoc_type_vap_6G:
        radio_index = 2;
        break;
    default:
        // Invalid doc_type return err
        wifi_util_error_print(WIFI_MGR, "%s:%d Invalid doc_type:%d\n", __func__, __LINE__,
            doc_type);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_MGR, "%s:%d Selected Radio Index:%d for doc_type:%d\n", __func__,
        __LINE__, radio_index, doc_type);
    mgr_vap_map = &mgr->radio_config[radio_index].vaps;
    if (mgr_vap_map == NULL) {
        wifi_util_error_print(WIFI_MGR, "%s:%d Error vap_map is NULL for Radio Index:%d\n",
            __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    // Consider all the Vap associated with the radio_index
    for (UINT index = 0; index < mgr_vap_map->num_vaps; index++) {
        vap_names[num_vaps] = mgr_vap_map->rdk_vap_array[index].vap_name;
        num_vaps++;
    }
    return webconfig_hal_vap_apply_by_name(ctrl, data, vap_names, num_vaps);
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
#ifdef NL80211_ACL
			    if (wifi_hal_delApAclDevice(current_config->vap_index, current_mac_str) != RETURN_OK) {
#else
                            if (wifi_delApAclDevice(current_config->vap_index, current_mac_str) != RETURN_OK) {
#endif
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
#ifdef NL80211_ACL
                wifi_hal_delApAclDevices(vap_index);
#else
		wifi_delApAclDevices(vap_index);
#endif
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
#ifdef NL80211_ACL
                        if (wifi_hal_addApAclDevice(current_config->vap_index, new_mac_str) != RETURN_OK) {
#else
                        if (wifi_addApAclDevice(current_config->vap_index, new_mac_str) != RETURN_OK) {
#endif
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

bool is_radio_feat_config_changed(rdk_wifi_radio_t *old, rdk_wifi_radio_t *new)
{
    if (IS_CHANGED(old->feature.OffChanTscanInMsec, new->feature.OffChanTscanInMsec)
        || (IS_CHANGED(old->feature.OffChanNscanInSec, new->feature.OffChanNscanInSec))
        || (IS_CHANGED(old->feature.OffChanTidleInSec, new->feature.OffChanTidleInSec))) {
        return true;
    } else {
        return false;
    }
}

static bool is_radio_param_config_changed(wifi_radio_operationParam_t *old , wifi_radio_operationParam_t *new)
{
    // Compare only which are changed from Wifi_Radio_Config
    new->operatingClass = old->operatingClass;

    if (IS_CHANGED(old->enable,new->enable)) return true;
    if (IS_CHANGED(old->band,new->band)) return true;
    if (IS_CHANGED(old->autoChannelEnabled,new->autoChannelEnabled)) return true;
    if (IS_CHANGED(old->channel,new->channel)) return true;
    if (IS_CHANGED(old->numSecondaryChannels,new->numSecondaryChannels)) return true;
    if (IS_CHANGED(old->channelWidth,new->channelWidth)) return true;
    if (IS_CHANGED(old->variant,new->variant)) return true;
    if (IS_CHANGED(old->csa_beacon_count,new->csa_beacon_count)) return true;
    if (IS_CHANGED(old->countryCode,new->countryCode)) return true;
    if (IS_CHANGED(old->operatingEnvironment,new->operatingEnvironment)) return true;
    if (IS_CHANGED(old->DCSEnabled,new->DCSEnabled)) return true;
    if (IS_CHANGED(old->dtimPeriod,new->dtimPeriod)) return true;
    if (IS_CHANGED(old->beaconInterval,new->beaconInterval)) return true;
    if (IS_CHANGED(old->operatingClass,new->operatingClass)) return true;
    if (IS_CHANGED(old->basicDataTransmitRates,new->basicDataTransmitRates)) return true;
    if (IS_CHANGED(old->operationalDataTransmitRates,new->operationalDataTransmitRates)) return true;
    if (IS_CHANGED(old->fragmentationThreshold,new->fragmentationThreshold)) return true;
    if (IS_CHANGED(old->guardInterval,new->guardInterval)) return true;
    if (IS_CHANGED(old->transmitPower,new->transmitPower)) return true;
    if (IS_CHANGED(old->rtsThreshold,new->rtsThreshold)) return true;
    if (IS_CHANGED(old->factoryResetSsid,new->factoryResetSsid)) return true;
    if (IS_CHANGED(old->radioStatsMeasuringRate,new->radioStatsMeasuringRate)) return true;
    if (IS_CHANGED(old->radioStatsMeasuringInterval,new->radioStatsMeasuringInterval)) return true;
    if (IS_CHANGED(old->ctsProtection,new->ctsProtection)) return true;
    if (IS_CHANGED(old->obssCoex,new->obssCoex)) return true;
    if (IS_CHANGED(old->stbcEnable,new->stbcEnable)) return true;
    if (IS_CHANGED(old->greenFieldEnable,new->greenFieldEnable)) return true;
    if (IS_CHANGED(old->userControl,new->userControl)) return true;
    if (IS_CHANGED(old->adminControl,new->adminControl)) return true;
    if (IS_CHANGED(old->chanUtilThreshold,new->chanUtilThreshold)) return true;
    if (IS_CHANGED(old->chanUtilSelfHealEnable,new->chanUtilSelfHealEnable)) return true;
    if (IS_CHANGED(old->variant,new->variant)) return true;
    if (IS_CHANGED(old->EcoPowerDown,new->EcoPowerDown)) return true;
    if (IS_CHANGED(old->DFSTimer, new->DFSTimer)) return true;

    return false;
}

#if defined (FEATURE_SUPPORT_ECOPOWERDOWN)
#define ECOMODE_COMPLETE_MARKER_FILE "/tmp/ecomode_operation_done"
#define MAX_RETRY_VALUE 15
void ecomode_telemetry_update_and_reboot(unsigned int index, bool active)
{
    CHAR eventName[32] = {0};
#ifndef DISABLE_ECO_REBOOT
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
#endif

    snprintf(eventName, sizeof(eventName), "WIFI_RADIO_%d_ECOPOWERMODE", index + 1);
    get_stubs_descriptor()->t2_event_s_fn(eventName, active ? "Active" : "Inactive");
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: EcoPowerDown telemetry: %s %s uploaded for Radio %d\n", __FUNCTION__, eventName, active ? "Active" : "Inactive", index + 1);
#ifdef DISABLE_ECO_REBOOT
    wifi_util_dbg_print(WIFI_WEBCONFIG,
        "%s: EcoPowerDown telemetry: Restarting OneWiFi to apply EcoMode. \n", __FUNCTION__);
    /**
     * The ECOMode operation in the lower layer stack typically takes approximately 10-12 seconds to
     * complete. This ensures the OneWiFi service is restarted once the EDPD operation is finished.
     */
    int max_retries = MAX_RETRY_VALUE;
    int attempt = 0;

    while (attempt < max_retries) {
        if (access(ECOMODE_COMPLETE_MARKER_FILE, F_OK) == 0) {
            /* EcoMode operation completed. */
            break;
        } else {
            sleep(1);
        }
        attempt++;
    }
    system("systemctl restart onewifi.service");
#else
    reboot_device(ctrl);
#endif
}
#endif // defined (FEATURE_SUPPORT_ECOPOWERDOWN)


void radio_param_config_changed_event_logging(wifi_radio_operationParam_t *old , wifi_radio_operationParam_t *new,char name[16])
{
    if(IS_CHANGED(old->enable,new->enable))
    {
        OneWifiEventTrace(("RDK_LOG_NOTICE, Wifi radio %s is set to %s\n",name,((new->enable==1)?"UP":"DOWN")));
    }
}

int webconfig_hal_radio_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data)
{
    unsigned int i, j;
    rdk_wifi_radio_t *radio_data, *mgr_radio_data;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    bool found_radio_index = false;
    int ret;
    int is_changed = 0;
    bool is_radio_6g_modified = false;
    vap_svc_t *pub_svc = NULL;
#if defined (FEATURE_SUPPORT_ECOPOWERDOWN)
    bool old_ecomode = false;
    bool new_ecomode = false;
#endif
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

        if (is_radio_band_5G(radio_data->oper.band) && is_radio_feat_config_changed(mgr_radio_data, radio_data))
        {
            //Not required currently for 2.4GHz, can be added later for 5GH and 6G after support is added
            is_changed = 1;
            wifi_util_dbg_print(WIFI_MGR,"%s:%d Tscan:%lu, Nscan:%lu, Tidle:%lu \n",__func__,__LINE__,radio_data->feature.OffChanTscanInMsec, radio_data->feature.OffChanNscanInSec, radio_data->feature.OffChanTidleInSec);
        }

        if ((is_radio_param_config_changed(&mgr_radio_data->oper, &radio_data->oper) == true)) {
            // radio data changed apply
            is_changed = 1;
            if (IS_CHANGED(mgr_radio_data->oper.enable,radio_data->oper.enable) &&
                is_6g_supported_device(&mgr->hal_cap.wifi_prop)) {
                wifi_util_info_print(WIFI_MGR,"Radio enable field is modified from mgr_radio_data->oper->enable=%d and radio_data->oper->enable=%d\n",
                    mgr_radio_data->oper.enable,radio_data->oper.enable);
                is_radio_6g_modified =  true;
            }
            wifi_util_info_print(WIFI_MGR, "%s:%d: Change detected in received radio config, applying new configuration for radio: %s\n",
                            __func__, __LINE__, radio_data->name);
            radio_param_config_changed_event_logging(&mgr_radio_data->oper,&radio_data->oper,radio_data->name);
            print_wifi_hal_radio_data(WIFI_WEBCONFIG, "old", i, &mgr_radio_data->oper);
            print_wifi_hal_radio_data(WIFI_WEBCONFIG, "New", i, &radio_data->oper);

// Optimizer will try to change, channel on current STA along with parent change, So it shouldn't skip for pods. 
            if (ctrl->network_mode == rdk_dev_mode_type_ext) {
                vap_svc_t *ext_svc;
                ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
                if (ext_svc != NULL) {
                    vap_svc_ext_t *ext;
                    ext = &ext_svc->u.ext;
                    unsigned int connected_radio_index = 0;
                    connected_radio_index = get_radio_index_for_vap_index(ext_svc->prop, ext->connected_vap_index);
                    if ((ext->conn_state == connection_state_connected) && (connected_radio_index == mgr_radio_data->vaps.radio_index) && (mgr_radio_data->oper.channel != radio_data->oper.channel)) {
                        start_wifi_sched_timer(mgr_radio_data->vaps.radio_index, ctrl, wifi_csa_sched);
                        ext_svc->event_fn(ext_svc, wifi_event_type_webconfig, wifi_event_webconfig_set_data, vap_svc_event_none, &radio_data->oper);
                        // driver does not change channel in STA connected state therefore skip
                        // wifi_hal_setRadioOperatingParameters and update channel on disconnection/CSA
                        continue;
                    }
                }
            }
#if defined (FEATURE_SUPPORT_ECOPOWERDOWN)
            // Save the ECO mode state before update to the DB
            old_ecomode = mgr_radio_data->oper.EcoPowerDown;
            new_ecomode = radio_data->oper.EcoPowerDown;
            if (old_ecomode != new_ecomode ) {
                radio_data->oper.enable = ((new_ecomode) ? false : true);
                wifi_util_info_print(WIFI_MGR, "%s:%d:Changing radio enable status:radio_data->oper.enable= %d\n",__func__,__LINE__, radio_data->oper.enable);
            }
#endif // defined (FEATURE_SUPPORT_ECOPOWERDOWN)
            wifi_util_dbg_print(WIFI_WEBCONFIG,"[%s]:WIFI RFC OW CORE THREAD DISABLED \r\n",__FUNCTION__);

            if (wifi_radio_operationParam_validation(&mgr->hal_cap, &radio_data->oper) !=
                RETURN_OK) {
                wifi_util_error_print(WIFI_MGR, "%s:%d: failed to validate %s parameters\n",
                    __func__, __LINE__, radio_data->name);
                return RETURN_ERR;
            }

            ret = wifi_hal_setRadioOperatingParameters(mgr_radio_data->vaps.radio_index, &radio_data->oper);

            if (ret != RETURN_OK) {
                wifi_util_error_print(WIFI_MGR, "%s:%d: failed to apply\n", __func__, __LINE__);
                ctrl->webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
                return RETURN_ERR;
            }

            start_wifi_sched_timer(mgr_radio_data->vaps.radio_index, ctrl, wifi_radio_sched);

            if (is_csa_sched_timer_trigger(mgr_radio_data->oper, radio_data->oper) == true) {
                start_wifi_sched_timer(mgr_radio_data->vaps.radio_index, ctrl, wifi_csa_sched);
            }
        }

        if (is_changed) {

// write the value to database
#ifndef LINUX_VM_PORT
            wifidb_update_wifi_radio_config(mgr_radio_data->vaps.radio_index, &radio_data->oper, &radio_data->feature);
#else
            // Update the cache in case of Linux targets
            memcpy(&mgr_radio_data->oper, &radio_data->oper, sizeof(wifi_radio_operationParam_t));
#endif

#if defined (FEATURE_SUPPORT_ECOPOWERDOWN)
            //Upload the telemetry marker and reboot the device
            //only if there is a change in the DM Device.WiFi.Radio.{i}.X_RDK_EcoPowerDown
            wifi_util_info_print(WIFI_MGR, "%s:%d: oldEco = %d  newEco = %d\n", __func__, __LINE__, old_ecomode, new_ecomode);
            if (old_ecomode != new_ecomode) {
                // write the value to database and reboot
                ecomode_telemetry_update_and_reboot(i, new_ecomode);
            }
#endif // defined (FEATURE_SUPPORT_ECOPOWERDOWN)
            if (is_radio_6g_modified) {
                pub_svc = get_svc_by_type(ctrl, vap_svc_type_public);
                if (pub_svc->event_fn != NULL) {
                    pub_svc->event_fn(pub_svc, wifi_event_type_command, wifi_event_type_xfinity_rrm,
                       vap_svc_event_none,NULL);
                }
            }
        } else {
            wifi_util_info_print(WIFI_MGR, "%s:%d: Received radio config for radio %u is same, not applying\n", __func__, __LINE__, mgr_radio_data->vaps.radio_index);
        }
    }
    return RETURN_OK;
}

int webconfig_hal_single_radio_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_decoded_data_t *data,
    webconfig_subdoc_type_t doc_type)
{
    unsigned int j;
    rdk_wifi_radio_t *radio_data, *mgr_radio_data;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    bool found_radio_index = false;
    int ret;
    int is_changed = 0;
    bool is_radio_6g_modified = false;
    vap_svc_t *pub_svc = NULL;
#if defined(FEATURE_SUPPORT_ECOPOWERDOWN)
    bool old_ecomode = false;
    bool new_ecomode = false;
#endif
    int radio_index = -1;

    switch (doc_type) {
    case webconfig_subdoc_type_radio_24G:
        radio_index = 0;
        break;
    case webconfig_subdoc_type_radio_5G:
        radio_index = 1;
        break;
    case webconfig_subdoc_type_radio_6G:
        radio_index = 2;
        break;
    default:
        // Invalid doc_type return err
        wifi_util_error_print(WIFI_MGR, "%s:%d Invalid doc_type:%d\n", __func__, __LINE__,
            doc_type);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_MGR, "%s:%d Selected Radio Index:%d for doc_type:%d\n", __func__,
        __LINE__, radio_index, doc_type);

    // apply the radio and vap data
    radio_data = &data->radios[radio_index];

    for (j = 0; j < getNumberRadios(); j++) {
        mgr_radio_data = &mgr->radio_config[j];
        if (mgr_radio_data->vaps.radio_index == radio_data->vaps.radio_index) {
            found_radio_index = true;
            break;
        }
    }

    if (found_radio_index == false) {
        wifi_util_error_print(WIFI_MGR, "%s:%d Radio with index:%d for doc_type:%d not found\n",
            __func__, __LINE__, radio_index, doc_type);
        return RETURN_ERR;
    }

    if (is_radio_band_5G(radio_data->oper.band) &&
        is_radio_feat_config_changed(mgr_radio_data, radio_data)) {
        // Not required currently for 2.4GHz, can be added later for 5GH and 6G after support is
        // added
        is_changed = 1;
        wifi_util_dbg_print(WIFI_MGR, "%s:%d Tscan:%lu, Nscan:%lu, Tidle:%lu \n", __func__,
            __LINE__, radio_data->feature.OffChanTscanInMsec, radio_data->feature.OffChanNscanInSec,
            radio_data->feature.OffChanTidleInSec);
    }

    if ((is_radio_param_config_changed(&mgr_radio_data->oper, &radio_data->oper) == true)) {
        // radio data changed apply
        is_changed = 1;
        if (IS_CHANGED(mgr_radio_data->oper.enable, radio_data->oper.enable) &&
            is_6g_supported_device(&mgr->hal_cap.wifi_prop)) {
            wifi_util_info_print(WIFI_MGR,
                "Radio enable field is modified from mgr_radio_data->oper->enable=%d and "
                "radio_data->oper->enable=%d\n",
                mgr_radio_data->oper.enable, radio_data->oper.enable);
            is_radio_6g_modified = true;
        }
        wifi_util_info_print(WIFI_MGR,
            "%s:%d: Change detected in received radio config, applying new configuration for "
            "radio: %s\n",
            __func__, __LINE__, radio_data->name);
        radio_param_config_changed_event_logging(&mgr_radio_data->oper, &radio_data->oper,
            radio_data->name);
        print_wifi_hal_radio_data(WIFI_WEBCONFIG, "old", radio_index, &mgr_radio_data->oper);
        print_wifi_hal_radio_data(WIFI_WEBCONFIG, "New", radio_index, &radio_data->oper);

        // Optimizer will try to change, channel on current STA along with parent change, So it
        // shouldn't skip for pods.
        if (ctrl->network_mode == rdk_dev_mode_type_ext) {
            vap_svc_t *ext_svc;
            ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
            if (ext_svc != NULL) {
                vap_svc_ext_t *ext;
                ext = &ext_svc->u.ext;
                unsigned int connected_radio_index = 0;
                connected_radio_index = get_radio_index_for_vap_index(ext_svc->prop,
                    ext->connected_vap_index);
                if ((ext->conn_state == connection_state_connected) &&
                    (connected_radio_index == mgr_radio_data->vaps.radio_index) &&
                    (mgr_radio_data->oper.channel != radio_data->oper.channel)) {
                    start_wifi_sched_timer(mgr_radio_data->vaps.radio_index, ctrl, wifi_csa_sched);
                    ext_svc->event_fn(ext_svc, wifi_event_type_webconfig,
                        wifi_event_webconfig_set_data, vap_svc_event_none, &radio_data->oper);
                    // driver does not change channel in STA connected state therefore skip
                    // wifi_hal_setRadioOperatingParameters and update channel on disconnection/CSA
                    return RETURN_OK;
                }
            }
        }
#if defined(FEATURE_SUPPORT_ECOPOWERDOWN)
        // Save the ECO mode state before update to the DB
        old_ecomode = mgr_radio_data->oper.EcoPowerDown;
        new_ecomode = radio_data->oper.EcoPowerDown;
        if (old_ecomode != new_ecomode) {
            radio_data->oper.enable = ((new_ecomode) ? false : true);
            wifi_util_info_print(WIFI_MGR,
                "%s:%d:Changing radio enable status:radio_data->oper.enable= %d\n", __func__,
                __LINE__, radio_data->oper.enable);
        }
#endif // defined (FEATURE_SUPPORT_ECOPOWERDOWN)
        wifi_util_dbg_print(WIFI_WEBCONFIG, "[%s]:WIFI RFC OW CORE THREAD DISABLED \r\n",
            __FUNCTION__);

        if (wifi_radio_operationParam_validation(&mgr->hal_cap, &radio_data->oper) != RETURN_OK) {
            wifi_util_error_print(WIFI_MGR, "%s:%d: failed to validate %s parameters\n", __func__,
                __LINE__, radio_data->name);
            return RETURN_ERR;
        }

        ret = wifi_hal_setRadioOperatingParameters(mgr_radio_data->vaps.radio_index,
            &radio_data->oper);

        if (ret != RETURN_OK) {
            wifi_util_error_print(WIFI_MGR, "%s:%d: failed to apply\n", __func__, __LINE__);
            return RETURN_ERR;
        }
        wifi_util_dbg_print(WIFI_MGR, "%s:%d: config applied.\n", __func__, __LINE__);

        start_wifi_sched_timer(mgr_radio_data->vaps.radio_index, ctrl, wifi_radio_sched);

        if (is_csa_sched_timer_trigger(mgr_radio_data->oper, radio_data->oper) == true) {
            start_wifi_sched_timer(mgr_radio_data->vaps.radio_index, ctrl, wifi_csa_sched);
        }
    }

    if (is_changed) {
        // write the value to database
#ifndef LINUX_VM_PORT
        wifidb_update_wifi_radio_config(mgr_radio_data->vaps.radio_index, &radio_data->oper,
            &radio_data->feature);
#else
        // Update the cache in case of Linux targets
        memcpy(&mgr_radio_data->oper, &radio_data->oper, sizeof(wifi_radio_operationParam_t));
#endif

#if defined(FEATURE_SUPPORT_ECOPOWERDOWN)
        // Upload the telemetry marker and reboot the device
        // only if there is a change in the DM Device.WiFi.Radio.{i}.X_RDK_EcoPowerDown
        wifi_util_info_print(WIFI_MGR, "%s:%d: oldEco = %d  newEco = %d\n", __func__, __LINE__,
            old_ecomode, new_ecomode);
        if (old_ecomode != new_ecomode) {
            // write the value to database and reboot
            ecomode_telemetry_update_and_reboot(radio_index, new_ecomode);
        }
#endif // defined (FEATURE_SUPPORT_ECOPOWERDOWN)
        if (is_radio_6g_modified) {
            pub_svc = get_svc_by_type(ctrl, vap_svc_type_public);
            if (pub_svc->event_fn != NULL) {
                pub_svc->event_fn(pub_svc, wifi_event_type_command, wifi_event_type_xfinity_rrm,
                    vap_svc_event_none, NULL);
            }
        }
    } else {
        wifi_util_info_print(WIFI_MGR,
            "%s:%d: Received radio config for radio %u is same, not applying\n", __func__, __LINE__,
            mgr_radio_data->vaps.radio_index);
    }
    return RETURN_OK;
}

int push_data_to_apply_pending_queue(webconfig_subdoc_data_t *data)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    webconfig_subdoc_data_t *temp_data;
    temp_data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (temp_data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Unable to allocate memory for subdoc_data type:%d\n", __func__, __LINE__, data->type);
        return RETURN_ERR;
    }
    memcpy(temp_data, data, sizeof(webconfig_subdoc_data_t));
    temp_data->u.encoded.raw = strdup(data->u.encoded.raw);
    queue_push(ctrl->vif_apply_pending_queue, temp_data);
    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_data_to_apply_pending_queue, data);
    return RETURN_OK;
}

void webconfig_analytic_event_data_to_hal_apply(webconfig_subdoc_data_t *data)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_data_to_hal_apply, data);
    return;
}

webconfig_error_t webconfig_ctrl_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data)
{
    int ret = RETURN_OK;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    vap_svc_t  *pub_svc = NULL;
    wifi_ctrl_webconfig_state_t conf_state_pending;
    wifi_ctrl_webconfig_state_t radio_state_pending;

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
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
                    ret = webconfig_hal_radio_apply(ctrl, &data->u.decoded);

                }
            }
        break;

        case webconfig_subdoc_type_private:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_private_cfg_rsp_pending) {
                    ctrl->webconfig_state  &= ~ctrl_webconfig_state_vap_private_cfg_rsp_pending;
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= ctrl_webconfig_state_vap_private_cfg_rsp_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
                    ret = webconfig_hal_private_vap_apply(ctrl, &data->u.decoded);
                    if (ret != RETURN_OK) {
                        static uint8_t max_re_apply_retry = 0;
                        if (max_re_apply_retry < MAX_VAP_RE_CFG_APPLY_RETRY) {
                            if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                                wifi_util_error_print(WIFI_WEBCONFIG, "%s:%d vap subdoc pending queue"
                                    " is failed\n", __func__, __LINE__);
                                return webconfig_error_apply;
                            }
                            max_re_apply_retry++;
                        } else {
                            max_re_apply_retry = 0;
                        }
                        // we will improve this code later.
                        // Beause this is not sending proper error code.
                        ret = RETURN_OK;
                    }
                }
            }
            //This is for captive_portal_check for private SSID when defaults modified
            captive_portal_check();
            break;

        case webconfig_subdoc_type_home:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_home_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_home_cfg_rsp_pending;
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= ctrl_webconfig_state_vap_home_cfg_rsp_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
                    ret = webconfig_hal_home_vap_apply(ctrl, &data->u.decoded);
                }
            }
        break;

        case webconfig_subdoc_type_xfinity:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_xfinity_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_xfinity_cfg_rsp_pending;
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= ctrl_webconfig_state_vap_xfinity_cfg_rsp_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
                    ret = webconfig_hal_xfinity_vap_apply(ctrl, &data->u.decoded);
                    bool status = ((ret == RETURN_OK) ? true : false);
                    hotspot_cfg_sem_signal(status);
                    wifi_util_info_print(WIFI_CTRL,":%s:%d xfinity blob cfg status:%d\n", __func__, __LINE__, ret);
                    webconfig_cac_apply(ctrl, &data->u.decoded);
                    if (is_6g_supported_device((&(get_wifimgr_obj())->hal_cap.wifi_prop))) {
                        wifi_util_info_print(WIFI_CTRL,"6g supported device add rnr of 6g\n");
                        pub_svc = get_svc_by_type(ctrl, vap_svc_type_public);
                        if (pub_svc->event_fn != NULL) {
                             pub_svc->event_fn(pub_svc, wifi_event_type_command, wifi_event_type_xfinity_rrm,
                             vap_svc_event_none,NULL);
                        }
                    }
                }
            }
        break;

        case webconfig_subdoc_type_lnf:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_lnf_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_lnf_cfg_rsp_pending;
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= ctrl_webconfig_state_vap_lnf_cfg_rsp_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
                    ret = webconfig_hal_lnf_vap_apply(ctrl, &data->u.decoded);
                }
            }
        break;

        case webconfig_subdoc_type_mesh:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_mesh_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_mesh_cfg_rsp_pending;
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_cfg_rsp_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
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
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
                    ret = webconfig_hal_mesh_sta_vap_apply(ctrl, &data->u.decoded);
                }
            }
            break;


        case webconfig_subdoc_type_mesh_backhaul:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending;
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_backhaul_cfg_rsp_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
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
            }
            break;

        case webconfig_subdoc_type_mesh_backhaul_sta:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_mesh_backhaul_sta_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_mesh_backhaul_sta_cfg_rsp_pending;
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= ctrl_webconfig_state_vap_mesh_backhaul_sta_cfg_rsp_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
                    ret = webconfig_hal_mesh_sta_vap_apply(ctrl, &data->u.decoded);
                    if (ret != RETURN_OK) {
                        wifi_util_error_print(WIFI_MGR, "%s:%d: mesh webconfig subdoc failed\n", __func__, __LINE__);
                        return webconfig_error_apply;
                    }
                }
            }
            break;

        case webconfig_subdoc_type_mac_filter:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_macfilter_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_macfilter_cfg_rsp_pending;
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
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
        case webconfig_subdoc_type_blaster:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                /* If Device is operating in POD Mode, send the status to cloud */
                if (ctrl->network_mode == rdk_dev_mode_type_ext) {
                    if (ctrl->webconfig_state & ctrl_webconfig_state_blaster_cfg_init_rsp_pending) {
                        wifi_util_info_print(WIFI_CTRL, "%s:%d: Blaster Status updated as new\n", __func__, __LINE__);
                        ctrl->webconfig_state &= ~ctrl_webconfig_state_blaster_cfg_init_rsp_pending;
                        ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                    } else if (ctrl->webconfig_state & ctrl_webconfig_state_blaster_cfg_complete_rsp_pending) {
                        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Blaster Status updated as complete\n", __func__, __LINE__);
                        ctrl->webconfig_state &= ~ctrl_webconfig_state_blaster_cfg_complete_rsp_pending;
                        ret = webconfig_bus_apply(ctrl, &data->u.encoded);

                    }
                } else if (ctrl->network_mode == rdk_dev_mode_type_gw) {
                    ctrl->webconfig_state &= ~(ctrl_webconfig_state_blaster_cfg_init_rsp_pending | ctrl_webconfig_state_blaster_cfg_complete_rsp_pending);
                    wifi_util_error_print(WIFI_CTRL, "%s:%d: Device is in GW Mode. No need to send blaster status\n", __func__, __LINE__);
                }
            } else {
                ret = webconfig_blaster_apply(ctrl, &data->u.decoded);
            }
            break;

        case webconfig_subdoc_type_harvester:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: havester webconfig subdoc\n", __func__, __LINE__);
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                wifi_util_error_print(WIFI_MGR, "%s:%d: Not expected publish of havester webconfig subdoc\n", __func__, __LINE__);
            }
            break;

        case webconfig_subdoc_type_cac:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: cac webconfig subdoc\n", __func__, __LINE__);
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                wifi_util_error_print(WIFI_MGR, "%s:%d: Not expected publish of cac webconfig subdoc\n", __func__, __LINE__);
            } else {
                ret = webconfig_cac_apply(ctrl, &data->u.decoded);
            }
            break;

        case webconfig_subdoc_type_wifi_config:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: global webconfig subdoc\n", __func__, __LINE__);
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_wifi_config_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_wifi_config_cfg_rsp_pending;
                    wifi_util_info_print(WIFI_MGR, "%s:%d: Publish of global wifi webconfig subdoc\n", __func__, __LINE__);
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_wifi_config_cfg_rsp_pending;
                ret = webconfig_global_config_apply(ctrl, &data->u.decoded);
            }
            break;

        case webconfig_subdoc_type_associated_clients:
            wifi_util_dbg_print(WIFI_MGR, "%s:%d: associated clients webconfig subdoc\n", __func__,
                __LINE__);
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state &
                    ctrl_webconfig_state_associated_clients_cfg_rsp_pending) {
                    ctrl->webconfig_state &=
                        ~ctrl_webconfig_state_associated_clients_cfg_rsp_pending;
                    ret = webconfig_client_notify_apply(ctrl, &data->u.encoded);
                } else if (ctrl->webconfig_state &
                    ctrl_webconfig_state_associated_clients_full_cfg_rsp_pending) {
                    ctrl->webconfig_state &=
                        ~ctrl_webconfig_state_associated_clients_full_cfg_rsp_pending;
                    ret = webconfig_client_notify_apply(ctrl, &data->u.encoded);
                }
            } else {
                wifi_util_error_print(WIFI_MGR,
                    "%s:%d: Not expected apply to associated clients webconfig subdoc\n", __func__,
                    __LINE__);
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

        case webconfig_subdoc_type_steering_config:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                //Not Applicable
            } else {
                wifi_util_dbg_print(WIFI_MGR, "%s:%d: steering config subdoc\n", __func__, __LINE__);
                ret = webconfig_steering_config_apply(ctrl, &data->u.decoded);
                if (ret != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_MGR, "%s:%d: steering_config failed\n", __func__, __LINE__);
                    return webconfig_error_apply;
                }
            }
            break;

        case webconfig_subdoc_type_stats_config:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                //Not Applicable
            } else {
                wifi_util_dbg_print(WIFI_MGR, "%s:%d: stats config subdoc\n", __func__, __LINE__);
#if SM_APP
                wifi_util_dbg_print(WIFI_MGR, "%s:%d: sending config for handling by sm app\n", __func__, __LINE__);
                ret = apps_mgr_sm_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_set_data_ovsm, (void *)data);
#else
                ret = webconfig_stats_config_apply(ctrl, &data->u.decoded);
#endif
                if (ret != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_MGR, "%s:%d: stats config failed\n", __func__, __LINE__);
                    return webconfig_error_apply;
                }
            }
            break;

        case webconfig_subdoc_type_steering_clients:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_steering_clients_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_steering_clients_rsp_pending;
                    //TBD : to uncomment as part of integration of steering clients hal wrapper
                    //ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                ctrl->webconfig_state |= ctrl_webconfig_state_steering_clients_rsp_pending;
                wifi_util_dbg_print(WIFI_MGR, "%s:%d: steering clients subdoc\n", __func__, __LINE__);
                ret = webconfig_steering_clients_apply(ctrl, &data->u.decoded);
                if (ret != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_MGR, "%s:%d: steering clients subdoc failed\n", __func__, __LINE__);
                    return webconfig_error_apply;
                }
            }
            break;

        case webconfig_subdoc_type_vif_neighbors:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                //Not Applicable
            } else {
                wifi_util_dbg_print(WIFI_MGR, "%s:%d: vif neighbors subdoc\n", __func__, __LINE__);
                ret = webconfig_vif_neighbors_apply(ctrl, &data->u.decoded);
                if (ret != RETURN_OK) {
                    wifi_util_dbg_print(WIFI_MGR, "%s:%d: vif neighbors failed\n", __func__, __LINE__);
                    return webconfig_error_apply;
                }
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
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                } else if (ctrl->webconfig_state & ctrl_webconfig_state_trigger_dml_thread_data_update_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_trigger_dml_thread_data_update_pending;
                    ret = webconfig_bus_apply_for_dml_thread_update(ctrl, &data->u.encoded);
                }

            } else {
                wifi_util_error_print(WIFI_MGR, "%s:%d: Not expected apply to dml webconfig subdoc\n", __func__, __LINE__);
            }
#endif
            break;

        case webconfig_subdoc_type_vap_24G:
        case webconfig_subdoc_type_vap_5G:
        case webconfig_subdoc_type_vap_6G:
            if (doc->type == webconfig_subdoc_type_vap_24G) {
                conf_state_pending = ctrl_webconfig_state_vap_24G_cfg_rsp_pending;
            } else if (doc->type == webconfig_subdoc_type_vap_5G) {
                conf_state_pending = ctrl_webconfig_state_vap_5G_cfg_rsp_pending;
            } else {
                conf_state_pending = ctrl_webconfig_state_vap_6G_cfg_rsp_pending;
            }
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & conf_state_pending) {
                    ctrl->webconfig_state &= ~conf_state_pending;
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= conf_state_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
                    ret = webconfig_hal_multivap_apply(ctrl, &data->u.decoded, doc->type);
                }
            }
            // This is for captive_portal_check for private SSID when defaults modified
            captive_portal_check();
            break;

        case webconfig_subdoc_type_radio_24G:
        case webconfig_subdoc_type_radio_5G:
        case webconfig_subdoc_type_radio_6G:
            if (doc->type == webconfig_subdoc_type_radio_24G) {
                radio_state_pending = ctrl_webconfig_state_radio_24G_rsp_pending;
            } else if (doc->type == webconfig_subdoc_type_radio_5G) {
                radio_state_pending = ctrl_webconfig_state_radio_5G_rsp_pending;
            } else {
                radio_state_pending = ctrl_webconfig_state_radio_6G_rsp_pending;
            }
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & radio_state_pending) {
                    ctrl->webconfig_state &= ~radio_state_pending;
                    ret = webconfig_bus_apply(ctrl, &data->u.encoded);
                }
            } else {
                if (check_wifi_csa_sched_timeout_active_status(ctrl) == true) {
                    if (push_data_to_apply_pending_queue(data) != RETURN_OK) {
                        return webconfig_error_apply;
                    }
                } else {
                    ctrl->webconfig_state |= radio_state_pending;
                    webconfig_analytic_event_data_to_hal_apply(data);
                    ret = webconfig_hal_single_radio_apply(ctrl, &data->u.decoded, doc->type);

                }
            }
        break;

        default:
            break;
    }

    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: new webconfig_state:%02x\n",
                                        __func__, __LINE__, ctrl->webconfig_state);

    return ((ret == RETURN_OK) ? webconfig_error_none:webconfig_error_apply);
}

// register subdocs with webconfig_framework
int register_with_webconfig_framework()
{
    if(webconfig_single_doc_init() != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to register single subdocs with framework\n", __func__);
        return RETURN_ERR;
    }

    if(webconfig_multi_doc_init() != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to register multicomp subdocs with framework\n", __func__);
        return RETURN_ERR;
    }

    wifi_util_info_print(WIFI_CTRL, "%s: Done Registering\n", __func__);
    return RETURN_OK;
}

