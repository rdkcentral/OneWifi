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
#include "const.h"
#define  WBCFG_MULTI_COMP_SUPPORT 1
#include "webconfig_framework.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_stubs.h"
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
#ifdef CCSP_COMMON
#include "ccsp_WifiLog_wrapper.h"
#endif

#define OW_CONF_BARRIER_TIMEOUT_MSEC (60 * 1000)
#define IS_CHANGED(old, new) ((old != new)? wifi_util_dbg_print(WIFI_CTRL,"%s:Changed param %s: [%d] -> [%d].\n",__func__,#old,old,new),1: 0)
#define IS_STR_CHANGED(old, new, size) ((strncmp(old, new, size) != 0)? wifi_util_dbg_print(WIFI_CTRL,"%s:Changed param %s: [%s] -> [%s].\n",__func__,#old,old,new), 1 : 0)
#define IS_BIN_CHANGED(old, new, size) ((memcmp(old, new, size) != 0)? wifi_util_dbg_print(WIFI_CTRL,"%s:Changed param %s.\n",__func__,#old), 1 : 0)

/* local functions */
static int decode_ssid_blob(wifi_vap_info_t *vap_info, cJSON *ssid,char *bridge_name,bool managed_wifi, pErr execRetVal);
static int decode_security_blob(wifi_vap_info_t *vap_info, cJSON *security, pErr execRetVal);
static int update_vap_info(void *data, wifi_vap_info_t *vap_info, pErr execRetVal);
static int update_vap_info_managed_guest(void *data, wifi_vap_info_t *vap_info, char *bridge_name,bool connected_building_enabled, pErr execRetVal);
static int update_vap_info_managed_xfinity(void *data, wifi_vap_info_t *vap_info,pErr execRetVal);
static int update_vap_info_with_blob_info(void *blob, webconfig_subdoc_data_t *data, const char *vap_prefix, bool managed_wifi, pErr execRetVal);
static int push_blob_data(webconfig_subdoc_data_t *data, webconfig_subdoc_type_t subdoc_type);
static pErr create_execRetVal(void);
static pErr private_home_exec_common_handler(void *blob, const char *vap_prefix, webconfig_subdoc_type_t subdoc_type);
static int validate_private_home_ssid_param(char *str, pErr execRetVal);
static int validate_private_home_security_param(char *mode_enabled, char*encryption_method, pErr execRetVal);
struct ow_conf_vif_config_cb_arg
{
    rdk_wifi_vap_info_t *rdk_vap_info;
    wifi_vap_info_t *vap_info;
};

void print_wifi_hal_radio_data(wifi_dbg_type_t log_file_type, char *prefix, unsigned int radio_index, wifi_radio_operationParam_t *radio_config)
{
    wifi_util_info_print(log_file_type, "%s:%d: [%s] Wifi_Radio[%d]_Config data: enable = %d\n band = %d\n autoChannelEnabled = %d\n op_class = %d\n channel = %d\n numSecondaryChannels = %d\n channelSecondary = %s\n channelWidth = %d\n variant = %d\n csa_beacon_count = %d\n countryCode = %d\n DCSEnabled = %d\n dtimPeriod = %d\n beaconInterval = %d\n operatingClass = %d\n basicDataTransmitRates = %d\n operationalDataTransmitRates = %d\n fragmentationThreshold = %d\n guardInterval = %d\n transmitPower = %d\n rtsThreshold = %d\n factoryResetSsid = %d\n radioStatsMeasuringRate = %d\n radioStatsMeasuringInterval = %d\n ctsProtection = %d\n obssCoex = %d\n stbcEnable = %d\n greenFieldEnable = %d\n userControl = %d\n adminControl = %d\n chanUtilThreshold = %d\n chanUtilSelfHealEnable = %d\n EcoPowerDown = %d\r\n", __func__, __LINE__, prefix, radio_index, radio_config->enable, radio_config->band, radio_config->autoChannelEnabled, radio_config->op_class, radio_config->channel, radio_config->numSecondaryChannels, radio_config->channelSecondary, radio_config->channelWidth, radio_config->variant, radio_config->csa_beacon_count, radio_config->countryCode, radio_config->DCSEnabled, radio_config->dtimPeriod, radio_config->beaconInterval, radio_config->operatingClass, radio_config->basicDataTransmitRates, radio_config->operationalDataTransmitRates, radio_config->fragmentationThreshold, radio_config->guardInterval, radio_config->transmitPower, radio_config->rtsThreshold, radio_config->factoryResetSsid, radio_config->radioStatsMeasuringRate, radio_config->radioStatsMeasuringInterval, radio_config->ctsProtection, radio_config->obssCoex, radio_config->stbcEnable, radio_config->greenFieldEnable, radio_config->userControl, radio_config->adminControl, radio_config->chanUtilThreshold, radio_config->chanUtilSelfHealEnable, radio_config->EcoPowerDown);
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
        wifi_util_info_print(log_file_type, "%s:%d: [%s] Mesh VAP Config Data: radioindex=%d\n vap_name=%s\n vap_index=%d\n ssid=%s\n bssid:%s\n enabled=%d\n conn_status=%d\n scan_period=%d\n scan_channel=%d\n scan_band =%d\n mac=%s\n exists=%d\r\n",__func__, __LINE__, prefix, l_vap_info->radio_index, l_vap_info->vap_name, l_vap_info->vap_index, l_sta_info->ssid, l_bssid_str, l_sta_info->enabled, l_sta_info->conn_status, l_sta_info->scan_params.period, l_sta_info->scan_params.channel.channel, l_sta_info->scan_params.channel.band, mac_str, l_rdk_vap_info->exists);
    } else {
        to_mac_str(l_bss_info->bssid, l_bssid_str);
        wifi_util_info_print(log_file_type, "%s:%d: [%s] VAP Config Data: radioindex=%d\n vap_name=%s\n vap_index=%d\n ssid=%s\n enabled=%d\n ssid_advertisement_enable=%d\n isolation_enabled=%d\n mgmt_power_control=%d\n bss_max_sta =%d\n bss_transition_activated=%d\n nbr_report_activated=%d\n rapid_connect_enabled=%d\n rapid_connect_threshold=%d\n vap_stats_enable=%d\n mac_filter_enabled =%d\n mac_filter_mode=%d\n wmm_enabled=%d\n uapsd_enabled =%d\n beacon_rate=%d\n bridge_name=%s\n mac=%s\n wmm_noack = %d\n wep_key_length = %d\n bss_hotspot = %d\n wps_push_button = %d\n beacon_rate_ctl =%s\n network_initiated_greylist=%d\n mcast2ucast=%d\n exists=%d\r\n",__func__, __LINE__, prefix, l_vap_info->radio_index, l_vap_info->vap_name, l_vap_info->vap_index, l_bss_info->ssid, l_bss_info->enabled, l_bss_info->showSsid, l_bss_info->isolation, l_bss_info->mgmtPowerControl, l_bss_info->bssMaxSta, l_bss_info->bssTransitionActivated, l_bss_info->nbrReportActivated, l_bss_info->rapidReconnectEnable, l_bss_info->rapidReconnThreshold, l_bss_info->vapStatsEnable, l_bss_info->mac_filter_enable, l_bss_info->mac_filter_mode, l_bss_info->wmm_enabled, l_bss_info->UAPSDEnabled, l_bss_info->beaconRate, l_vap_info->bridge_name, l_bssid_str, l_bss_info->wmmNoAck, l_bss_info->wepKeyLength, l_bss_info->bssHotspot, l_bss_info->wpsPushButton, l_bss_info->beaconRateCtl, l_bss_info->network_initiated_greylist, l_bss_info->mcast2ucast, l_rdk_vap_info->exists);
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
    wifi_util_info_print(log_file_type,"%s:%d: [%s] Wifi_wps_Config vap_index=%d\n enable:%d\n methods:%d\r\n", __func__, __LINE__, prefix, vap_index, l_wifi_wps->enable, l_wifi_wps->methods);
}

#define WEBCONFIG_DML_SUBDOC_STATES (ctrl_webconfig_state_vap_all_cfg_rsp_pending| \
                                     ctrl_webconfig_state_macfilter_cfg_rsp_pending| \
                                     ctrl_webconfig_state_factoryreset_cfg_rsp_pending)

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
                wifi_util_error_print(WIFI_CTRL,"%s:%d NULL rdk_vap_info pointer\n", __func__, __LINE__);
                return RETURN_ERR;
            }
            tmp_rdk_vap_info->associated_devices_diff_map = NULL;
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

int webconfig_analyze_pending_states(wifi_ctrl_t *ctrl)
{
    static int pending_state = ctrl_webconfig_state_max;
    webconfig_subdoc_type_t type = webconfig_subdoc_type_unknown;

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
            type = webconfig_subdoc_type_mesh_sta;
            webconfig_send_vap_subdoc_status(ctrl, type);
        break;
        case ctrl_webconfig_state_vap_mesh_sta_cfg_rsp_pending:
            if (check_wifi_vap_sched_timeout_active_status(ctrl, isVapSTAMesh) == false) {
                type = webconfig_subdoc_type_mesh_sta;
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
        case ctrl_webconfig_state_blaster_cfg_complete_rsp_pending:
                /* Once the blaster triggered successfully, update the status as completed and pass it to OVSM */
                mgr->blaster_config_global.Status = blaster_state_completed;
                webconfig_send_blaster_status(ctrl);
            break;
        case ctrl_webconfig_state_steering_clients_rsp_pending:
            webconfig_send_steering_clients_status(ctrl);
            break;
        case ctrl_webconfig_state_trigger_dml_thread_data_update_pending:
            type = webconfig_subdoc_type_dml;
            webconfig_send_dml_subdoc_status(ctrl);
            break;
        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d - default pending subdoc status:0x%x\r\n", __func__, __LINE__, (ctrl->webconfig_state & CTRL_WEBCONFIG_STATE_MASK));
            break;
    }

#if CCSP_COMMON
    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_set_status, &type);
#endif // CCSP_COMMON

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
        || (IS_STR_CHANGED(old->u.bss_info.preassoc.sixGOpInfoMinRate, new->u.bss_info.preassoc.sixGOpInfoMinRate, sizeof(old->u.bss_info.preassoc.sixGOpInfoMinRate)))) {
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
#ifdef CCSP_COMMON
    if (radio->enable) {
        CcspWifiEventTrace(("RDK_LOG_NOTICE,  WiFi radio %s is set to UP\n",name));
        if (new->u.bss_info.enabled) {
            if (IS_CHANGED(old->u.bss_info.enabled, new->u.bss_info.enabled)) {
                CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi VAP Changed to UP\n"));
            }
            if (IS_STR_CHANGED(old->u.bss_info.ssid, new->u.bss_info.ssid,sizeof(old->u.bss_info.ssid))) {
                CcspWifiEventTrace(("RDK_LOG_NOTICE, SSID Changed \n"));
            }
            if (IS_STR_CHANGED(old->u.bss_info.security.u.key.key, new->u.bss_info.security.u.key.key,sizeof(old->u.bss_info.security.u.key.key))) {
                CcspWifiEventTrace(("RDK_LOG_NOTICE, KeyPassphrase Changed \n "));
            }
            if (IS_CHANGED(old->u.bss_info.security.mode, new->u.bss_info.security.mode)) {
                switch (new->u.bss_info.security.mode) {
                    case wifi_security_mode_none:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode None is enabled\n"));
                        break;
                    case wifi_security_mode_wep_64:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WEP-64 is enabled\n"));
                        break;
                    case wifi_security_mode_wep_128:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WEP-128 is enabled\n"));
                        break;
                    case wifi_security_mode_wpa_personal:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA-Personal is enabled\n"));
                        break;
                    case wifi_security_mode_wpa2_personal:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA2-Personal is enabled\n"));
                        break;
                    case wifi_security_mode_wpa_wpa2_personal:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA-WPA2-Personal is enabled\n"));
                        break;
                    case wifi_security_mode_wpa_enterprise:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA-Enterprise is enabled\n"));
                        break;
                    case wifi_security_mode_wpa2_enterprise:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA2-Enterprise is enabled\n"));
                        break;
                    case wifi_security_mode_wpa_wpa2_enterprise:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA-WPA2-Enterprise is enabled\n"));
                        break;
                    case wifi_security_mode_wpa3_personal:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA3-Personal is enabled\n"));
                        break;
                    case wifi_security_mode_wpa3_transition:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA3-Transition is enabled\n"));
                        break;
                    case wifi_security_mode_wpa3_enterprise:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode WPA3-Enterprise is enabled\n"));
                        break;
                    case wifi_security_mode_enhanced_open:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi security mode Open is enabled\n"));
                        break;
                    default:
                        CcspWifiEventTrace(("RDK_LOG_NOTICE, Incorrect Wifi Security mode %d is enabled.\n",new->u.bss_info.security.mode));
                        break;
                }
            }
        } else {
              CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi VAP is set to down\n"));
        }
    } else {
          CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi radio %s is set to DOWN\n",name));
    }
#else
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Not Inside CCSP_COMMON macro. \n",__func__,__LINE__);
    return;
#endif
}

static bool is_vap_param_config_changed(wifi_vap_info_t *old, wifi_vap_info_t *new,
    rdk_wifi_vap_info_t *rdk_old, rdk_wifi_vap_info_t *rdk_new, bool isSta)
{
    if (IS_CHANGED(rdk_old->exists, rdk_new->exists)) {
        return true;
    }

#ifndef CCSP_COMMON
    if ((rdk_old->exists | rdk_new->exists) == false) {
        return false;
    }
#endif // CCSP_COMMON

    if (IS_CHANGED(old->vap_index, new->vap_index) ||
            IS_STR_CHANGED(old->vap_name, new->vap_name, sizeof(wifi_vap_name_t)) ||
            IS_CHANGED(old->radio_index, new->radio_index) ||
            IS_STR_CHANGED(old->bridge_name, new->bridge_name, sizeof(old->bridge_name)) ||
            IS_CHANGED(old->vap_mode, new->vap_mode)) {
        return true;
    }

    if (isSta) {
        // Ignore change of conn_status, scan_params, mac to avoid reconfiguration and disconnection
        // BSSID change is handled by event.
        if (IS_STR_CHANGED(old->u.sta_info.ssid, new->u.sta_info.ssid, sizeof(ssid_t)) ||
                IS_CHANGED(old->u.sta_info.enabled, new->u.sta_info.enabled) ||
                IS_BIN_CHANGED(&old->u.sta_info.security, &new->u.sta_info.security,
                sizeof(wifi_vap_security_t))) {
            return true;
        }
#ifndef CCSP_COMMON
        char old_bssid_str[32], new_bssid_str[32];

        if (memcmp(old->u.sta_info.bssid, new->u.sta_info.bssid, sizeof(bssid_t)) != 0) {
            uint8_mac_to_string_mac(old->u.sta_info.bssid, old_bssid_str);
            uint8_mac_to_string_mac(new->u.sta_info.bssid, new_bssid_str);
            wifi_util_info_print(WIFI_CTRL, "%s:%d: mesh sta bssid changed [%s] -> [%s]\n", __func__,
        __LINE__, old_bssid_str, new_bssid_str);
            return true;
        }
#endif
    } else {
        // Ignore bssid change to avoid reconfiguration and disconnection
        if (IS_STR_CHANGED(old->u.bss_info.ssid, new->u.bss_info.ssid,
                sizeof(old->u.bss_info.ssid)) ||
                IS_CHANGED(old->u.bss_info.enabled, new->u.bss_info.enabled) ||
                IS_CHANGED(old->u.bss_info.showSsid, new->u.bss_info.showSsid) ||
                IS_CHANGED(old->u.bss_info.isolation, new->u.bss_info.isolation) ||
                IS_CHANGED(old->u.bss_info.mgmtPowerControl, new->u.bss_info.mgmtPowerControl) ||
                IS_CHANGED(old->u.bss_info.bssMaxSta, new->u.bss_info.bssMaxSta) ||
                IS_CHANGED(old->u.bss_info.bssTransitionActivated,
                new->u.bss_info.bssTransitionActivated) ||
                IS_CHANGED(old->u.bss_info.nbrReportActivated,
                new->u.bss_info.nbrReportActivated) ||
                IS_CHANGED(old->u.bss_info.rapidReconnectEnable,
                new->u.bss_info.rapidReconnectEnable) ||
                IS_CHANGED(old->u.bss_info.rapidReconnThreshold,
                new->u.bss_info.rapidReconnThreshold) ||
                IS_CHANGED(old->u.bss_info.vapStatsEnable, new->u.bss_info.vapStatsEnable) ||
                IS_BIN_CHANGED(&old->u.bss_info.security, &new->u.bss_info.security,
                sizeof(wifi_vap_security_t)) ||
                IS_BIN_CHANGED(&old->u.bss_info.interworking, &new->u.bss_info.interworking,
                sizeof(wifi_interworking_t)) ||
                IS_CHANGED(old->u.bss_info.mac_filter_enable, new->u.bss_info.mac_filter_enable) ||
                IS_CHANGED(old->u.bss_info.mac_filter_mode, new->u.bss_info.mac_filter_mode) ||
                IS_CHANGED(old->u.bss_info.sec_changed, new->u.bss_info.sec_changed) ||
                IS_BIN_CHANGED(&old->u.bss_info.wps, &new->u.bss_info.wps, sizeof(wifi_wps_t)) ||
                IS_CHANGED(old->u.bss_info.wmm_enabled, new->u.bss_info.wmm_enabled) ||
                IS_CHANGED(old->u.bss_info.UAPSDEnabled, new->u.bss_info.UAPSDEnabled) ||
                IS_CHANGED(old->u.bss_info.beaconRate, new->u.bss_info.beaconRate) ||
                IS_CHANGED(old->u.bss_info.wmmNoAck, new->u.bss_info.wmmNoAck) ||
                IS_CHANGED(old->u.bss_info.wepKeyLength, new->u.bss_info.wepKeyLength) ||
                IS_CHANGED(old->u.bss_info.bssHotspot, new->u.bss_info.bssHotspot) ||
                IS_CHANGED(old->u.bss_info.wpsPushButton, new->u.bss_info.wpsPushButton) ||
                IS_CHANGED(old->u.bss_info.connected_building_enabled, new->u.bss_info.connected_building_enabled) ||
                IS_BIN_CHANGED(&old->u.bss_info.beaconRateCtl, &new->u.bss_info.beaconRateCtl,
                sizeof(old->u.bss_info.beaconRateCtl)) ||
                IS_CHANGED(old->u.bss_info.network_initiated_greylist,
                new->u.bss_info.network_initiated_greylist) ||
                IS_CHANGED(old->u.bss_info.mcast2ucast, new->u.bss_info.mcast2ucast) ||
                IS_STR_CHANGED(old->u.bss_info.preassoc.basic_data_transmit_rates, new->u.bss_info.preassoc.basic_data_transmit_rates, sizeof(old->u.bss_info.preassoc.basic_data_transmit_rates)) ||
                IS_STR_CHANGED(old->u.bss_info.preassoc.operational_data_transmit_rates, new->u.bss_info.preassoc.operational_data_transmit_rates, sizeof(old->u.bss_info.preassoc.operational_data_transmit_rates)) ||
                IS_STR_CHANGED(old->u.bss_info.preassoc.supported_data_transmit_rates ,new->u.bss_info.preassoc.supported_data_transmit_rates, sizeof(old->u.bss_info.preassoc.supported_data_transmit_rates)) ||
                IS_STR_CHANGED(old->u.bss_info.preassoc.minimum_advertised_mcs, new->u.bss_info.preassoc.minimum_advertised_mcs, sizeof(old->u.bss_info.preassoc.minimum_advertised_mcs)) ||
                IS_STR_CHANGED(old->u.bss_info.preassoc.sixGOpInfoMinRate, new->u.bss_info.preassoc.sixGOpInfoMinRate, sizeof(old->u.bss_info.preassoc.sixGOpInfoMinRate))) {
            return true;
        }
    }
    return false;
}

#ifdef CCSP_COMMON
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
#endif

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
#if CCSP_COMMON
    char update_status[128];
    public_vaps_data_t pub;
#endif // CCSP_COMMON
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
#if CCSP_COMMON
        // STA BSSID change is handled by event to avoid disconnection.
        webconfig_send_sta_bssid_change_event(ctrl, mgr_vap_info, vap_info);

        // Ignore exists flag change because STA interfaces always enabled in HAL. This allows to
        // avoid redundant reconfiguration with STA disconnection.
        // For pods, STA is just like any other AP interface, deletion is allowed.
        if (ctrl->network_mode == rdk_dev_mode_type_ext && isVapSTAMesh(tgt_vap_index)) {
            mgr_rdk_vap_info->exists = rdk_vap_info->exists;
        }
#endif

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
                if (memcmp(&mgr_vap_info->u.bss_info.wps, &vap_info->u.bss_info.wps, sizeof(wifi_wps_t))) {
                    print_wifi_hal_vap_wps_data(WIFI_WEBCONFIG, "Old", tgt_vap_index, &mgr_vap_info->u.bss_info.wps);
                    print_wifi_hal_vap_wps_data(WIFI_WEBCONFIG, "New", tgt_vap_index, &vap_info->u.bss_info.wps);
                }
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
                stop_wifi_sched_timer(vap_info->vap_index, ctrl, wifi_vap_sched);
                free(p_tgt_vap_map);
                p_tgt_vap_map = NULL;
                return RETURN_ERR;
            }

#if CCSP_COMMON
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
#endif // CCSP_COMMON
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
                // cac data changed apply
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
    new->op_class = old->op_class;

    if (IS_CHANGED(old->enable,new->enable)) return true;
    if (IS_CHANGED(old->band,new->band)) return true;
    if (IS_CHANGED(old->autoChannelEnabled,new->autoChannelEnabled)) return true;
    if (IS_CHANGED(old->op_class,new->op_class)) return true;
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

    return false;
}

#if defined (FEATURE_SUPPORT_ECOPOWERDOWN)
void ecomode_telemetry_update_and_reboot(unsigned int index, bool active)
{
    CHAR eventName[32] = {0};
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    snprintf(eventName, sizeof(eventName), "WIFI_RADIO_%d_ECOPOWERMODE", index + 1);
    get_stubs_descriptor()->t2_event_s_fn(eventName, active ? "Active" : "Inactive");
    wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: EcoPowerDown telemetry: %s %s uploaded for Radio %d\n", __FUNCTION__, eventName, active ? "Active" : "Inactive", index + 1);
    reboot_device(ctrl);
}
#endif // defined (FEATURE_SUPPORT_ECOPOWERDOWN)


void radio_param_config_changed_event_logging(wifi_radio_operationParam_t *old , wifi_radio_operationParam_t *new,char name[16])
{
#ifdef CCSP_COMMON
    if(IS_CHANGED(old->enable,new->enable))
    {
        CcspWifiEventTrace(("RDK_LOG_NOTICE, Wifi radio %s is set to %s\n",name,((new->enable==1)?"UP":"DOWN")));
    }
#else
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Not Inside CCSP_COMMON Macro. \n",__func__,__LINE__);
    return;
#endif
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
#ifdef CCSP_COMMON
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
#endif // CCSP_COMMON
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
#if CCSP_COMMON
    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_data_to_apply_pending_queue, data);
#endif // CCSP_COMMON

    return RETURN_OK;
}

void webconfig_analytic_event_data_to_hal_apply(webconfig_subdoc_data_t *data)
{
#if CCSP_COMMON
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_webconfig, wifi_event_webconfig_data_to_hal_apply, data);
#endif // CCSP_COMMON
    return;
}

webconfig_error_t webconfig_ctrl_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data)
{
    int ret = RETURN_OK;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    vap_svc_t  *pub_svc = NULL;
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
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
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
                }
            }
#if CCSP_COMMON
            //This is for captive_portal_check for private SSID when defaults modified
            captive_portal_check();
#endif
            break;

        case webconfig_subdoc_type_home:
            if (data->descriptor & webconfig_data_descriptor_encoded) {
                if (ctrl->webconfig_state & ctrl_webconfig_state_vap_home_cfg_rsp_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_vap_home_cfg_rsp_pending;
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
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
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
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
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
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
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
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
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
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
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
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
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
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
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                }
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
                    //ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
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
                    ret = webconfig_rbus_apply(ctrl, &data->u.encoded);
                } else if (ctrl->webconfig_state & ctrl_webconfig_state_trigger_dml_thread_data_update_pending) {
                    ctrl->webconfig_state &= ~ctrl_webconfig_state_trigger_dml_thread_data_update_pending;
                    ret = webconfig_rbus_apply_for_dml_thread_update(ctrl, &data->u.encoded);
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
    push_event_to_ctrl_queue(blob, strlen(blob), wifi_event_type_webconfig, wifi_event_webconfig_set_data_webconfig, NULL);

    wifi_util_dbg_print(WIFI_CTRL, "%s: return success\n", __func__);
    return exec_ret_val;
}
static int validate_private_home_security_param(char *mode_enabled, char *encryption_method, pErr execRetVal)
{
     wifi_util_info_print(WIFI_CTRL,"Enter %s mode_enabled=%s,encryption_method=%s\n",__func__,mode_enabled,encryption_method);

    if ((strcmp(mode_enabled, "None") != 0) &&
        ((strcmp(encryption_method, "TKIP") != 0) && (strcmp(encryption_method, "AES") != 0) &&
        (strcmp(encryption_method, "AES+TKIP") != 0))) {
         wifi_util_error_print(WIFI_CTRL,"%s: Invalid Encryption Method \n",__FUNCTION__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Encryption Method",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }

    if (((strcmp(mode_enabled, "WPA-WPA2-Enterprise") == 0) || (strcmp(mode_enabled, "WPA-WPA2-Personal") == 0)) &&
        ((strcmp(encryption_method, "AES+TKIP") != 0) && (strcmp(encryption_method, "AES") != 0))) {
         wifi_util_error_print(WIFI_CTRL,"%s: Invalid Encryption Security Combination\n",__FUNCTION__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Encryption Security Combination",sizeof(execRetVal->ErrorMsg)-1);
        }
     return RETURN_ERR;
    }
     wifi_util_info_print(WIFI_CTRL,"%s: securityparam validation passed \n",__FUNCTION__);
    return RETURN_OK;

}
static int validate_private_home_ssid_param(char *ssid_name, pErr execRetVal)
{
    int ssid_len = 0;
    int i = 0;

     wifi_util_info_print(WIFI_CTRL,"Enter %s and ssid_name=%s\n",__func__,ssid_name);
    ssid_len = strlen(ssid_name);
    if ((ssid_len == 0) || (ssid_len > MAX_SSID_NAME_LEN)) {
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid SSID string size",sizeof(execRetVal->ErrorMsg)-1);
        }
        wifi_util_error_print(WIFI_CTRL,"%s: Invalid SSID size for ssid_name %s \n",__FUNCTION__, ssid_name);
        return RETURN_ERR;
    }

    for (i = 0; i < ssid_len; i++) {
        if (!((ssid_name[i] >= ' ') && (ssid_name[i] <= '~'))) {
            wifi_util_error_print(WIFI_CTRL,"%s: Invalid character present in SSID \n",__FUNCTION__);
            if (execRetVal) {
                strncpy(execRetVal->ErrorMsg,"Invalid character in SSID",sizeof(execRetVal->ErrorMsg)-1);
            }
            return RETURN_ERR;
        }
    }

   wifi_util_info_print(WIFI_CTRL,"%s: ssidparam validation passed \n",__FUNCTION__);
  return RETURN_OK;
}
static int decode_ssid_blob(wifi_vap_info_t *vap_info, cJSON *ssid, char *bridge_name, bool managed_wifi, pErr execRetVal)
{
    char *value;
    cJSON *param;

    wifi_util_info_print(WIFI_CTRL, "SSID blob:\n");
    param = cJSON_GetObjectItem(ssid, "SSID");
    if (param) {
        value = cJSON_GetStringValue(param);
        wifi_util_info_print(WIFI_CTRL, "   \"SSID\": %s\n", value);
        if (validate_private_home_ssid_param(value,execRetVal) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL, "SSID validation failed\n");
            return -1;
        }
        snprintf(vap_info->u.bss_info.ssid, sizeof(vap_info->u.bss_info.ssid), "%s", value);
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"SSID\"\n", __func__);
        return -1;
    }

    param = cJSON_GetObjectItem(ssid, "Enable");
    if (!param) {
       param = cJSON_GetObjectItem(ssid, "Enabled");
    }
    if (param) {
        if (cJSON_IsBool(param)) {
            vap_info->u.bss_info.enabled = cJSON_IsTrue(param) ? true : false;
            wifi_util_info_print(WIFI_CTRL, "   \"Enable\": %s\n", (vap_info->u.bss_info.enabled) ? "true" : "false");
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s: \"Enable\" is not boolean\n", __func__);
            return -1;
        }
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"Enable\"\n", __func__);
        return -1;
    }

    param = cJSON_GetObjectItem(ssid, "SSIDAdvertisementEnabled");
    if (param) {
        if (cJSON_IsBool(param)) {
            vap_info->u.bss_info.showSsid = cJSON_IsTrue(param) ? true : false;
            wifi_util_info_print(WIFI_CTRL, "   \"SSIDAdvertisementEnabled\": %s\n", (vap_info->u.bss_info.showSsid) ? "true" : "false");
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s: \"SSIDAdvertisementEnabled\" is not boolean\n", __func__);
            return -1;
        }
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"SSIDAdvertisementEnabled\"\n", __func__);
        return -1;
    }
    if (managed_wifi) {
        if (strlen(bridge_name) == 0) {
            wifi_util_dbg_print(WIFI_CTRL,"BridgeName is empty\n");
            snprintf(vap_info->bridge_name, sizeof(vap_info->bridge_name), "brlan15");
        } else {
            wifi_util_dbg_print(WIFI_CTRL,"BridgeName is %s\n",bridge_name);
            snprintf(vap_info->bridge_name, sizeof(vap_info->bridge_name), "%s", bridge_name);
        }
        param = cJSON_GetObjectItem(ssid, "BssMaxNumSta");
        if (param) {
            vap_info->u.bss_info.bssMaxSta = param->valuedouble;
            wifi_util_info_print(WIFI_CTRL, "   \"BssMax\": %d\n", vap_info->u.bss_info.bssMaxSta);
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s: missing \"BssMax\"\n", __func__);
            return -1;
        }
    }

    return 0;
}

static int decode_security_blob(wifi_vap_info_t *vap_info, cJSON *security,pErr execRetVal)
{
    char *value;
    cJSON *param;
    int pass_len =0;
    char encryption_method[128] = "";

    wifi_util_info_print(WIFI_CTRL, "Security blob:\n");
    param = cJSON_GetObjectItem(security, "Passphrase");
    if (param) {
        value = cJSON_GetStringValue(param);
        snprintf(vap_info->u.bss_info.security.u.key.key, sizeof(vap_info->u.bss_info.security.u.key.key), "%s", value);
        wifi_util_info_print(WIFI_CTRL, "   \"Passphrase\": <Masked>\n");
        pass_len = strlen(value);

    if ((pass_len < MIN_PWD_LEN) || (pass_len > MAX_PWD_LEN)) {
         wifi_util_error_print(WIFI_CTRL,"%s: Invalid Key passphrase length \n",__FUNCTION__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Passphrase length",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;

    }
    if (pass_len == 0) {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"Passphrase\"\n", __func__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Passphrase length",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }
    }
    param = cJSON_GetObjectItem(security, "EncryptionMethod");
    if (param) {
        value = cJSON_GetStringValue(param);
        wifi_util_info_print(WIFI_CTRL, "   \"EncryptionMethod\": %s\n", value);
        if (!strcmp(value, "AES")) {
            vap_info->u.bss_info.security.encr = wifi_encryption_aes;
        } else if (!strcmp(value, "AES+TKIP")) {
            vap_info->u.bss_info.security.encr = wifi_encryption_aes_tkip;
        } else if (!strcmp(value, "TKIP")) {
            vap_info->u.bss_info.security.encr = wifi_encryption_tkip;
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s: unknown \"EncryptionMethod\n: %s\n", __func__, value);
            if (execRetVal) {
                strncpy(execRetVal->ErrorMsg,"Invalid Encryption Method",sizeof(execRetVal->ErrorMsg)-1);
            }
            return RETURN_ERR;
        }
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"EncryptionMethod\"\n", __func__);
         if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Encryption Method",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }
    strcpy(encryption_method,value);

    param = cJSON_GetObjectItem(security, "ModeEnabled");
    if (!param) {
       param = cJSON_GetObjectItem(security, "Mode");
    }
    if (param) {
        value = cJSON_GetStringValue(param);
        wifi_util_info_print(WIFI_CTRL, "   \"ModeEnabled\": %s\n", value);
        if (!strcmp(value, "None")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_none;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk;
        } else if (!strcmp(value, "WPA-Personal")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_personal;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk;
        } else if (!strcmp(value, "WPA2-Personal")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa2_personal;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk;
        } else if (!strcmp(value, "WPA-WPA2-Personal")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa_wpa2_personal;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_disabled;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk;
        } else if (!strcmp(value, "WPA3-Personal")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_personal;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_required;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_sae;
        } else if (!strcmp(value, "WPA3-Personal-Transition")) {
            vap_info->u.bss_info.security.mode = wifi_security_mode_wpa3_transition;
            vap_info->u.bss_info.security.mfp = wifi_mfp_cfg_optional;
            vap_info->u.bss_info.security.u.key.type = wifi_security_key_type_psk_sae;
        } else {
            if (execRetVal) {
                strncpy(execRetVal->ErrorMsg,"Invalid Security Mode",sizeof(execRetVal->ErrorMsg)-1);
            }

            wifi_util_error_print(WIFI_CTRL, "%s: unknown \"ModeEnabled\": %s\n", __func__, value);
            return RETURN_ERR;
        }
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: missing \"ModeEnabled\"\n", __func__);
        if (execRetVal) {
            strncpy(execRetVal->ErrorMsg,"Invalid Security Mode",sizeof(execRetVal->ErrorMsg)-1);
        }
        return RETURN_ERR;
    }
    if (validate_private_home_security_param(value,encryption_method,execRetVal) != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s: Invalid Encryption Security Combination \n", __func__);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

static int update_vap_info(void *data, wifi_vap_info_t *vap_info,pErr execRetVal)
{
    int status = RETURN_OK;
    char *suffix;
    char band[8];
    cJSON *root = NULL;
    cJSON *ssid_obj = NULL;
    cJSON *security_obj = NULL;
    wifi_vap_name_t ssid;
    wifi_vap_name_t security;

    root = cJSON_Parse((char *)data);
    if(root == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        return RETURN_ERR;
    }

    suffix = strrchr(vap_info->vap_name, (int)'_');
    if (suffix == NULL) {
        goto done;
    }
    /*
    For products with 5GHz lower and upper band radios like XLE,
    the webconfig will support only the VAP names append with '_5gl'. '_5gh' and '_5gu'.
    The blob is using '_5gl' and '_5gu'. VAP names with '_5gh' will be changed to use '_5gu'.
    */
    if (!strcmp(suffix, "_5gh")) {
        snprintf(band, sizeof(band), "_5gu");
    } else {
        snprintf(band, sizeof(band), "%s", suffix);
    }
    if (!strncmp(vap_info->vap_name, VAP_PREFIX_PRIVATE, strlen(VAP_PREFIX_PRIVATE))) {
        snprintf(ssid, sizeof(wifi_vap_name_t), "private_ssid%s", band);
        snprintf(security, sizeof(wifi_vap_name_t), "private_security%s", band);
    } else if (!strncmp(vap_info->vap_name, VAP_PREFIX_IOT, strlen(VAP_PREFIX_IOT))) {
        snprintf(ssid, sizeof(wifi_vap_name_t), "home_ssid%s", band);
        snprintf(security, sizeof(wifi_vap_name_t), "home_security%s", band);
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: No SSID and security info\n", __func__);
        status = RETURN_ERR;
        goto done;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s: parsing %s and %s blob\n", __func__, ssid, security);
    ssid_obj = cJSON_GetObjectItem(root, ssid);
    if (ssid_obj == NULL) {
        status = RETURN_ERR;
        wifi_util_dbg_print(WIFI_CTRL, "%s: Failed to get %s SSID\n", __func__, vap_info->vap_name);
        goto done;
    }

    security_obj = cJSON_GetObjectItem(root, security);
    if (security_obj == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to get %s security\n", __func__, vap_info->vap_name);
        status = RETURN_ERR;
        goto done;
    }

    /* get SSID */
    if (decode_ssid_blob(vap_info, ssid_obj, NULL, false, execRetVal) != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to decode SSID blob\n", __func__);
        status = RETURN_ERR;
        goto done;
    }

    /* decode security blob */
    if (decode_security_blob(vap_info, security_obj, execRetVal) != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to decode security blob\n", __func__);
        status = RETURN_ERR;
        goto done;
    }

done:
    if (root) {
        cJSON_Delete(root);
    }
    return status;
}

static int update_vap_info_managed_guest(void *data, wifi_vap_info_t *vap_info, char * bridge_name,bool connected_building_enabled,pErr execRetVal)
{
    int status = RETURN_OK;
    cJSON *root = NULL;
    cJSON *security_obj = NULL;
    cJSON *vb_entry = NULL;
    char repurposed_vap_name[64];
    char ssid[128] = {0};
    char password[128] = {0};
    memset(repurposed_vap_name,0,sizeof(repurposed_vap_name));
    char *saveptr = NULL;
    char *blob = NULL;

    if (connected_building_enabled) {
        wifi_util_info_print(WIFI_CTRL, "%s: %d connected_building_enabled %d \n", __func__,__LINE__,connected_building_enabled);
        blob = cJSON_Print((cJSON *)data);
        wifi_util_dbg_print(WIFI_CTRL,"Managed guest  blob is %s\n",blob);
        root = cJSON_Parse(blob);
        if(root == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:Managed guest json  parse failure\n", __func__);
            return RETURN_ERR;
        }

        cJSON_ArrayForEach(vb_entry, root) {

            cJSON *blob_vap_name = cJSON_GetObjectItem(vb_entry, "VapName");
            if((blob_vap_name == NULL) || (cJSON_IsString(blob_vap_name) == false)) {
                wifi_util_info_print(WIFI_CTRL, "%s: Missing VapName\n", __func__);
                continue;
            }

            char *blob_vap_name_str = cJSON_GetStringValue(blob_vap_name);
            strncpy(repurposed_vap_name,blob_vap_name_str,sizeof(repurposed_vap_name)-1);
            wifi_util_info_print(WIFI_CTRL, "repurposed_vap_name:%s %s: %d \n",repurposed_vap_name, __func__,__LINE__ );

            if (strstr(blob_vap_name_str,"managed_guest_")) {
                saveptr = strrchr(blob_vap_name_str, (int)'_');
                if (saveptr == NULL) {
                    wifi_util_error_print(WIFI_CTRL, "%s: %d vapname is not proper \n", __func__,__LINE__);
                    goto done;
                }
                snprintf(blob_vap_name_str,strlen(blob_vap_name_str)-1,"lnf_psk%s",saveptr);
            } else {
                wifi_util_error_print(WIFI_CTRL, "%s: %d vapname is not proper \n", __func__,__LINE__);
                goto done;
            }
            if (!strcmp(vap_info->vap_name,blob_vap_name_str)) {
                wifi_util_error_print(WIFI_CTRL, "%s: %d connected_building_enabled %d \n", __func__,__LINE__,connected_building_enabled);
                if (decode_ssid_blob(vap_info, vb_entry, bridge_name, true, execRetVal) != 0) {
                    wifi_util_error_print(WIFI_CTRL, "%s: Failed to decode SSID blob\n", __func__);
                    status = RETURN_ERR;
                    goto done;
                 }

                security_obj = cJSON_GetObjectItem(vb_entry, "Security");
                if (security_obj == NULL) {
                    wifi_util_error_print(WIFI_CTRL, "%s: Failed to get %s security\n", __func__, vap_info->vap_name);
                    status = RETURN_ERR;
                    goto done;
                }


                /* decode security blob */
                if (decode_security_blob(vap_info, security_obj, execRetVal) != 0) {
                    wifi_util_error_print(WIFI_CTRL, "%s: Failed to decode security blob\n", __func__);
                    status = RETURN_ERR;
                    goto done;
                }
                if (strlen(repurposed_vap_name) != 0) {
                    strncpy(vap_info->repurposed_vap_name, repurposed_vap_name, (strlen(repurposed_vap_name) + 1));
                }
            }
        }
    } else {
        wifi_util_info_print(WIFI_CTRL, "%s: %d connected_building_enabled %d \n", __func__,__LINE__,connected_building_enabled);
        snprintf(vap_info->bridge_name, sizeof(vap_info->bridge_name), "br106");
        vap_info->u.bss_info.showSsid = false;
        vap_info->u.bss_info.enabled = true;
        vap_info->u.bss_info.bssMaxSta = 75;
        wifi_hal_get_default_ssid(ssid, vap_info->vap_index);
        wifi_hal_get_default_keypassphrase(password, vap_info->vap_index);
        snprintf(vap_info->u.bss_info.ssid, sizeof(vap_info->u.bss_info.ssid), "%s", ssid);
        snprintf(vap_info->u.bss_info.security.u.key.key, sizeof(vap_info->u.bss_info.security.u.key.key), "%s", password);
        strncpy(vap_info->repurposed_vap_name,"",(strlen(repurposed_vap_name) + 1));
    }
done:
    if (root) {
        cJSON_free(blob);
        cJSON_Delete(root);
    }
    return status;
}

static int update_vap_info_managed_xfinity(void *data, wifi_vap_info_t *vap_info, pErr execRetVal)
{
    int status = RETURN_OK;
    cJSON *root = NULL;
    cJSON *param = NULL;
    bool connected_building_enabled = false;
    char *blob = cJSON_Print((cJSON *)data);

    root = cJSON_Parse(blob);

    if (root == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:Managed xfinity json parse failure\n", __func__);
        return RETURN_ERR;
    }
    param = cJSON_GetObjectItem(root, "connected_building_enabled");

    if (param) {
        if (cJSON_IsBool(param)) {
            connected_building_enabled = cJSON_IsTrue(param) ? true : false;
            wifi_util_dbg_print(WIFI_CTRL, "   \"connected_building_enabled\": %s\n", (connected_building_enabled) ? "true" : "false");
        } else {
            wifi_util_dbg_print(WIFI_CTRL, "%s: \"connected_building_enabled\" is not boolean\n", __func__);
            cJSON_Delete(root);
            return RETURN_ERR;
        }
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s: \"connected_building_enabled\" is not present\n", __func__);
    }
    vap_info->u.bss_info.connected_building_enabled = connected_building_enabled;
    wifi_util_info_print(WIFI_CTRL, "  LINE %d \"connected_building_enabled\": %s and vap_name=%s\n", __LINE__,(vap_info->u.bss_info.connected_building_enabled) ? "true" : "false",vap_info->vap_name);
    cJSON_Delete(root);
    return status;
}

static int update_vap_info_with_blob_info(void *blob, webconfig_subdoc_data_t *data, const char *vap_prefix, bool managed_wifi_enabled,pErr execRetVal)
{
    int status = RETURN_OK;
    int num_vaps = 0;
    int vap_index;
    int radio_index = 0, rc = -1;
    int vap_array_index = 0;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS];
    wifi_vap_name_t vap_names_xfinity[MAX_NUM_RADIOS * 2];
    char brval[32];


    memset(brval,0,sizeof(brval));
    if (!strcmp(vap_prefix,"lnf_psk")) {
        rc = get_managed_guest_bridge(&brval, sizeof(brval));
        if ( rc != 0) {
            wifi_util_dbg_print(WIFI_CTRL,"Managed wifi bridge not found\n");
            strncpy(brval,"brlan15",sizeof(brval)-1);
        }
    }

    if (!strcmp(vap_prefix,"hotspot")){
        /* get a list of VAP names */
        num_vaps= get_list_of_hotspot_open(&data->u.decoded.hal_cap.wifi_prop, MAX_NUM_RADIOS, vap_names_xfinity);
        /* get list of hotspot_secure SSID */
        num_vaps += get_list_of_hotspot_secure(&data->u.decoded.hal_cap.wifi_prop, MAX_NUM_RADIOS, &vap_names_xfinity[num_vaps]);
    }
    else {
        num_vaps = get_list_of_vap_names(&data->u.decoded.hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS, 1, vap_prefix);
    }

    for (int index = 0; index < num_vaps; index++) {
        if (!strcmp(vap_prefix,"hotspot")) {
            /* from VAP name, obtain radio index and array index within the radio */
            vap_index = convert_vap_name_to_index(&data->u.decoded.hal_cap.wifi_prop, vap_names_xfinity[index]);
        } else {
            /* from VAP name, obtain radio index and array index within the radio */
            vap_index = convert_vap_name_to_index(&data->u.decoded.hal_cap.wifi_prop, vap_names[index]);
        }
        status = get_vap_and_radio_index_from_vap_instance(&data->u.decoded.hal_cap.wifi_prop, vap_index, (uint8_t *)&radio_index, (uint8_t *)&vap_array_index);
        if (status == RETURN_ERR) {
            break;
        }
        /* fill the VAP info with current settings */
        if (!strcmp(vap_prefix,"hotspot")) {
            if (update_vap_info_managed_xfinity(blob, &data->u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index], execRetVal) == RETURN_ERR) {
                status = RETURN_ERR;
                break;
            }
        } else if (!strcmp(vap_prefix,"lnf_psk")) {
            if(update_vap_info_managed_guest(blob, &data->u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index], brval,managed_wifi_enabled, execRetVal) == RETURN_ERR) {
                status = RETURN_ERR;
                break;
            }
         } else {
            if (update_vap_info(blob, &data->u.decoded.radios[radio_index].vaps.vap_map.vap_array[vap_array_index], execRetVal) == RETURN_ERR) {
                status = RETURN_ERR;
                break;
            }
        }
    }

    return status;
}

static int push_blob_data(webconfig_subdoc_data_t *data, webconfig_subdoc_type_t subdoc_type)
{
    char *str;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (webconfig_encode(&ctrl->webconfig, data, subdoc_type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d - Failed webconfig_encode for subdoc type %d\n", __FUNCTION__, __LINE__, subdoc_type);
        return RETURN_ERR;
    }

    str = data->u.encoded.raw;
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Encoded blob:\n%s\n", __func__, __LINE__, str);
    push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data_webconfig, NULL);

    webconfig_data_free(data);

    return RETURN_OK;
}

static pErr create_execRetVal(void)
{
    pErr execRetVal;

    execRetVal = (pErr) malloc(sizeof(Err));
    if (execRetVal == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return execRetVal;
    }

    memset(execRetVal,0,(sizeof(Err)));
    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;

    return execRetVal;
}

static pErr private_home_exec_common_handler(void *blob, const char *vap_prefix, webconfig_subdoc_type_t subdoc_type)
{
    pErr execRetVal = NULL;
    webconfig_subdoc_data_t *data = NULL;
    if (blob == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        return NULL;
    }

    data = (webconfig_subdoc_data_t *) malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", \
                              __func__, sizeof(webconfig_subdoc_data_t));
        goto done;
    }

    execRetVal = create_execRetVal();
    if (execRetVal == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        goto done;
    }
    webconfig_init_subdoc_data(data);

    if (update_vap_info_with_blob_info(blob, data, vap_prefix, false, execRetVal) != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        goto done;
    }

    if (push_blob_data(data, subdoc_type) != RETURN_OK) {
        execRetVal->ErrorCode = WIFI_HAL_FAILURE;
        strncpy(execRetVal->ErrorMsg, "push_blob_to_ctrl_queue failed", sizeof(execRetVal->ErrorMsg)-1);
        wifi_util_error_print(WIFI_CTRL, "%s: failed to encode %s subdoc\n", \
                              __func__, (subdoc_type == webconfig_subdoc_type_private) ? "private" : "home");
        goto done;
    }

done:
    if (data) {
        free(data);
    }
    return execRetVal;
}
static int connected_subdoc_handler(void *blob, char *vap_prefix, webconfig_subdoc_type_t subdoc_type,bool  managed_wifi_enabled, pErr execRetVal)
{
    int ret = RETURN_ERR;
    wifi_vap_name_t vap_names[MAX_NUM_RADIOS];
    int num_vaps = 0,i = 0, vap_index = 0;
    webconfig_subdoc_data_t *data = NULL;
    wifi_interface_name_t *lnf_psk_ifname = NULL;
    char managed_interfaces[128];

    memset(managed_interfaces,0,sizeof(managed_interfaces));

    if (blob == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        return ret;
    }

    data = (webconfig_subdoc_data_t *) malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", \
                              __func__, sizeof(webconfig_subdoc_data_t));
        goto done;
    }

    webconfig_init_subdoc_data(data);

    if (update_vap_info_with_blob_info(blob, data, vap_prefix, managed_wifi_enabled, execRetVal) != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s: json parse failure\n", __func__);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        goto done;
    }
    if (push_blob_data(data, subdoc_type) != RETURN_OK) {
        execRetVal->ErrorCode = WIFI_HAL_FAILURE;
        strncpy(execRetVal->ErrorMsg, "push_blob_to_ctrl_queue failed", sizeof(execRetVal->ErrorMsg)-1);
        wifi_util_error_print(WIFI_CTRL, "%s: failed to encode %s subdoc\n", \
                              __func__, (subdoc_type == webconfig_subdoc_type_lnf) ? "lnf_psk" : "xfinity");
        goto done;
    }

    if (strcmp(vap_prefix,"lnf_psk")== 0) {
        num_vaps = get_list_of_vap_names(&data->u.decoded.hal_cap.wifi_prop, vap_names, MAX_NUM_RADIOS, 1, VAP_PREFIX_LNF_PSK);
        wifi_util_error_print(WIFI_CTRL, "%s: num_vaps =%d \n", __func__,num_vaps);
        for (i =0; i < num_vaps; i++) {
            vap_index = convert_vap_name_to_index(&data->u.decoded.hal_cap.wifi_prop, vap_names[i]);
            lnf_psk_ifname = get_interface_name_for_vap_index(vap_index,(&data->u.decoded.hal_cap.wifi_prop));

            if ((lnf_psk_ifname != NULL) &&(strlen(managed_interfaces) == 0) && managed_wifi_enabled) {
                snprintf(managed_interfaces,sizeof(managed_interfaces),"ManagedWifi:%s",*lnf_psk_ifname);
            } else if ((lnf_psk_ifname != NULL) && managed_wifi_enabled) {
               strncat(managed_interfaces,",",2);
               strncat(managed_interfaces,*lnf_psk_ifname,strlen(*lnf_psk_ifname));
            } else {
                wifi_util_error_print(WIFI_CTRL, "%s: managed_wifi_enabled is false \n", __func__);
                strncpy(managed_interfaces,"ManagedWifi:",sizeof(managed_interfaces)-1);
            }
        }
        wifi_util_info_print(WIFI_CTRL, "managed_interfaces = %s and lnf_psk_ifname=%s\n",managed_interfaces,(char *)lnf_psk_ifname);
        set_managed_guest_interfaces(managed_interfaces);
    }
    ret = RETURN_OK;
done:
    if (data) {
        free(data);
    }
   return ret;
}

pErr wifi_private_vap_exec_handler(void *blob)
{
    return private_home_exec_common_handler(blob, VAP_PREFIX_PRIVATE, webconfig_subdoc_type_private);
}

pErr wifi_home_vap_exec_handler(void *blob)
{
    return private_home_exec_common_handler(blob, VAP_PREFIX_IOT, webconfig_subdoc_type_home);
}

#define MAX_JSON_BUFSIZE 21240

char *unpackDecode(const char* enb)
{
    unsigned long msg_size = 0L;
    unsigned char *msg = NULL;

    msg_size = b64_get_decoded_buffer_size(strlen((char *)enb));
    msg = (unsigned char *) calloc(sizeof(unsigned char), msg_size);
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
//    wifi_util_dbg_print(WIFI_CTRL, "%s, blob\n%s\n", __func__, dej);
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

bool webconfig_to_wifi_update_params(const char* raw)
{
    webconfig_t *config;
    webconfig_subdoc_data_t data = {0};
    wifi_ctrl_t *ctrl = (wifi_ctrl_t*)get_wifictrl_obj();
    wifi_mgr_t *mgr = (wifi_mgr_t*)get_wifimgr_obj();

    config = &ctrl->webconfig;
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));
    if (webconfig_decode(config, &data, raw) == webconfig_error_none && webconfig_data_free(&data) == webconfig_error_none)
    {
        wifi_util_info_print(WIFI_CTRL,"%s:%d: WebConfig blob has been successfully applied\n",__FUNCTION__,__LINE__);
        return true;
    }
    wifi_util_error_print(WIFI_CTRL,"%s:%d: WebConfig blob apply has failed\n",__FUNCTION__,__LINE__);
    return false;
}

pErr webconf_process_managed_subdoc(void* data)
{
    pErr execRetVal = NULL;
    unsigned long msg_size = 0L;
    unsigned char *msg = NULL;
    int ret = RETURN_ERR;
    bool connected_wifi_enabled = false;

    execRetVal = create_execRetVal();
    if (execRetVal == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return NULL;
    }
    memset(execRetVal,0,(sizeof(Err)));
    if(data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        if (execRetVal) {
            execRetVal->ErrorCode = VALIDATION_FALIED;
            strncpy(execRetVal->ErrorMsg, "Empty subdoc", sizeof(execRetVal->ErrorMsg)-1);
        }
        return execRetVal;
    }


    msg_size = b64_get_decoded_buffer_size(strlen((char *)data));
    msg = (unsigned char *) calloc(sizeof(unsigned char), msg_size);
    if (!msg) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s: Failed to allocate memory.\n",__FUNCTION__);
        strncpy(execRetVal->ErrorMsg, "Failed to allocate memory", sizeof(execRetVal->ErrorMsg)-1);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        return execRetVal;
    }

    msg_size = 0;
    msg_size = b64_decode((unsigned char *)data, strlen((char *)data), msg );
    if (msg_size == 0) {
        wifi_util_error_print(WIFI_WEBCONFIG,"%s: Failed in Decoding multicomp blob\n",__FUNCTION__);
        free(msg);
        strncpy(execRetVal->ErrorMsg, "Failed in Decoding multicomp blob", sizeof(execRetVal->ErrorMsg)-1);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        return execRetVal;
    }

    wifidb_print("%s:%d [Start] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());

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

    wifi_util_info_print(WIFI_CTRL, "%s, Managed wifi blob\n%s\n", __func__, blob_buf);

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
    cJSON *managed_wifi_enabled = cJSON_GetObjectItem(root, "ManagedWifiEnabled");
    if (managed_wifi_enabled == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "Failed to Get ManagedWifiEnabled", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to Get ManagedWifiEnabled\n", __func__);
        return execRetVal;
    }
    connected_wifi_enabled = cJSON_IsTrue(managed_wifi_enabled)? true : false;
    wifi_util_dbg_print(WIFI_CTRL,"managed_wifi_enabled is %d\n",connected_wifi_enabled);

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
    ret = connected_subdoc_handler(vap_blob, VAP_PREFIX_LNF_PSK, webconfig_subdoc_type_lnf, connected_wifi_enabled,  execRetVal);
    if (ret != RETURN_OK) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        free(blob_buf);
        free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to apply managed_guest vaps\n", __func__);
        return execRetVal;
    }

    cJSON *xfinity_blob = cJSON_DetachItemFromObject(root, "xfinityWifiVapConfig");
    if(xfinity_blob == NULL) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        strncpy(execRetVal->ErrorMsg, "Failed to detach xfinity_blob", sizeof(execRetVal->ErrorMsg)-1);
        free(blob_buf);
        free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to detach xfinity_blob\n", __func__);
        return execRetVal;
    }

    ret = connected_subdoc_handler(xfinity_blob, VAP_PREFIX_HOTSPOT, webconfig_subdoc_type_xfinity, connected_wifi_enabled, execRetVal);
    if (ret != RETURN_OK) {
        msgpack_zone_destroy(&msg_z);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        free(blob_buf);
        free(msg);
        cJSON_Delete(root);
        wifi_util_error_print(WIFI_CTRL, "%s: Failed to update connectedbuilding AVPs in  Xfinity vaps \n", __func__);
        return execRetVal;
    }
    if (connected_wifi_enabled) {
        wifi_util_info_print(WIFI_CTRL,"lnf_psk vaps are repurposed to managed_guest\n");
    } else {
        wifi_util_info_print(WIFI_CTRL,"managed_guest vaps are reverted back to lnf_psk\n");
    }


    wifi_util_info_print(WIFI_CTRL,"Managed guest blob is applied successfuly \n");
    cJSON_Delete(root); // don't need this anymore

    execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
    return execRetVal;
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
        strncpy(execDataPf->subdoc_name, "homessid", sizeof(execDataPf->subdoc_name)-1);
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
    unsigned long msg_size = 0L;
    unsigned char *msg = NULL;
    rdk_wifi_vap_info_t *rdk_vap_info = NULL;
    execRetVal = create_execRetVal();
    if (execRetVal == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return NULL;
    }
    memset(execRetVal,0,(sizeof(Err)));
    if(data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: Null blob\n", __func__);
        if (execRetVal) {
            execRetVal->ErrorCode = VALIDATION_FALIED;
            strncpy(execRetVal->ErrorMsg, "Empty subdoc", sizeof(execRetVal->ErrorMsg)-1);
        }
        return execRetVal;
    }

    msg_size = b64_get_decoded_buffer_size(strlen((char *)data));
    msg = (unsigned char *) calloc(sizeof(unsigned char), msg_size);
    if (!msg) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed to allocate memory.\n",__FUNCTION__);
        strncpy(execRetVal->ErrorMsg, "Failed to allocate memory", sizeof(execRetVal->ErrorMsg)-1);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        return execRetVal;
    }

    msg_size = 0;
    msg_size = b64_decode((unsigned char *)data, strlen((char *)data), msg );
    if (msg_size == 0) {
        wifi_util_dbg_print(WIFI_WEBCONFIG,"%s: Failed in Decoding multicomp blob\n",__FUNCTION__);
        free(msg);
        strncpy(execRetVal->ErrorMsg, "Failed  in Decoding multicomp blob", sizeof(execRetVal->ErrorMsg)-1);
        execRetVal->ErrorCode = VALIDATION_FALIED;
        return execRetVal;
    }

    wifidb_print("%s:%d [Start] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());

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

    int status = RETURN_OK;
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
        rdk_vap_info = get_wifidb_rdk_vap_info(wifi_vap_map->vap_array[vapArrayIndex].vap_index);
        if(rdk_vap_info == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get rdk_vap_info from vap)index %d\n", __func__, rindx);
            continue;
        }

        cJSON_AddNumberToObject(vb_entry, "RadioIndex", rindx);
        cJSON_AddNumberToObject(vb_entry, "VapMode", 0);
        cJSON_AddItemToObject(vb_entry, "BridgeName", cJSON_CreateString(br_name));
        cJSON_AddItemToObject(vb_entry, "BSSID", cJSON_CreateString("00:00:00:00:00:00"));
#if !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_)
       if(rdk_vap_info->exists == false) {
#if defined(_SR213_PRODUCT_REQ_)
           if(wifi_vap_map->vap_array[vapArrayIndex].vap_index != 2 && wifi_vap_map->vap_array[vapArrayIndex].vap_index != 3) {
               wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,wifi_vap_map->vap_array[vapArrayIndex].vap_index);
               rdk_vap_info->exists = true;
           }
#else
           wifi_util_error_print(WIFI_CTRL,"%s:%d VAP_EXISTS_FALSE for vap_index=%d, setting to TRUE. \n",__FUNCTION__,__LINE__,wifi_vap_map->vap_array[vapArrayIndex].vap_index);
           rdk_vap_info->exists = true;
#endif /* _SR213_PRODUCT_REQ_ */
       }
#endif /* !defined(_WNXL11BWL_PRODUCT_REQ_) && !defined(_PP203X_PRODUCT_REQ_) */
        cJSON_AddBoolToObject(vb_entry, "Exists", rdk_vap_info->exists);

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
            cJSON_AddItemToObject(vb_entry, "WpsConfigPin", cJSON_CreateString(wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.wps.pin));
        }
        if(wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.beaconRateCtl[0] != 0) {
            cJSON_AddStringToObject(vb_entry, "BeaconRateCtl", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.beaconRateCtl);
        }
        else {
            cJSON_AddStringToObject(vb_entry, "BeaconRateCtl", "6Mbps");
        }
        cJSON *connected_building_enabled_o = cJSON_GetObjectItem(vb_entry, "Connected_building_enabled");
        if (connected_building_enabled_o == NULL) {
            wifi_util_dbg_print(WIFI_CTRL, "connected_building_enabled param is not present\n");
            cJSON_AddBoolToObject(vb_entry,"Connected_building_enabled",wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.connected_building_enabled);
        }

        cJSON_AddStringToObject(vb_entry, "RepurposedVapName", wifi_vap_map->vap_array[vapArrayIndex].repurposed_vap_name);

        cJSON *vapConnectionControl_o = cJSON_GetObjectItem(vb_entry, "VapConnectionControl");
        if (vapConnectionControl_o == NULL) {
            wifi_util_info_print(WIFI_CTRL, "vapConnectionContro param is not present\n");
            vapConnectionControl_o = cJSON_AddObjectToObject(vb_entry,"VapConnectionControl");

            cJSON *PreAssocDeny =  cJSON_AddObjectToObject(vapConnectionControl_o,"PreAssociationDeny");
            cJSON_AddStringToObject(PreAssocDeny, "RssiUpThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.rssi_up_threshold);
            cJSON_AddStringToObject(PreAssocDeny, "SnrThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.snr_threshold);
            cJSON_AddStringToObject(PreAssocDeny, "CuThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.cu_threshold);
            cJSON_AddStringToObject(PreAssocDeny, "BasicDataTransmitRates", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.basic_data_transmit_rates);
            cJSON_AddStringToObject(PreAssocDeny, "OperationalDataTransmitRates", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.operational_data_transmit_rates);
            cJSON_AddStringToObject(PreAssocDeny, "SupportedDataTransmitRates", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.supported_data_transmit_rates);
            cJSON_AddStringToObject(PreAssocDeny, "MinimumAdvertisedMCS", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.minimum_advertised_mcs);
            cJSON_AddStringToObject(PreAssocDeny, "6GOpInfoMinRate", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.preassoc.sixGOpInfoMinRate);
 
            cJSON *PostAssocDeny =  cJSON_AddObjectToObject(vapConnectionControl_o,"PostAssociationDeny");
            cJSON_AddStringToObject(PostAssocDeny, "RssiUpThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.postassoc.rssi_up_threshold);
            cJSON_AddStringToObject(PostAssocDeny, "SnrThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.postassoc.snr_threshold);
            cJSON_AddStringToObject(PostAssocDeny, "CuThreshold", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.postassoc.cu_threshold);
            cJSON_AddStringToObject(PostAssocDeny, "SamplingInterval", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.postassoc.sampling_interval);
            cJSON_AddStringToObject(PostAssocDeny, "SamplingCount", wifi_vap_map->vap_array[vapArrayIndex].u.bss_info.postassoc.sampling_count);


        }
        else {
            wifi_util_info_print(WIFI_CTRL, "vapConnectionContro param is present in blob\n");
        }

        /*
        Correct integrity of interworking field in the VAP object is very important. Let's check it here to avoid
        reporting code 300 (SUCCESS) for webconfig agent even if it's not correct.
        */
        cJSON *interworking_o = cJSON_GetObjectItem(vb_entry, "Interworking");
        if(interworking_o == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s: Failed to get Interworking obj for %s\n", __func__, nm_s);
            continue;
        }

        if ((status = early_validate_interworking(interworking_o,  execRetVal)) != RETURN_OK) {
            break;
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

    if (status == RETURN_OK) {
        cJSON *n_blob = cJSON_CreateObject();
        cJSON_AddItemToObject(n_blob, "Version", cJSON_CreateString("1.0"));
        cJSON_AddItemToObject(n_blob, "SubDocName", cJSON_CreateString("xfinity"));
        cJSON_AddItemToObject(n_blob, "WifiVapConfig", vap_blob);

        char *vap_blob_str = cJSON_Print(n_blob);
        wifi_util_dbg_print(WIFI_CTRL,"WebConfig blob is %s\n",vap_blob_str);
        if (webconfig_to_wifi_update_params(vap_blob_str))
        {
            execRetVal->ErrorCode = BLOB_EXEC_SUCCESS;
        }
        else
        {
            execRetVal->ErrorCode = VALIDATION_FALIED;
            wifi_util_error_print(WIFI_CTRL, "%s(): Validation failed: %s\n", __FUNCTION__, execRetVal->ErrorMsg);
        }
        cJSON_free(vap_blob_str);
        cJSON_Delete(n_blob);
    }
    else {
        execRetVal->ErrorCode = VALIDATION_FALIED;
        wifi_util_error_print(WIFI_CTRL, "%s(): Validation failed: %s\n", __FUNCTION__, execRetVal->ErrorMsg);
    }

    free(blob_buf);
    msgpack_zone_destroy(&msg_z);
    free(msg);

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

void process_managed_wifi_disable ()
{
    int ret = RETURN_ERR;
    pErr execRetVal = NULL;

    wifi_util_info_print(WIFI_CTRL,"Enter %s:%d\n", __func__, __LINE__);
    execRetVal = create_execRetVal();
    if (execRetVal == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failure\n", __func__);
        return ;
    }

    cJSON *managed_blob = cJSON_CreateObject();
    cJSON_AddBoolToObject(managed_blob, "connected_building_enabled", false);


    ret = connected_subdoc_handler(managed_blob, VAP_PREFIX_LNF_PSK, webconfig_subdoc_type_lnf, false,  execRetVal);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s:Managed LNF vaps were not disabled \n", __func__);
    }
    ret = connected_subdoc_handler(managed_blob, VAP_PREFIX_HOTSPOT, webconfig_subdoc_type_xfinity, false, execRetVal);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s:Managed xfinity vaps were not disabled \n", __func__);
    }

    wifi_util_info_print(WIFI_CTRL,"managed_guest vaps are reverted back to lnf_psk\n");
    free(execRetVal);
    cJSON_Delete(managed_blob);
}

int register_multicomp_subdocs()
{
    // PAM delivers xfinity blob  and connectedbuilding blobs as hotspot,connectedbuilding - so OneWifi will register for both blobs
    char *multi_sub_docs[MULTI_COMP_SUPPORTED_SUBDOC_COUNT+1]= {"hotspot","connectedbuilding",(char *) 0 };
    multiCompSubDocReg *multiCompData = NULL ;
    multiCompData = (multiCompSubDocReg*) malloc(MULTI_COMP_SUPPORTED_SUBDOC_COUNT * sizeof(multiCompSubDocReg));
    memset(multiCompData, 0, MULTI_COMP_SUPPORTED_SUBDOC_COUNT * sizeof(multiCompSubDocReg));
    multiCompSubDocReg *multiCompDataPointer = multiCompData ;
    int j ;

    for (j=0; j < MULTI_COMP_SUPPORTED_SUBDOC_COUNT ; j++ )
    {
        strncpy(multiCompDataPointer->multi_comp_subdoc , multi_sub_docs[j], sizeof(multiCompDataPointer->multi_comp_subdoc)-1) ;
        if ( strcmp(multiCompDataPointer->multi_comp_subdoc,"hotspot") == 0 )
        {
            multiCompDataPointer->executeBlobRequest = wifi_vap_cfg_subdoc_handler;
        }
        else if ( strcmp(multiCompDataPointer->multi_comp_subdoc,"connectedbuilding") == 0 )
        {
            multiCompDataPointer->executeBlobRequest = webconf_process_managed_subdoc;
        }
 
        multiCompDataPointer->calcTimeout = wifi_vap_cfg_timeout_handler;
        multiCompDataPointer->rollbackFunc = wifi_vap_cfg_rollback_handler;
        multiCompDataPointer->freeResources = NULL;
        multiCompDataPointer++ ;
    }
    multiCompDataPointer = multiCompData ;
    register_MultiComp_subdoc_handler(multiCompData,MULTI_COMP_SUPPORTED_SUBDOC_COUNT);
 
    return RETURN_OK;
}

// static char *sub_docs[] = { "privatessid", "home", "xfinity", (char *) 0 };
static char *sub_docs[] = { "privatessid", "homessid", (char *)0 };

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

