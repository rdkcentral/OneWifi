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
#include "log.h"
#include "wifi_passpoint.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "msgpack.h"
#include <unistd.h>
#include <rbus.h>

int webconfig_csi_notify_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_encoded_data_t *data)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    int rc;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, WIFI_WEBCONFIG_GET_CSI, value);
    rbusValue_SetBytes(value, (uint8_t *)data->raw, strlen(data->raw));
    event.name = WIFI_WEBCONFIG_GET_CSI;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return RETURN_OK;
}

int webconfig_client_notify_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_encoded_data_t *data)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    int rc;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, WIFI_WEBCONFIG_GET_ASSOC, value);
    rbusValue_SetBytes(value, (uint8_t *)data->raw, strlen(data->raw));
    event.name = WIFI_WEBCONFIG_GET_ASSOC;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return RETURN_OK;
}

int webconfig_null_subdoc_notify_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_encoded_data_t *data)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    int rc;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, WIFI_WEBCONFIG_GET_NULL_SUBDOC, value);
    rbusValue_SetBytes(value, (uint8_t *)data->raw, strlen(data->raw));
    event.name = WIFI_WEBCONFIG_GET_NULL_SUBDOC;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return RETURN_OK;
}


int notify_associated_entries(wifi_ctrl_t *ctrl, int ap_index, ULONG new_count, ULONG old_count)
{
    int rc;
    char str[2048];
    memset(str, 0, 2048);

    if (ctrl == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    snprintf(str, sizeof(str), "Device.WiFi.AccessPoint.%d.AssociatedDeviceNumberOfEntries,%d,%lu,%lu,%d", ap_index+1, 0, new_count, old_count, 2);
    rc = rbus_setStr(ctrl->rbus_handle, WIFI_NOTIFY_ASSOCIATED_ENTRIES, str);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusWrite Failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int notify_hotspot(wifi_ctrl_t *ctrl, assoc_dev_data_t *assoc_device)
{
    int rc;
    char str[2048];
    mac_addr_str_t mac_str;
    memset(str, 0, 2048);

    if (ctrl == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    to_mac_str(assoc_device->dev_stats.cli_MACAddress, mac_str);
    snprintf(str, sizeof(str), "%d|%d|%d|%s", assoc_device->dev_stats.cli_Active,
                assoc_device->ap_index+1, assoc_device->dev_stats.cli_RSSI, mac_str);

    rc = rbus_setStr(ctrl->rbus_handle, WIFI_HOTSPOT_NOTIFY, str);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusWrite Failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int notify_LM_Lite(wifi_ctrl_t *ctrl, LM_wifi_hosts_t* phosts, bool sync)
{
    int rc, itr;
    char str[2048];
    memset(str, 0, 2048);

    if (ctrl == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (sync) {
        snprintf(str, sizeof(str), "%s,%s,%s,%d,%d",
                (char*)phosts->host[0].phyAddr,
                ('\0' != phosts->host[0].AssociatedDevice[ 0 ]) ? (char*)phosts->host[0].AssociatedDevice : "NULL",
                ('\0' != phosts->host[0].ssid[ 0 ]) ? (char*)phosts->host[0].ssid : "NULL",
                phosts->host[0].RSSI,
                (phosts->host[0].Status == TRUE) ? 1 : 0);

        rc = rbus_setStr(ctrl->rbus_handle, WIFI_LMLITE_NOTIFY, str);
        if (rc != RBUS_ERROR_SUCCESS) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusWrite Failed %d\n", __func__, __LINE__, rc);
            return RETURN_ERR;
        }
    } else {
        for (itr=0; itr<phosts->count; itr++) {
            snprintf(str, sizeof(str), "%s,%s,%s,%d,%d",
                (char*)phosts->host[itr].phyAddr,
                ('\0' != phosts->host[itr].AssociatedDevice[ 0 ]) ? (char*)phosts->host[itr].AssociatedDevice : "NULL",
                ('\0' != phosts->host[itr].ssid[ 0 ]) ? (char*)phosts->host[0].ssid : "NULL",
                phosts->host[itr].RSSI,
                (phosts->host[itr].Status == TRUE) ? 1 : 0);

           rc = rbus_setStr(ctrl->rbus_handle, WIFI_LMLITE_NOTIFY, str);
           if (rc != RBUS_ERROR_SUCCESS) {
               wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusWrite Failed %d\n", __func__, __LINE__, rc);
               return RETURN_ERR;
           }
        }
    }
    return RETURN_OK;
}

int webconfig_rbus_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_encoded_data_t *data)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    int rc;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, WIFI_WEBCONFIG_DOC_DATA_NORTH, value);
    rbusValue_SetBytes(value, (uint8_t *)data->raw, strlen(data->raw));
    event.name = WIFI_WEBCONFIG_DOC_DATA_NORTH;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return RETURN_OK;
}

rbusError_t webconfig_get_subdoc(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    vap_svc_t *ext_svc;
    unsigned int num_of_radios = getNumberRadios();
    #define MAX_ACSD_SYNC_TIME_WAIT 12
    static int sync_retries = 0;

    if (!ctrl->ctrl_initialized) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Ctrl not initialized skip request.\n",__FUNCTION__, __LINE__);
        return RBUS_ERROR_INVALID_OPERATION;
     }

   if(ctrl->network_mode == rdk_dev_mode_type_gw) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Rbus property=%s, Gateway mode\n",__FUNCTION__, __LINE__, name);
        if (strcmp(name, WIFI_WEBCONFIG_INIT_DATA) != 0) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d Rbus property invalid '%s'\n",__FUNCTION__, __LINE__, name);
            return RBUS_ERROR_INVALID_INPUT;
        }
        if ((sync_retries < MAX_ACSD_SYNC_TIME_WAIT)) {
            if ((is_acs_channel_updated(num_of_radios) == false) || (check_wifi_radio_sched_timeout_active_status(ctrl) == true)) {
                sync_retries++;
                wifi_util_info_print(WIFI_CTRL,"%s:%d: sync_retries=%d wifidb and global radio config not updated\n",__FUNCTION__,__LINE__, sync_retries);
                return RBUS_ERROR_INVALID_OPERATION;
            }
        }

        wifi_util_info_print(WIFI_CTRL,"%s:%d: sync_retries=%d wifidb and global radio config updated\n",__FUNCTION__,__LINE__, sync_retries);

        for (unsigned int index = 0; index < num_of_radios; index++) {
            if (ctrl->acs_pending[index] == true) {
                ctrl->acs_pending[index] = false;
            }
        }
        sync_retries = MAX_ACSD_SYNC_TIME_WAIT;

        rbusValue_Init(&value);
        memset(&data, 0, sizeof(webconfig_subdoc_data_t));

        memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, num_of_radios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&mgr->global_config, sizeof(wifi_global_config_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));
        data.u.decoded.num_radios = num_of_radios;
        // tell webconfig to encode
        webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_dml);

        // the encoded data is a string
        rbusValue_SetString(value, data.u.encoded.raw);
        rbusProperty_SetValue(property, value);

        rbusValue_Release(value);
    } else if (ctrl->network_mode == rdk_dev_mode_type_ext) {
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s, Extender mode\n",__FUNCTION__, name);

        if (strcmp(name, WIFI_WEBCONFIG_INIT_DATA) != 0) {
            wifi_util_error_print(WIFI_CTRL,"%s Rbus property valid\n",__FUNCTION__);
            return RBUS_ERROR_INVALID_INPUT;
        }
        
        ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
        if (ext_svc->u.ext.conn_state != connection_state_connected) {
            wifi_util_dbg_print(WIFI_CTRL,"%s Extender is not connected\n",__FUNCTION__);
            return RBUS_ERROR_INVALID_OPERATION;
        }

        rbusValue_Init(&value);
        memset(&data, 0, sizeof(webconfig_subdoc_data_t));

        memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, num_of_radios*sizeof(rdk_wifi_radio_t));
        memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));
        data.u.decoded.num_radios = num_of_radios;
        // tell webconfig to encode
        webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_mesh_sta);

        // the encoded data is a string
        rbusValue_SetString(value, data.u.encoded.raw);
        rbusProperty_SetValue(property, value);

        rbusValue_Release(value);
    }

    return RBUS_ERROR_SUCCESS;
}

rbusError_t webconfig_get_dml_subdoc(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus property=%s\r\n", __func__, __LINE__, name);
    if (strcmp(name, WIFI_WEBCONFIG_INIT_DML_DATA) != 0) {
        wifi_util_error_print(WIFI_CTRL,"%s Rbus property invalid '%s'\n",__FUNCTION__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&mgr->global_config, sizeof(wifi_global_config_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));
    data.u.decoded.num_radios = getNumberRadios();
    // tell webconfig to encode
    webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_dml);

    // the encoded data is a string
    rbusValue_SetString(value, data.u.encoded.raw);
    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t webconfig_set_subdoc(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    rbusValueType_t type = rbusValue_GetType(value);
    int rc = RBUS_ERROR_INVALID_INPUT;
    int len = 0;
    const char * pTmp = NULL;

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);
    if (type != RBUS_STRING) {
        wifi_util_error_print(WIFI_CTRL,"%sWrong data type %s\n",__FUNCTION__,name);
        return rc;
    }

    pTmp = rbusValue_GetString(value, &len);
    if (pTmp != NULL) {
        rc = RBUS_ERROR_SUCCESS;
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus set string len=%d\n",__FUNCTION__,len);
        push_data_to_ctrl_queue((const cJSON *)pTmp, (strlen(pTmp) + 1), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_ovsm);
    }
    return rc;
}

static void MarkerListConfigHandler (rbusHandle_t handle, rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    marker_list_t list_type;
    const char * pTmp = NULL;
    int len = 0;

    if (!event) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid Event Received %s",
                __func__, __LINE__, subscription->eventName);
        return;
    }
 
    if(strcmp(subscription->eventName, WIFI_NORMALIZED_RSSI_LIST) == 0) {
        list_type = ctrl_event_type_normalized_rssi;

    } else if(strcmp(subscription->eventName, WIFI_SNR_LIST) == 0) {
        list_type = ctrl_event_type_snr;

    } else if(strcmp(subscription->eventName, WIFI_CLI_STAT_LIST) == 0) {
        list_type = ctrl_event_type_cli_stat;

    } else if(strcmp(subscription->eventName, WIFI_TxRx_RATE_LIST) == 0) {
        list_type = ctrl_event_type_txrx_rate;

    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid Event Received %s",
                __func__, __LINE__, subscription->eventName);
        return;
    }

    value = rbusObject_GetValue(event->data, "value");
    if (!value) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid value in event:%s",
                    __func__, __LINE__, subscription->eventName);
        return;
    }

    pTmp = rbusValue_GetString(value, &len);
    if(pTmp == NULL) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Unable to get  value in event:%s\n", __func__, __LINE__);
        return;
    }
    push_data_to_ctrl_queue(pTmp, (strlen(pTmp) + 1), ctrl_event_type_command, list_type);

    UNREFERENCED_PARAMETER(handle);
}


#if defined(GATEWAY_FAILOVER_SUPPORTED)
static void activeGatewayCheckHandler(rbusHandle_t handle, rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    //int csi_session;
    bool other_gateway_present = false;

    if(!event || (strcmp(subscription->eventName, WIFI_ACTIVE_GATEWAY_CHECK) != 0)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Invalid Event Received %s",
                __func__, __LINE__, subscription->eventName);
        return;
    }

    value = rbusObject_GetValue(event->data, NULL);
    if (!value) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Invalid value in event:%s",
                    __func__, __LINE__, subscription->eventName);
        return;
    }

    other_gateway_present = rbusValue_GetBoolean(value);
    push_data_to_ctrl_queue(&other_gateway_present, sizeof(other_gateway_present), ctrl_event_type_command, ctrl_event_type_command_sta_connect);

    UNREFERENCED_PARAMETER(handle);
}
#endif
static void wan_failover_handler(rbusHandle_t handle, rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    bool data_value = false;

    if(!event || (strcmp(subscription->eventName, WIFI_WAN_FAILOVER_TEST) != 0)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Invalid Event Received %s",
                __func__, __LINE__, subscription->eventName);
        return;
    }

    value = rbusObject_GetValue(event->data, subscription->eventName);
    if (!value) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Invalid value in event:%s",
                    __func__, __LINE__, subscription->eventName);
        return;
    }

    data_value = rbusValue_GetBoolean(value);
    wifi_util_dbg_print(WIFI_CTRL, "%s:%d: recv data:%d\r\n", __func__, __LINE__, data_value);

    UNREFERENCED_PARAMETER(handle);
}

static void hotspotTunnelHandler(rbusHandle_t handle, rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    UNREFERENCED_PARAMETER(handle);

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Recvd Event\n",  __func__, __LINE__);
    if(!event) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d null event\n", __func__, __LINE__);
        return;
    }

    if(strcmp(subscription->eventName, "TunnelStatus") != 0) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Not Tunnel event, %s\n", __func__, __LINE__, subscription->eventName);
        return;
    }

    rbusValue_t value = rbusObject_GetValue(event->data, subscription->eventName);
    if (!value) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Invalid value in event:%s\n",
                    __func__, __LINE__, subscription->eventName);
        return;
    }

    int len = 0;
    const char * pTmp = rbusValue_GetString(value, &len);
    if(pTmp == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Unable to get  value in event:%s\n", __func__, __LINE__);
        return;
    }

    bool tunnel_status = false;
    if(strcmp(pTmp, "TUNNEL_UP") == 0) {
        tunnel_status = true;
    }

    ctrl_event_subtype_t ces_t = tunnel_status ? ctrl_event_type_xfinity_tunnel_up : ctrl_event_type_xfinity_tunnel_down;
    push_data_to_ctrl_queue(&tunnel_status, sizeof(tunnel_status), ctrl_event_type_command, ces_t);
}

rbusError_t get_assoc_clients_data(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;
    webconfig_subdoc_data_t data;
#if DML_SUPPORT
    assoc_dev_data_t *assoc_dev_data;
    int itr, itrj;
#endif
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if ((mgr == NULL) || (ctrl == NULL)) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);

    if (strcmp(name, WIFI_WEBCONFIG_GET_ASSOC) != 0) {
        wifi_util_error_print(WIFI_CTRL,"%s Rbus property invalid '%s'\n",__FUNCTION__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);

#if DML_SUPPORT
    pthread_mutex_lock(&ctrl->lock);
    for (itr=0; itr<MAX_NUM_RADIOS; itr++) {
        for (itrj=0; itrj<MAX_NUM_VAP_PER_RADIO; itrj++) {
            if (mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_map != NULL) {
                assoc_dev_data = hash_map_get_first(mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_map);
                while (assoc_dev_data != NULL) {
                   get_sta_stats_info(assoc_dev_data);
                   assoc_dev_data = hash_map_get_next(mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_map, assoc_dev_data);
                }
            }
        }
    }
    pthread_mutex_unlock(&ctrl->lock);
#endif
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));

    data.u.decoded.num_radios = getNumberRadios();
    data.u.decoded.assoclist_notifier_type = assoclist_notifier_full;
    webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_associated_clients);

    rbusValue_SetString(value, data.u.encoded.raw);
    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}


rbusError_t get_null_subdoc_data(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if ((mgr == NULL) || (ctrl == NULL)) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);

    if (strcmp(name, WIFI_WEBCONFIG_GET_NULL_SUBDOC) != 0) {
        wifi_util_error_print(WIFI_CTRL,"%s Rbus property invalid '%s'\n",__FUNCTION__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));

    data.u.decoded.num_radios = getNumberRadios();
    webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_null);

    rbusValue_SetString(value, data.u.encoded.raw);
    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t get_sta_disconnection(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;

    rbusValue_Init(&value);
    if (strcmp(name, WIFI_STA_TRIGGER_DISCONNECTION) == 0) {
        rbusValue_SetBoolean(value, false);
        rbusProperty_SetValue(property, value);
    }

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t set_sta_disconnection(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    rbusValueType_t type = rbusValue_GetType(value);
    int rc = RBUS_ERROR_INVALID_INPUT;
    bool sta_disconnect = false;

    if (type != RBUS_BOOLEAN) {
        wifi_util_dbg_print(WIFI_CTRL,"%sWrong data type %s\n",__FUNCTION__,name);
        return rc;
    }

    sta_disconnect = rbusValue_GetBoolean(value);
    if (sta_disconnect) {
        rc = RBUS_ERROR_SUCCESS;
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus set bool %d\n",__FUNCTION__, sta_disconnect);
        push_data_to_ctrl_queue(&sta_disconnect, sizeof(sta_disconnect), ctrl_event_type_command, ctrl_event_type_trigger_disconnection);
    }

    return rc;
}

rbusError_t set_kickassoc_command(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    rbusValueType_t type = rbusValue_GetType(value);
    int rc = RBUS_ERROR_INVALID_INPUT;
    int len = 0;
    const char * pTmp = NULL;

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);
    if (type != RBUS_STRING) {
        wifi_util_dbg_print(WIFI_CTRL,"%sWrong data type %s\n",__FUNCTION__,name);
        return rc;
    }

    pTmp = rbusValue_GetString(value, &len);
    if (pTmp != NULL) {
        rc = RBUS_ERROR_SUCCESS;
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus set string %s\n",__FUNCTION__, pTmp);
        push_data_to_ctrl_queue(pTmp, (strlen(pTmp) + 1), ctrl_event_type_command, ctrl_event_type_command_kick_assoc_devices);
    }

    return rc;
}

rbusError_t set_wifiapi_command(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    rbusValueType_t type = rbusValue_GetType(value);
    int rc = RBUS_ERROR_INVALID_INPUT;
    int len = 0;
    const char * pTmp = NULL;

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);
    if (type != RBUS_STRING) {
        wifi_util_dbg_print(WIFI_CTRL,"%sWrong data type %s\n",__FUNCTION__,name);
        return rc;
    }

    pTmp = rbusValue_GetString(value, &len);
    if (pTmp != NULL) {
        rc = RBUS_ERROR_SUCCESS;
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus set string len=%d\n",__FUNCTION__,len);
        push_data_to_ctrl_queue((char *)pTmp, (strlen(pTmp) + 1), ctrl_event_type_wifiapi, ctrl_event_type_wifiapi_execution);
    }
    return rc;
}

rbusError_t wifiapi_event_handler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    (void)handle;
    (void)filter;
    (void)autoPublish;
    (void)interval;
    wifi_util_dbg_print(WIFI_CTRL,
        "wifiapi_event_handler called:\n" \
        "\taction=%s\n" \
        "\teventName=%s\n",
        action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe",
        eventName);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t hotspot_event_handler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    (void)handle;
    (void)filter;
    (void)autoPublish;
    (void)interval;
    wifi_util_dbg_print(WIFI_CTRL,
        "hotspot_event_handler called:\n" \
        "\taction=%s\n" \
        "\teventName=%s\n",
        action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe",
        eventName);

    return RBUS_ERROR_SUCCESS;
}

int wifiapi_result_publish(void)
{
    int rc = RBUS_ERROR_SUCCESS;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }
    rbusValue_t value;
    rbusObject_t data;

    rbusValue_Init(&value);

    pthread_mutex_unlock(&ctrl->lock);

    if (ctrl->wifiapi.result == NULL) {
        rbusValue_SetString(value, "Result not avaiable");
    } else {
        rbusValue_SetString(value, ctrl->wifiapi.result);
    }

    rbusObject_Init(&data, NULL);
    rbusObject_SetValue(data, "value", value);

    rbusEvent_t event;
    event.name = WIFI_RBUS_WIFIAPI_RESULT;
    event.data = data;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(ctrl->rbus_handle, &event);

    pthread_mutex_unlock(&ctrl->lock);

    if(rc != RBUS_ERROR_SUCCESS)
        wifi_util_error_print(WIFI_CTRL,"%s:%d rbusEvent_Publish %s failed: %d\n", __func__,
                                    event.name ,__LINE__, rc);

    rbusValue_Release(value);
    rbusObject_Release(data);

    return rc;
}

//Function used till the rbus_get invalid context issue is resolved
void get_assoc_devices_blob(char *str)
{
    webconfig_subdoc_data_t data;
#if DML_SUPPORT
    assoc_dev_data_t *assoc_dev_data;
    int itr, itrj;
#endif
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if ((mgr == NULL) || (ctrl == NULL)) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
        return;
    }

#if DML_SUPPORT
    pthread_mutex_lock(&ctrl->lock);
    for (itr=0; itr<MAX_NUM_RADIOS; itr++) {
        for (itrj=0; itrj<MAX_NUM_VAP_PER_RADIO; itrj++) {
            if (mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_map != NULL) {
                assoc_dev_data = hash_map_get_first(mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_map);
                while (assoc_dev_data != NULL) {
                    get_sta_stats_info(assoc_dev_data);
                    assoc_dev_data = hash_map_get_next(mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_map, assoc_dev_data);
                }
            }
        }
    }
    pthread_mutex_unlock(&ctrl->lock);

#endif
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));

    data.u.decoded.num_radios = getNumberRadios();
    data.u.decoded.assoclist_notifier_type = assoclist_notifier_full;

    webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_associated_clients);
    memcpy(str, data.u.encoded.raw, strlen(data.u.encoded.raw));

    return;
}

rbusError_t get_acl_device_data(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if ((mgr == NULL) || (ctrl == NULL)) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);

    if (strncmp(name, WIFI_WEBCONFIG_GET_ACL, strlen(WIFI_WEBCONFIG_GET_ACL)+1) != 0) {
        wifi_util_error_print(WIFI_CTRL,"%s Rbus property invalid '%s'\n",__FUNCTION__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&mgr->hal_cap, sizeof(wifi_hal_capability_t));

    data.u.decoded.num_radios = getNumberRadios();

    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_mac_filter) == webconfig_error_none) {
        rbusValue_SetString(value, data.u.encoded.raw);
        rbusProperty_SetValue(property, value);
        wifi_util_info_print(WIFI_DMCLI, "%s: ACL DML cache encoded successfully  \n", __FUNCTION__);
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s: ACL DML cache encode failed  \n", __FUNCTION__);
    }

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;

}

extern void webconf_process_private_vap(const char* enb);
rbusError_t get_private_vap(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    rbusValueType_t type = rbusValue_GetType(value);
    int rc = RBUS_ERROR_INVALID_INPUT;

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);
    if (type != RBUS_STRING) {
        wifi_util_error_print(WIFI_CTRL,"%sWrong data type %s\n",__FUNCTION__,name);
        return rc;
    }

    int len = 0;
    const char* pTmp = rbusValue_GetString(value, &len);
    if(pTmp == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s null string data recvd\n", __FUNCTION__ );
        return rc;
    }

    rc = RBUS_ERROR_SUCCESS;
    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus set string len=%d, str: \n%s\n",__FUNCTION__, len, pTmp);

    wifidb_print("%s:%d [Start] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());
    webconf_process_private_vap(pTmp);

    return rc;
}

extern void webconf_process_home_vap(const char* enb);
rbusError_t get_home_vap(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    rbusValueType_t type = rbusValue_GetType(value);
    int rc = RBUS_ERROR_INVALID_INPUT;
    int len = 0;
    const char * pTmp = NULL;

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);
    if (type != RBUS_STRING) {
        wifi_util_error_print(WIFI_CTRL,"%sWrong data type %s\n",__FUNCTION__,name);
        return rc;
    }

    pTmp = rbusValue_GetString(value, &len);
    if (pTmp != NULL) {
        rc = RBUS_ERROR_SUCCESS;
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus set string len=%d, str: %s\n",__FUNCTION__,len, pTmp);
    }

    wifidb_print("%s:%d [Start] Current time:[%llu]\r\n", __func__, __LINE__, get_current_ms_time());
    webconf_process_home_vap(pTmp);

    return rc;
}

#if defined (RDKB_EXTENDER_ENABLED) || defined (WAN_FAILOVER_SUPPORTED) 
static void deviceModeHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    int device_mode;
    UNREFERENCED_PARAMETER(handle);

    if(!event) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d null event\n", __func__, __LINE__);
        return;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d recvd event:%s\n",  __func__, __LINE__, event->name);

    rbusValue_t value = rbusObject_GetValue(event->data, NULL);
    if (!value) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Invalid value for event:%s \n",
                                       __func__, __LINE__, event->name);
        return;
    }

    if (strcmp(event->name, WIFI_DEVICE_MODE) == 0) {
        device_mode = rbusValue_GetUInt32(value);
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: event:%s: value:%d\n", __func__, __LINE__, event->name, device_mode);
        push_data_to_ctrl_queue(&device_mode, sizeof(device_mode), ctrl_event_type_command, ctrl_event_type_device_network_mode);

    } else {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Unsupported event:%s\n", __func__, __LINE__, event->name);
    }
}
#endif
static void testDeviceModeHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    int device_mode;
    UNREFERENCED_PARAMETER(handle);

    if(!event) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d null event\n", __func__, __LINE__);
        return;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d recvd event:%s\n",  __func__, __LINE__, event->name);

    rbusValue_t value = rbusObject_GetValue(event->data, subscription->eventName);
    if (!value) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Invalid value in event:%s\n",
                    __func__, __LINE__, event->name);
        return;
    }

    if (strcmp(event->name, TEST_WIFI_DEVICE_MODE) == 0) {
        device_mode = rbusValue_GetUInt32(value);
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: event:%s: value:%d\n", __func__, __LINE__, event->name, device_mode);
        push_data_to_ctrl_queue(&device_mode, sizeof(device_mode), ctrl_event_type_command, ctrl_event_type_device_network_mode);
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Unsupported event:%s\n", __func__, __LINE__, event->name);
    }
}

static void meshStatusHandler(rbusHandle_t handle, rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    UNREFERENCED_PARAMETER(handle);

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Recvd Event\n",  __func__, __LINE__);
    if(!event) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d null event\n", __func__, __LINE__);
        return;
    }

    if(strcmp(subscription->eventName, MESH_STATUS) != 0) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d Invalid event received, %s\n", __func__, __LINE__, subscription->eventName);
        return;
    }

    bool mesh_status = false;

    rbusValue_t value = rbusObject_GetValue(event->data, NULL);
    if (!value) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid value in event:%s\n", __func__, __LINE__, subscription->eventName);
        return;
    }

    mesh_status = rbusValue_GetBoolean(value);
    push_data_to_ctrl_queue(&mesh_status, sizeof(mesh_status), ctrl_event_type_command, ctrl_event_type_command_mesh_status);
}

static void eventReceiveHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    bool tunnel_status = false;
    int len =0 ;
    UNREFERENCED_PARAMETER(handle);

    wifi_util_dbg_print(WIFI_CTRL, " %s:%d Recvd Event\n",  __func__, __LINE__);
    if(!event) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d null event\n", __func__, __LINE__);
        return;
    }

    rbusValue_t value = rbusObject_GetValue(event->data, NULL);
    if (!value) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid value in event:%s\n",
                    __func__, __LINE__, event->name);
        return;
    }

    if (strcmp(event->name, WIFI_DEVICE_TUNNEL_STATUS) == 0) {
        const char * pTmp = rbusValue_GetString(value, &len);
        if(pTmp == NULL) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d: Unable to get  value in event:%s\n", __func__, __LINE__);
            return;
        }
        if(strcmp(pTmp,"Up") == 0) {
            tunnel_status = true;
        } else if(strcmp(pTmp,"Down") == 0) {
            tunnel_status = false;
        } else {
            wifi_util_error_print(WIFI_CTRL, "%s:%d: Received Unsupported value\n", __func__, __LINE__);
            return;
        }
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: event:%s: value:%d\n", __func__, __LINE__, event->name, tunnel_status);

    } else {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Unsupported event:%s\n", __func__, __LINE__, event->name);
        return;
    }
    ctrl_event_subtype_t ces_t = tunnel_status ? ctrl_event_type_xfinity_tunnel_up : ctrl_event_type_xfinity_tunnel_down;
    push_data_to_ctrl_queue(&tunnel_status, sizeof(tunnel_status), ctrl_event_type_command, ces_t);
}

static void frame_802_11_injector_Handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    frame_data_t *data_ptr;
    const unsigned char *rbus_data;
    int len = 0;
    frame_data_t frame_data;
    UNREFERENCED_PARAMETER(handle);
    memset(&frame_data, 0, sizeof(frame_data));

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Recvd Event\n",  __func__, __LINE__);
    if(!event) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d null event\n", __func__, __LINE__);
        return;
    }

    rbusValue_t value = rbusObject_GetValue(event->data, subscription->eventName);
    if (!value) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid value in event:%s\n",
                    __func__, __LINE__, event->name);
        return;
    }

    rbus_data = rbusValue_GetBytes(value, &len);
    data_ptr = (frame_data_t *)rbus_data;
    if (data_ptr != NULL && len != 0) {
        memcpy((uint8_t *)&frame_data.frame.sta_mac, (uint8_t *)&data_ptr->frame.sta_mac, sizeof(mac_address_t));
        frame_data.frame.ap_index = data_ptr->frame.ap_index;
        frame_data.frame.len = data_ptr->frame.len;
        frame_data.frame.type = data_ptr->frame.type;
        frame_data.frame.dir = data_ptr->frame.dir;
        frame_data.frame.sig_dbm = data_ptr->frame.sig_dbm;
        frame_data.frame.data = data_ptr->frame.data;

        memcpy(&frame_data.data, data_ptr->data, data_ptr->frame.len);
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: vap_index:%d len:%d frame_byte:%d\r\n", __func__, __LINE__, frame_data.frame.ap_index, len, frame_data.frame.len);
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: frame_data.type:%d frame_data.dir:%d frame_data.sig_dbm:%d\r\n", __func__, __LINE__, frame_data.frame.type, frame_data.frame.dir, frame_data.frame.sig_dbm);
#ifdef WIFI_HAL_VERSION_3_PHASE2
        mgmt_wifi_frame_recv(frame_data.frame.ap_index, &frame_data.frame);
#else
#if defined (_XB7_PRODUCT_REQ_) && defined (_COSA_BCM_ARM_) && !defined(_XB8_PRODUCT_REQ_)
        mgmt_wifi_frame_recv(frame_data.frame.ap_index,frame_data.frame.sta_mac,frame_data.data,frame_data.frame.len,frame_data.frame.type,frame_data.frame.dir, frame_data.frame.sig_dbm);
#else
        mgmt_wifi_frame_recv(frame_data.frame.ap_index,frame_data.frame.sta_mac,frame_data.data,frame_data.frame.len,frame_data.frame.type,frame_data.frame.dir);
#endif
#endif

    }
}

static void wps_test_event_receive_handler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    uint32_t vap_index = 0;
    UNREFERENCED_PARAMETER(handle);

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Recvd Event\n",  __func__, __LINE__);

    if(!event) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d null event\n", __func__, __LINE__);
        return;
    }

    rbusValue_t value = rbusObject_GetValue(event->data, subscription->eventName);
    if (!value) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Invalid value in event:%s\n",
                    __func__, __LINE__, event->name);
        return;
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus event name=%s\n",__func__, __LINE__, event->name);

    vap_index = rbusValue_GetUInt32(value);
    if (wifi_util_is_vap_index_valid(&((wifi_mgr_t*) get_wifimgr_obj())->hal_cap.wifi_prop, (int)vap_index)) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi wps test vap_index:%d\n",__func__, __LINE__, vap_index);
        push_data_to_ctrl_queue(&vap_index, sizeof(vap_index), ctrl_event_type_command, ctrl_event_type_command_wps);
    } else {
        uint32_t max_vaps = MAX_NUM_VAP_PER_RADIO * getNumberRadios();
        wifi_util_error_print(WIFI_CTRL,"%s:%d wifi wps test invalid vap_index:%d max_vap:%d\n",__func__, __LINE__,
                vap_index, max_vaps);
    }
}

void rbus_subscribe_events(wifi_ctrl_t *ctrl)
{
    rbusEventSubscription_t rbusMarkerEvents[] = {
        { WIFI_NORMALIZED_RSSI_LIST, NULL, 0, 0, MarkerListConfigHandler, NULL, NULL, NULL, false},
        { WIFI_SNR_LIST, NULL, 0, 0, MarkerListConfigHandler, NULL, NULL, NULL, false},
        { WIFI_CLI_STAT_LIST, NULL, 0, 0, MarkerListConfigHandler, NULL, NULL, NULL, false},
        { WIFI_TxRx_RATE_LIST, NULL, 0, 0, MarkerListConfigHandler, NULL, NULL, NULL, false},
    };

    int consumer_app_file = -1;
    char file_name[512] = "/tmp/wifi_webconfig_consumer_app";
    consumer_app_file =  access(file_name, F_OK);

    if(consumer_app_file == 0 && ctrl->rbus_events_subscribed == false) {
        if (rbusEvent_Subscribe(ctrl->rbus_handle, WIFI_WAN_FAILOVER_TEST, wan_failover_handler, NULL, 0) != RBUS_ERROR_SUCCESS) {
            //wifi_util_dbg_print(WIFI_CTRL, "%s:%d Rbus event:%s subscribe failed\n",__FUNCTION__, __LINE__, WIFI_WAN_FAILOVER_TEST);
        } else {
            ctrl->rbus_events_subscribed = true;
            wifi_util_info_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe success\n",__FUNCTION__, __LINE__, WIFI_WAN_FAILOVER_TEST);
        }
    }

    if(ctrl->marker_list_config_subscribed == false) {
        if (rbusEvent_SubscribeEx(ctrl->rbus_handle, rbusMarkerEvents, ARRAY_SIZE(rbusMarkerEvents), 0) != RBUS_ERROR_SUCCESS) {
        } else {
            ctrl->marker_list_config_subscribed = true;
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus event subscribe success\n",__FUNCTION__, __LINE__);
        }
    }

#if defined(GATEWAY_FAILOVER_SUPPORTED)
    if(ctrl->active_gateway_check_subscribed == false) {
        if (rbusEvent_Subscribe(ctrl->rbus_handle, WIFI_ACTIVE_GATEWAY_CHECK, activeGatewayCheckHandler, NULL, 0) != RBUS_ERROR_SUCCESS) {
            //wifi_util_dbg_print(WIFI_CTRL, "%s:%d Rbus event:%s subscribe failed\n",__FUNCTION__, __LINE__, WIFI_ACTIVE_GATEWAY_CHECK);
        } else {
            ctrl->active_gateway_check_subscribed = true;
            wifi_util_info_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe success\n",__FUNCTION__, __LINE__, WIFI_ACTIVE_GATEWAY_CHECK);
        }
    }
#endif

    if(consumer_app_file == 0 && ctrl->tunnel_events_subscribed == false) {
        //TODO - what's the namespace for the event
        int rc = rbusEvent_Subscribe(ctrl->rbus_handle, "TunnelStatus", hotspotTunnelHandler, NULL, 0);
        if(rc != RBUS_ERROR_SUCCESS) {
            //wifi_util_dbg_print(WIFI_CTRL,"%s:%d TunnelStatus subscribe Failed, rc: %d\n",__FUNCTION__, __LINE__, rc);
        }
        else {
            ctrl->tunnel_events_subscribed = true;
            wifi_util_info_print(WIFI_CTRL,"%s:%d TunnelStatus subscribe success, rc: %d\n",__FUNCTION__, __LINE__, rc);
        }
    }

    if(ctrl->mesh_status_subscribed == false) {
        int rc = rbusEvent_Subscribe(ctrl->rbus_handle, MESH_STATUS, meshStatusHandler, NULL, 0);
        if(rc != RBUS_ERROR_SUCCESS) {
            // wifi_util_dbg_print(WIFI_CTRL,"%s:%d MeshStatus subscribe Failed, rc: %d\n",__FUNCTION__, __LINE__, rc);
        } else {
            ctrl->mesh_status_subscribed = true;
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d MeshStatus subscribe success, rc: %d\n",__FUNCTION__, __LINE__, rc);
        }
    }

#if defined (RDKB_EXTENDER_ENABLED) || defined (WAN_FAILOVER_SUPPORTED)
    if(ctrl->device_mode_subscribed == false) {
        if (rbusEvent_Subscribe(ctrl->rbus_handle, WIFI_DEVICE_MODE, deviceModeHandler, NULL, 0) != RBUS_ERROR_SUCCESS) {
            //wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe failed\n",__FUNCTION__, __LINE__, WIFI_DEVICE_MODE);
        } else {
            ctrl->device_mode_subscribed = true;
            wifi_util_info_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe success\n",__FUNCTION__, __LINE__, WIFI_DEVICE_MODE);
        }
    }
#endif

    if(ctrl->device_tunnel_status_subscribed == false) {
        if (rbusEvent_Subscribe(ctrl->rbus_handle, WIFI_DEVICE_TUNNEL_STATUS, eventReceiveHandler, NULL, 0) != RBUS_ERROR_SUCCESS) {
            //wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe failed\n",__FUNCTION__, __LINE__, WIFI_DEVICE_TUNNEL_STATUS);
        } else {
            ctrl->device_tunnel_status_subscribed = true;
            wifi_util_info_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe success\n",__FUNCTION__, __LINE__, WIFI_DEVICE_TUNNEL_STATUS);
        }
    }

    if(consumer_app_file == 0 && ctrl->device_wps_test_subscribed == false) {
        if (rbusEvent_Subscribe(ctrl->rbus_handle, RBUS_WIFI_WPS_PIN_START, wps_test_event_receive_handler, NULL, 0) != RBUS_ERROR_SUCCESS) {
            //wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe failed\n",__FUNCTION__, __LINE__, RBUS_WIFI_WPS_PIN_START);
        } else {
            ctrl->device_wps_test_subscribed = true;
            wifi_util_info_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe success\n",__FUNCTION__, __LINE__, RBUS_WIFI_WPS_PIN_START);
        }
    }

    if(consumer_app_file == 0 && ctrl->test_device_mode_subscribed == false) {
        if (rbusEvent_Subscribe(ctrl->rbus_handle, TEST_WIFI_DEVICE_MODE, testDeviceModeHandler, NULL, 0) != RBUS_ERROR_SUCCESS) {
            //wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe failed\n",__FUNCTION__, __LINE__, TEST_WIFI_DEVICE_MODE);
        } else {
            ctrl->test_device_mode_subscribed = true;
            wifi_util_info_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe success\n",__FUNCTION__, __LINE__, TEST_WIFI_DEVICE_MODE);
        }
    }

    if (consumer_app_file == 0 && ctrl->frame_802_11_injector_subscribed == false) {
        if (rbusEvent_Subscribe(ctrl->rbus_handle, WIFI_FRAME_INJECTOR_TO_ONEWIFI, frame_802_11_injector_Handler, NULL, 0) != RBUS_ERROR_SUCCESS) {
            //wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe failed\n",__FUNCTION__, __LINE__, WIFI_FRAME_INJECTOR_TO_ONEWIFI);
        } else {
            ctrl->frame_802_11_injector_subscribed = true;
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus event:%s subscribe success\n",__FUNCTION__, __LINE__, WIFI_FRAME_INJECTOR_TO_ONEWIFI);
        }
    }

}

rbusError_t get_sta_connection_timeout(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;
    vap_svc_t *ext_svc;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);

    rbusValue_Init(&value);
    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    if (ext_svc != NULL) {
        if (strcmp(name, WIFI_STA_SELFHEAL_CONNECTION_TIMEOUT) == 0) {
            rbusValue_SetBoolean(value, ext_svc->u.ext.selfheal_status);
        }
    }

    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t get_sta_attribs(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;
    unsigned int index, vap_index = 0, i;
    char extension[64] = {0};
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_vap_info_map_t *vap_map;
    wifi_sta_conn_info_t sta_conn_info;
    memset(&sta_conn_info, 0, sizeof(wifi_sta_conn_info_t));
    wifi_interface_name_t *l_interface_name;
    mac_address_t l_bssid = {0};
    memset(l_bssid, 0, sizeof(l_bssid));

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);



    sscanf(name, "Device.WiFi.STA.%d.%s", &index, extension);
    if (index > getNumberRadios()) {
        wifi_util_error_print(WIFI_CTRL,"%s Invalid index %d\n",__FUNCTION__, index);
        return RBUS_ERROR_INVALID_INPUT;
    }

    vap_map = &mgr->radio_config[(index - 1)].vaps.vap_map;
    vap_index = get_sta_vap_index_for_radio(&mgr->hal_cap.wifi_prop, index-1);

    rbusValue_Init(&value);

    if (strcmp(extension, "Connection.Status") == 0) {
        for (i = 0; i < vap_map->num_vaps; i++) {
            if (vap_map->vap_array[i].vap_index == vap_index) {
                sta_conn_info.connect_status = vap_map->vap_array[i].u.sta_info.conn_status;
                memcpy (sta_conn_info.bssid, vap_map->vap_array[i].u.sta_info.bssid, sizeof(vap_map->vap_array[i].u.sta_info.bssid));
                break;
            }
        }

        rbusValue_SetBytes(value, (uint8_t *)&sta_conn_info, sizeof(sta_conn_info));
    } else if (strcmp(extension, "Bssid") == 0) {
        for (i = 0; i < vap_map->num_vaps; i++) {
            if (vap_map->vap_array[i].vap_index == vap_index) {
                memcpy(l_bssid, vap_map->vap_array[i].u.sta_info.bssid, sizeof(l_bssid));
                break;
            }
        }

        rbusValue_SetBytes(value, (uint8_t *)l_bssid, sizeof(l_bssid));
    } else if (strcmp(extension, "InterfaceName") == 0) {
        l_interface_name = get_interface_name_for_vap_index(vap_index, &mgr->hal_cap.wifi_prop);
        rbusValue_SetString(value, *l_interface_name);
    }

    // the encoded data is a string
    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t set_sta_attribs(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
//    rbusValue_t value = rbusProperty_GetValue(property);

    (void)handle;
    (void)opts;

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d handler\r\n",__FUNCTION__, __LINE__);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d: setHandler1 called: property=%s\n", __func__, __LINE__, name);
    return RBUS_ERROR_SUCCESS;
}

rbusError_t events_STAtable_removerowhandler(rbusHandle_t handle, char const* rowName)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    ctrl->sta_tree_instance_num--;
    wifi_util_dbg_print(WIFI_CTRL,
        "tableRemoveRowHandler1 called:\n" \
        "\trowName=%s: instance_num:%d\n", rowName, ctrl->sta_tree_instance_num);
    return RBUS_ERROR_SUCCESS;
}

rbusError_t events_STAtable_addrowhandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d handler\r\n",__FUNCTION__, __LINE__);
        wifi_util_dbg_print(WIFI_CTRL,
        "tableAddRowHandler1 called:\n" \
        "\ttableName=%s\n" \
        "\taliasName=%s\n",
        tableName, aliasName);

    *instNum = ++ctrl->sta_tree_instance_num;
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d instance_num:%d\r\n",__func__, __LINE__, ctrl->sta_tree_instance_num);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t eventSubHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    (void)handle;
    (void)filter;
    (void)interval;
    *autoPublish = false;
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d eventSubHandler called: action=%s\n eventName=%s autoPublish:%d\n",
        __func__, __LINE__, action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe",
        eventName, *autoPublish);

    return RBUS_ERROR_SUCCESS;
}

void rbus_register_handlers(wifi_ctrl_t *ctrl)
{
    int rc = RBUS_ERROR_SUCCESS;
    unsigned char num_of_radio = 0, index = 0;
    char *component_name = "WifiCtrl";
    rbusDataElement_t dataElements[] = {
                                { WIFI_WEBCONFIG_DOC_DATA_SOUTH, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, webconfig_set_subdoc, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_DOC_DATA_NORTH, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_INIT_DATA, RBUS_ELEMENT_TYPE_METHOD,
                                { webconfig_get_subdoc, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_INIT_DML_DATA, RBUS_ELEMENT_TYPE_METHOD,
                                { webconfig_get_dml_subdoc, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_GET_ASSOC, RBUS_ELEMENT_TYPE_METHOD,
                                { get_assoc_clients_data, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_STA_NAMESPACE, RBUS_ELEMENT_TYPE_TABLE,
                                { NULL, NULL, events_STAtable_addrowhandler, events_STAtable_removerowhandler, eventSubHandler, NULL}},
                                { WIFI_STA_CONNECT_STATUS, RBUS_ELEMENT_TYPE_PROPERTY,
                                { get_sta_attribs, set_sta_attribs, NULL, NULL, eventSubHandler, NULL }},
                                { WIFI_STA_INTERFACE_NAME, RBUS_ELEMENT_TYPE_PROPERTY,
                                { get_sta_attribs, set_sta_attribs, NULL, NULL, eventSubHandler, NULL }},
                                { WIFI_STA_CONNECTED_GW_BSSID, RBUS_ELEMENT_TYPE_PROPERTY,
                                { get_sta_attribs, set_sta_attribs, NULL, NULL, eventSubHandler, NULL }},
                                { WIFI_RBUS_WIFIAPI_COMMAND, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, set_wifiapi_command, NULL, NULL, NULL, NULL }},
                                {WIFI_RBUS_WIFIAPI_RESULT, RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, wifiapi_event_handler, NULL}},
                                { WIFI_WEBCONFIG_GET_CSI, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, NULL, NULL, NULL, NULL, NULL}},
                                { WIFI_WEBCONFIG_GET_ACL, RBUS_ELEMENT_TYPE_METHOD,
                                { get_acl_device_data, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_PRIVATE_VAP, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, get_private_vap, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_HOME_VAP, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, get_home_vap, NULL, NULL, NULL, NULL }},
                                {WIFI_RBUS_HOTSPOT_UP, RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, hotspot_event_handler, NULL}},
                                {WIFI_RBUS_HOTSPOT_DOWN, RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, hotspot_event_handler, NULL}},
                                {WIFI_WEBCONFIG_KICK_MAC, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, set_kickassoc_command, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_GET_NULL_SUBDOC, RBUS_ELEMENT_TYPE_METHOD,
                                { get_null_subdoc_data, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_STA_TRIGGER_DISCONNECTION, RBUS_ELEMENT_TYPE_METHOD,
                                { get_sta_disconnection, set_sta_disconnection, NULL, NULL, NULL, NULL}}, 
                                { WIFI_STA_SELFHEAL_CONNECTION_TIMEOUT, RBUS_ELEMENT_TYPE_EVENT,
                                { get_sta_connection_timeout, NULL, NULL, NULL, NULL, NULL}},
    };

    rc = rbus_open(&ctrl->rbus_handle, component_name);

    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL,"%s Rbus open failed\n",__FUNCTION__);
        return;
    }

    wifi_util_info_print(WIFI_CTRL,"%s rbus open success\n",__FUNCTION__);

    rc = rbus_regDataElements(ctrl->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL,"%s rbus_regDataElements failed\n",__FUNCTION__);
        rbus_unregDataElements(ctrl->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
        rbus_close(ctrl->rbus_handle);
    }

    num_of_radio = getNumberRadios();
    for (index = 0; index < num_of_radio; index++) {
        rc = rbusTable_addRow(ctrl->rbus_handle, "Device.WiFi.STA.", NULL, NULL);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            wifi_util_info_print(WIFI_MON, "%s() rbusTable_addRow failed for Device.WiFi.STA.%d\n", __FUNCTION__, rc);
        }
    }

    wifi_util_info_print(WIFI_CTRL,"%s rbus event register:[%s]:%s\r\n",__FUNCTION__, WIFI_STA_2G_VAP_CONNECT_STATUS, WIFI_STA_5G_VAP_CONNECT_STATUS);

    return;
}

