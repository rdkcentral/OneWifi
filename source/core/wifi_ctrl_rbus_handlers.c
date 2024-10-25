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
#include "wifi_monitor.h"
#include <unistd.h>
#include <rbus.h>

#define MAX_EVENT_NAME_SIZE     200

int webconfig_csi_notify_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_encoded_data_t *data)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    int rc;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, WIFI_WEBCONFIG_GET_CSI, value);
    rbusValue_SetString(value, data->raw);
    event.name = WIFI_WEBCONFIG_GET_CSI;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);

        rbusValue_Release(value);
        rbusObject_Release(rdata);

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
    rbusValue_SetString(value, data->raw);
    event.name = WIFI_WEBCONFIG_GET_ASSOC;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);

        rbusValue_Release(value);
        rbusObject_Release(rdata);

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
    rbusValue_SetString(value, data->raw);
    event.name = WIFI_WEBCONFIG_GET_NULL_SUBDOC;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);

        rbusValue_Release(value);
        rbusObject_Release(rdata);

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

int notify_force_disassociation(wifi_ctrl_t *ctrl, int band, char *threshold, mac_addr_str_t mac, int ap_index)
{
    int rc;
    char str[2048];
    wifi_vap_info_t *vap_info = NULL;
    memset(str, 0, 2048);

    vap_info = getVapInfo(ap_index);

    if (ctrl == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    snprintf(str, sizeof(str), "%d, %s, %s", band, threshold, mac);

    if (vap_info != NULL) {
        strncpy(vap_info->u.bss_info.postassoc.client_force_disassoc_info, str, sizeof(vap_info->u.bss_info.postassoc.client_force_disassoc_info));
    }

    rc = rbus_setStr(ctrl->rbus_handle, WIFI_NOTIFY_FORCE_DISASSOCIATION, str);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusWrite Failed %d\n", __func__, __LINE__, rc);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int notify_deny_association(wifi_ctrl_t *ctrl, int band, char *threshold, mac_addr_str_t mac, int ap_index)
{
    int rc;
    char str[2048];
    wifi_vap_info_t *vap_info = NULL;

    memset(str, 0, 2048);

    if (ctrl == NULL ) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    vap_info = getVapInfo(ap_index);

    snprintf(str, sizeof(str), "%d, %s, %s", band, threshold, mac);

    if (vap_info != NULL) {
        strncpy(vap_info->u.bss_info.preassoc.client_deny_assoc_info, str, sizeof(vap_info->u.bss_info.preassoc.client_deny_assoc_info));
    }

    rc = rbus_setStr(ctrl->rbus_handle, WIFI_NOTIFY_DENY_ASSOCIATION, str);
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

 int webconfig_rbus_apply_for_dml_thread_update(wifi_ctrl_t *ctrl, webconfig_subdoc_encoded_data_t *data)
 {
     rbusEvent_t event;
     rbusObject_t rdata;
     rbusValue_t value;
     int rc;
     rbusValue_Init(&value);
     rbusObject_Init(&rdata, NULL);

     rbusObject_SetValue(rdata, WIFI_WEBCONFIG_INIT_DML_DATA, value);
     rbusValue_SetString(value, data->raw);
     event.name = WIFI_WEBCONFIG_INIT_DML_DATA;
     event.data = rdata;
     event.type = RBUS_EVENT_GENERAL;

     rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
     if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
         wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);

         rbusValue_Release(value);
         rbusObject_Release(rdata);

         return RETURN_ERR;
     }

     rbusValue_Release(value);
     rbusObject_Release(rdata);

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
    rbusValue_SetString(value, data->raw);
    event.name = WIFI_WEBCONFIG_DOC_DATA_NORTH;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    rc = rbusEvent_Publish(ctrl->rbus_handle, &event);
    if ((rc != RBUS_ERROR_SUCCESS) && (rc != RBUS_ERROR_NOSUBSCRIBERS)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed %d\n", __func__, __LINE__, rc);

        rbusValue_Release(value);
        rbusObject_Release(rdata);

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
    unsigned int num_of_radios = getNumberRadios();
    #define MAX_ACSD_SYNC_TIME_WAIT 12
    static int sync_retries = 0;

    if (!ctrl->ctrl_initialized) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d: Ctrl not initialized skip request.\n",__FUNCTION__, __LINE__);
        return RBUS_ERROR_INVALID_OPERATION;
     }

   if (ctrl->network_mode == rdk_dev_mode_type_gw) {
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

        if (check_wifi_radio_sched_timeout_active_status(ctrl) == true) {
            wifi_util_dbg_print(WIFI_CTRL,"%s wifidb and cache are not synced!\n", __FUNCTION__);
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
        push_event_to_ctrl_queue((const cJSON *)pTmp, (strlen(pTmp) + 1), wifi_event_type_webconfig, wifi_event_webconfig_set_data_ovsm, NULL);
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
        list_type = wifi_event_type_normalized_rssi;

    } else if(strcmp(subscription->eventName, WIFI_SNR_LIST) == 0) {
        list_type = wifi_event_type_snr;

    } else if(strcmp(subscription->eventName, WIFI_CLI_STAT_LIST) == 0) {
        list_type = wifi_event_type_cli_stat;

    } else if(strcmp(subscription->eventName, WIFI_TxRx_RATE_LIST) == 0) {
        list_type = wifi_event_type_txrx_rate;

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
    push_event_to_ctrl_queue(pTmp, (strlen(pTmp) + 1), wifi_event_type_command, list_type, NULL);

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
    push_event_to_ctrl_queue(&other_gateway_present, sizeof(other_gateway_present), wifi_event_type_command, wifi_event_type_command_sta_connect, NULL);

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

    wifi_event_subtype_t ces_t = tunnel_status ? wifi_event_type_xfinity_tunnel_up : wifi_event_type_xfinity_tunnel_down;
    push_event_to_ctrl_queue(&tunnel_status, sizeof(tunnel_status), wifi_event_type_command, ces_t, NULL);
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
        rbusValue_SetUInt32(value, 0);
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
    unsigned int disconnection_type = 0;

    if (type != RBUS_UINT32) {
        wifi_util_dbg_print(WIFI_CTRL,"%sWrong data type %s\n",__FUNCTION__,name);
        return RBUS_ERROR_INVALID_INPUT;
    }

    // 0 - no action
    // 1 - disconnection
    // 2 - disconnection + ignore current radio on next scan
    disconnection_type = rbusValue_GetUInt32(value);
    wifi_util_dbg_print(WIFI_CTRL, "%s Rbus set %d\n", __FUNCTION__, disconnection_type);
    push_event_to_ctrl_queue(&disconnection_type, sizeof(disconnection_type),
        wifi_event_type_command, wifi_event_type_trigger_disconnection, NULL);

    return RBUS_ERROR_SUCCESS;
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
        push_event_to_ctrl_queue(pTmp, (strlen(pTmp) + 1), wifi_event_type_command, wifi_event_type_command_kick_assoc_devices, NULL);
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
        push_event_to_ctrl_queue((char *)pTmp, (strlen(pTmp) + 1), wifi_event_type_wifiapi, wifi_event_type_wifiapi_execution, NULL);
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
        push_event_to_ctrl_queue(&device_mode, sizeof(device_mode), wifi_event_type_command, wifi_event_type_device_network_mode, NULL);

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
        push_event_to_ctrl_queue(&device_mode, sizeof(device_mode), wifi_event_type_command, wifi_event_type_device_network_mode, NULL);
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
    push_event_to_ctrl_queue(&mesh_status, sizeof(mesh_status), wifi_event_type_command, wifi_event_type_command_mesh_status, NULL);
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
    wifi_event_subtype_t ces_t = tunnel_status ? wifi_event_type_xfinity_tunnel_up : wifi_event_type_xfinity_tunnel_down;
    push_event_to_ctrl_queue(&tunnel_status, sizeof(tunnel_status), wifi_event_type_command, ces_t, NULL);
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
#if defined (_XB7_PRODUCT_REQ_)
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
        push_event_to_ctrl_queue(&vap_index, sizeof(vap_index), wifi_event_type_command, wifi_event_type_command_wps, NULL);
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

#ifdef CCSP_COMMON
static event_rbus_element_t *events_getEventElement(char *eventName)
{
    int i;
    event_rbus_element_t *event;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    int count = queue_count(ctrl->events_rbus_data.events_rbus_queue);

    if (count == 0) {
        return NULL;
    }

    for (i = 0; i < count; i++) {
        event = queue_peek(ctrl->events_rbus_data.events_rbus_queue, i);
        if ((event != NULL) && (strncmp(event->name, eventName, MAX_EVENT_NAME_SIZE) == 0)) {
            return event;
        }
    }
    return NULL;
}
#endif

rbusError_t eventSubHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(filter);

    *autoPublish = false;
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d eventSubHandler called: action=%s\n eventName=%s autoPublish:%d\n",
            __func__, __LINE__, action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe",
            eventName, *autoPublish);

#ifdef CCSP_COMMON
    int csi_session = 0;
    unsigned int idx = 0;
    event_rbus_element_t *event;
    char *telemetry_start = NULL;
    char *telemetry_cancel = NULL;
    char tmp[128] = {0};
    unsigned int vap_array_index;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    events_rbus_data_t *events_rbus_data = &(ctrl->events_rbus_data);
    const char *wifi_log = "/rdklogs/logs/WiFilog.txt.0";

    pthread_mutex_lock(&events_rbus_data->events_rbus_lock);
    event = events_getEventElement((char *)eventName);
    if(event != NULL)
    {
        switch(event->type)
        {
            case wifi_event_monitor_diagnostics:
                idx = event->idx;
                getVAPArrayIndexFromVAPIndex((unsigned int) idx-1, &vap_array_index);
                if(action == RBUS_EVENT_ACTION_SUBSCRIBE)
                {
                    if(interval < MIN_DIAG_INTERVAL)
                    {
                        get_formatted_time(tmp);
                        wifi_util_dbg_print(WIFI_CTRL, "WiFi_DiagData_SubscriptionFailed %d\n", idx );
                        write_to_file(wifi_log, "%s WiFi_DiagData_SubscriptionFailed %d\n",tmp, idx);

                        pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);
                        wifi_util_dbg_print(WIFI_CTRL, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                        return RBUS_ERROR_BUS_ERROR;
                    }
                    if(events_rbus_data->diag_events_json_buffer[vap_array_index] == NULL)
                    {
                        memset(tmp, 0, sizeof(tmp));
                        get_formatted_time(tmp);
                        events_rbus_data->diag_events_json_buffer[vap_array_index] = (char *)malloc(CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS);
                        if(events_rbus_data->diag_events_json_buffer[vap_array_index] == NULL)
                            if(events_rbus_data->diag_events_json_buffer[vap_array_index] == NULL)
                            {
                                wifi_util_dbg_print(WIFI_CTRL, "WiFi_DiagData_SubscriptionFailed %d\n", idx );
                                write_to_file(wifi_log, "%s WiFi_DiagData_SubscriptionFailed %d\n",tmp, idx);
                                pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);
                                wifi_util_dbg_print(WIFI_CTRL, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                                return RBUS_ERROR_BUS_ERROR;
                            }
                        memset(events_rbus_data->diag_events_json_buffer[vap_array_index], 0, (CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS));
                        snprintf(events_rbus_data->diag_events_json_buffer[vap_array_index], 
                                CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS,
                                "{"
                                "\"Version\":\"1.0\","
                                "\"AssociatedClientsDiagnostics\":["
                                "{"
                                "\"VapIndex\":\"%d\","
                                "\"AssociatedClientDiagnostics\":[]"
                                "}"
                                "]"
                                "}",
                                idx);
                    }
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    wifi_util_dbg_print(WIFI_CTRL, "WiFi_DiagData_SubscriptionStarted %d\n",idx);
                    write_to_file(wifi_log, "%s WiFi_DiagData_SubscriptionStarted %d\n", tmp,idx);

                    event->num_subscribers++;
                    event->subscribed = TRUE;

                    //unlock event mutex before updating monitor data to avoid deadlock
                    pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);

                    diagdata_set_interval(interval, idx - 1);

                    wifi_util_dbg_print(WIFI_CTRL, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                    return RBUS_ERROR_SUCCESS;
                } else {
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    wifi_util_dbg_print(WIFI_CTRL, "WiFi_DiagData_SubscriptionCancelled %d\n", idx);
                    write_to_file(wifi_log, "%s WiFi_DiagData_SubscriptionCancelled %d\n",tmp, idx);

                    event->num_subscribers--;
                    if(event->num_subscribers == 0) {
                        event->subscribed = FALSE;
                        if(events_rbus_data->diag_events_json_buffer[vap_array_index] != NULL)
                        {
                            free(events_rbus_data->diag_events_json_buffer[vap_array_index]);
                            events_rbus_data->diag_events_json_buffer[vap_array_index] = NULL;
                        }
                        //unlock event mutex before updating monitor data to avoid deadlock
                        pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);

                        diagdata_set_interval(0, idx - 1);
                        wifi_util_dbg_print(WIFI_CTRL, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                        return RBUS_ERROR_SUCCESS;
                    }
                }
            break;

            case wifi_event_monitor_connect:
            case wifi_event_monitor_disconnect:
            case wifi_event_monitor_deauthenticate:
                idx = event->idx;
                if(event->type == wifi_event_monitor_connect) {
                    telemetry_start = "WiFi_deviceConnected_SubscriptionStarted";
                    telemetry_cancel = "WiFi_deviceConnected_SubscriptionCancelled";
                } else if( event->type == wifi_event_monitor_disconnect) {
                    telemetry_start = "WiFi_deviceDisconnected_SubscriptionStarted";
                    telemetry_cancel = "WiFi_deviceDisconnected_SubscriptionCancelled";
                } else {
                    telemetry_start = "WiFi_deviceDeauthenticated_SubscriptionStarted";
                    telemetry_cancel = "WiFi_deviceDeauthenticated_SubscriptionCancelled";
                }
                if(action == RBUS_EVENT_ACTION_SUBSCRIBE)
                {
                    event->num_subscribers++;
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    write_to_file(wifi_log, "%s %s %d\n",tmp, telemetry_start, idx);
                    wifi_util_dbg_print(WIFI_CTRL, "%s %d\n", telemetry_start, idx);
                    event->subscribed = TRUE;
                } else {
                    wifi_util_dbg_print(WIFI_CTRL, "%s  %d\n",telemetry_cancel, idx);
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    write_to_file(wifi_log,  "%s %s %d\n",tmp, telemetry_cancel, idx);
                    event->num_subscribers--;
                    if(event->num_subscribers == 0) {
                        event->subscribed = FALSE;
                    }
                }
            break;

            case wifi_event_monitor_csi:
                csi_session = event->idx;
                if(action == RBUS_EVENT_ACTION_SUBSCRIBE)
                {
                    /* TODO: interval needs to be multiple of WifiMonitor basic interval */
                    if(interval > MAX_CSI_INTERVAL || interval < MIN_CSI_INTERVAL
                            ||  event->subscribed == TRUE)
                    {
                        //telemetry
                        printf("WiFi_Motion_SubscriptionFailed %d\n", csi_session);
                        memset(tmp, 0, sizeof(tmp));
                        get_formatted_time(tmp);
                        wifi_util_dbg_print(WIFI_CTRL, "WiFi_Motion_SubscriptionFailed %d\n", csi_session);
                        write_to_file(wifi_log,  "%s WiFi_CSI_SubscriptionFailed %d\n", tmp,csi_session);
                        pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);
                        wifi_util_dbg_print(WIFI_CTRL, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                        return RBUS_ERROR_BUS_ERROR;
                    }
                    event->subscribed = TRUE;
                    wifi_util_dbg_print(WIFI_CTRL, "WiFi_Motion_SubscriptionStarted %d\n", csi_session);
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    write_to_file(wifi_log,  "%s WiFi_CSI_SubscriptionStarted %d\n", tmp,csi_session);

                    //unlock event mutex before updating monitor data to avoid deadlock
                    pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);
                    csi_set_interval(interval, csi_session);
                    csi_enable_subscription(TRUE, csi_session);
                    wifi_util_dbg_print(WIFI_CTRL, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                    return RBUS_ERROR_SUCCESS;
                } else {
                    event->subscribed = FALSE;
                    wifi_util_dbg_print(WIFI_CTRL, "WiFi_Motion_SubscriptionStopped %d\n", csi_session);
                    memset(tmp, 0, sizeof(tmp));
                    get_formatted_time(tmp);
                    write_to_file(wifi_log,  "%s WiFi_CSI_SubscriptionCancelled %d\n", tmp,csi_session);
                    //unlock event mutex before updating monitor data to avoid deadlock
                    pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);
                    csi_enable_subscription(FALSE, csi_session);
                    wifi_util_dbg_print(WIFI_CTRL, "Exit %s: Event %s\n", __FUNCTION__, eventName);
                    return RBUS_ERROR_SUCCESS;
                }
            break;
            default:
                wifi_util_dbg_print(WIFI_CTRL, "%s(): Invalid event type\n", __FUNCTION__);
            break;
        }
    }
    pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);
    wifi_util_dbg_print(WIFI_CTRL, "Exit %s: Event %s\n", __FUNCTION__, eventName);
#endif

    return RBUS_ERROR_SUCCESS;
}

#ifdef CCSP_COMMON
rbusError_t ap_get_handler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(opts);
    char const* name;
    rbusValue_t value;
    unsigned int idx = 0;
    int ret;
    unsigned int vap_array_index;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    events_rbus_data_t *events_rbus_data = &(ctrl->events_rbus_data);

    name = rbusProperty_GetName(property);
    if (!name)
    {
        return RBUS_ERROR_INVALID_INPUT;
    }

    pthread_mutex_lock(&events_rbus_data->events_rbus_lock);
    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, name);

    ret = sscanf(name, "Device.WiFi.AccessPoint.%d.X_RDK_DiagData", &idx);
    if(ret==1 && idx > 0 && idx <= MAX_VAP)
    {
        rbusValue_Init(&value);

        getVAPArrayIndexFromVAPIndex((unsigned int) idx-1, &vap_array_index);
        if(events_rbus_data->diag_events_json_buffer[vap_array_index] != NULL)
        {
            rbusValue_SetString(value, events_rbus_data->diag_events_json_buffer[vap_array_index]);
        }
        else
        {
            //unlock event mutex before updating monitor data to avoid deadlock
            pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);
            char *harvester_buf[MAX_VAP];
            harvester_buf[vap_array_index] = (char *) malloc(CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS);
            if (harvester_buf[vap_array_index] == NULL) {
                wifi_util_error_print(WIFI_CTRL, "%s %d Memory allocation failed\n", __func__, __LINE__);
                return  RBUS_ERROR_BUS_ERROR;
            }
            wifi_util_error_print(WIFI_CTRL, "%s %d vap index : %u\n", __func__, __LINE__, vap_array_index);
            int res = harvester_get_associated_device_info(vap_array_index, harvester_buf);
            if (res < 0) {
                wifi_util_error_print(WIFI_CTRL, "%s %d Associated Device Info collection failed\n", __func__, __LINE__);
                if (harvester_buf[vap_array_index] != NULL) {
                    wifi_util_error_print(WIFI_CTRL, "%s %d Freeing Harvester Memory\n", __func__, __LINE__);
                    free(harvester_buf[vap_array_index]);
                    harvester_buf[vap_array_index] = NULL;
                }
                return RBUS_ERROR_BUS_ERROR;
            }
            pthread_mutex_lock(&events_rbus_data->events_rbus_lock);
            rbusValue_SetString(value, harvester_buf[vap_array_index]);
            if (harvester_buf[vap_array_index] != NULL) {
                free(harvester_buf[vap_array_index]);
                harvester_buf[vap_array_index] = NULL;
            }
        }
        rbusProperty_SetValue(property, value);
        rbusValue_Release(value);

        pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);
        return RBUS_ERROR_SUCCESS;
    }

    pthread_mutex_unlock(&events_rbus_data->events_rbus_lock);
    return RBUS_ERROR_INVALID_INPUT;
}

static int push_csi_data_dml_to_ctrl_queue(queue_t *csi_queue) 
{
    webconfig_subdoc_data_t *data;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    char *str = NULL;

    if ((csi_queue == NULL)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Error, queue is NULL\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }
    data = (webconfig_subdoc_data_t *) malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", \
                __func__, sizeof(webconfig_subdoc_data_t));
        return RBUS_ERROR_BUS_ERROR;
    }
    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    wifi_util_dbg_print(WIFI_CTRL, "%s: queue count is %lu\n", __func__, queue_count(csi_queue));
    data->u.decoded.csi_data_queue = csi_queue;

    if (webconfig_encode(&ctrl->webconfig, data, webconfig_subdoc_type_csi) == webconfig_error_none) {
        str = data->u.encoded.raw;
        wifi_util_info_print(WIFI_CTRL, "%s: CSI cache encoded successfully  \n", __FUNCTION__);
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data_dml, NULL);
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
        free(data);
        return RBUS_ERROR_BUS_ERROR;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:  CSI cache pushed to queue encoded data is %s\n", __FUNCTION__, str);
    free(data);
    return RBUS_ERROR_SUCCESS;
}

queue_t *update_csi_local_queue_from_mgr_queue()
{
    queue_t *mgr_csi_queue = NULL;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    mgr_csi_queue = mgr->csi_data_queue;
    csi_data_t *tmp_csi_data;
    unsigned int itr;
    queue_t *local_csi_queue;

    if (mgr_csi_queue == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: mgr csi queue is NULL\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    local_csi_queue = queue_create();
    if (local_csi_queue == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: csi queue create failed\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    pthread_mutex_lock(&ctrl->lock);

    //update the local queue from mgr csi queue
    for (itr=0; itr<queue_count(mgr_csi_queue); itr++) {
        tmp_csi_data = (csi_data_t *)queue_peek(mgr_csi_queue, itr);
        if (tmp_csi_data != NULL) {
            csi_data_t *to_queue = (csi_data_t *)malloc(sizeof(csi_data_t));
            if (to_queue == NULL) {
                wifi_util_error_print(WIFI_CTRL, "%s %d: malloc failed for itr : %d\n", __FUNCTION__, __LINE__, itr);
                queue_destroy(local_csi_queue);
                pthread_mutex_unlock(&ctrl->lock);
                return NULL;
            }
            memcpy(to_queue, tmp_csi_data, sizeof(csi_data_t));
            queue_push(local_csi_queue, to_queue);
        }
    }

    pthread_mutex_unlock(&ctrl->lock);

    return local_csi_queue;
}

rbusError_t csi_get_handler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(opts);
    char const* name;
    rbusValue_t value;
    unsigned int idx = 0;
    int ret;
    char parameter[MAX_EVENT_NAME_SIZE];
    unsigned int itr, count, qcount;
    csi_data_t *csi_data =  NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_mgr_t *mgr = get_wifimgr_obj();

    name = rbusProperty_GetName(property);
    if (!name) {
        wifi_util_dbg_print(WIFI_CTRL, "%s(): invalid property name : %s \n", __FUNCTION__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }

    if (mgr->csi_data_queue == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d queue pointer is NULL\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    pthread_mutex_lock(&ctrl->lock);

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, name);
    if (strcmp(name, "Device.WiFi.X_RDK_CSINumberOfEntries") == 0) {
        count = queue_count(mgr->csi_data_queue);
        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, count);
        rbusProperty_SetValue(property, value);
        rbusValue_Release(value);

        pthread_mutex_unlock(&ctrl->lock);
        return RBUS_ERROR_SUCCESS;
    }

    ret = sscanf(name, "Device.WiFi.X_RDK_CSI.%4d.%200s", &idx, parameter);
    if(ret==2 && idx > 0 && idx <= MAX_VAP)
    {
        qcount = queue_count(mgr->csi_data_queue);
        for (itr=0; itr<qcount; itr++) {
            csi_data = queue_peek(mgr->csi_data_queue, itr);
            if (csi_data->csi_session_num == idx) {
                break;
            }
        }

        if (csi_data == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d Could not find entry\n", __func__, __LINE__);
            pthread_mutex_unlock(&ctrl->lock);
            return RBUS_ERROR_BUS_ERROR;
        }

        rbusValue_Init(&value);
        if (strcmp(parameter, "ClientMaclist") == 0) {
            char tmp_cli_list[128];
            mac_addr_str_t mac_str;
            memset(tmp_cli_list, 0, sizeof(tmp_cli_list));
            if (csi_data->csi_client_count > 0) {
                for (itr=0; itr<csi_data->csi_client_count; itr++) {
                    snprintf(mac_str, sizeof(mac_str), "%02x%02x%02x%02x%02x%02x",
                            csi_data->csi_client_list[itr][0], csi_data->csi_client_list[itr][1],
                            csi_data->csi_client_list[itr][2], csi_data->csi_client_list[itr][3],
                            csi_data->csi_client_list[itr][4], csi_data->csi_client_list[itr][5]);
                    strncat(tmp_cli_list, mac_str, strlen(tmp_cli_list)-1);
                    strncat(tmp_cli_list, ",", strlen(tmp_cli_list)-1);
                }
                int len  = strlen(tmp_cli_list);
                tmp_cli_list[len-1] = '\0';
            }
            rbusValue_SetString(value, tmp_cli_list);
        } else if(strcmp(parameter, "Enable") == 0) {
            rbusValue_SetBoolean(value, csi_data->enabled);
        }
        rbusProperty_SetValue(property, value);
        rbusValue_Release(value);

        pthread_mutex_unlock(&ctrl->lock);
        return RBUS_ERROR_SUCCESS;
    }

    pthread_mutex_unlock(&ctrl->lock);
    return RBUS_ERROR_INVALID_INPUT;
}

rbusError_t csi_set_handler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    char const* name;
    rbusValue_t value;
    rbusValueType_t type;
    unsigned int idx = 0;
    int ret, apply = false;
    char parameter[MAX_EVENT_NAME_SIZE];
    unsigned int itr, i, j, k, qcount, num_unique_mac=0;
    csi_data_t *csi_data =  NULL, *tmp_csi_data;
    mac_address_t unique_mac_list[MAX_NUM_CSI_CLIENTS];
    bool found = false;
    unsigned int csi_client_count;
    mac_address_t csi_client_list[MAX_NUM_CSI_CLIENTS];

    name = rbusProperty_GetName(property);
    value = rbusProperty_GetValue(property);
    type = rbusValue_GetType(value);

    if (!name) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: invalid rbus property name %s\n", __FUNCTION__, __LINE__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }
    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, name);

    queue_t *local_csi_queue = NULL;

    local_csi_queue = update_csi_local_queue_from_mgr_queue();
    if (local_csi_queue == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d update csi Queue from mgr Queue failed\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    ret = sscanf(name, "Device.WiFi.X_RDK_CSI.%4d.%200s", &idx, parameter);
    if(ret==2 && idx > 0 && idx <= MAX_VAP) {
        qcount = queue_count(local_csi_queue);
        for (itr=0; itr<qcount; itr++) {
            csi_data = queue_peek(local_csi_queue, itr);
            if (csi_data->csi_session_num == idx) {
                break;
            }
        }

        if (csi_data == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d Could not find entry\n", __func__, __LINE__);
            queue_destroy(local_csi_queue);
            return RBUS_ERROR_BUS_ERROR;
        }
        if (strcmp(parameter, "ClientMaclist") == 0) {

            if (type != RBUS_STRING) {
                wifi_util_error_print(WIFI_CTRL,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
                queue_destroy(local_csi_queue);
                return RBUS_ERROR_INVALID_INPUT;
            } else {
                char *str, *cptr, *str_dup;
                mac_address_t l_client_list[MAX_NUM_CSI_CLIENTS];
                char const* pTmp = NULL;
                int len = 0;
                memset(l_client_list, 0, MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));

                pTmp = rbusValue_GetString(value, &len);
                str_dup = strdup(pTmp);
                if (str_dup == NULL) {
                    wifi_util_error_print(WIFI_CTRL,"%s:%d strdup failed\n", __func__, __LINE__);
                    queue_destroy(local_csi_queue);
                    return RBUS_ERROR_BUS_ERROR;
                }
                itr = 0;
                str = strtok_r(str_dup, ",", &cptr);
                while (str != NULL) {
                    str_to_mac_bytes(str, l_client_list[itr]);
                    str = strtok_r(NULL, ",", &cptr);
                    itr++;
                    if (itr > MAX_NUM_CSI_CLIENTS) {
                        wifi_util_error_print(WIFI_CTRL,"%s:%d client list is big %d\n", __func__, __LINE__, itr);
                        if (str_dup) {
                            free(str_dup);
                        }
                        queue_destroy(local_csi_queue);
                        return RBUS_ERROR_BUS_ERROR;
                    }
                }
                if (memcmp(csi_data->csi_client_list, l_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t)) != 0) {
                    //check new configuration did not exceed the max number of csi clients
                    num_unique_mac = 0;
                    for (i=0; i<qcount; i++) {
                        tmp_csi_data = (csi_data_t *)queue_peek(local_csi_queue, i);
                        if ((tmp_csi_data != NULL) && (tmp_csi_data->enabled)) {
                            if (tmp_csi_data->csi_session_num == csi_data->csi_session_num) {
                                csi_client_count = itr;
                                memcpy(csi_client_list, l_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));
                            } else {
                                csi_client_count = tmp_csi_data->csi_client_count;
                                memcpy(csi_client_list, tmp_csi_data->csi_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));
                            }
                            for (j=0; j < csi_client_count; j++) {
                                found  = false;
                                for (k=0; k < num_unique_mac; k++) {
                                    if (memcmp(csi_client_list[j], unique_mac_list[k], sizeof(mac_address_t)) == 0) {
                                        found  = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    num_unique_mac++;
                                    if (num_unique_mac > MAX_NUM_CSI_CLIENTS) {
                                        wifi_util_error_print(WIFI_CTRL, "%s %d MAX_NUM_CSI_CLIENTS reached\n", __func__, __LINE__);
                                        if (str_dup) {
                                            free(str_dup);
                                        }
                                        queue_destroy(local_csi_queue);
                                        return RBUS_ERROR_BUS_ERROR;
                                    } else {
                                        memcpy(unique_mac_list[num_unique_mac-1], csi_client_list[j], sizeof(mac_address_t));
                                    }
                                }
                            }
                        }
                    }

                    memcpy(csi_data->csi_client_list, l_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));
                    csi_data->csi_client_count = itr;
                    apply = true;
                } else {
                    wifi_util_error_print(WIFI_CTRL,"%s:%d config not change\n", __func__, __LINE__);
                }
                if (str_dup) {
                    free(str_dup);
                }
            }
        } else if(strcmp(parameter, "Enable") == 0) {
            if (type != RBUS_BOOLEAN)
            {
                wifi_util_error_print(WIFI_CTRL,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
                queue_destroy(local_csi_queue);
                return RBUS_ERROR_INVALID_INPUT;
            } else {
                bool enabled = rbusValue_GetBoolean(value);
                if (enabled != csi_data->enabled) {
                    //check new configuration did not exceed the max number of csi clients
                    num_unique_mac = 0;
                    if (enabled == true) {
                        for (i=0; i<qcount; i++) {
                            tmp_csi_data = (csi_data_t *)queue_peek(local_csi_queue, i);
                            if (tmp_csi_data != NULL) {
                                if (tmp_csi_data->csi_session_num != csi_data->csi_session_num) {
                                    if (tmp_csi_data->enabled == false) {
                                        continue;
                                    }
                                }
                                for (j=0; j < tmp_csi_data->csi_client_count; j++) {
                                    found  = false;
                                    for (k=0; k < num_unique_mac; k++) {
                                        if (memcmp(tmp_csi_data->csi_client_list[j], unique_mac_list[k], sizeof(mac_address_t)) == 0) {
                                            found  = true;
                                            break;
                                        }
                                    }
                                    if (!found) {
                                        num_unique_mac++;
                                        if (num_unique_mac > MAX_NUM_CSI_CLIENTS) {
                                            wifi_util_error_print(WIFI_CTRL,"%s %d MAX_NUM_CSI_CLIENTS reached\n", __func__, __LINE__);
                                            queue_destroy(local_csi_queue);
                                            return RBUS_ERROR_BUS_ERROR;
                                        } else {
                                            memcpy(unique_mac_list[num_unique_mac-1], tmp_csi_data->csi_client_list[j], sizeof(mac_address_t));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    csi_data->enabled = enabled;
                    apply = true;
                }
            }
        }
        if (apply) {
            push_csi_data_dml_to_ctrl_queue(local_csi_queue);
        }
        queue_destroy(local_csi_queue);
        return RBUS_ERROR_SUCCESS;
    }

    queue_destroy(local_csi_queue);
    return RBUS_ERROR_INVALID_INPUT;
}

rbusError_t csi_table_addrowhandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum)
{
    static int instanceCounter = 1;
    event_rbus_element_t *event;
    queue_t *local_csi_queue = NULL;
    csi_data_t *csi_data;
    *instNum = instanceCounter++;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s %d\n", __FUNCTION__, tableName, *instNum);

    event = (event_rbus_element_t *) malloc(sizeof(event_rbus_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.X_RDK_CSI.%d.data", *instNum);
        event->idx = *instNum;
        event->type = wifi_event_monitor_csi;
        event->subscribed = FALSE;
    }

    local_csi_queue = update_csi_local_queue_from_mgr_queue();
    if (local_csi_queue == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d update csi Queue from mgr Queue failed\n", __func__, __LINE__);
        free(event);
        return RBUS_ERROR_BUS_ERROR;
    }

    csi_data = (csi_data_t *)malloc(sizeof(csi_data_t));
    if (csi_data == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL Pointer\n", __func__, __LINE__);
        queue_destroy(local_csi_queue);
        free(event);
        return RBUS_ERROR_BUS_ERROR;
    }
    memset(csi_data, 0, sizeof(csi_data_t));
    csi_data->csi_session_num = *instNum;

    queue_push(local_csi_queue, csi_data);
    pthread_mutex_lock(&ctrl->events_rbus_data.events_rbus_lock);
    queue_push(ctrl->events_rbus_data.events_rbus_queue, event);
    pthread_mutex_unlock(&ctrl->events_rbus_data.events_rbus_lock);

    push_csi_data_dml_to_ctrl_queue(local_csi_queue);
    queue_destroy(local_csi_queue);

    wifi_util_dbg_print(WIFI_CTRL, "%s(): exit\n", __FUNCTION__);
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(aliasName);
    return RBUS_ERROR_SUCCESS;
}

rbusError_t csi_table_removerowhandler(rbusHandle_t handle, char const *rowName)
{
    unsigned int i = 0;
    event_rbus_element_t *event = NULL;
    csi_data_t *tmp_csi_data =  NULL;
    unsigned int itr, qcount;
    queue_t *local_csi_queue = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, rowName);

    local_csi_queue = update_csi_local_queue_from_mgr_queue();
    if (local_csi_queue == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d update csi Queue from mgr Queue failed\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    pthread_mutex_lock(&ctrl->events_rbus_data.events_rbus_lock);

    qcount = queue_count(ctrl->events_rbus_data.events_rbus_queue);
    while(i < qcount) {
        event = queue_peek(ctrl->events_rbus_data.events_rbus_queue, i);
        if ((event != NULL) && (strstr(event->name, rowName) != NULL))
        {
            event = queue_remove(ctrl->events_rbus_data.events_rbus_queue, i);
            break;
        }
        else {
            i++;
        }
    }

    if (event == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d Could not find entry\n", __func__, __LINE__);
        pthread_mutex_unlock(&ctrl->events_rbus_data.events_rbus_lock);
        queue_destroy(local_csi_queue);
        return RBUS_ERROR_BUS_ERROR;
    }

    qcount = queue_count(local_csi_queue);
    for (itr=0; itr<qcount; itr++) {
        tmp_csi_data = queue_peek(local_csi_queue, itr);
        if (tmp_csi_data->csi_session_num == (unsigned long) event->idx) {
            tmp_csi_data = queue_remove(local_csi_queue, itr);
            if (tmp_csi_data) {
                free(tmp_csi_data);
            }
            break;
        }
    }
    free(event);
    pthread_mutex_unlock(&ctrl->events_rbus_data.events_rbus_lock);

    push_csi_data_dml_to_ctrl_queue(local_csi_queue);
    queue_destroy(local_csi_queue);

    UNREFERENCED_PARAMETER(handle);

    return RBUS_ERROR_SUCCESS;
}


rbusError_t ap_table_addrowhandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum)
{
    static int instanceCounter = 1;
    wifi_mgr_t *mgr = get_wifimgr_obj();

    event_rbus_element_t *event;
    unsigned int vap_index;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    vap_index  = VAP_INDEX(mgr->hal_cap, (instanceCounter-1)) + 1;
    *instNum = vap_index;
    instanceCounter++;

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s %d\n", __FUNCTION__, tableName, *instNum);

    pthread_mutex_lock(&ctrl->events_rbus_data.events_rbus_lock);

    //Device.WiFi.AccessPoint.{i}.X_RDK_deviceConnected
    event = (event_rbus_element_t *) malloc(sizeof(event_rbus_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.AccessPoint.%d.X_RDK_deviceConnected", *instNum);
        event->idx = vap_index;
        event->type = wifi_event_monitor_connect;
        event->subscribed = FALSE;
        event->num_subscribers = 0;
        queue_push(ctrl->events_rbus_data.events_rbus_queue, event);
    }

    //Device.WiFi.AccessPoint.{i}.X_RDK_deviceDisconnected
    event = (event_rbus_element_t *) malloc(sizeof(event_rbus_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.AccessPoint.%d.X_RDK_deviceDisconnected", *instNum);
        event->idx = vap_index;
        event->type = wifi_event_monitor_disconnect;
        event->subscribed = FALSE;
        event->num_subscribers = 0;
        queue_push(ctrl->events_rbus_data.events_rbus_queue, event);
    }
    //Device.WiFi.AccessPoint.{i}.X_RDK_deviceDeauthenticated
    event = (event_rbus_element_t *) malloc(sizeof(event_rbus_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.AccessPoint.%d.X_RDK_deviceDeauthenticated", *instNum);
        event->idx = vap_index;
        event->type = wifi_event_monitor_deauthenticate;
        event->subscribed = FALSE;
        event->num_subscribers = 0;
        queue_push(ctrl->events_rbus_data.events_rbus_queue, event);    }

    //Device.WiFi.AccessPoint.{i}.X_RDK_DiagData
    event = (event_rbus_element_t *) malloc(sizeof(event_rbus_element_t));
    if(event != NULL)
    {
        sprintf(event->name, "Device.WiFi.AccessPoint.%d.X_RDK_DiagData", *instNum);
        event->idx = vap_index;
        event->type = wifi_event_monitor_diagnostics;
        event->subscribed = FALSE;
        event->num_subscribers = 0;
        queue_push(ctrl->events_rbus_data.events_rbus_queue, event);
    }

    pthread_mutex_unlock(&ctrl->events_rbus_data.events_rbus_lock);
    wifi_util_dbg_print(WIFI_CTRL, "%s(): exit\n", __FUNCTION__);

    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(aliasName);
    return RBUS_ERROR_SUCCESS;
}


rbusError_t ap_table_removerowhandler(rbusHandle_t handle, char const* rowName)
{
    int i = 0;
    event_rbus_element_t *event;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    int count = queue_count(ctrl->events_rbus_data.events_rbus_queue);

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, rowName);

    pthread_mutex_lock(&ctrl->events_rbus_data.events_rbus_lock);

    while(i < count)
    {
        event = queue_peek(ctrl->events_rbus_data.events_rbus_queue, i);
        if ((event != NULL) && (strstr(event->name, rowName) != NULL))
        {
            wifi_util_dbg_print(WIFI_CTRL, "%s():event remove from queue %s\n", __FUNCTION__, event->name);
            event = queue_remove(ctrl->events_rbus_data.events_rbus_queue, i);
            if(event) {
                free(event);
            }
            count--;
        }
        else {
            i++;
        }
    }

    pthread_mutex_unlock(&ctrl->events_rbus_data.events_rbus_lock);

    UNREFERENCED_PARAMETER(handle);

    return RBUS_ERROR_SUCCESS;
}

static BOOL events_getSubscribed(char *eventName)
{
    int i;
    event_rbus_element_t *event;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    int count = queue_count(ctrl->events_rbus_data.events_rbus_queue);

    if (count == 0) {
        return FALSE;
    }

    for (i = 0; i < count; i++) {
        event = queue_peek(ctrl->events_rbus_data.events_rbus_queue, i);
        if ((event != NULL) && (strncmp(event->name, eventName, MAX_EVENT_NAME_SIZE) == 0)) {
            return event->subscribed;
        }
    }
    return FALSE;
}

int events_rbus_publish(wifi_event_t *evt)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    bool should_publish = FALSE;
    char eventName[MAX_EVENT_NAME_SIZE];
    int rc;
    unsigned int vap_array_index;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (evt == NULL) {
        wifi_util_info_print(WIFI_CTRL, "%s(): Input arguements is NULL\n", __FUNCTION__);
        return 0;
    }

    pthread_mutex_lock(&ctrl->events_rbus_data.events_rbus_lock);
    if (evt->sub_type != wifi_event_monitor_csi) {
        rbusValue_Init(&value);
        rbusObject_Init(&rdata, NULL);
        wifi_util_info_print(WIFI_CTRL, "%s(): rbusEvent_Publish Event %d\n", __FUNCTION__, evt->sub_type);
    }

    switch(evt->sub_type)
    {
        case wifi_event_monitor_diagnostics:
            sprintf(eventName, "Device.WiFi.AccessPoint.%d.X_RDK_DiagData", evt->u.mon_data->ap_index + 1);
            getVAPArrayIndexFromVAPIndex((unsigned int) evt->u.mon_data->ap_index, &vap_array_index);
            if(ctrl->events_rbus_data.diag_events_json_buffer[vap_array_index] != NULL)
            {
                rbusValue_SetString(value, ctrl->events_rbus_data.diag_events_json_buffer[vap_array_index]);
                wifi_util_dbg_print(WIFI_CTRL, "%s(): device_diagnostics Event %d %s \n", __FUNCTION__, evt->sub_type, eventName);
                should_publish = TRUE;
            }
        break;
        case wifi_event_monitor_connect:
        case wifi_event_monitor_disconnect:
        case wifi_event_monitor_deauthenticate:
            if(evt->sub_type == wifi_event_monitor_connect) {
                sprintf(eventName, "Device.WiFi.AccessPoint.%d.X_RDK_deviceConnected", evt->u.mon_data->ap_index + 1);
            }
            else if(evt->sub_type == wifi_event_monitor_disconnect) {
                sprintf(eventName, "Device.WiFi.AccessPoint.%d.X_RDK_deviceDisconnected", evt->u.mon_data->ap_index + 1);
            }
            else {
                sprintf(eventName, "Device.WiFi.AccessPoint.%d.X_RDK_deviceDeauthenticated", evt->u.mon_data->ap_index + 1);
            }
            if(events_getSubscribed(eventName) == TRUE)
            {
                rbusValue_SetBytes(value, (uint8_t *)&evt->u.mon_data->u.dev.sta_mac[0], sizeof(evt->u.mon_data->u.dev.sta_mac));
                wifi_util_dbg_print(WIFI_CTRL, "%s(): Event - %d %s \n", __FUNCTION__, evt->sub_type, eventName);
                should_publish = TRUE;
            }
        break;
        case wifi_event_monitor_csi:
            {
                //Construct Header.
                unsigned int total_length, num_csi_clients, csi_data_length, curr_length = 0;
                time_t datetime;
                char *header = evt->u.mon_data->u.csi.header;

                sprintf(eventName, "Device.WiFi.X_RDK_CSI.%d.data", evt->u.mon_data->csi_session);

                memcpy(header,"CSI", (strlen("CSI") + 1));
                curr_length = curr_length + strlen("CSI") + 1;

                total_length = sizeof(time_t) + (sizeof(unsigned int)) + (1 *(sizeof(mac_addr_t) + sizeof(unsigned int) + sizeof(wifi_csi_data_t)));
                memcpy((header + curr_length), &total_length, sizeof(unsigned int));
                curr_length = curr_length + sizeof(unsigned int);

                datetime = time(NULL);
                memcpy((header + curr_length), &datetime, sizeof(time_t));
                curr_length = curr_length + sizeof(time_t);

                num_csi_clients = 1;
                memcpy((header + curr_length), &num_csi_clients, sizeof(unsigned int));
                curr_length = curr_length + sizeof(unsigned int);

                memcpy((header + curr_length), evt->u.mon_data->u.csi.sta_mac, sizeof(mac_addr_t));
                curr_length = curr_length + sizeof(mac_addr_t);

                csi_data_length = sizeof(wifi_csi_data_t);
                memcpy((header + curr_length), &csi_data_length, sizeof(unsigned int));

                int buffer_size = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t);

                //Publish using new API
                rbusEventRawData_t event_data;
                event_data.name  = eventName;
                event_data.rawData = &evt->u.mon_data->u.csi.header;
                event_data.rawDataLen = buffer_size;
                rbusEvent_PublishRawData(ctrl->rbus_handle, &event_data);

                pthread_mutex_unlock(&ctrl->events_rbus_data.events_rbus_lock);
                return 0;

            }
        break;
        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s(): Invalid event type\n", __FUNCTION__);
        break;
    }
    if(should_publish == TRUE) {
        rbusObject_SetValue(rdata, eventName, value);
        event.name = eventName;
        event.data = rdata;
        event.type = RBUS_EVENT_GENERAL;

        rc = rbusEvent_Publish(ctrl->rbus_handle, &event);

        if(rc != RBUS_ERROR_SUCCESS)
        {
            wifi_util_error_print(WIFI_CTRL, "%s(): rbusEvent_Publish Event failed: %d\n", __FUNCTION__, rc);
        }
    }
    rbusValue_Release(value);
    rbusObject_Release(rdata);
    pthread_mutex_unlock(&ctrl->events_rbus_data.events_rbus_lock);

    return 0;
}
#endif

static int push_levl_data_dml_to_ctrl_queue(levl_config_t **levl) 
{
    webconfig_subdoc_data_t *data;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    char *str = NULL;

    if (*levl == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: NULL Pointer\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    data = (webconfig_subdoc_data_t *) malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", \
                __func__, sizeof(webconfig_subdoc_data_t));
        return RBUS_ERROR_BUS_ERROR;
    }

    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy(&(data->u.decoded.levl), *levl, sizeof(levl_config_t));

    if (webconfig_encode(&ctrl->webconfig, data, webconfig_subdoc_type_levl) == webconfig_error_none) {
        str = data->u.encoded.raw;
        wifi_util_info_print(WIFI_CTRL, "%s: Levl encoded successfully  \n", __FUNCTION__);
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data_dml, NULL);
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
        if (data != NULL) {
            free(data);
        }
        return RBUS_ERROR_BUS_ERROR;
    }

    wifi_util_info_print(WIFI_CTRL, "%s: Levl pushed to queue encoded data is %s\n", __FUNCTION__, str);
    if (data != NULL) {
        free(data);
    }
    return RBUS_ERROR_SUCCESS;
}

rbusError_t levl_get_handler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(opts);
    char const* name;
    rbusValue_t value;
    int max_value = 0, duration = 0;
    char parameter[MAX_EVENT_NAME_SIZE];
    wifi_mgr_t *mgr = get_wifimgr_obj();

    name = rbusProperty_GetName(property);
    if (!name) {
        wifi_util_dbg_print(WIFI_CTRL, "%s(): invalid property name : %s \n", __FUNCTION__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, name);
    sscanf(name, "Device.WiFi.X_RDK_CSI_LEVL.%200s", parameter);
    rbusValue_Init(&value);

    if (strcmp(parameter, "clientMac") == 0) {

        char mac_string[18];
        memset(mac_string, 0, 18);
        to_mac_str(mgr->levl.clientMac, mac_string);
        rbusValue_SetString(value, mac_string);
    } else if(strcmp(parameter, "maxNumberCSIClients") == 0) {
        if (mgr->levl.max_num_csi_clients == 0) {
            max_value = MAX_LEVL_CSI_CLIENTS;
        } else {
            max_value = mgr->levl.max_num_csi_clients;
        }

        rbusValue_SetUInt32(value, max_value);
    } else if(strcmp(parameter, "Duration") == 0) {
        if (mgr->levl.levl_sounding_duration == 0) {
            duration = DEFAULT_SOUNDING_DURATION_MS;
        } else {
            duration = mgr->levl.levl_sounding_duration;
        }
        rbusValue_SetUInt32(value, duration);
    }
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);
    return RBUS_ERROR_SUCCESS;
}

void update_levl_config_from_mgr(levl_config_t *levl) {
    wifi_mgr_t *mgr = get_wifimgr_obj();

    levl->max_num_csi_clients = mgr->levl.max_num_csi_clients;
    levl->levl_sounding_duration = mgr->levl.levl_sounding_duration; 

    return;
}

rbusError_t levl_set_handler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)opts;
    char const* name;
    rbusValue_t value;
    rbusValueType_t type;
    int len = 0, levl_sounding_duration = 0;
    char const* pTmp = NULL;
    char parameter[MAX_EVENT_NAME_SIZE];
    unsigned int csinum = 0;
    levl_config_t *levl = NULL;

    name = rbusProperty_GetName(property);
    value = rbusProperty_GetValue(property);
    type = rbusValue_GetType(value);

    if (!name) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: invalid rbus property name %s\n", __FUNCTION__, __LINE__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }
    levl = (levl_config_t *)malloc(sizeof(levl_config_t));
    if (levl == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: NULL Pointer\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }
    memset(levl, 0, sizeof(levl_config_t));
    update_levl_config_from_mgr(levl);

    wifi_util_dbg_print(WIFI_CTRL, "%s(): %s\n", __FUNCTION__, name);

    //get levl Instance
    wifi_mgr_t *mgr = get_wifimgr_obj();
    if (mgr == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s %d: NULL Pointer\n", __func__, __LINE__);
        if (levl != NULL) {
            free(levl);
        }
        return RBUS_ERROR_BUS_ERROR;
    }

    sscanf(name, "Device.WiFi.X_RDK_CSI_LEVL.%200s", parameter);
    if (strcmp(parameter, "clientMac") == 0) {
        if (type != RBUS_STRING) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
            if (levl != NULL) {
                free(levl);
            }
            return RBUS_ERROR_INVALID_INPUT;
        }

        pTmp = rbusValue_GetString(value, &len);
        str_to_mac_bytes((char *)pTmp, levl->clientMac);
    } else if(strcmp(parameter, "maxNumberCSIClients") == 0) {
        if (type != RBUS_UINT32) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
            if (levl != NULL) {
                free(levl);
            }
            return RBUS_ERROR_INVALID_INPUT;
        }

        csinum = rbusValue_GetUInt32(value);
        if (csinum > MAX_LEVL_CSI_CLIENTS) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d Exceeds MAX_LEVL_CSI_CLIENTS\n", __func__, __LINE__);
            if (levl != NULL) {
                free(levl);
            }
            return RBUS_ERROR_INVALID_INPUT;
        }
        levl->max_num_csi_clients = csinum;
    } else if (strcmp(parameter, "Duration") == 0) {
        if (type != RBUS_UINT32) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
            if (levl != NULL) {
                free(levl);
            }
            return RBUS_ERROR_INVALID_INPUT;
        }
        levl_sounding_duration = rbusValue_GetUInt32(value);
        if (levl_sounding_duration == 0) {
            levl->levl_sounding_duration = DEFAULT_SOUNDING_DURATION_MS;
        } else {
            levl->levl_sounding_duration = levl_sounding_duration;
        }
    }

    push_levl_data_dml_to_ctrl_queue(&levl);
    if (levl != NULL) {
        free(levl);
    }
    return RBUS_ERROR_SUCCESS;
}


rbusError_t get_client_assoc_request_multi(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams,rbusMethodAsyncHandle_t asyncHandle)
{
#ifdef CCSP_COMMON
    sta_key_t sta_key;
    sta_data_t *sta;
    unsigned int vap_index =0;
    frame_data_t   tmp_data;
    frame_data_t   *l_data;
    rbusValue_t value;
    rbusObject_t rdata;
    int len;
    char vapname[16];
    bm_client_assoc_req mac_addr;
    value = rbusObject_GetValue(inParams,NULL);
    const unsigned char *pTmp = rbusValue_GetBytes(value, &len);
    wifi_platform_property_t *prop = NULL;

    if(pTmp == NULL) {
        wifi_util_error_print(WIFI_MON,"%s:%d hash_map object not found for vap_index:\r\n", __func__, __LINE__);
        return  RBUS_ERROR_DESTINATION_NOT_FOUND;
    }
    memcpy(&mac_addr,pTmp,len);
    memset(&tmp_data,0,sizeof(tmp_data));
    prop = (wifi_platform_property_t *) get_wifi_hal_cap_prop();
    convert_ifname_to_vapname(prop, mac_addr.if_name, vapname, sizeof(vapname));
    vap_index = convert_vap_name_to_index(prop, vapname);

    hash_map_t     *sta_map = get_sta_data_map(vap_index);

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d %s,%svap_index:%d\r\n", __func__, __LINE__,mac_addr.mac_addr,mac_addr.if_name,vap_index);
    if( sta_map != NULL) {
            sta = (sta_data_t *)hash_map_get(sta_map, mac_addr.mac_addr);
    } else {
            wifi_util_info_print(WIFI_CTRL,"%s:%d , sta_map is null  \n", __func__, __LINE__);
            return  RBUS_ERROR_INVALID_INPUT;
    }
    if (sta != NULL) {
        if (sta->assoc_frame_data.msg_data.frame.len != 0) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d rbus_namespace_publish event:%s for vap_index:%d\r\n", __func__, __LINE__, ACCESSPOINT_ASSOC_REQ_EVENT, vap_index);
            memcpy(&tmp_data,&sta->assoc_frame_data.msg_data, sizeof(frame_data_t));
            l_data = &tmp_data;

        } else {
            wifi_util_info_print(WIFI_CTRL,"%s:%d assoc req frame not found for vap_index:%d: sta_mac:%s time:%ld\r\n",
                    __func__, __LINE__, vap_index, sta_key, sta->assoc_frame_data.frame_timestamp);
            return  RBUS_ERROR_INVALID_INPUT;
        }
    } else {
            wifi_util_info_print(WIFI_CTRL,"%s:%d , sta is null  \n", __func__, __LINE__);
            return  RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);
    rbusValue_SetBytes(value, (uint8_t *)l_data,(sizeof(l_data->frame) + l_data->frame.len));
    rbusObject_SetValue(outParams,WIFI_CLIENT_GET_ASSOC_REQ,value);
#endif
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
                                { WIFI_RBUS_WIFIAPI_RESULT, RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, wifiapi_event_handler, NULL}},
                                { WIFI_WEBCONFIG_GET_CSI, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, NULL, NULL, NULL, NULL, NULL}},
                                { WIFI_WEBCONFIG_GET_ACL, RBUS_ELEMENT_TYPE_METHOD,
                                { get_acl_device_data, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_PRIVATE_VAP, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, get_private_vap, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_HOME_VAP, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, get_home_vap, NULL, NULL, NULL, NULL }},
                                { WIFI_RBUS_HOTSPOT_UP, RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, hotspot_event_handler, NULL}},
                                { WIFI_RBUS_HOTSPOT_DOWN, RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, hotspot_event_handler, NULL}},
                                { WIFI_WEBCONFIG_KICK_MAC, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, set_kickassoc_command, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_GET_NULL_SUBDOC, RBUS_ELEMENT_TYPE_METHOD,
                                { get_null_subdoc_data, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_STA_TRIGGER_DISCONNECTION, RBUS_ELEMENT_TYPE_METHOD,
                                { get_sta_disconnection, set_sta_disconnection, NULL, NULL, NULL, NULL}},
                                { WIFI_STA_SELFHEAL_CONNECTION_TIMEOUT, RBUS_ELEMENT_TYPE_EVENT,
                                { get_sta_connection_timeout, NULL, NULL, NULL, NULL, NULL}},
#ifdef CCSP_COMMON
                                { WIFI_ACCESSPOINT_TABLE, RBUS_ELEMENT_TYPE_TABLE,
                                { NULL, NULL, ap_table_addrowhandler, ap_table_removerowhandler,NULL, NULL}},
                                { WIFI_ACCESSPOINT_DEV_CONNECTED, RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, eventSubHandler, NULL}},
                                { WIFI_ACCESSPOINT_DEV_DISCONNECTED, RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, eventSubHandler, NULL}},
                                { WIFI_ACCESSPOINT_DEV_DEAUTH,RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, eventSubHandler, NULL}},
                                { WIFI_ACCESSPOINT_DIAGDATA, RBUS_ELEMENT_TYPE_EVENT,
                                { ap_get_handler, NULL, NULL, NULL, eventSubHandler, NULL}},
                                { WIFI_CSI_TABLE, RBUS_ELEMENT_TYPE_TABLE,
                                { NULL, NULL, csi_table_addrowhandler, csi_table_removerowhandler, NULL, NULL}},
                                { WIFI_CSI_DATA, RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, eventSubHandler, NULL}},
                                { WIFI_CSI_CLIENTMACLIST, RBUS_ELEMENT_TYPE_PROPERTY,
                                { csi_get_handler, csi_set_handler, NULL, NULL, NULL, NULL}},
                                { WIFI_CSI_ENABLE, RBUS_ELEMENT_TYPE_PROPERTY,
                                { csi_get_handler, csi_set_handler, NULL, NULL, NULL, NULL}},
                                { WIFI_CSI_NUMBEROFENTRIES, RBUS_ELEMENT_TYPE_PROPERTY,
                                { csi_get_handler, NULL, NULL, NULL, NULL, NULL}},
                                { WIFI_LEVL_CLIENTMAC, RBUS_ELEMENT_TYPE_PROPERTY,
                                { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}},
                                { WIFI_LEVL_NUMBEROFENTRIES, RBUS_ELEMENT_TYPE_PROPERTY,
                                { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}},
                                { WIFI_LEVL_SOUNDING_DURATION, RBUS_ELEMENT_TYPE_PROPERTY,
                                { levl_get_handler, levl_set_handler, NULL, NULL, NULL, NULL}},
#endif
                                { ACCESSPOINT_ASSOC_REQ_EVENT, RBUS_ELEMENT_TYPE_METHOD,
                                    { NULL, NULL, NULL, NULL, NULL, NULL}},
                                { WIFI_CLIENT_GET_ASSOC_REQ,RBUS_ELEMENT_TYPE_METHOD,
                                    { NULL, NULL, NULL, NULL, NULL, get_client_assoc_request_multi}},
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
            wifi_util_info_print(WIFI_CTRL, "%s() rbusTable_addRow failed for Device.WiFi.STA.%d\n", __FUNCTION__, rc);
        }
    }

#ifdef CCSP_COMMON
    for(index = 1; index <= getTotalNumberVAPs(NULL); index++) {
        rc = rbusTable_addRow(ctrl->rbus_handle, "Device.WiFi.AccessPoint.", NULL, NULL);
        if(rc != RBUS_ERROR_SUCCESS) {
            wifi_util_info_print(WIFI_CTRL, "%s() rbusTable_addRow failed %d\n", __FUNCTION__, rc);
        }
    }
#endif

    wifi_util_info_print(WIFI_CTRL,"%s rbus event register:[%s]:%s\r\n",__FUNCTION__, WIFI_STA_2G_VAP_CONNECT_STATUS, WIFI_STA_5G_VAP_CONNECT_STATUS);

    return;
}

