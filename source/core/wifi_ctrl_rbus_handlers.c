#include <stdio.h>
#include <stdbool.h>
#include "ansc_platform.h"
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include <unistd.h>
#include <rbus.h>

int webconfig_rbus_apply(wifi_ctrl_t *ctrl, webconfig_subdoc_encoded_data_t *data)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, WIFI_WEBCONFIG_DOC_DATA, value);
    rbusValue_SetBytes(value, (uint8_t *)data->raw, strlen(data->raw));
    event.name = WIFI_WEBCONFIG_DOC_DATA;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    if (rbusEvent_Publish(ctrl->rbus_handle, &event) != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed\n", __func__, __LINE__);
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

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);

    if (strcmp(name, WIFI_WEBCONFIG_INIT_DATA) != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property valid\n",__FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&mgr->global_config, sizeof(wifi_global_config_t));
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
        wifi_util_dbg_print(WIFI_CTRL,"%sWrong data type %s\n",__FUNCTION__,name);
        return rc;
    }

    pTmp = rbusValue_GetString(value, &len);
    if (pTmp != NULL) {
        rc = RBUS_ERROR_SUCCESS;
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus set string len=%d\n",__FUNCTION__,len);
        push_data_to_ctrl_queue((const cJSON *)pTmp, (strlen(pTmp) + 1), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data);
    }
    return rc;
}

rbusError_t get_sta_vap_connect_status(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;
    unsigned int index, vap_index = 0, i;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_vap_info_map_t *vap_map;
    wifi_connection_status_t status = wifi_connection_status_disabled;

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);

    if ((strcmp(name, WIFI_STA_2G_VAP_CONNECT_STATUS) != 0) && (strcmp(name, WIFI_STA_5G_VAP_CONNECT_STATUS) != 0)) {
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property valid\n",__FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    sscanf(name, "Device.WiFi.STA.%d.Connection.Status", &index);
    if (index >= getNumberRadios()) {
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property valid\n",__FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    vap_map = &mgr->radio_config[index].vaps.vap_map;
    if (index == 0) {
        vap_index = 14;
    } else if (index == 1) {
        vap_index = 15;
    }

    for (i = 0; i < vap_map->num_vaps; i++) {
        if (vap_map->vap_array[i].vap_index == vap_index) {
            status = vap_map->vap_array[i].u.sta_info.conn_status;
            break;
        }
    }

    rbusValue_Init(&value);

    // the encoded data is a string
    rbusValue_SetInt32(value, status);
    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

static void activeGatewayCheckHandler(rbusHandle_t handle, rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    rbusValue_t value;
    //int csi_session;
    bool other_gateway_present = false;

    if(!event || (strcmp(subscription->eventName, WIFI_ACTIVE_GATEWAY_CHECK) != 0)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid Event Received %s",
                __func__, __LINE__, subscription->eventName);
        return;
    }

    value = rbusObject_GetValue(event->data, subscription->eventName);
    if (!value) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: Invalid value in event:%s",
                    __func__, __LINE__, subscription->eventName);
        return;
    }

    other_gateway_present = rbusValue_GetBoolean(value);
    push_data_to_ctrl_queue(&other_gateway_present, sizeof(other_gateway_present), ctrl_event_type_command, ctrl_event_type_command_sta_connect);

    UNREFERENCED_PARAMETER(handle);
}

rbusError_t get_assoc_clients_data(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value;
    webconfig_subdoc_data_t data;
    int itr, itrj, citr;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if ((mgr == NULL) || (ctrl == NULL)) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);

    if (strcmp(name, WIFI_WEBCONFIG_GET_ASSOC) != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property valid\n",__FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);

    pthread_mutex_lock(&ctrl->lock);
    for (itr=0; itr<MAX_NUM_RADIOS; itr++) {
        for (itrj=0; itrj<MAX_NUM_VAP_PER_RADIO; itrj++) {
            if (mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_queue != NULL) {
               int count = queue_count(mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_queue);
               for (citr=0; citr<count; citr++) {
                   assoc_dev_data_t *assoc_dev_data = (assoc_dev_data_t *)queue_peek(mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_queue, citr);
                   get_sta_stats_info(assoc_dev_data);
               }
            }
        }
    }
    pthread_mutex_unlock(&ctrl->lock);
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));

    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    data.u.decoded.num_radios = getNumberRadios();
    webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_associated_clients);

    rbusValue_SetString(value, data.u.encoded.raw);
    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
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

int wifiapi_result_publish(void)
{
    int rc = RBUS_ERROR_SUCCESS;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
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
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d rbusEvent_Publish %s failed: %d\n", __func__,
                                    event.name ,__LINE__, rc);

    rbusValue_Release(value);
    rbusObject_Release(data);

    return rc;
}

//Function used till the rbus_get invalid context issue is resolved
void get_assoc_devices_blob(char *str)
{
    webconfig_subdoc_data_t data;
    int itr, itrj, citr;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();


    if ((mgr == NULL) || (ctrl == NULL)) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
        return;
    }

    pthread_mutex_lock(&ctrl->lock);
    for (itr=0; itr<MAX_NUM_RADIOS; itr++) {
        for (itrj=0; itrj<MAX_NUM_VAP_PER_RADIO; itrj++) {
            if (mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_queue != NULL) {
               int count = queue_count(mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_queue);
               for (citr=0; citr<count; citr++) {
                   assoc_dev_data_t *assoc_dev_data = (assoc_dev_data_t *)queue_peek(mgr->radio_config[itr].vaps.rdk_vap_array[itrj].associated_devices_queue, citr);
                   get_sta_stats_info(assoc_dev_data);
               }
            }
        }
    }
    pthread_mutex_unlock(&ctrl->lock);

    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    data.u.decoded.num_radios = getNumberRadios();
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
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property=%s\n",__FUNCTION__,name);

    if (strncmp(name, WIFI_WEBCONFIG_GET_ACL, strlen(WIFI_WEBCONFIG_GET_ACL)+1) != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus property valid\n",__FUNCTION__);
        return RBUS_ERROR_INVALID_INPUT;
    }

    rbusValue_Init(&value);
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    data.u.decoded.num_radios = getNumberRadios();

    if (webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_mac_filter) == webconfig_error_none) {
        rbusValue_SetString(value, data.u.encoded.raw);
        rbusProperty_SetValue(property, value);
        wifi_util_dbg_print(WIFI_DMCLI, "%s: ACL DML cache encoded successfully  \n", __FUNCTION__);
    } else {
        wifi_util_dbg_print(WIFI_DMCLI, "%s: ACL DML cache encode failed  \n", __FUNCTION__);
    }

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;

}

void get_acl_data_blob(char *str)
{
    webconfig_subdoc_data_t data;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if ((mgr == NULL) || (ctrl == NULL)) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL pointers\n", __func__,__LINE__);
        return;
    }
    
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Aquiring Lock\n", __func__,__LINE__);
    pthread_mutex_lock(&ctrl->lock);
    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&mgr->radio_config, getNumberRadios()*sizeof(rdk_wifi_radio_t));
    pthread_mutex_unlock(&ctrl->lock);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Lock Released\n", __func__,__LINE__);
    data.u.decoded.num_radios = getNumberRadios();

    webconfig_encode(&ctrl->webconfig, &data, webconfig_subdoc_type_mac_filter);
    memcpy(str, data.u.encoded.raw, strlen(data.u.encoded.raw));

    return;
        
}

void rbus_subscribe_events(wifi_ctrl_t *ctrl)
{
    rbusEventSubscription_t rbusEvents[] = {
        { WIFI_ACTIVE_GATEWAY_CHECK, NULL, 0, 0, activeGatewayCheckHandler, NULL, NULL, NULL}, // WAN Manager
        { WIFI_WAN_FAILOVER_TEST, NULL, 0, 0, activeGatewayCheckHandler, NULL, NULL, NULL}, // Test Module
    };

    if (rbusEvent_SubscribeEx(ctrl->rbus_handle, rbusEvents, ARRAY_SZ(rbusEvents), 0) != RBUS_ERROR_SUCCESS) {
        //wifi_util_dbg_print(WIFI_CTRL,"%s Rbus events subscribe failed\n",__FUNCTION__);
        ctrl->rbus_events_subscribed = false;
        return;
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus events subscribe success\n",__FUNCTION__, __LINE__);
    }

    ctrl->rbus_events_subscribed = true;
}

void rbus_register_handlers(wifi_ctrl_t *ctrl)
{
    int rc = RBUS_ERROR_SUCCESS;
    char *component_name = "WifiCtrl";
    rbusDataElement_t dataElements[] = {
                                { WIFI_WEBCONFIG_DOC_DATA, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, webconfig_set_subdoc, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_INIT_DATA, RBUS_ELEMENT_TYPE_METHOD,
                                { webconfig_get_subdoc, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_STA_2G_VAP_CONNECT_STATUS, RBUS_ELEMENT_TYPE_METHOD,
                                { get_sta_vap_connect_status, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_STA_5G_VAP_CONNECT_STATUS, RBUS_ELEMENT_TYPE_METHOD,
                                { get_sta_vap_connect_status, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_WEBCONFIG_GET_ASSOC, RBUS_ELEMENT_TYPE_METHOD,
                                { get_assoc_clients_data, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_RBUS_WIFIAPI_COMMAND, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, set_wifiapi_command, NULL, NULL, NULL, NULL }},
                                {WIFI_RBUS_WIFIAPI_RESULT, RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, wifiapi_event_handler, NULL}},
                                { WIFI_WEBCONFIG_GET_ACL, RBUS_ELEMENT_TYPE_METHOD,
                                { get_acl_device_data, NULL, NULL, NULL, NULL, NULL }},
    };

    rc = rbus_open(&ctrl->rbus_handle, component_name);

    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_CTRL,"%s Rbus open failed\n",__FUNCTION__);
        return;
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s rbus open success\n",__FUNCTION__);

    rc = rbus_regDataElements(ctrl->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_CTRL,"%s rbus_regDataElements failed\n",__FUNCTION__);
        rbus_unregDataElements(ctrl->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
        rbus_close(ctrl->rbus_handle);
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s rbus event register:%s:%s\r\n",__FUNCTION__, WIFI_STA_2G_VAP_CONNECT_STATUS, WIFI_STA_5G_VAP_CONNECT_STATUS);
    return;
}


