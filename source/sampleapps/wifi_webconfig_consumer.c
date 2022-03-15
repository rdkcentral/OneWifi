#include <stdio.h>
#include <stdbool.h>
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "scheduler.h"
#include <unistd.h>
#include <pthread.h>
#include <rbus.h>
#include <libgen.h>
#include "wifi_webconfig_consumer.h"

void webconfig_consumer_set(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    int len = 0;
    const char *str;
    rbusValue_t value = rbusObject_GetValue(event->data, NULL );
    if(!value)
    {
        printf("%s:%d FAIL: value is NULL\n",__FUNCTION__, __LINE__);
        return;
    }

    printf("%s:%d Rbus event name=%s\n",__FUNCTION__, __LINE__, event->name);

    str = rbusValue_GetString(value, &len);
    if (str == NULL) {
        printf("%s Null pointer,Rbus set string len=%d\n",__FUNCTION__,len);
        return;
    }

    printf("%s:%d data send to consumer queue\n",__FUNCTION__, __LINE__);
    push_data_to_consumer_queue(str, len, consumer_event_type_webconfig, consumer_event_webconfig_set_data);

    return;
}

rbusError_t webconfig_consumer_set_subdoc(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    rbusValue_t value = rbusProperty_GetValue(property);
    rbusValueType_t type = rbusValue_GetType(value);
    int rc = RBUS_ERROR_INVALID_INPUT;
    int len = 0;
    const char * pTmp = NULL;

    printf("%s:%d Rbus property=%s\n",__FUNCTION__, __LINE__, name);
    if (type != RBUS_STRING) {
        printf("%s:%d Wrong data type %s\n",__FUNCTION__, __LINE__, name);
        return rc;
    }

    pTmp = rbusValue_GetString(value, &len);
    if (pTmp != NULL) {
        rc = RBUS_ERROR_SUCCESS;
        printf("%s:%d Rbus set string len=%d\n",__FUNCTION__, __LINE__, len);
        //push_data_to_ctrl_queue((const cJSON *)pTmp, (strlen(pTmp) + 1), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data);
    }
    return rc;
}

int webconfig_consumer_rbus_register_events(webconfig_consumer_t *consumer)
{
    int rc;
    rbusDataElement_t rbusEvents[] = {
                                { WIFI_ACTIVE_GATEWAY_CHECK, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, webconfig_consumer_set_subdoc, NULL, NULL, NULL, NULL }},
                                { WIFI_WAN_FAILOVER_TEST, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, webconfig_consumer_set_subdoc, NULL, NULL, NULL, NULL }},
    };

    rc = rbus_regDataElements(consumer->rbus_handle, ARRAY_SZ(rbusEvents), rbusEvents);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf("%s:%d rbus_regDataElements failed\n",__FUNCTION__, __LINE__);
        rbus_unregDataElements(consumer->rbus_handle, ARRAY_SZ(rbusEvents), rbusEvents);
        rbus_close(consumer->rbus_handle);
        return RETURN_ERR;
    } else {
        printf("%s:%d rbus_regDataElements :%s\n",__FUNCTION__, __LINE__, WIFI_ACTIVE_GATEWAY_CHECK);
    }

    return RETURN_OK;
}

int webconfig_rbus_other_gateway_state_publish(webconfig_consumer_t *consumer, bool status)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, WIFI_ACTIVE_GATEWAY_CHECK, value);
    rbusValue_SetBoolean(value, status);
    event.name = WIFI_ACTIVE_GATEWAY_CHECK;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    if (rbusEvent_Publish(consumer->rbus_handle, &event) != RBUS_ERROR_SUCCESS) {
        printf( "%s:%d: rbusEvent_Publish Event failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return RETURN_OK;
}

int consumer_events_subscribe(webconfig_consumer_t *consumer)
{
    rbusEventSubscription_t rbusEvents[] = {
        { WIFI_STA_2G_VAP_CONNECT_STATUS, NULL, 0, 0, webconfig_consumer_sta_conn_status, NULL, NULL, NULL},
        { WIFI_STA_5G_VAP_CONNECT_STATUS, NULL, 0, 0, webconfig_consumer_sta_conn_status, NULL, NULL, NULL},
        { WIFI_WEBCONFIG_DOC_DATA, NULL, 0, 0, webconfig_consumer_set, NULL, NULL, NULL},
    };

    if (rbusEvent_SubscribeEx(consumer->rbus_handle, rbusEvents, ARRAY_SZ(rbusEvents), 0) != RBUS_ERROR_SUCCESS) {
        printf("%s Rbus events subscribe failed\n",__FUNCTION__);
        return -1;
    } else {
        printf("%s:%d webconfig sample app able to subscribe to event with rbus\r\n", __func__, __LINE__);
    }
    consumer->rbus_events_subscribed = true;

    return 0;
}

int webconfig_consumer_register(webconfig_consumer_t *consumer)
{
    int rc = RBUS_ERROR_SUCCESS;
    char *component_name = "WebconfigSampleApp";

    rc = rbus_open(&consumer->rbus_handle, component_name);

    if (rc != RBUS_ERROR_SUCCESS) {
        printf("%s Rbus open failed\n",__FUNCTION__);
        return webconfig_error_init;
    }

    printf("%s rbus open success\n",__FUNCTION__);

    rc = webconfig_consumer_rbus_register_events(consumer);
    if (rc != RETURN_OK) {
        printf("%s:%d Unable to register to event  with rbus error code : %d\n", __func__, __LINE__, rc);
        return webconfig_error_invalid_subdoc;
    }

    return webconfig_error_none;
}

int initial_sync(webconfig_consumer_t *consumer)
{
    rbusValue_t value;
    int rc = RBUS_ERROR_SUCCESS;
    const char *paramNames[] = {WIFI_WEBCONFIG_INIT_DATA};

    rc = rbus_get(consumer->rbus_handle, paramNames[0], &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf ("rbus_get failed for [%s] with error [%d]\n", paramNames[0], rc);
        return -1;
    }

    printf("%s:%d: init cache trigger successful\n", __func__, __LINE__);

    return 0;
}

int main (int argc, char *argv[])
{
    printf("%s:%d: Enter\n", __func__, __LINE__);

    wifi_hal_capability_t l_hal_cap;

    int ret = wifi_hal_init();
    if (ret != RETURN_OK) {
        printf("%s wifi_init failed:ret :%d\n",__FUNCTION__, ret);
        return RETURN_ERR;
    }

    ret = wifi_hal_getHalCapability(&l_hal_cap);
    if (ret != RETURN_OK) {
        printf("%s wifi_hal_get_capability failed:ret :%d\n",__FUNCTION__, ret);
        return RETURN_ERR;
    }

    //Register wifi hal sta connect/disconnect callback
    wifi_hal_staConnectionStatus_callback_register(sta_connection_status_event);

    run_tests();
    return 0;
}
