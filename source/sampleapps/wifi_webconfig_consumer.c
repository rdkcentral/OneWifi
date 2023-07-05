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
#include <sys/resource.h>
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
#define CONSUMER_APP_FILE "/tmp/wifi_webconfig_consumer_app"
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


void webconfig_consumer_get(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
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
    push_data_to_consumer_queue(str, len, consumer_event_type_webconfig, consumer_event_webconfig_get_data);

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
    }
    return rc;
}

rbusError_t generic_event_handler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    (void)handle;
    (void)filter;
    (void)autoPublish;
    (void)interval;
    printf(
        "slave_event_handler called:\n" \
        "\taction=%s\n" \
        "\teventName=%s\n",
        action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe",
        eventName);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t get_device_param(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    webconfig_consumer_t *consumer = get_consumer_object();
    rbusValue_t value;
    unsigned int temp_param = 0;

    printf("%s:%d Rbus property=%s\n",__func__, __LINE__, name);

    if (consumer->test_state < consumer_test_state_cache_init_complete) {
        printf("%s:%d data init in-progress:%d\r\n", __func__, __LINE__, consumer->test_state);
        return RBUS_ERROR_NOT_INITIALIZED;
    }

    rbusValue_Init(&value);

    if (strcmp(name, TEST_WIFI_DEVICE_MODE) == 0) {
        temp_param = consumer->config.global_parameters.device_network_mode;
        printf("%s:%d send device mode:%d\r\n", __func__, __LINE__, temp_param);
        rbusValue_SetUInt32(value, temp_param);
    } else if (strcmp(name, WIFI_DEVICE_TUNNEL_STATUS) == 0) {
        temp_param = DEVICE_TUNNEL_DOWN; // tunnel down
        printf("%s:%d send tunnel status:%d\r\n", __func__, __LINE__, temp_param);
        rbusValue_SetBoolean(value, temp_param);
    }

    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);

    return RBUS_ERROR_SUCCESS;
}

static void eventReceiveHandler(
    rbusHandle_t handle,
    rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    printf("%s:%d:user data: %s:%d event name:%s\n", __func__, __LINE__, (char*)subscription->userData, event->type, event->name);
}

int webconfig_consumer_rbus_register_events(webconfig_consumer_t *consumer)
{
    int rc;
    rbusDataElement_t rbusEvents[] = {
                                { WIFI_WAN_FAILOVER_TEST, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, webconfig_consumer_set_subdoc, NULL, NULL, NULL, NULL }},
                                { "TunnelStatus", RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, generic_event_handler, NULL}},
                                // This below parametrs are registered for testing perpose only
                                { TEST_WIFI_DEVICE_MODE, RBUS_ELEMENT_TYPE_METHOD,
                                { get_device_param, NULL, NULL, NULL, NULL, NULL }},
                                { RBUS_WIFI_WPS_PIN_START, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_FRAME_INJECTOR_TO_ONEWIFI, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, NULL, NULL, NULL, NULL, NULL }},
    };

    rc = rbus_regDataElements(consumer->rbus_handle, ARRAY_SIZE(rbusEvents), rbusEvents);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf("%s:%d rbus_regDataElements failed\n",__FUNCTION__, __LINE__);
        rbus_unregDataElements(consumer->rbus_handle, ARRAY_SIZE(rbusEvents), rbusEvents);
        rbus_close(consumer->rbus_handle);
        return RETURN_ERR;
    } else {
        printf("%s:%d rbus_regDataElements :%s\n",__FUNCTION__, __LINE__, WIFI_ACTIVE_GATEWAY_CHECK);
    }

    unsigned int i = 0;
    rbusDataElement_t extra_rbusEvents[] = {
                                { WIFI_ACTIVE_GATEWAY_CHECK, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, webconfig_consumer_set_subdoc, NULL, NULL, NULL, NULL }},
                                { WIFI_DEVICE_TUNNEL_STATUS, RBUS_ELEMENT_TYPE_METHOD,
                                { get_device_param, NULL, NULL, NULL, NULL, NULL }},
    };

    for (i = 0; i < ARRAY_SIZE(extra_rbusEvents); i++) {
        rc = rbusEvent_Subscribe(consumer->rbus_handle, extra_rbusEvents[i].name, eventReceiveHandler, NULL, 0);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            printf("consumer: rbusEvent_Subscribe failed: %d event name:%s\n", rc, extra_rbusEvents[i].name);
            rc = rbus_regDataElements(consumer->rbus_handle, 1, (extra_rbusEvents + i));
            if (rc != RBUS_ERROR_SUCCESS) {
                printf("%s:%d rbus_regDataElements failed index:%d event name:%s\n",__FUNCTION__, __LINE__, i, extra_rbusEvents[i].name);
                rbus_unregDataElements(consumer->rbus_handle, 1, (extra_rbusEvents + i));
                rbus_close(consumer->rbus_handle);
                return RETURN_ERR;
            } else {
                printf("%s:%d rbus_regDataElements event[%d] name:%s\n",__FUNCTION__, __LINE__, i, extra_rbusEvents[i].name);
            }
        }
    }

    return RETURN_OK;
}

void de_init_rbus_object(void)
{
    webconfig_consumer_t *consumer = get_consumer_object();
    rbusDataElement_t rbusEvents[] = {
                                { WIFI_WAN_FAILOVER_TEST, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, webconfig_consumer_set_subdoc, NULL, NULL, NULL, NULL }},
                                { "TunnelStatus", RBUS_ELEMENT_TYPE_EVENT,
                                { NULL, NULL, NULL, NULL, generic_event_handler, NULL}},
                                // This below parametrs are registered for testing perpose only
                                { TEST_WIFI_DEVICE_MODE, RBUS_ELEMENT_TYPE_METHOD,
                                { get_device_param, NULL, NULL, NULL, NULL, NULL }},
                                { RBUS_WIFI_WPS_PIN_START, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, NULL, NULL, NULL, NULL, NULL }},
                                { WIFI_FRAME_INJECTOR_TO_ONEWIFI, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, NULL, NULL, NULL, NULL, NULL }},
    };

    if (consumer->rbus_handle != NULL) {
        printf("%s:%d: un-register rbus data element\n", __func__, __LINE__);
        rbus_unregDataElements(consumer->rbus_handle, ARRAY_SIZE(rbusEvents), rbusEvents);
        rbus_close(consumer->rbus_handle);
    }
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
    char name[64] = { 0 };
    int rc;
    rbusEventSubscription_t rbusEvents[] = {
        { WIFI_WEBCONFIG_DOC_DATA_NORTH, NULL, 0, 0, webconfig_consumer_set, NULL, NULL, NULL, false},
        { WIFI_WEBCONFIG_GET_ASSOC, NULL, 0, 0, webconfig_consumer_get, NULL, NULL, NULL, false},
        { WIFI_WEBCONFIG_GET_NULL_SUBDOC, NULL, 0, 0, webconfig_consumer_get, NULL, NULL, NULL, false}
    };

    if (rbusEvent_SubscribeEx(consumer->rbus_handle, rbusEvents, ARRAY_SIZE(rbusEvents), 0) != RBUS_ERROR_SUCCESS) {
        printf("%s Rbus events subscribe failed\n",__FUNCTION__);
        return -1;
    } else {
        printf("%s:%d webconfig sample app able to subscribe to event with rbus\r\n", __func__, __LINE__);
    }

    rc = rbusEvent_Subscribe(consumer->rbus_handle, "Device.WiFi.STA.", eventReceiveHandler, NULL, 0);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        printf("consumer: rbusEvent_Subscribe failed: %d\n", rc);
        return -1;
    }

    strcpy(name, "Device.WiFi.STA.*.InterfaceName");
    printf("%s:%d Rbus events subscription start name:%s\n",__FUNCTION__, __LINE__, name);
    rc = rbusEvent_Subscribe(consumer->rbus_handle, name, eventReceiveHandler, NULL, 0);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf("%s:%d Rbus events subscribe failed:%d\n",__FUNCTION__, __LINE__, rc);
        return -1;
    }

    strcpy(name, "Device.WiFi.STA.*.Connection.Status");
    printf("%s:%d Rbus events subscription start name:%s\n",__FUNCTION__, __LINE__, name);
    rc = rbusEvent_Subscribe(consumer->rbus_handle, name, webconfig_consumer_sta_conn_status, NULL, 0);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf("%s:%d Rbus events subscribe failed:%d\n",__FUNCTION__, __LINE__, rc);
        return -1;
    }

    strcpy(name, "Device.WiFi.STA.*.Bssid");
    printf("%s:%d Rbus events subscription start name:%s\n",__FUNCTION__, __LINE__, name);
    rc = rbusEvent_Subscribe(consumer->rbus_handle, name, eventReceiveHandler, NULL, 0);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf("%s:%d Rbus events subscribe failed:%d\n",__FUNCTION__, __LINE__, rc);
        return -1;
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
    const char *paramNames[] = {WIFI_WEBCONFIG_INIT_DML_DATA};
    const char *str;
    int len = 0;

    rc = rbus_get(consumer->rbus_handle, paramNames[0], &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        printf ("rbus_get failed for [%s] with error [%d]\n", paramNames[0], rc);
        return -1;
    }

    printf("%s:%d: init cache trigger successful\n", __func__, __LINE__);

    str = rbusValue_GetString(value, &len);
    if (str == NULL) {
        printf("%s Null pointer,Rbus set string len=%d\n",__FUNCTION__,len);
        return -1;
    }

    printf("%s:%d data send to consumer event len : %d\n",__FUNCTION__, __LINE__, len);
    handle_webconfig_consumer_event(consumer, str, len, consumer_event_webconfig_set_data);

    return 0;
}
void sig_handler(int sig)
{
    exit(0);
}
void cleanup_function()
{
    remove(CONSUMER_APP_FILE);
}
int main (int argc, char *argv[])
{
    struct rlimit rl;
    int result;
    const rlim_t stack_size = 8L * 1024L * 1024L; // 8mb

    atexit(cleanup_function);
    signal(SIGINT,sig_handler);
    signal(SIGTERM,sig_handler);
    signal(SIGTSTP,sig_handler);
    signal(SIGKILL,sig_handler);

    result = getrlimit(RLIMIT_STACK, &rl);

    if (result == 0)
    {
        if (rl.rlim_cur < stack_size)
        {
            rl.rlim_cur = stack_size;
            rl.rlim_max = stack_size;
            result = setrlimit(RLIMIT_STACK, &rl);

            if (result != 0)
            {
                printf("%s:%d: setrlimit failed\n", __func__, __LINE__);
                return -1;
            }
        }
    }
    
    printf("%s:%d: Enter\n", __func__, __LINE__);
    FILE *fp = fopen(CONSUMER_APP_FILE, "a+");
    if(fp != NULL) {
        fclose(fp);
    }
    run_tests();
    return 0;
}
