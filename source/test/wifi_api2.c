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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <rbus.h>

#define WIFI_RBUS_WIFIAPI_COMMAND               "Device.WiFi.WiFiAPI.command"
#define WIFI_RBUS_WIFIAPI_RESULT                "Device.WiFi.WiFiAPI.result"

#define WIFI_API2_MAX_COMMAND_SIZE              1024

#define WIFI_API2_RBUS_SUBSCRIBE_TIMEOUT_SEC    1

char help[] = "Usage: wifi_api2 <WiFi API name> <args>";

static void wifi_api2_eventhandler(
    rbusHandle_t handle,
    rbusEvent_t const* event,
    rbusEventSubscription_t* subscription)
{
    rbusValue_t wifi_api_result;

    wifi_api_result = rbusObject_GetValue(event->data, "value");

    if (wifi_api_result) {
        printf("%s\n", rbusValue_GetString(wifi_api_result, NULL));
    } else {
        printf("wifi_api2: Error - failed to read the result\n");
    }

    (void)handle;
    exit(0);
}

int main(int argc, char *argv[])
{
    rbusHandle_t handle;
    char component_name[RBUS_MAX_NAME_LENGTH];
    int rc = RBUS_ERROR_SUCCESS, len = 0;
    pid_t pid;
    char command[WIFI_API2_MAX_COMMAND_SIZE];

    if (argc < 2) {
        printf("%s\n", help);
        exit(0);
    }
    /* Add pid to rbus component name */
    pid = getpid();
    snprintf(component_name, RBUS_MAX_NAME_LENGTH, "%s%d", "wifi_api2", pid);

    for (int i = 1; i < argc; i++) {
        if(len < WIFI_API2_MAX_COMMAND_SIZE) {
            len += snprintf(&command[len], WIFI_API2_MAX_COMMAND_SIZE-len, "%s ", argv[i]);
        } else {
            break;
        }
    }

    rc = rbus_open(&handle, component_name);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        printf("wifi_api2: Error - rbus_open failed: %d\n", rc);
        return rc;
    }
    
    rc = rbusEvent_Subscribe(handle, WIFI_RBUS_WIFIAPI_RESULT, wifi_api2_eventhandler, NULL,
                                WIFI_API2_RBUS_SUBSCRIBE_TIMEOUT_SEC);
    if(rc != RBUS_ERROR_SUCCESS)
    {
        printf("wifi_api2: Error - failed to subscribe to %s: %d\n", WIFI_RBUS_WIFIAPI_RESULT, rc);
        rbus_close(handle);
        return rc;
    }

    rbus_setStr(handle, WIFI_RBUS_WIFIAPI_COMMAND, command);

    sleep(5);

    rbus_close(handle);
    printf("wifi_api2: Error - command timeout\n");
    exit(rc);
}
