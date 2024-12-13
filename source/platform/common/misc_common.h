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

#ifndef MISC_COMMON_H
#define MISC_COMMON_H

#include "wifi_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (* sysevent_open_t) (char *ip, unsigned short port, int version, char *id, unsigned int *token);
typedef int (* sysevent_close_t) (const int fd, const unsigned int token);
typedef int (* wifi_enableCSIEngine_t) (int apIndex, mac_address_t sta, bool enable);
typedef int (* initparodusTask_t) ();
typedef int (* wifi_getRadioTrafficStats2_t) (int radioIndex, wifi_radioTrafficStats2_t *output_struct);
typedef int (* WiFi_InitGasConfig_t) ();
typedef void (* daemonize_t) ();
typedef void (* sendWebpaMsg_t) (char *serviceName, char *dest, char *trans_id, char *traceParent, char *traceState, char *contentType, char *payload, unsigned int payload_len);

typedef struct {
    sysevent_open_t sysevent_open_fn;
    sysevent_close_t sysevent_close_fn;
    wifi_enableCSIEngine_t wifi_enableCSIEngine_fn;
    initparodusTask_t initparodusTask_fn;
    wifi_getRadioTrafficStats2_t wifi_getRadioTrafficStats2_fn;
    WiFi_InitGasConfig_t WiFi_InitGasConfig_fn;
    daemonize_t daemonize_fn;
    sendWebpaMsg_t sendWebpaMsg_fn;
} wifi_misc_desc_t;

#ifdef __cplusplus
}
#endif

#endif

