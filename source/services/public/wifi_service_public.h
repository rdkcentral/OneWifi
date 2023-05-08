/************************************************************************************ If not stated otherwise in this file or this component's LICENSE file the  
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

#ifndef WIFI_SERVICE_PUBLIC_H
#define WIFI_SERVICE_PUBLIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi_events.h"
#include "wifi_services_mgr.h"
#include "wifi_service_node.h"

typedef struct service  service_t;
typedef struct wifi_service wifi_service_t;
typedef struct wifi_service_node wifi_service_node_t;

int public_service_init(wifi_service_t *svc);
int public_service_create_nodes(wifi_service_t *svc, rdk_wifi_radio_t *radio_config, wifi_hal_capability_t *hal_cap, const service_t *service);
void public_service_delete_nodes(wifi_service_t *svc);
int public_service_start(wifi_service_t *svc);
int public_service_stop(wifi_service_t *svc);
int public_service_update(wifi_service_t *svc);
int public_service_event(wifi_service_t *svc, wifi_event_t *event);

int public_open_node_start(wifi_service_node_t *node);
int public_open_node_stop(wifi_service_node_t *node);
int public_open_node_update(wifi_service_node_t *node);
int public_open_node_event(wifi_service_node_t *node, wifi_event_t *event);


int public_secure_node_start(wifi_service_node_t *node);
int public_secure_node_stop(wifi_service_node_t *node);
int public_secure_node_update(wifi_service_node_t *node);
int public_secure_node_event(wifi_service_node_t *node, wifi_event_t *event);

#ifdef __cplusplus
}
#endif

#endif // WIFI_SERVICE_PUBLIC_H

