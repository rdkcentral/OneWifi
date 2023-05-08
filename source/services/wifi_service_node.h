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

#ifndef WIFI_SERVICES_NODE_H
#define WIFI_SERVICES_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <math.h>
#include "wifi_hal.h"
#include "wifi_base.h"
#include "wifi_events.h"
#include "wifi_service_mesh.h"
#include "wifi_service_public.h"

typedef struct wifi_ctrl wifi_ctrl_t;
typedef struct wifi_service_node wifi_service_node_t;
typedef char wifi_node_name_t[32];

typedef int (* wifi_node_start_fn_t)(wifi_service_node_t *node);
typedef int (* wifi_node_stop_fn_t)(wifi_service_node_t *node);
typedef int (* wifi_node_update_fn_t)(wifi_service_node_t *node);
typedef int (* wifi_node_event_fn_t)(wifi_service_node_t *node, wifi_event_t *event);

typedef struct {
    union {
            mesh_sta_node_data_t   sta_node_data;
    } u;
} wifi_service_node_data_t;

typedef struct {
    wifi_node_name_t   name;
    unsigned int reg_events_types; // bit mask of registered event types
    wifi_node_start_fn_t    node_start_fn;
    wifi_node_stop_fn_t     node_stop_fn;
    wifi_node_update_fn_t   node_update_fn;
    wifi_node_event_fn_t    node_event_fn;
} wifi_node_descriptor_t;

typedef struct wifi_service_node {
    wifi_node_descriptor_t  desc;
    unsigned int radio_index;
    wifi_hal_capability_t    *cap;
    wifi_radio_operationParam_t *radio_op;
    wifi_vap_info_t *vap_info;
    wifi_service_t  *svc;
    wifi_ctrl_t     *ctrl;
    wifi_service_node_data_t    data;
} wifi_service_node_t;

#ifdef __cplusplus
}
#endif

#endif // WIFI_SERVICES_NODE_H
