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

#ifndef WIFI_SERVICES_MGR_H
#define WIFI_SERVICES_MGR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <math.h>
#include "wifi_hal.h"
#include "wifi_base.h"
#include "wifi_events.h"
#include "wifi_service_node.h"
#include "wifi_service_public.h"
#include "wifi_service_private.h"
#include "wifi_service_mesh.h"
#include "wifi_util.h"

#define MAX_SERVICES    6
#define MAX_NODES       6

typedef struct wifi_ctrl wifi_ctrl_t;
typedef char    wifi_service_name_t[64];
typedef hash_map_t *wifi_registered_services_t;
typedef hash_map_t *wifi_service_nodes_t;
typedef struct service  service_t;

typedef enum {
    wifi_service_type_private,
    wifi_service_type_public,
    wifi_service_type_mesh,
    wifi_service_type_managed,
    wifi_service_type_dynamic_ps,
    wifi_service_type_dynamic_tr,
} wifi_service_type_t;

typedef int (* wifi_service_init_fn_t)(wifi_service_t *svc);
typedef int (* wifi_service_create_nodes_fn_t)(wifi_service_t *svc, rdk_wifi_radio_t *radio_config, wifi_hal_capability_t *hal_cap, const service_t *service);
typedef void (* wifi_service_delete_nodes_fn_t)(wifi_service_t *svc);
typedef int (* wifi_service_start_fn_t)(wifi_service_t *svc);
typedef int (* wifi_service_stop_fn_t)(wifi_service_t *svc);
typedef int (* wifi_service_update_fn_t)(wifi_service_t *svc);
typedef int (* wifi_service_event_fn_t)(wifi_service_t *svc, wifi_event_t *event);

typedef struct {
    wifi_service_type_t           type;
    wifi_service_name_t           name;
    wifi_service_init_fn_t        init_fn;
    wifi_service_create_nodes_fn_t       create_nodes_fn;
    wifi_service_delete_nodes_fn_t       delete_nodes_fn;
    wifi_service_start_fn_t       start_fn;
    wifi_service_stop_fn_t        stop_fn;
    wifi_service_update_fn_t      update_fn;
    wifi_service_event_fn_t       event_fn;
} wifi_service_descriptor_t;

typedef struct wifi_services_mgr wifi_services_mgr_t;

typedef struct wifi_service {
    bool                     created;
    wifi_service_descriptor_t    desc;
    wifi_services_mgr_t    *mgr;
    wifi_ctrl_t            *ctrl;
    wifi_hal_capability_t  *cap;
    wifi_service_nodes_t   nodes;
} __attribute__((packed)) wifi_service_t;

typedef struct wifi_services_mgr {
    wifi_ctrl_t              *ctrl;
    wifi_hal_capability_t *cap;
    wifi_registered_services_t svcs_map;
} wifi_services_mgr_t;

typedef struct {
    char    name[32];
    char    radio[32];
    char    type[32];
} nodes_t;

typedef struct service {
    char    name[64];
    char    description[128];
    nodes_t nodes[MAX_NODES];
} service_t;

int services_mgr_init(wifi_ctrl_t *ctrl, rdk_wifi_radio_t *radio_config, wifi_hal_capability_t *hal_cap, const service_t *services, unsigned int num_services);
void services_mgr_deinit(wifi_services_mgr_t *mgr);
int services_mgr_start_service_by_type(wifi_services_mgr_t *mgr, wifi_service_type_t type);
int services_mgr_stop_service_by_type(wifi_services_mgr_t *mgr, wifi_service_type_t type);
int services_mgr_event(wifi_services_mgr_t *svc_mgr, wifi_event_t *event);
wifi_service_t *get_service_by_type(wifi_services_mgr_t *mgr, wifi_service_type_t type);
void services_mgr_delete_service_by_type(wifi_services_mgr_t *mgr, wifi_service_type_t type);
void services_mgr_delete_service(wifi_services_mgr_t *mgr, wifi_service_name_t name);

#ifdef __cplusplus
}
#endif

#endif // WIFI_SERVICES_MGR_H
