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
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include "wifi_hal.h"
#include "wifi_services_mgr.h"

wifi_service_descriptor_t public_service_desc = {
    wifi_service_type_public, "Public",
    public_service_init,
    public_service_create_nodes,
    public_service_delete_nodes,
    public_service_start,
    public_service_stop,
    public_service_update,
    public_service_event
};

wifi_node_descriptor_t hotspot_open_5g_desc = {
    "hotspot_open_5g",
    0,
    public_open_node_start,
    public_open_node_stop,
    public_open_node_update,
    public_open_node_event
};

wifi_node_descriptor_t hotspot_open_6g_desc = {
    "hotspot_open_6g",
    0,
    public_open_node_start,
    public_open_node_stop,
    public_open_node_update,
    public_open_node_event
};

wifi_node_descriptor_t hotspot_secure_2g_desc = {
    "hotspot_secure_2g",
    0,
    public_secure_node_start,
    public_secure_node_stop,
    public_secure_node_update,
    public_secure_node_event
};

wifi_node_descriptor_t hotspot_secure_5g_desc = {
    "hotspot_secure_5g",
    0,
    public_secure_node_start,
    public_secure_node_stop,
    public_secure_node_update,
    public_secure_node_event
};

wifi_node_descriptor_t hotspot_secure_6g_desc = {
    "hotspot_secure_6g",
    0,
    public_secure_node_start,
    public_secure_node_stop,
    public_secure_node_update,
    public_secure_node_event
};

int public_service_init(wifi_service_t *svc)
{
    return 0;
}

void public_service_delete_nodes(wifi_service_t *svc)
{
    wifi_service_node_t *svc_node, *tmp;

    svc_node = hash_map_get_first(svc->nodes);
    while (svc_node != NULL) {
        tmp = svc_node;
        svc_node = hash_map_get_next(svc->nodes, svc_node);
        tmp->desc.node_stop_fn(tmp);
        hash_map_remove(svc->nodes, tmp->desc.name);
        free(tmp);
    }
}

int public_service_create_nodes(wifi_service_t *svc, rdk_wifi_radio_t *radio_config, wifi_hal_capability_t *hal_cap, const service_t *service)
{
    unsigned int i, j, k;
    bool node_configurable = false;
    nodes_t *node;
    wifi_service_node_t *svc_node;
    wifi_node_name_t node_name;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_t *vap_info = NULL;
    wifi_node_descriptor_t *node_desc = NULL;

    for (i = 0; i < hal_cap->wifi_prop.numRadios; i++) {
        radio = &radio_config[i];

        for (j = 0; j < MAX_NODES; j++) {
            node = (nodes_t *)&service->nodes[j];

            // see if the platform radio can support this node
            if (node->radio[0] == '\0') {
                continue;
            }

            if (strncmp(radio->name, node->radio, 16) != 0) {
                continue;
            }

            snprintf(node_name, sizeof(node_name), "%s_%s", node->name, node->radio);

            node_configurable = false;
            for (k = 0; k < radio->vaps.vap_map.num_vaps; k++) {
                vap_info = &radio->vaps.vap_map.vap_array[k];
                if (strncmp(node_name, vap_info->vap_name, sizeof(wifi_vap_name_t)) == 0) {
                    node_configurable = true;
                    break;
                }
            }

            if (node_configurable == false) {
                wifi_util_error_print(WIFI_SERVICES,"%s:%d: This service node: %s can not be configured on this platform\n", __func__, __LINE__, node_name);
                continue;
            }

            node_desc = NULL;

            if (strncmp(node_name, "hotspot_open_5g", sizeof(node_name)) == 0) {
                node_desc = &hotspot_open_5g_desc;
            } else if (strncmp(node_name, "hotspot_open_6g", sizeof(node_name)) == 0) {
                node_desc = &hotspot_open_6g_desc;
            } else if (strncmp(node_name, "hotspot_secure_2g", sizeof(node_name)) == 0) {
                node_desc = &hotspot_secure_2g_desc;
            } else if (strncmp(node_name, "hotspot_secure_5g", sizeof(node_name)) == 0) {
                node_desc = &hotspot_secure_5g_desc;
            } else if (strncmp(node_name, "hotspot_secure_6g", sizeof(node_name)) == 0) {
                node_desc = &hotspot_secure_6g_desc;
            }

            if (node_desc == NULL) {
                wifi_util_error_print(WIFI_SERVICES,"%s:%d: Could not find descriptor for node: %s\n", __func__, __LINE__, node_name);
                continue;
            }

            // all is good, we can create the node

            svc_node = (wifi_service_node_t *)malloc(sizeof(wifi_service_node_t));
            memset((unsigned char *)svc_node, 0, sizeof(wifi_service_node_t));
            memcpy(&svc_node->desc, node_desc, sizeof(wifi_node_descriptor_t));

            svc_node->radio_index = radio->vaps.radio_index;
            svc_node->radio_op = &radio->oper;
            svc_node->vap_info = vap_info;
            svc_node->svc = svc;
            svc_node->ctrl = svc->ctrl;
            svc_node->cap = hal_cap;

            wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s initialized\n", __func__, __LINE__, node_name);

            hash_map_put(svc->nodes, strdup(node_name), svc_node);
        }
    }
    return 0;
}

int public_service_start(wifi_service_t *svc)
{
    wifi_service_node_t *node = NULL;

    node = hash_map_get_first(svc->nodes);
    while (node != NULL) {
        node->desc.node_start_fn(node);
        node = hash_map_get_next(svc->nodes, node);
    }

    return 0;
}

int public_service_stop(wifi_service_t *svc)
{
    wifi_service_node_t *node = NULL;

    node = hash_map_get_first(svc->nodes);
    while (node != NULL) {
        node->desc.node_stop_fn(node);
        node = hash_map_get_next(svc->nodes, node);
    }

    return 0;
}

int public_service_update(wifi_service_t *svc)
{
    return 0;
}

int public_service_event(wifi_service_t *svc, wifi_event_t *event)
{
    wifi_service_node_t *node = NULL;

    node = hash_map_get_first(svc->nodes);
    while (node != NULL) {
        if (node->desc.reg_events_types & event->event_type) {
            node->desc.node_event_fn(node, event);
        }
        node = hash_map_get_next(svc->nodes, node);
    }

    return 0;
}

int public_open_node_start(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int public_open_node_stop(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int public_open_node_update(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int public_open_node_event(wifi_service_node_t *node, wifi_event_t *event)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int public_secure_node_start(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int public_secure_node_stop(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int public_secure_node_update(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int public_secure_node_event(wifi_service_node_t *node, wifi_event_t *event)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}
