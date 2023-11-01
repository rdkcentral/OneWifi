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
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include "wifi_util.h"
#include "wifi_hal.h"
#include "wifi_services_mgr.h"
#include "wifi_ctrl.h"
#include "scheduler.h"

wifi_service_descriptor_t mesh_service_desc = {
    wifi_service_type_public, "Mesh",
    mesh_service_init,
    mesh_service_create_nodes,
    mesh_service_delete_nodes,
    mesh_service_start,
    mesh_service_stop,
    mesh_service_update,
    mesh_service_event
};

wifi_node_descriptor_t mesh_backhaul_2g_desc = {
    "mesh_backhaul_2g",
    0,
    mesh_backhaul_node_start,
    mesh_backhaul_node_stop,
    mesh_backhaul_node_update,
    mesh_backhaul_node_event
};

wifi_node_descriptor_t mesh_backhaul_5g_desc = {
    "mesh_backhaul_5g",
    0,
    mesh_backhaul_node_start,
    mesh_backhaul_node_stop,
    mesh_backhaul_node_update,
    mesh_backhaul_node_event
};

wifi_node_descriptor_t 	mesh_backhaul_6g_desc = {
    "mesh_backhaul_6g",
    0,
    mesh_backhaul_node_start,
    mesh_backhaul_node_stop,
    mesh_backhaul_node_update,
    mesh_backhaul_node_event
};

wifi_node_descriptor_t mesh_sta_2g_desc = {
    "mesh_sta_2g",
    wifi_event_type_exec | wifi_event_type_command | wifi_event_type_hal_ind | wifi_event_type_webconfig,
    mesh_sta_node_start,
    mesh_sta_node_stop,
    mesh_sta_node_update,
    mesh_sta_node_event
};

wifi_node_descriptor_t mesh_sta_5g_desc = {
    "mesh_sta_5g",
    wifi_event_type_exec | wifi_event_type_command | wifi_event_type_hal_ind | wifi_event_type_webconfig,
    mesh_sta_node_start,
    mesh_sta_node_stop,
    mesh_sta_node_update,
    mesh_sta_node_event
};

wifi_node_descriptor_t mesh_sta_6g_desc = {
    "mesh_sta_6g",
    wifi_event_type_exec | wifi_event_type_command | wifi_event_type_hal_ind | wifi_event_type_webconfig,
    mesh_sta_node_start,
    mesh_sta_node_stop,
    mesh_sta_node_update,
    mesh_sta_node_event
};

int mesh_service_init(wifi_service_t *svc)
{
    return 0;
}

void mesh_service_delete_nodes(wifi_service_t *svc)
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

int mesh_service_create_nodes(wifi_service_t *svc, rdk_wifi_radio_t *radio_config, wifi_hal_capability_t *hal_cap, const service_t *service)
{
    unsigned int i, j, k;
    bool node_configurable = false;
    nodes_t    *node;
    wifi_service_node_t  *svc_node;
    wifi_node_name_t node_name;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_t  *vap_info = NULL;
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

            if (strncmp(node_name, "mesh_backhaul_2g", sizeof(node_name)) == 0) {
                node_desc = &mesh_backhaul_2g_desc;
            } else if (strncmp(node_name, "mesh_backhaul_5g", sizeof(node_name)) == 0) {
                node_desc = &mesh_backhaul_5g_desc;
            } else if (strncmp(node_name, "mesh_backhaul_6g", sizeof(node_name)) == 0) {
                node_desc = &mesh_backhaul_6g_desc;
            } else if (strncmp(node_name, "mesh_sta_2g", sizeof(node_name)) == 0) {
                node_desc = &mesh_sta_2g_desc;
            } else if (strncmp(node_name, "mesh_sta_5g", sizeof(node_name)) == 0) {
                node_desc = &mesh_sta_5g_desc;
            } else if (strncmp(node_name, "mesh_sta_6g", sizeof(node_name)) == 0) {
                node_desc = &mesh_sta_6g_desc;
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

int mesh_service_start(wifi_service_t *svc)
{
    wifi_service_node_t *node = NULL;

    node = hash_map_get_first(svc->nodes);
    while (node != NULL) {
        node->desc.node_start_fn(node);
        node = hash_map_get_next(svc->nodes, node);
    }

    return 0;
}

int mesh_service_stop(wifi_service_t *svc)
{
    wifi_service_node_t *node = NULL;

    node = hash_map_get_first(svc->nodes);
    while (node != NULL) {
        node->desc.node_stop_fn(node);
        node = hash_map_get_next(svc->nodes, node);
    }

    return 0;
}

int mesh_service_update(wifi_service_t *svc)
{
    return 0;
}

int mesh_service_event(wifi_service_t *svc, wifi_event_t *event)
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


int mesh_backhaul_node_start(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int mesh_backhaul_node_stop(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int mesh_backhaul_node_update(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int mesh_backhaul_node_event(wifi_service_node_t *node, wifi_event_t *event)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int mesh_sta_node_start(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int mesh_sta_node_stop(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

int mesh_sta_node_update(wifi_service_node_t *node)
{
    wifi_util_info_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);
    return 0;
}

static char *ext_conn_state_to_str(connection_state_t conn_state)
{
    switch (conn_state) {
    case connection_state_disconnected_scan_list_none:
        return "disconnected_scan_list_none";
    case connection_state_disconnected_scan_list_in_progress:
        return "disconnected_scan_list_in_progress";
    case connection_state_disconnected_scan_list_all:
        return "disconnected_scan_list_all";
    case connection_state_connection_in_progress:
        return "connection_in_progress";
    case connection_state_connection_to_lcb_in_progress:
        return "connection_to_lcb_in_progress";
    case connection_state_connection_to_nb_in_progress:
        return "connection_to_nb_in_progress";
    case connection_state_connected:
        return "connected";
    case connection_state_connected_wait_for_csa:
        return "connected_wait_for_csa";
    case connection_state_connected_scan_list:
        return "connected_scan_list";
    case connection_state_disconnection_in_progress:
        return "disconnection_in_progress";
    default:
        break;
    }

    return "udefined state";
}

static char *ext_conn_status_to_str(wifi_connection_status_t status)
{
    switch (status) {
    case wifi_connection_status_disabled:
        return "disabled";
    case wifi_connection_status_disconnected:
        return "disconnected";
    case wifi_connection_status_connected:
        return "connected";
    case wifi_connection_status_ap_not_found:
        return "not found";
    default:
        break;
    }

    return "undefined status";
}

#define PATH_TO_RSSI_NORMALIZER_FILE "/tmp/rssi_normalizer_2_4.cfg"
#define DEFAULT_RSSI_NORMALIZER_2_4_VALUE 20

static void swap_bss(bss_candidate_t *a, bss_candidate_t *b)
{
    bss_candidate_t t = *a;
    *a = *b;
    *b = t;
}
static int partition(bss_candidate_t *bss, int start, int end, int rssi_2_4_normalizer_val)
{
    int normalizer_val = 0;
    int pivot = bss[end].external_ap.rssi;
    int pidx = start;

    if (bss[end].radio_freq_band == WIFI_FREQUENCY_2_4_BAND) {
        pivot = bss[end].external_ap.rssi - rssi_2_4_normalizer_val;
    }

    for (int i = start; i < end; i++) {
        normalizer_val = 0;
        if (bss[i].radio_freq_band == WIFI_FREQUENCY_2_4_BAND) {
            normalizer_val = rssi_2_4_normalizer_val;
        }
        if ((bss[i].external_ap.rssi - normalizer_val) > pivot) {
            swap_bss(&bss[pidx], &bss[i]);
            pidx++;
        }
    }
    swap_bss(&bss[pidx], &bss[end]);
    return pidx;
}

#define DWELL_TIME_PATH "/nvram/wifi_dwell_time"
#define DEFAULT_DWELL_TIME_MS 50
int get_dwell_time()
{
    FILE *fp = NULL;
    int dwell_time = DEFAULT_DWELL_TIME_MS;
    if (access(DWELL_TIME_PATH, R_OK) == 0) {
        fp = fopen(DWELL_TIME_PATH, "r");
        if (fp == NULL) {
            return dwell_time;
        }
        fscanf(fp, "%d", &dwell_time);
    }
    return dwell_time;
}

static void get_rssi_normalizer_value(char *path_to_file, int *rssi_2_4_normalizer_val)
{
    FILE *fp = fopen(path_to_file, "r");
    char buff[512] = {0};

    *rssi_2_4_normalizer_val = DEFAULT_RSSI_NORMALIZER_2_4_VALUE;

    if (fp) {
        int rc = fread(buff, 1, sizeof(buff) - 1, fp);
        fclose(fp);
        if (rc > 0 && isdigit(*buff)) {
            *rssi_2_4_normalizer_val = atoi(buff);
        }
    }
}

static void start_sorting_by_rssi(bss_candidate_t *bss, int start, int end, int rssi_2_4_normalizer_val)
{
    if (start < end) {
        int pidx = partition(bss, start, end, rssi_2_4_normalizer_val);

        start_sorting_by_rssi(bss, start, pidx - 1, rssi_2_4_normalizer_val);
        start_sorting_by_rssi(bss, pidx + 1, end, rssi_2_4_normalizer_val);
    }
}

void sort_bss_results_by_rssi(bss_candidate_t *bss, int start, int end)
{
    int rssi_2_4_normalizer_val = 0;

    get_rssi_normalizer_value(PATH_TO_RSSI_NORMALIZER_FILE, &rssi_2_4_normalizer_val);
    wifi_util_dbg_print(WIFI_SERVICES, "%s():[%d] RSSI normalizer value [%d]\n", __FUNCTION__, __LINE__, rssi_2_4_normalizer_val);
    start_sorting_by_rssi(bss, start, end, rssi_2_4_normalizer_val);
}


static void ext_set_conn_state(mesh_sta_node_data_t *ext, connection_state_t new_conn_state,
    const char *func, int line)
{
    wifi_util_info_print(WIFI_SERVICES, "%s:%d change connection state: %s -> %s\r\n", func, line,
        ext_conn_state_to_str(ext->conn_state), ext_conn_state_to_str(new_conn_state));
    ext->conn_state = new_conn_state;
}

static void ext_reset_radios(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    reset_wifi_radios();
    ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__, __LINE__);
    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
        process_ext_connect_algorithm, node, EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
}

int scan_result_wait_timeout(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;


    if (ext->conn_state == connection_state_disconnected_scan_list_in_progress) {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d - received only %u radio scan results\r\n", __func__,
            __LINE__, ext->scanned_radios);

        ext_set_conn_state(ext, connection_state_disconnected_scan_list_all, __func__, __LINE__);
        ext->scanned_radios = 0;
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, node,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }
    return 0;
}

int process_connected_scan_result_timeout(wifi_service_node_t *node)
{
    unsigned int radio_index = 0;
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (ext->conn_state == connection_state_connected_scan_list) {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d Time out on connected scan \n", __func__, __LINE__);
        ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, node,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }

    return 0;
}

void ext_connected_scan(wifi_service_node_t *node)
{
    unsigned int radio_index = 0;
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (node == NULL) {
        wifi_util_error_print(WIFI_SERVICES,"%s:%d NULL pointer\n", __func__, __LINE__);
        return;
    }
    wifi_util_dbg_print(WIFI_SERVICES,"%s:%d Enter \n", __func__, __LINE__);

    radio_index = node->radio_index;
    int dwell_time = get_dwell_time();

    if (ext->conn_state == connection_state_connected_scan_list) {
        cancel_scan_result_timer(node);
        if (ext->candidates_list.scan_list != NULL) {
            ext->candidates_list.scan_count = 0;
            free(ext->candidates_list.scan_list);
            ext->candidates_list.scan_list = NULL;
        }

        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d start Scan on radio index %d channel %d\n", __func__, __LINE__, radio_index, ext->go_to_channel);
        wifi_hal_startScan(radio_index, WIFI_RADIO_SCAN_MODE_OFFCHAN, dwell_time, 1, &ext->go_to_channel);
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connected_scan_result_timeout_handler_id,
                process_connected_scan_result_timeout, node,
                EXT_SCAN_RESULT_TIMEOUT, 0, FALSE);
    return;
}


int csa_wait_timeout(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (node == NULL) {
        wifi_util_error_print(WIFI_SERVICES,"%s:%d NULL pointer\n", __func__, __LINE__);
        return 0;
    }

    wifi_util_dbg_print(WIFI_SERVICES,"%s:%d Enter \n", __func__, __LINE__);

    if (ext->conn_state == connection_state_connected_wait_for_csa) {
        ext_set_conn_state(ext, connection_state_connected_scan_list, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                   process_ext_connect_algorithm, node,
                   EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }

    return 0;
}

void ext_wait_for_csa(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (node == NULL) {
        wifi_util_error_print(WIFI_SERVICES,"%s:%d NULL pointer\n", __func__, __LINE__);
        return;
    }

    wifi_util_dbg_print(WIFI_SERVICES,"%s:%d Enter\n", __func__, __LINE__);

    if (ext->conn_state == connection_state_connected_wait_for_csa) {
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_csa_wait_timeout_handler_id,
                    csa_wait_timeout, node,
                    EXT_CSA_WAIT_TIMEOUT, 1, FALSE);
    }

    return;
}

static void ext_try_disconnecting(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (ext->conn_state != connection_state_disconnection_in_progress) {
        wifi_util_dbg_print(WIFI_SERVICES, "%s:%d ignore disconnection request due to "
            "connection state: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        return;
    }

    wifi_util_info_print(WIFI_SERVICES, "%s:%d execute sta disconnect for vap index: %d\n", __func__,
        __LINE__, ext->connected_vap_index);

    if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_SERVICES, "%s:%d sta disconnect failed for vap index: %d\n",
            __func__, __LINE__, ext->connected_vap_index);
        process_disconnection_event_timeout(node);
        return;
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_disconnection_event_timeout_handler_id,
        process_disconnection_event_timeout, node, EXT_DISCONNECTION_IND_TIMEOUT, 1, FALSE);
}


void cancel_scan_result_timer(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (ext->ext_scan_result_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d - cancel wifi start scan timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_scan_result_timeout_handler_id);
        ext->ext_scan_result_timeout_handler_id = 0;
    }
    if (ext->ext_connected_scan_result_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d - cancel wifi start scan timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_connected_scan_result_timeout_handler_id);
        ext->ext_connected_scan_result_timeout_handler_id = 0;
    }
}

static int process_ext_connect_event_timeout(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    ext->ext_conn_status_ind_timeout_handler_id = 0;

    if (ext->conn_state != connection_state_connection_in_progress &&
            ext->conn_state != connection_state_connection_to_lcb_in_progress &&
            ext->conn_state != connection_state_connection_to_nb_in_progress) {
        wifi_util_dbg_print(WIFI_SERVICES, "%s:%d not received connection event, exit due to "
            "connection state: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        ext->conn_retry = 0;
        return 0;
    }

    if (ext->conn_retry >= STA_MAX_CONNECT_ATTEMPT) {
        wifi_util_error_print(WIFI_SERVICES, "%s:%d not received connection event, reset radios\n",
            __func__, __LINE__);
        ext_reset_radios(node);
        ext->conn_retry = 0;
        return 0;
    }

    ext->conn_retry++;
    wifi_util_error_print(WIFI_SERVICES, "%s:%d not received connection event, retry\n", __func__,
        __LINE__);
    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
        process_ext_connect_algorithm, node, EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);

    return 0;
}

int process_disconnection_event_timeout(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (ext->conn_state == connection_state_disconnection_in_progress) {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d !!!!!!!ERROR!!!!!!! Not received disconnection event \n", __func__, __LINE__);
        ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                process_ext_connect_algorithm, node,
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }

    return 0;
}

void ext_start_scan(wifi_service_node_t *node)
{
    wifi_channels_list_t *channels;
    unsigned int radio_index;
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;
    wifi_hal_capability_t *cap;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;
    cap = node->cap;

    if (ext->conn_state != connection_state_disconnected_scan_list_none) {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d wifi_scan completed, current state: %s\r\n",__func__,
            __LINE__, ext_conn_state_to_str(ext->conn_state));
        return;
    }

    cancel_scan_result_timer(node);
    wifi_util_dbg_print(WIFI_SERVICES,"%s:%d Enter......\r\n",__func__, __LINE__);
    // first free up scan list
    if (ext->candidates_list.scan_list != NULL) {
        ext->candidates_list.scan_count = 0;
        free(ext->candidates_list.scan_list);
        ext->candidates_list.scan_list = NULL;
    }
    ext->scanned_radios = 0;

    int dwell_time = get_dwell_time();
    for (radio_index = 0; radio_index < cap->wifi_prop.numRadios; radio_index++) {
        wifi_util_dbg_print(WIFI_SERVICES, "%s:%d start Scan on radio index %u\n", __func__, __LINE__,
            radio_index);

        channels = &cap->wifi_prop.radiocap[radio_index].channel_list[0];
        wifi_hal_startScan(radio_index, WIFI_RADIO_SCAN_MODE_OFFCHAN, dwell_time, channels->num_channels,
            channels->channels_list);
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_scan_result_timeout_handler_id,
                process_scan_result_timeout, node,
                EXT_SCAN_RESULT_TIMEOUT, 0, FALSE);
}

void ext_process_scan_list(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (ext->conn_state != connection_state_connection_in_progress) {
        wifi_util_info_print(WIFI_SERVICES,"%s:%d start wifi connection:%s scan_count:%d\n", __func__,
            __LINE__, ext_conn_state_to_str(ext->conn_state), ext->candidates_list.scan_count);
        ext->wait_scan_result = 0;
        // process scan list, arrange candidates according to policies
        if (ext->candidates_list.scan_count != 0) {
            ext_set_conn_state(ext, connection_state_connection_in_progress, __func__, __LINE__);
        } else {
            ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__,
                __LINE__);
        }

        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, node,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    } else {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d wifi connection already in process state\n",__func__, __LINE__);
    }
}

void ext_incomplete_scan_list(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    ext->wait_scan_result++;
    if (ext->wait_scan_result > MAX_SCAN_RESULT_WAIT) {
        ext->wait_scan_result = 0;
        ext_set_conn_state(ext, connection_state_disconnected_scan_list_all, __func__, __LINE__);
        ext->scanned_radios = 0;

        // schedule extender connetion algorithm
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, node,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }
}

int process_scan_result_timeout(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (ext->conn_state == connection_state_disconnected_scan_list_none) {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d - start wifi scan timer\r\n", __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, node,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }
    return 0;
}

void ext_try_connecting(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;
    wifi_vap_info_t *vap_info;
    unsigned int i, vap_index, radio_index;
    bss_candidate_t         *candidate;
    mac_addr_str_t bssid_str;
    bool found_at_least_one_candidate = false;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;
    vap_info = node->vap_info;


    if (ext->conn_state == connection_state_connection_to_nb_in_progress) {
        candidate = &ext->new_bss;
        candidate->conn_retry_attempt++;
        found_at_least_one_candidate = true;
    } else if (ext->conn_state == connection_state_connection_to_lcb_in_progress) {
        found_at_least_one_candidate = true;
        candidate = &ext->last_connected_bss;
        candidate->conn_retry_attempt++;
    } else if (ext->conn_state == connection_state_connection_in_progress) {
        candidate = ext->candidates_list.scan_list;

        for (i = 0; i < ext->candidates_list.scan_count; i++) {
            if ((candidate->conn_attempt == connection_attempt_wait) && (candidate->conn_retry_attempt < STA_MAX_CONNECT_ATTEMPT)) {
                candidate->conn_retry_attempt++;
                found_at_least_one_candidate = true;
                break;
            }

            candidate++;
        }
    } else {
        wifi_util_error_print(WIFI_SERVICES, "%s:%d: assert - conn_state : %s\n", __func__, __LINE__,
            ext_conn_state_to_str(ext->conn_state));
        // should not come here in any states other than connection_state_connection_in_progress
        assert((ext->conn_state != connection_state_connection_in_progress) ||
        (ext->conn_state != connection_state_connection_to_lcb_in_progress));
    }

    if (found_at_least_one_candidate == true) {
        if (candidate != NULL) {
            convert_freq_band_to_radio_index(candidate->radio_freq_band, (int *)&radio_index);
        } else {
            wifi_util_error_print(WIFI_SERVICES, "%s:%d: candidate param NULL\n", __func__, __LINE__);
        }
        vap_index = vap_info->vap_index;

        wifi_util_info_print(WIFI_SERVICES,"%s:%d connecting to ssid:%s bssid:%s rssi:%d frequency:%d on vap:%d radio:%d\n",
                    __func__, __LINE__, candidate->external_ap.ssid,
                    to_mac_str(candidate->external_ap.bssid, bssid_str),
                    candidate->external_ap.rssi, candidate->external_ap.freq, vap_index, radio_index);
        // Set to disabled in order to detect state change on connection retry
        vap_info->u.sta_info.conn_status = wifi_connection_status_disabled;
        ext->conn_retry++;
        if (wifi_hal_connect(vap_index, &candidate->external_ap) == RETURN_ERR) {
            wifi_util_error_print(WIFI_SERVICES, "%s:%d sta connect failed for vap index: %d, "
                "retry after timeout\n", __func__, __LINE__, vap_index);
        }

        if (ext->ext_conn_status_ind_timeout_handler_id != 0) {
            wifi_util_dbg_print(WIFI_SERVICES, "%s:%d connect status timer is in progress, cancel\n",
                __func__, __LINE__);
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_conn_status_ind_timeout_handler_id);
        }
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_conn_status_ind_timeout_handler_id,
            process_ext_connect_event_timeout, node, EXT_CONN_STATUS_IND_TIMEOUT, 1, FALSE);

#if CCSP_COMMON
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_command, wifi_event_type_sta_connect_in_progress, candidate);
#endif // CCSP_COMMON
    } else {
        ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                process_ext_connect_algorithm, node,
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }
}

int process_ext_connect_algorithm(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;

    ext = &node->data.u.sta_node_data;

    wifi_util_dbg_print(WIFI_SERVICES, "%s:%d process connection state: %s\r\n", __func__, __LINE__,
        ext_conn_state_to_str(ext->conn_state));

    switch (ext->conn_state) {
        case connection_state_disconnected_scan_list_none:
            ext_start_scan(node);
            break;

        case connection_state_disconnected_scan_list_in_progress:
            ext_incomplete_scan_list(node);
            break;

        case connection_state_disconnected_scan_list_all:
            ext_process_scan_list(node);
            break;

        case connection_state_connection_in_progress:
        case connection_state_connection_to_lcb_in_progress:
        case connection_state_connection_to_nb_in_progress:
            ext_try_connecting(node);
            break;

        case connection_state_connected:
            break;

        case connection_state_connected_wait_for_csa:
            ext_wait_for_csa(node);
            break;

        case connection_state_connected_scan_list:
            ext_connected_scan(node);
            break;

        case connection_state_disconnection_in_progress:
            ext_try_disconnecting(node);
            break;
    }

    return 0;
}


static int process_sta_webconfig_set_data_sta_bssid(wifi_service_node_t *node, wifi_core_data_t *data)
{
    bss_candidate_t *candidate;
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;
    char bssid_str[32];
    int band, channel, freq;
    wifi_vap_info_t *vap_info;
    wifi_radio_operationParam_t *radio_op;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;
    candidate = &ext->new_bss;
    vap_info = node->vap_info;
    radio_op = node->radio_op;

    uint8_mac_to_string_mac(vap_info->u.sta_info.bssid, bssid_str);

    // Support only connected/wait_for_csa -> connection_to_nb_in_progress state change
    if (ext->conn_state != connection_state_connected &&
        ext->conn_state != connection_state_connected_wait_for_csa) {
        wifi_util_info_print(WIFI_SERVICES, "%s:%d skip sta bssid change event: connection state: %s,"
            "vap: %s, bssid: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state),
            vap_info->vap_name, bssid_str);
        return 0;
    }

    // Clear old bssid
    if (candidate->vap_index == vap_info->vap_index) {
        wifi_util_info_print(WIFI_SERVICES, "%s:%d clear old sta bssid for vap %s\n", __func__,
            __LINE__, vap_info->vap_name);
        memset(candidate, 0, sizeof(bss_candidate_t));
    }

    // Skip zero bssid and disabled vaps
    if (!is_bssid_valid(vap_info->u.sta_info.bssid) || !vap_info->u.sta_info.enabled) {
        wifi_util_info_print(WIFI_SERVICES, "%s:%d skip sta bssid change event, vap: %s, bssid: %s, "
            "enabled: %d\n", __func__, __LINE__, vap_info->vap_name, bssid_str,
            vap_info->u.sta_info.enabled);
        return 0;
    }

    band = radio_op->band;
    channel = radio_op->channel;
    freq = convert_channel_to_freq(band, channel);
    if (freq == -1) {
        wifi_util_error_print(WIFI_SERVICES, "%s:%d failed to convert channel %d to frequency\n",
            __func__, __LINE__, channel);
        return -1;
    }

    memset(candidate, 0, sizeof(bss_candidate_t));
    memcpy(candidate->external_ap.bssid, vap_info->u.sta_info.bssid, sizeof(bssid_t));
    strncpy(candidate->external_ap.ssid, vap_info->u.sta_info.ssid, sizeof(ssid_t) - 1);
    candidate->vap_index = vap_info->vap_index;
    candidate->external_ap.freq = freq;
    candidate->radio_freq_band = band;
    candidate->conn_attempt = connection_attempt_wait;
    candidate->conn_retry_attempt = 0;

    wifi_util_info_print(WIFI_SERVICES, "%s:%d new sta bssid: %s, ssid: %s, channel: %d, "
        "freq: %d, band: %d connection state: %s\n", __func__, __LINE__, bssid_str,
        candidate->external_ap.ssid, channel, candidate->external_ap.freq,
        candidate->radio_freq_band, ext_conn_state_to_str(ext->conn_state));

#if DML_SUPPORT
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_command, wifi_event_type_new_bssid, ext);
#endif

    // Channel change for connected STA may fail therefore need to re-apply it on disconnection.
    // For example, STA is connected to 2.4 GHz. Optimization for extender is 1->11, 2.4 Ghz->5 Ghz.
    // Gateway is left on channel 1 so extender will not receive CSA. One the other hand,
    // driver cannot apply new channel while STA is connected.
    if (ext->conn_state == connection_state_connected_wait_for_csa) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_csa_wait_timeout_handler_id);
        ext->ext_csa_wait_timeout_handler_id = 0;
        ext->channel_change_pending_map |= 1 << ext->connected_vap_index;
    }


    ext_set_conn_state(ext, connection_state_connection_to_nb_in_progress, __func__,
        __LINE__);

    // If BSSID changed on the same band need to initiate disconnection before connection to avoid
    // HAL error. On different band try to connect to new BSSID before disconnection.
    if (ext->connected_vap_index == vap_info->vap_index) {
        wifi_util_info_print(WIFI_SERVICES, "%s:%d execute sta disconnect for vap index: %d\n",
            __func__, __LINE__, ext->connected_vap_index);
        if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
            wifi_util_error_print(WIFI_SERVICES, "%s:%d sta disconnect failed for vap index: %d\n",
                __func__, __LINE__, ext->connected_vap_index);
        }
        return 0;
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
        process_ext_connect_algorithm, node,
        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);

    return 0;
}

void process_ext_connected_scan_results(wifi_service_node_t *node, wifi_core_data_t *data)
{
    unsigned int i = 0, num = 0, band = 0, channel = 0;
    scan_results_t *results;
    wifi_bss_info_t *bss;
    wifi_bss_info_t *tmp_bss;
    bss_candidate_t *scan_list;
    bool found_candidate = false;
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    if ((node == NULL) || (data == NULL)){
        wifi_util_error_print(WIFI_SERVICES, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    results = (scan_results_t*)data->msg;

    num = results->num;
    bss = results->bss;

    wifi_util_dbg_print(WIFI_SERVICES, "%s:%d Enter\n", __func__, __LINE__);

    if (ext->ext_connected_scan_result_timeout_handler_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_connected_scan_result_timeout_handler_id);
        ext->ext_connected_scan_result_timeout_handler_id = 0;
    }

    if ((num == 0) || (bss == NULL)) {
        wifi_util_dbg_print(WIFI_SERVICES, "%s:%d No AP in the go to channel \n", __func__, __LINE__);
        ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                  process_ext_connect_algorithm, node,
                  EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        return;
    }

    tmp_bss = bss;
    convert_radio_index_to_freq_band(&node->cap->wifi_prop, results->radio_index, (int *)&band);
    if ((ext->candidates_list.scan_list == NULL) && num) {
        ext->candidates_list.scan_list = (bss_candidate_t *) malloc(num * sizeof(bss_candidate_t));
        scan_list = ext->candidates_list.scan_list;
        ext->candidates_list.scan_count = num;
    } else  {
        wifi_util_dbg_print(WIFI_SERVICES, "%s:%d NULL scan list should not reach this condition\n", __func__, __LINE__);
        ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, node,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        return;
    }

    for (i = 0; (i < num) && (tmp_bss != NULL) ; i++) {
        convert_freq_to_channel(tmp_bss->freq, (unsigned char *) &channel);
        if (channel == ext->go_to_channel)
        {
            found_candidate =  true;
            memcpy(&scan_list->external_ap, tmp_bss, sizeof(wifi_bss_info_t));
            scan_list->conn_attempt = connection_attempt_wait;
            scan_list->conn_retry_attempt = 0;
            scan_list->radio_freq_band = band;
            scan_list++;
        }
        tmp_bss++;
    }

    if (found_candidate) {
        ext_set_conn_state(ext, connection_state_disconnection_in_progress, __func__, __LINE__);
    } else {
        ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
    }
    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, node,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);

    return;
}

int process_ext_scan_results(wifi_service_node_t *node, wifi_core_data_t *data)
{
    wifi_bss_info_t *bss;
    wifi_bss_info_t *tmp_bss;
    unsigned int i, num = 0;
    scan_results_t *results;
    bss_candidate_t *scan_list;
    unsigned int band = 0;
    mac_addr_str_t bssid_str;
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    results = (scan_results_t *)data->msg;
    bss = results->bss;
    num = results->num;

    tmp_bss = bss;

    if (ext->conn_state == connection_state_connected_scan_list) {
        process_ext_connected_scan_results(node, data);
        return 0;
    }

    if (ext->conn_state >= connection_state_disconnected_scan_list_all) {
        wifi_util_error_print(WIFI_SERVICES, "%s:%d Received scan resuts when already have result or connection in progress, should not happen\n",
                        __FUNCTION__,__LINE__);
        return 0;
    }

    convert_radio_index_to_freq_band(&node->cap->wifi_prop, results->radio_index, (int *)&band);
    if (ext->ext_scan_result_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d - cancel wifi start scan timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_scan_result_timeout_handler_id);
        ext->ext_scan_result_timeout_handler_id = 0;
    }

    wifi_util_info_print(WIFI_SERVICES, "%s:%d Extender Mode radio:%u, num of scan results:%d,"
        " connection state:%s\n", __FUNCTION__,__LINE__, results->radio_index, num,
        ext_conn_state_to_str(ext->conn_state));

    if ((ext->candidates_list.scan_list == NULL) && num) {
        ext->candidates_list.scan_list = (bss_candidate_t *) malloc(num * sizeof(bss_candidate_t));
        scan_list = ext->candidates_list.scan_list;
        ext->candidates_list.scan_count = num;
    } else if (num) {
        ext->candidates_list.scan_list = (bss_candidate_t *) realloc(ext->candidates_list.scan_list,
                    ((num + ext->candidates_list.scan_count) * sizeof(bss_candidate_t)));
        scan_list = ext->candidates_list.scan_list + ext->candidates_list.scan_count;
        ext->candidates_list.scan_count += num;
    }

    for (i = 0; i < num; i++) {
        memcpy(&scan_list->external_ap, tmp_bss, sizeof(wifi_bss_info_t));
        scan_list->conn_attempt = connection_attempt_wait;
        scan_list->conn_retry_attempt = 0;
        scan_list->radio_freq_band = band;
        wifi_util_dbg_print(WIFI_SERVICES, "%s:%d: AP with ssid:%s, bssid:%s, rssi:%d, freq:%d\n",
            __func__, __LINE__, tmp_bss->ssid, to_mac_str(tmp_bss->bssid, bssid_str), tmp_bss->rssi, tmp_bss->freq);
        wifi_util_info_print(WIFI_SERVICES, "%s:%d: AP with ssid:%s, bssid:%s, rssi:%d, freq:%d\n",
            __func__, __LINE__, scan_list->external_ap.ssid, to_mac_str(scan_list->external_ap.bssid, bssid_str), scan_list->external_ap.rssi, scan_list->external_ap.freq);
        tmp_bss++;
        scan_list++;
    }

    if (ext->candidates_list.scan_list && (ext->candidates_list.scan_count > 1))
        sort_bss_results_by_rssi(ext->candidates_list.scan_list, 0, ext->candidates_list.scan_count - 1);

    ext->scanned_radios++;
    if (ext->scanned_radios >= node->cap->wifi_prop.numRadios) {
        ext_set_conn_state(ext, connection_state_disconnected_scan_list_all, __func__, __LINE__);
        ext->scanned_radios = 0;

        if (ext->ext_scan_result_wait_timeout_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_scan_result_wait_timeout_handler_id);
            ext->ext_scan_result_wait_timeout_handler_id = 0;
        }
        // schedule extender connetion algorithm
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, node,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    } else {
        ext_set_conn_state(ext, connection_state_disconnected_scan_list_in_progress, __func__,
            __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_scan_result_wait_timeout_handler_id,
                        scan_result_wait_timeout, node,
                        EXT_SCAN_RESULT_WAIT_TIMEOUT, 1, FALSE);
    }

    return 0;
}

static void process_ext_trigger_disconnection(wifi_service_node_t *node, wifi_core_data_t *data)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (ext->conn_state != connection_state_connected) {
        wifi_util_dbg_print(WIFI_SERVICES, "%s:%d ignore disconnection event due to "
            "connection state: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        return;
    }

#if DML_SUPPORT
    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_command, wifi_event_type_trigger_disconnection_analytics, ext);
#endif

    wifi_util_info_print(WIFI_SERVICES, "%s:%d execute sta disconnect for vap index: %d\n", __func__,
        __LINE__, ext->connected_vap_index);

    ext->disconn_retry++;
    if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_SERVICES, "%s:%d sta disconnect failed for vap index: %d, "
            "retry after timeout\n", __func__, __LINE__, ext->connected_vap_index);
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_trigger_disconnection_timeout_handler_id,
        process_trigger_disconnection_event_timeout, node, EXT_DISCONNECTION_IND_TIMEOUT, 1, FALSE);
}

int process_trigger_disconnection_event_timeout(wifi_service_node_t *node)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    ext->ext_trigger_disconnection_timeout_handler_id = 0;

    if (ext->conn_state != connection_state_connected) {
        wifi_util_dbg_print(WIFI_SERVICES, "%s:%d not received disconnection event, exit due to "
            "connection state: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        ext->disconn_retry = 0;
        return 0;
    }

    if (ext->disconn_retry >= STA_MAX_DISCONNECT_ATTEMPT) {
        wifi_util_error_print(WIFI_SERVICES, "%s:%d not received disconnection event, reset radios\n",
            __func__, __LINE__);
        ext_reset_radios(node);
        ext->disconn_retry = 0;
        return 0;
    }

    wifi_util_error_print(WIFI_SERVICES, "%s:%d not received disconnection event, retry\n", __func__,
        __LINE__);

    ext->disconn_retry++;

    wifi_util_info_print(WIFI_SERVICES, "%s:%d execute sta disconnect for vap index: %d\n", __func__,
        __LINE__, ext->connected_vap_index);
    if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_SERVICES, "%s:%d sta disconnect failed for vap index: %d, "
            "retry after timeout\n", __func__, __LINE__, ext->connected_vap_index);
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_trigger_disconnection_timeout_handler_id,
        process_trigger_disconnection_event_timeout, node, EXT_DISCONNECTION_IND_TIMEOUT, 1, FALSE);

    return 0;
}

int process_ext_exec_timeout(wifi_service_node_t *node, wifi_core_data_t *data)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    wifi_util_dbg_print(WIFI_SERVICES,"%s:%d - start timeout timer\r\n", __func__, __LINE__);
    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                process_ext_connect_algorithm, node,
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);

    return 0;
}

int process_ext_sta_conn_status(wifi_service_node_t *node, wifi_core_data_t *data)
{
#ifdef FIXME
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *temp_vap_info = NULL;
    rdk_sta_data_t *sta_data = (rdk_sta_data_t *)data->msg;
    bss_candidate_t *candidate = NULL;
    bool found_candidate = false, send_event = false;
    unsigned int i = 0, index, j = 0;
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    char name[64];
    wifi_sta_conn_info_t sta_conn_info;
    wifi_radio_operationParam_t *radio_params = NULL;
    wifi_radio_feature_param_t *radio_feat = NULL;
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    ext->conn_retry = 0;
    if (ext->ext_conn_status_ind_timeout_handler_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_conn_status_ind_timeout_handler_id);
        ext->ext_conn_status_ind_timeout_handler_id = 0;
    }

    /* first update the internal cache */
    index = get_radio_index_for_vap_index(&node->cap->wifi_prop, sta_data->stats.vap_index);
    wifi_util_info_print(WIFI_SERVICES,"%s:%d - radio index %d, VAP index %d connect_status : %s\n",
        __func__, __LINE__, index, sta_data->stats.vap_index,
        ext_conn_status_to_str(sta_data->stats.connect_status));
    vap_map = &mgr->radio_config[index].vaps.vap_map;


    for (i = 0; i < vap_map->num_vaps; i++) {
        if (vap_map->vap_array[i].vap_index == sta_data->stats.vap_index) {
            if (vap_map->vap_array[i].u.sta_info.conn_status != sta_data->stats.connect_status) {
                // send rbus connect indication
                send_event = true;
            }
            temp_vap_info = &vap_map->vap_array[i];
            if (temp_vap_info->u.sta_info.conn_status == sta_data->stats.connect_status &&
                memcmp(temp_vap_info->u.sta_info.bssid, sta_data->bss_info.bssid, sizeof(bssid_t)) == 0) {
                wifi_util_info_print(WIFI_SERVICES, "%s:%d: received duplicated wifi_event_hal_sta_conn_status event\n", __func__, __LINE__);
                return 0;
            }
            temp_vap_info->u.sta_info.conn_status = sta_data->stats.connect_status;
            memset(temp_vap_info->u.sta_info.bssid, 0, sizeof(bssid_t));

            // Avoid releasing IP on connected interface when disconnect is received on another.
            // Mesh agent supports one DHCP client for all sta interfaces so when it receives any
            // disconnection event it will release IP.
            if (temp_vap_info->u.sta_info.conn_status != wifi_connection_status_connected &&
                    temp_vap_info->vap_index != ext->connected_vap_index) {
                send_event = false;
            }
            break;
        }
    }

    if (temp_vap_info == NULL) {
        wifi_util_error_print(WIFI_SERVICES, "%s:%d: temp_vap_info is NULL \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (sta_data->stats.connect_status == wifi_connection_status_connected) {
        if ((ext->conn_state == connection_state_connection_in_progress) ||
            (ext->conn_state == connection_state_connection_to_lcb_in_progress) ||
            (ext->conn_state == connection_state_connection_to_nb_in_progress)) {

            // copy the bss info to lcb
            memset(&ext->last_connected_bss, 0, sizeof(bss_candidate_t));
            memcpy(&ext->last_connected_bss.external_ap, &sta_data->bss_info, sizeof(wifi_bss_info_t));
            ext->connected_vap_index = sta_data->stats.vap_index;

            // clear new bssid since it is not used for reconnection
            memset(&ext->new_bss, 0, sizeof(bss_candidate_t));

            convert_radio_index_to_freq_band(&node->vap->wifi_prop, index, (int*)&ext->last_connected_bss.radio_freq_band);
            wifi_util_dbg_print(WIFI_SERVICES,"%s:%d - connected radio_band:%d\r\n", __func__, __LINE__, ext->last_connected_bss.radio_freq_band);

            // copy the bss bssid info to global chache
            memcpy (temp_vap_info->u.sta_info.bssid, sta_data->bss_info.bssid, sizeof(temp_vap_info->u.sta_info.bssid));

            // change the state
            ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);

            /* Self heal to check if the connected interface received valid ip after a timeout if not trigger a reconnection */

            if (ext->ext_udhcp_ip_check_id != 0) {
                scheduler_cancel_timer_task(ctrl->sched, ext->ext_udhcp_ip_check_id);
                ext->ext_udhcp_ip_check_id = 0;
            }

            if (ext->ext_udhcp_disconnect_event_timeout_handler_id != 0) {
                scheduler_cancel_timer_task(ctrl->sched,  ext->ext_udhcp_disconnect_event_timeout_handler_id);
                ext->ext_udhcp_disconnect_event_timeout_handler_id = 0;
            }

            if (ext->ext_trigger_disconnection_timeout_handler_id != 0) {
                scheduler_cancel_timer_task(ctrl->sched, ext->ext_trigger_disconnection_timeout_handler_id);
                ext->ext_trigger_disconnection_timeout_handler_id = 0;
            }

            scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_udhcp_ip_check_id,
                process_udhcp_ip_check, node,
                EXT_UDHCP_IP_CHECK_INTERVAL, 0, FALSE);

            /* Make Self Heal Timeout to flase once connected */
            ext->selfheal_status = false;

            radio_feat = (wifi_radio_feature_param_t *)get_wifidb_radio_feat_map(index);
            radio_params = (wifi_radio_operationParam_t *)get_wifidb_radio_map(index);
            if (radio_params != NULL) {
                if ((radio_params->channel != sta_data->stats.channel) || (radio_params->channelWidth != sta_data->stats.channelWidth)) {
                    pthread_mutex_lock(&mgr->data_cache_lock);
                    radio_params->channel = sta_data->stats.channel;
                    radio_params->channelWidth = sta_data->stats.channelWidth;
                    radio_params->op_class = sta_data->stats.op_class;
                    pthread_mutex_unlock(&mgr->data_cache_lock);

                    mgr->ctrl.webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
                    start_wifi_sched_timer(&index, ctrl, wifi_radio_sched);
                    update_wifi_radio_config(index, radio_params, radio_feat);
                }
            }

        }

        if (ext->conn_state == connection_state_connected) {
            //After moving to connected state, check if there is another sta interface in connected state.
            for (i = 0; i < getNumberRadios(); i++) {
                vap_map = &mgr->radio_config[i].vaps.vap_map;
                for (j = 0; j< vap_map->num_vaps; j++) {
                    //Check for the station vaps and connect_status
                    if ((vap_svc_is_mesh_ext(vap_map->vap_array[j].vap_index) == true) &&
                            (vap_map->vap_array[j].vap_index != temp_vap_info->vap_index) &&
                            (vap_map->vap_array[j].u.sta_info.conn_status == wifi_connection_status_connected)) {
                        //Send the disconnect for the other station vap_index
                        wifi_util_info_print(WIFI_SERVICES, "%s:%d more than one sta associated, "
                            "execute sta disconnect for vap index: %d\n", __func__, __LINE__,
                            vap_map->vap_array[j].vap_index);
                        if (wifi_hal_disconnect(vap_map->vap_array[j].vap_index) == RETURN_ERR) {
                            wifi_util_error_print(WIFI_SERVICES, "%s:%d sta disconnect failed for "
                                "vap index: %d\n", __func__, __LINE__,
                                vap_map->vap_array[j].vap_index);
                        }
                        break;
                    }
                }
            }
        }
    } else if (sta_data->stats.connect_status == wifi_connection_status_ap_not_found || sta_data->stats.connect_status == wifi_connection_status_disconnected) {

        apply_pending_channel_change(node, sta_data->stats.vap_index);

        if (ext->conn_state == connection_state_connection_to_nb_in_progress) {
            candidate = &ext->new_bss;
            found_candidate = true;
        } else if ((ext->conn_state == connection_state_connection_to_lcb_in_progress) ||
                (ext->conn_state == connection_state_connected)) {

            if (ext->conn_state == connection_state_connected && ext->connected_vap_index != sta_data->stats.vap_index) {
                wifi_util_info_print(WIFI_SERVICES, "%s:%d: vap index %d is connected and received disconnection event on vap index %d\n", __func__, __LINE__, ext->connected_vap_index, sta_data->stats.vap_index);
                return 0;
            }
            candidate = &ext->last_connected_bss;
            found_candidate = true;
            ext_set_conn_state(ext, connection_state_connection_to_lcb_in_progress, __func__,
                __LINE__);

            if (ext->ext_udhcp_ip_check_id != 0) {
                scheduler_cancel_timer_task(ctrl->sched, ext->ext_udhcp_ip_check_id);
                ext->ext_udhcp_ip_check_id = 0;
            }

            ext->disconn_retry = 0;
            if (ext->ext_udhcp_disconnect_event_timeout_handler_id != 0) {
                scheduler_cancel_timer_task(ctrl->sched, ext->ext_udhcp_disconnect_event_timeout_handler_id);
                ext->ext_udhcp_disconnect_event_timeout_handler_id = 0;
            }

            if (ext->ext_trigger_disconnection_timeout_handler_id != 0) {
                scheduler_cancel_timer_task(ctrl->sched, ext->ext_trigger_disconnection_timeout_handler_id);
                ext->ext_trigger_disconnection_timeout_handler_id = 0;
            }

        } else if (ext->conn_state == connection_state_connection_in_progress) {
            candidate = ext->candidates_list.scan_list;
            for (i = 0; i < ext->candidates_list.scan_count; i++) {
                if ((candidate->conn_attempt == connection_attempt_wait) && (candidate->conn_retry_attempt < STA_MAX_CONNECT_ATTEMPT)) {
                    found_candidate = true;
                    break;
                }
                candidate++;
            }
        } else if (ext->conn_state == connection_state_disconnection_in_progress) {
            ext_set_conn_state(ext, connection_state_connection_in_progress, __func__, __LINE__);
            candidate = ext->candidates_list.scan_list;
            found_candidate = true;
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_disconnection_event_timeout_handler_id);
            ext->ext_disconnection_event_timeout_handler_id = 0;
        }
    }

    if (send_event == true) {
        sprintf(name, "Device.WiFi.STA.%d.Connection.Status", index + 1);

        wifi_util_dbg_print(WIFI_SERVICES, "%s:%d Rbus name: %s connection status: %s\n", __func__,
            __LINE__, name, ext_conn_status_to_str(sta_data->stats.connect_status));

        memset(&sta_conn_info, 0, sizeof(wifi_sta_conn_info_t));

        rbusValue_Init(&value);
        rbusObject_Init(&rdata, NULL);
        rbusObject_SetValue(rdata, name, value);
        sta_conn_info.connect_status =  sta_data->stats.connect_status;
        memcpy(sta_conn_info.bssid, sta_data->bss_info.bssid, sizeof(sta_conn_info.bssid));
        rbusValue_SetBytes(value, (uint8_t *)&sta_conn_info, sizeof(sta_conn_info));

        event.name = name;
        event.data = rdata;
        event.type = RBUS_EVENT_GENERAL;

        if (rbusEvent_Publish(ctrl->rbus_handle, &event) != RBUS_ERROR_SUCCESS) {
            wifi_util_dbg_print(WIFI_SERVICES, "%s:%d: rbusEvent_Publish Event failed\n", __func__, __LINE__);

            rbusValue_Release(value);
            rbusObject_Release(rdata);

            return RETURN_ERR;
        }

        rbusValue_Release(value);
        rbusObject_Release(rdata);
    }

    if (candidate != NULL) {
        if ((found_candidate == false && (ext->conn_state != connection_state_connected)) ||
                ((found_candidate == true) && (candidate->conn_retry_attempt >= STA_MAX_CONNECT_ATTEMPT))) {
            // fallback to last connected bssid if new bssid fails
            if (ext->conn_state == connection_state_connection_to_nb_in_progress) {
                // clear new bssid since it is not used for reconnection
                memset(&ext->new_bss, 0, sizeof(bss_candidate_t));

                // connection to new bssid is done before disconnection so the last bssid
                // still can be connected
                if (!is_connected_to_bssid(ext)) {
                    ext_set_conn_state(ext, connection_state_connection_to_lcb_in_progress,
                        __func__, __LINE__);
                    candidate = &ext->last_connected_bss;
                } else {
                    ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
                }
            } else {
                candidate->conn_attempt = connection_attempt_failed;
                ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__,
                    __LINE__);
            }

            scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, node,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        } else {
            //ext_try_connecting(node);
            wifi_util_info_print(WIFI_SERVICES, "%s:%d connection state: %s\r\n", __func__,
                __LINE__, ext_conn_state_to_str(ext->conn_state));
            scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, node,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        }
    } else if((found_candidate == false) && (ext->conn_state != connection_state_connected)) {
        wifi_util_info_print(WIFI_SERVICES, "%s:%d candidate null connection state: %s\r\n",
            __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__, __LINE__);

        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, node,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    } else {
        wifi_util_dbg_print(WIFI_SERVICES, "%s:%d: candidate null connection state: %s\r\n", __func__,
            __LINE__, ext_conn_state_to_str(ext->conn_state));
    }

#endif

    return 0;
}

int process_ext_channel_change(wifi_service_node_t *node, wifi_core_data_t *data)
{
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;
    wifi_channel_change_event_t *ch_chg;

    ch_chg = (wifi_channel_change_event_t *)data->msg;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    if (ext->conn_state == connection_state_connected_wait_for_csa) {
        if (ch_chg->channel == ext->go_to_channel) {
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_csa_wait_timeout_handler_id);
            ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
            scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, node,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        }
    }

    return 0;
}

int process_ext_webconfig_set_data_sta_bssid(wifi_service_node_t *node, wifi_core_data_t *data)
{

#ifdef FIXME
    bss_candidate_t *candidate;
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;
    char bssid_str[32];
    int band, channel, freq;
    wifi_vap_info_t *vap_info = arg;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    ext = &svc->u.ext;
    ctrl = svc->ctrl;
    candidate = &ext->new_bss;

    uint8_mac_to_string_mac(vap_info->u.sta_info.bssid, bssid_str);

    // Support only connected/wait_for_csa -> connection_to_nb_in_progress state change
    if (ext->conn_state != connection_state_connected &&
        ext->conn_state != connection_state_connected_wait_for_csa) {
        wifi_util_info_print(WIFI_SERVICES, "%s:%d skip sta bssid change event: connection state: %s,"
            "vap: %s, bssid: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state),
            vap_info->vap_name, bssid_str);
        return 0;
    }

    // Clear old bssid
    if (candidate->vap_index == vap_info->vap_index) {
        wifi_util_info_print(WIFI_SERVICES, "%s:%d clear old sta bssid for vap %s\n", __func__,
            __LINE__, vap_info->vap_name);
        memset(candidate, 0, sizeof(bss_candidate_t));
    }

    // Skip zero bssid and disabled vaps
    if (!is_bssid_valid(vap_info->u.sta_info.bssid) || !vap_info->u.sta_info.enabled) {
        wifi_util_info_print(WIFI_SERVICES, "%s:%d skip sta bssid change event, vap: %s, bssid: %s, "
            "enabled: %d\n", __func__, __LINE__, vap_info->vap_name, bssid_str,
            vap_info->u.sta_info.enabled);
        return 0;
    }

    band = mgr->radio_config[vap_info->radio_index].oper.band;
    channel = mgr->radio_config[vap_info->radio_index].oper.channel;
    freq = convert_channel_to_freq(band, channel);
    if (freq == -1) {
        wifi_util_error_print(WIFI_SERVICES, "%s:%d failed to convert channel %d to frequency\n",
            __func__, __LINE__, channel);
        return -1;
    }

    memset(candidate, 0, sizeof(bss_candidate_t));
    memcpy(candidate->external_ap.bssid, vap_info->u.sta_info.bssid, sizeof(bssid_t));
    strncpy(candidate->external_ap.ssid, vap_info->u.sta_info.ssid, sizeof(ssid_t) - 1);
    candidate->vap_index = vap_info->vap_index;
    candidate->external_ap.freq = freq;
    candidate->radio_freq_band = band;
    candidate->conn_attempt = connection_attempt_wait;
    candidate->conn_retry_attempt = 0;

    wifi_util_info_print(WIFI_SERVICES, "%s:%d new sta bssid: %s, ssid: %s, channel: %d, "
        "freq: %d, band: %d connection state: %s\n", __func__, __LINE__, bssid_str,
        candidate->external_ap.ssid, channel, candidate->external_ap.freq,
        candidate->radio_freq_band, ext_conn_state_to_str(ext->conn_state));

#if DML_SUPPORT
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_command, wifi_event_type_new_bssid, ext);
#endif

    // Channel change for connected STA may fail therefore need to re-apply it on disconnection.
    // For example, STA is connected to 2.4 GHz. Optimization for extender is 1->11, 2.4 Ghz->5 Ghz.
    // Gateway is left on channel 1 so extender will not receive CSA. One the other hand,
    // driver cannot apply new channel while STA is connected.
    if (ext->conn_state == connection_state_connected_wait_for_csa) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_csa_wait_timeout_handler_id);
        ext->ext_csa_wait_timeout_handler_id = 0;
        ext->channel_change_pending_map |= 1 << ext->connected_vap_index;
    }

    ext_set_conn_state(ext, connection_state_connection_to_nb_in_progress, __func__,
        __LINE__);

    // If BSSID changed on the same band need to initiate disconnection before connection to avoid
    // HAL error. On different band try to connect to new BSSID before disconnection.
    if (ext->connected_vap_index == vap_info->vap_index) {
        wifi_util_info_print(WIFI_SERVICES, "%s:%d execute sta disconnect for vap index: %d\n",
            __func__, __LINE__, ext->connected_vap_index);
        if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
            wifi_util_error_print(WIFI_SERVICES, "%s:%d sta disconnect failed for vap index: %d\n",
                __func__, __LINE__, ext->connected_vap_index);
        }
        return 0;
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
        process_ext_connect_algorithm, svc,
        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
#endif
    return 0;
}

int process_ext_webconfig_set_data(wifi_service_node_t *node, wifi_core_data_t *data)
{
    bss_candidate_t         *candidate;
    unsigned int connected_radio_index = 0;
    wifi_radio_operationParam_t *radio_oper_param;
    mesh_sta_node_data_t *ext;
    wifi_ctrl_t *ctrl;

    ext = &node->data.u.sta_node_data;
    ctrl = node->ctrl;

    radio_oper_param = (wifi_radio_operationParam_t *)data->msg;

    if (radio_oper_param == NULL) {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return 0;
    }

    if (ext->conn_state == connection_state_connected) {
        candidate = &ext->last_connected_bss;
        if (candidate == NULL) {
            wifi_util_dbg_print(WIFI_SERVICES,"%s:%d last_connected_bss is NULL \n", __func__, __LINE__);
            return 0;
        }
    } else {
        wifi_util_dbg_print(WIFI_SERVICES,"%s:%d Not in connected state no need to process event\n", __func__, __LINE__);
        return 0;
    }

    convert_freq_band_to_radio_index(candidate->radio_freq_band, (int *)&connected_radio_index);
    ext->go_to_channel = radio_oper_param->channel;
    ext->go_to_channel_width = radio_oper_param->channelWidth;
    ext_set_conn_state(ext, connection_state_connected_wait_for_csa, __func__, __LINE__);
    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
            process_ext_connect_algorithm, node,
            EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    return 0;
}


int process_sta_hal_ind(wifi_service_node_t *node, wifi_event_subtype_t sub_type, wifi_core_data_t *data)
{
    switch (sub_type) {
        case wifi_event_scan_results:
            process_ext_scan_results(node, data);
            break;

        case wifi_event_hal_sta_conn_status:
            process_ext_sta_conn_status(node, data);
            break;

        case wifi_event_hal_channel_change:
            process_ext_channel_change(node, data);
            break;

        default:
            wifi_util_dbg_print(WIFI_SERVICES, "%s:%d: assert - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            assert(sub_type >= wifi_event_hal_max);
        break;
    }

    return 0;
}

int process_sta_command(wifi_service_node_t *node, wifi_event_subtype_t sub_type, wifi_core_data_t *data)
{
    switch (sub_type) {
        case wifi_event_type_device_network_mode:
            break;

        case wifi_event_type_trigger_disconnection:
            process_ext_trigger_disconnection(node, data);
            break;

        default:
            wifi_util_dbg_print(WIFI_SERVICES, "%s:%d: assert - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            assert(sub_type >= wifi_event_command_max);
            break;
    }

    return 0;
}

int process_sta_exec(wifi_service_node_t *node, wifi_event_subtype_t sub_type, wifi_core_data_t *data)
{
    switch (sub_type) {
        case wifi_event_exec_timeout:
            process_ext_exec_timeout(node, data);
            break;

        default:
            wifi_util_dbg_print(WIFI_SERVICES, "%s:%d: assert - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            assert(sub_type >= wifi_event_exec_max);
            break;
    }

    return 0;
}

int process_sta_webconfig(wifi_service_node_t *node, wifi_event_subtype_t sub_type, wifi_core_data_t *data)
{
    switch (sub_type) {
        case wifi_event_webconfig_set_data:
            process_ext_webconfig_set_data(node, data);
            break;

        case wifi_event_webconfig_set_data_sta_bssid:
            process_sta_webconfig_set_data_sta_bssid(node, data);
            break;

        default:
            break;
    }

    return 0;
}

int mesh_sta_node_event(wifi_service_node_t *node, wifi_event_t *event)
{
    wifi_util_dbg_print(WIFI_SERVICES,"%s:%d: node: %s\n", __func__, __LINE__, node->desc.name);

    switch (event->event_type) {
        case wifi_event_type_exec:
            process_sta_exec(node, event->sub_type, &event->u.core_data);
            break;

        case wifi_event_type_command:
            process_sta_command(node, event->sub_type, &event->u.core_data);
            break;

        case wifi_event_type_hal_ind:
            process_sta_hal_ind(node, event->sub_type, &event->u.core_data);
            break;

        case wifi_event_type_webconfig:
            process_sta_webconfig(node, event->sub_type, &event->u.core_data);
            break;

        default:
            wifi_util_dbg_print(WIFI_SERVICES, "%s:%d: default - sub_type:%d\r\n", __func__, __LINE__, event->sub_type);
            break;
    }

    return 0;
}

