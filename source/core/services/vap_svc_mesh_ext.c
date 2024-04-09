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
#include <errno.h>
#include "stdlib.h"
#include <sys/time.h>
#include <assert.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "const.h"
#include <unistd.h>
#include "vap_svc.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_hal_rdk_framework.h"
#include <rbus.h>

#define PATH_TO_RSSI_NORMALIZER_FILE "/tmp/rssi_normalizer_2_4.cfg"
#define DEFAULT_RSSI_NORMALIZER_2_4_VALUE 20

#define EXT_DISCONNECTION_NO_ACTION 0
#define EXT_DISCONNECTION_DISCONNECT 1
#define EXT_DISCONNECTION_DISCONNECT_AND_IGNORE_RADIO 2

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
static int get_dwell_time()
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
    wifi_util_dbg_print(WIFI_CTRL, "%s():[%d] RSSI normalizer value [%d]\n", __FUNCTION__, __LINE__, rssi_2_4_normalizer_val);
    start_sorting_by_rssi(bss, start, end, rssi_2_4_normalizer_val);
}

bool vap_svc_is_mesh_ext(unsigned int vap_index)
{
    return isVapSTAMesh(vap_index) ? true : false;
}


void cancel_all_running_timer(vap_svc_t *svc)
{
    vap_svc_ext_t *l_ext;
    wifi_ctrl_t *l_ctrl;

    l_ctrl = svc->ctrl;
    l_ext = &svc->u.ext;

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel all started timer\r\n", __func__, __LINE__);
    if (l_ext->ext_connect_algo_processor_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel started timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_connect_algo_processor_id);
        l_ext->ext_connect_algo_processor_id = 0;
    }
    if (l_ext->ext_scan_result_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel started timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_scan_result_timeout_handler_id);
        l_ext->ext_scan_result_timeout_handler_id = 0;
    }
    if (l_ext->ext_scan_result_wait_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel started timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_scan_result_wait_timeout_handler_id);
        l_ext->ext_scan_result_wait_timeout_handler_id = 0;
    }
    if (l_ext->ext_conn_status_ind_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel started timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_conn_status_ind_timeout_handler_id);
        l_ext->ext_conn_status_ind_timeout_handler_id = 0;
    }
    if (l_ext->ext_csa_wait_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel started timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_csa_wait_timeout_handler_id);
        l_ext->ext_csa_wait_timeout_handler_id = 0;
    }
    if (l_ext->ext_connected_scan_result_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel started timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_connected_scan_result_timeout_handler_id);
        l_ext->ext_connected_scan_result_timeout_handler_id = 0;
    }
    if (l_ext->ext_disconnection_event_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel started timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_disconnection_event_timeout_handler_id);
        l_ext->ext_disconnection_event_timeout_handler_id = 0;
    }
    if (l_ext->ext_udhcp_ip_check_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel started timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_udhcp_ip_check_id);
        l_ext->ext_udhcp_ip_check_id = 0;
    }
    if (l_ext->ext_udhcp_disconnect_event_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel started timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_udhcp_disconnect_event_timeout_handler_id);
        l_ext->ext_udhcp_disconnect_event_timeout_handler_id = 0;
    }
    if (l_ext->ext_trigger_disconnection_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel started timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_trigger_disconnection_timeout_handler_id);
        l_ext->ext_trigger_disconnection_timeout_handler_id = 0;
    }
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

static void ext_set_conn_state(vap_svc_ext_t *ext, connection_state_t new_conn_state,
    const char *func, int line)
{
    wifi_util_info_print(WIFI_CTRL, "%s:%d change connection state: %s -> %s\r\n", func, line,
        ext_conn_state_to_str(ext->conn_state), ext_conn_state_to_str(new_conn_state));
    ext->conn_state = new_conn_state;
}

static void ext_reset_radios(vap_svc_t *svc)
{
    wifi_ctrl_t *ctrl = svc->ctrl;
    vap_svc_ext_t *ext = &svc->u.ext;

    reset_wifi_radios();
    ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__, __LINE__);
    int id = ext->ext_connect_algo_processor_id;
    scheduler_add_timer_task(ctrl->sched, FALSE, &id,
        process_ext_connect_algorithm, svc, EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    ext->ext_connect_algo_processor_id = id;
}

void ext_incomplete_scan_list(vap_svc_t *svc)
{
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    ext->wait_scan_result++;
    if (ext->wait_scan_result > MAX_SCAN_RESULT_WAIT) {
        ext->wait_scan_result = 0;
        ext_set_conn_state(ext, connection_state_disconnected_scan_list_all, __func__, __LINE__);
        ext->scanned_radios = 0;
        int id = ext->ext_connect_algo_processor_id;
        // schedule extender connetion algorithm
        scheduler_add_timer_task(ctrl->sched, FALSE, &id,
                        process_ext_connect_algorithm, svc,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        ext->ext_connect_algo_processor_id = id;
    }
}

int process_scan_result_timeout(vap_svc_t *svc)
{
    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if (ext->conn_state == connection_state_disconnected_scan_list_none) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - start wifi scan timer\r\n", __func__, __LINE__);
        int id = ext->ext_connect_algo_processor_id;
        scheduler_add_timer_task(ctrl->sched, FALSE, &id,
                    process_ext_connect_algorithm, svc,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        ext->ext_connect_algo_processor_id = id;
    }
    return 0;
}

static int process_ext_connect_event_timeout(vap_svc_t *svc)
{
    wifi_ctrl_t *ctrl = svc->ctrl;
    vap_svc_ext_t *ext = &svc->u.ext;

    ext->ext_conn_status_ind_timeout_handler_id = 0;

    if (ext->conn_state != connection_state_connection_in_progress &&
            ext->conn_state != connection_state_connection_to_lcb_in_progress &&
            ext->conn_state != connection_state_connection_to_nb_in_progress) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d not received connection event, exit due to "
            "connection state: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        ext->conn_retry = 0;
        return 0;
    }

    if (ext->conn_retry >= STA_MAX_CONNECT_ATTEMPT) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d not received connection event, reset radios\n",
            __func__, __LINE__);
        ext_reset_radios(svc);
        ext->conn_retry = 0;
        return 0;
    }

    ext->conn_retry++;
    wifi_util_error_print(WIFI_CTRL, "%s:%d not received connection event, retry\n", __func__,
        __LINE__);
    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
        process_ext_connect_algorithm, svc, EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);

    return 0;
}

int process_disconnection_event_timeout(vap_svc_t *svc)
{
    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if (ext->conn_state == connection_state_disconnection_in_progress) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d !!!!!!!ERROR!!!!!!! Not received disconnection event \n", __func__, __LINE__);
        ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                process_ext_connect_algorithm, svc,
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }

    return 0;
}

static int process_udhcp_disconnect_event_timeout(vap_svc_t *svc)
{
    wifi_ctrl_t *ctrl = svc->ctrl;
    vap_svc_ext_t *ext = &svc->u.ext;

    ext->ext_udhcp_disconnect_event_timeout_handler_id = 0;

    if (ext->conn_state != connection_state_connected) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d not received disconnection event, exit due to "
            "connection state: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        ext->disconn_retry = 0;
        return 0;
    }

    if (ext->disconn_retry >= STA_MAX_DISCONNECT_ATTEMPT) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d not received disconnection event, reset radios\n",
            __func__, __LINE__);
        ext_reset_radios(svc);
        ext->disconn_retry = 0;
        return 0;
    }

    wifi_util_error_print(WIFI_CTRL, "%s:%d not received disconnection event, retry\n", __func__,
        __LINE__);

    ext->disconn_retry++;

    wifi_util_info_print(WIFI_CTRL, "%s:%d execute sta disconnect for vap index: %d\n",
        __func__, __LINE__, ext->connected_vap_index);
    if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d sta disconnect failed for vap index: %d, "
            "retry after timeout\n", __func__, __LINE__, ext->connected_vap_index);
    }

    scheduler_add_timer_task(ctrl->sched, FALSE,
        &ext->ext_udhcp_disconnect_event_timeout_handler_id, process_udhcp_disconnect_event_timeout,
        svc, EXT_DISCONNECTION_IND_TIMEOUT, 1, FALSE);

    return 0;
}

static int process_trigger_disconnection_event_timeout(vap_svc_t *svc)
{
    wifi_ctrl_t *ctrl = svc->ctrl;
    vap_svc_ext_t *ext = &svc->u.ext;

    ext->ext_trigger_disconnection_timeout_handler_id = 0;

    if (ext->conn_state != connection_state_connected) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d not received disconnection event, exit due to "
            "connection state: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        ext->disconn_retry = 0;
        return 0;
    }

    if (ext->disconn_retry >= STA_MAX_DISCONNECT_ATTEMPT) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d not received disconnection event, reset radios\n",
            __func__, __LINE__);
        ext_reset_radios(svc);
        ext->disconn_retry = 0;
        return 0;
    }

    wifi_util_error_print(WIFI_CTRL, "%s:%d not received disconnection event, retry\n", __func__,
        __LINE__);

    ext->disconn_retry++;

    wifi_util_info_print(WIFI_CTRL, "%s:%d execute sta disconnect for vap index: %d\n", __func__,
        __LINE__, ext->connected_vap_index);
    if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d sta disconnect failed for vap index: %d, "
            "retry after timeout\n", __func__, __LINE__, ext->connected_vap_index);
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_trigger_disconnection_timeout_handler_id,
        process_trigger_disconnection_event_timeout, svc, EXT_DISCONNECTION_IND_TIMEOUT, 1, FALSE);

    return 0;
}

int process_udhcp_ip_check(vap_svc_t *svc)
{
    static int ip_check_count = 0;
    struct sockaddr_in sa;
    char value[128];
    char file_name[128];
    char command[256];
    size_t len = 0;
    wifi_interface_name_t *interface_name;
    FILE *fp = NULL;

    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;
    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    memset(value, '\0', sizeof(value));
    memset(value, '\0', sizeof(file_name));
    memset(command, '\0', sizeof(command));

    interface_name = get_interface_name_for_vap_index(ext->connected_vap_index, svc->prop);
    if ((interface_name == NULL) && (ip_check_count < EXT_UDHCP_IP_CHECK_NUM)) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d Unable to fetch proper Interface name for connected index%d\n", __func__, __LINE__, ext->connected_vap_index);
        ip_check_count++;
        return 0;
    }

    snprintf(file_name, sizeof(file_name), "/var/run/udhcpc-%s.opts", *interface_name);
    snprintf(command, sizeof(command), "grep \"ip=\" %s | cut -d '=' -f 2", file_name);

    if ((ip_check_count < EXT_UDHCP_IP_CHECK_NUM) &&
        (ext->conn_state == connection_state_connected)) {
        if (access(file_name , F_OK) == 0) {
            fp = popen(command, "r");
            if (fp != NULL) {
                fgets(value, sizeof(value), fp);
                len  = strlen(value);
                if (len > 0) {
                    value[len-1] = '\0';
                    if ((inet_pton(AF_INET, value, &(sa.sin_addr)) == 1) || (inet_pton(AF_INET6, value, &(sa.sin_addr)) == 1)) {
                        scheduler_cancel_timer_task(ctrl->sched, ext->ext_udhcp_ip_check_id);
                        ext->ext_udhcp_ip_check_id = 0;
                        ip_check_count = 0;
                        pclose(fp);
                        return 0;
                    }
                }
                pclose(fp);
            }
        }
    }

    if (ip_check_count >= EXT_UDHCP_IP_CHECK_NUM) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_udhcp_ip_check_id);
        ext->ext_udhcp_ip_check_id = 0;
        ip_check_count = 0;
        wifi_util_error_print(WIFI_CTRL,"%s:%d No IP on connected interface triggering a disconnect\n", __func__, __LINE__);
#if CCSP_COMMON
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_command, wifi_event_type_udhcp_ip_fail, ext);
#endif
        ext->disconn_retry++;
        wifi_util_info_print(WIFI_CTRL, "%s:%d execute sta disconnect for vap index: %d\n",
            __func__, __LINE__, ext->connected_vap_index);
        if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d sta disconnect failed for vap index:%d, "
                "retry after timeout\n", __func__, __LINE__, ext->connected_vap_index);
        }

        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_udhcp_disconnect_event_timeout_handler_id,
                process_udhcp_disconnect_event_timeout, svc,
                EXT_DISCONNECTION_IND_TIMEOUT, 1, FALSE);
        return 0;
    }

    ip_check_count++;
    return 0;
}

void cancel_scan_result_timer(wifi_ctrl_t *l_ctrl, vap_svc_ext_t *l_ext)
{
    if (l_ext->ext_scan_result_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel wifi start scan timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_scan_result_timeout_handler_id);
        l_ext->ext_scan_result_timeout_handler_id = 0;
    }
    if (l_ext->ext_connected_scan_result_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel wifi start scan timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_connected_scan_result_timeout_handler_id);
        l_ext->ext_connected_scan_result_timeout_handler_id = 0;
    }
}

void ext_start_scan(vap_svc_t *svc)
{
    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;
    unsigned int radio_index;
    wifi_channels_list_t channels;
    wifi_radio_operationParam_t *radio_oper_param;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    INT num_channels;
    INT channels_list[MAX_CHANNELS];

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if (ext->conn_state != connection_state_disconnected_scan_list_none) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi_scan completed, current state: %s\r\n",__func__,
            __LINE__, ext_conn_state_to_str(ext->conn_state));
        return;
    }

    cancel_scan_result_timer(ctrl, ext);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Enter......\r\n",__func__, __LINE__);
    // first free up scan list
    if (ext->candidates_list.scan_list != NULL) {
        ext->candidates_list.scan_count = 0;
        free(ext->candidates_list.scan_list);
        ext->candidates_list.scan_list = NULL;
    }
    ext->scanned_radios = 0;
    
    int dwell_time = get_dwell_time();
    for (radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        if (ext->is_radio_ignored == true && radio_index == ext->ignored_radio_index) {
            wifi_util_info_print(WIFI_CTRL, "%s:%d ignore radio index %u\n", __func__, __LINE__,
                radio_index);
            ext->scanned_radios++;
            ext->is_radio_ignored = false;
            ext->ignored_radio_index = 0;
            continue;
        }

        wifi_util_dbg_print(WIFI_CTRL, "%s:%d start Scan on radio index %u\n", __func__, __LINE__,
            radio_index);

        radio_oper_param = get_wifidb_radio_map(radio_index);
        if (get_allowed_channels(radio_oper_param->band, &mgr->hal_cap.wifi_prop.radiocap[radio_index],
                channels_list, &num_channels,
                radio_oper_param->DfsEnabled) != RETURN_OK) {
            continue;
        }
        (void)memcpy(channels.channels_list, channels_list,
               sizeof(*channels_list) * num_channels);
        channels.num_channels = num_channels;

        wifi_hal_startScan(radio_index, WIFI_RADIO_SCAN_MODE_OFFCHAN, dwell_time,
            channels.num_channels, channels.channels_list);
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_scan_result_timeout_handler_id,
                process_scan_result_timeout, svc,
                EXT_SCAN_RESULT_TIMEOUT, 0, FALSE);
}

void ext_process_scan_list(vap_svc_t *svc)
{
    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if (ext->conn_state != connection_state_connection_in_progress) {
        wifi_util_info_print(WIFI_CTRL,"%s:%d start wifi connection:%s scan_count:%d\n", __func__,
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
                    process_ext_connect_algorithm, svc,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi connection already in process state\n",__func__, __LINE__);
    }
}

int process_connected_scan_result_timeout(vap_svc_t *svc)
{
    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    ext->ext_connected_scan_result_timeout_handler_id = 0;

    if (ext->conn_state == connection_state_connected_scan_list) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d Time out on connected scan \n", __func__, __LINE__);
        ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, svc,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }

    return 0;
}

void ext_connected_scan(vap_svc_t *svc)
{
    if (svc == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL pointer\n", __func__, __LINE__);
        return;
    }
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Enter \n", __func__, __LINE__);

    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;
    unsigned int radio_index = 0;
    radio_index = get_radio_index_for_vap_index(svc->prop, ext->connected_vap_index);
    int dwell_time = get_dwell_time();

    if (ext->conn_state == connection_state_connected_scan_list) {
        cancel_scan_result_timer(ctrl, ext);
        if (ext->candidates_list.scan_list != NULL) {
            ext->candidates_list.scan_count = 0;
            free(ext->candidates_list.scan_list);
            ext->candidates_list.scan_list = NULL;
        }

        wifi_util_dbg_print(WIFI_CTRL,"%s:%d start Scan on radio index %d channel %d\n", __func__, __LINE__, radio_index, ext->go_to_channel);
        wifi_hal_startScan(radio_index, WIFI_RADIO_SCAN_MODE_OFFCHAN, dwell_time, 1, &ext->go_to_channel); 
    }
    
    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connected_scan_result_timeout_handler_id,
                process_connected_scan_result_timeout, svc,
                EXT_SCAN_RESULT_TIMEOUT, 0, FALSE);
    return;
}

int csa_wait_timeout(vap_svc_t *svc)
{
    if (svc == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL pointer\n", __func__, __LINE__);
        return 0;
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Enter \n", __func__, __LINE__);

    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    ext->ext_csa_wait_timeout_handler_id = 0;

    if (ext->conn_state == connection_state_connected_wait_for_csa) {
        ext_set_conn_state(ext, connection_state_connected_scan_list, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                   process_ext_connect_algorithm, svc,
                   EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }

    return 0;
}

void ext_wait_for_csa(vap_svc_t *svc)
{

    if (svc == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL pointer\n", __func__, __LINE__);
        return;
    }

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d Enter\n", __func__, __LINE__);
    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if (ext->conn_state == connection_state_connected_wait_for_csa) {
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_csa_wait_timeout_handler_id,
                    csa_wait_timeout, svc,
                    EXT_CSA_WAIT_TIMEOUT, 1, FALSE);
    }

    return;
}

static void ext_try_disconnecting(vap_svc_t *svc)
{
    vap_svc_ext_t *ext = &svc->u.ext;
    wifi_ctrl_t *ctrl = svc->ctrl;

    if (ext->conn_state != connection_state_disconnection_in_progress) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d ignore disconnection request due to "
            "connection state: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        return;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d execute sta disconnect for vap index: %d\n", __func__,
        __LINE__, ext->connected_vap_index);

    if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d sta disconnect failed for vap index: %d\n",
            __func__, __LINE__, ext->connected_vap_index);
        process_disconnection_event_timeout(svc);
        return;
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_disconnection_event_timeout_handler_id,
        process_disconnection_event_timeout, svc, EXT_DISCONNECTION_IND_TIMEOUT, 1, FALSE);
}

static void reset_sta_state(vap_svc_t *svc, unsigned int vap_index)
{
    unsigned int i;
    int radio_index;
    wifi_vap_info_map_t *vap_map;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    radio_index = get_radio_index_for_vap_index(svc->prop, vap_index);
    if (radio_index == RETURN_ERR) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: failed to get radio index for vap index %u\n",
            __func__, __LINE__, vap_index);
        return;
    }

    vap_map = &mgr->radio_config[radio_index].vaps.vap_map;
    for (i = 0; i < vap_map->num_vaps; i++) {
        if (vap_map->vap_array[i].vap_index == vap_index) {
            vap_map->vap_array[i].u.sta_info.conn_status = wifi_connection_status_disabled;
            break;
        }
    }
}

void ext_try_connecting(vap_svc_t *svc)
{
    vap_svc_ext_t   *ext;
    unsigned int i, vap_index, radio_index;
    bss_candidate_t         *candidate;
    mac_addr_str_t bssid_str;
    bool found_at_least_one_candidate = false;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

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
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: assert - conn_state : %s\n", __func__, __LINE__,
            ext_conn_state_to_str(ext->conn_state));
        // should not come here in any states other than connection_state_connection_in_progress
        assert((ext->conn_state != connection_state_connection_in_progress) ||
        (ext->conn_state != connection_state_connection_to_lcb_in_progress));
    }

    if (found_at_least_one_candidate == true) {
        if (candidate != NULL) {
            convert_freq_band_to_radio_index(candidate->radio_freq_band, (int *)&radio_index);
        } else {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: candidate param NULL\n", __func__, __LINE__);
        }
        vap_index = get_sta_vap_index_for_radio(svc->prop, radio_index);

        wifi_util_info_print(WIFI_CTRL,"%s:%d connecting to ssid:%s bssid:%s rssi:%d frequency:%d on vap:%d radio:%d\n",
                    __func__, __LINE__, candidate->external_ap.ssid,
                    to_mac_str(candidate->external_ap.bssid, bssid_str), candidate->external_ap.rssi,
                    candidate->external_ap.freq, vap_index, radio_index);
        // wifi-telemetry print
        wifi_util_info_print(WIFI_CTRL,"%s:%d connecting to rssi:%d\n",
                    __func__, __LINE__, candidate->external_ap.rssi);
        // Set to disabled in order to detect state change on connection retry
        reset_sta_state(svc, vap_index);
        ext->conn_retry++;
        if (wifi_hal_connect(vap_index, &candidate->external_ap) == RETURN_ERR) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d sta connect failed for vap index: %d, "
                "retry after timeout\n", __func__, __LINE__, vap_index);
        }

        if (ext->ext_conn_status_ind_timeout_handler_id != 0) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d connect status timer is in progress, cancel\n",
                __func__, __LINE__);
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_conn_status_ind_timeout_handler_id);
        }
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_conn_status_ind_timeout_handler_id,
            process_ext_connect_event_timeout, svc, EXT_CONN_STATUS_IND_TIMEOUT, 1, FALSE);

#if CCSP_COMMON
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_command, wifi_event_type_sta_connect_in_progress, candidate);
#endif // CCSP_COMMON
    } else {
        ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                process_ext_connect_algorithm, svc,
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }
}

int process_ext_connect_algorithm(vap_svc_t *svc)
{
    vap_svc_ext_t   *ext;
    ext = &svc->u.ext;

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d process connection state: %s\r\n", __func__, __LINE__,
        ext_conn_state_to_str(ext->conn_state));

    ext->ext_connect_algo_processor_id = 0;

    switch (ext->conn_state) {
        case connection_state_disconnected_scan_list_none:
            ext_start_scan(svc);
            break;

        case connection_state_disconnected_scan_list_in_progress:
            ext_incomplete_scan_list(svc);
            break;

        case connection_state_disconnected_scan_list_all:
            ext_process_scan_list(svc);
            break;

        case connection_state_connection_in_progress:
        case connection_state_connection_to_lcb_in_progress:
        case connection_state_connection_to_nb_in_progress:
            ext_try_connecting(svc);
            break;

        case connection_state_connected:
            break;

        case connection_state_connected_wait_for_csa:
            ext_wait_for_csa(svc);
            break;

        case connection_state_connected_scan_list:
            ext_connected_scan(svc);
            break;

        case connection_state_disconnection_in_progress:
            ext_try_disconnecting(svc);
            break;
    }

    return 0;
}

int vap_svc_mesh_ext_disconnect(vap_svc_t *svc)
{
    uint8_t num_of_radios;
    unsigned int i, j;
    wifi_vap_info_map_t *vap_map = NULL;
    wifi_vap_info_t *vap;
    vap_svc_ext_t   *ext;

    ext = &svc->u.ext;

    if ((num_of_radios = getNumberRadios()) > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_CTRL,"WIFI %s : Number of Radios %d exceeds supported %d Radios \n",__FUNCTION__, getNumberRadios(), MAX_NUM_RADIOS);
        return -1;
    }

    for (i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        if (vap_map == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:failed to get vap map for radio index: %d\n",__FUNCTION__, i);
            return -1;
        }

        for (j = 0; j < vap_map->num_vaps; j++) {
            if (vap_svc_is_mesh_ext(vap_map->vap_array[j].vap_index) == true) {
                vap = &vap_map->vap_array[j];
                if ((vap->vap_mode == wifi_vap_mode_sta) &&
                    (vap->u.sta_info.conn_status == wifi_connection_status_connected)) {
                    wifi_util_info_print(WIFI_CTRL, "%s:%d execute sta disconnect for "
                        "vap index: %d\n", __func__, __LINE__, vap->vap_index);
                    if (wifi_hal_disconnect(vap->vap_index) == RETURN_ERR) {
                        wifi_util_error_print(WIFI_CTRL, "%s:%d sta disconnect failed for "
                            "vap index: %d\n", __func__, __LINE__, vap->vap_index);
                    }
                    ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__,
                        __LINE__);
                }
            }
        }
    }

    return 0;
}

int vap_svc_mesh_ext_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    wifi_util_info_print(WIFI_CTRL, "%s:%d mesh service start\n", __func__, __LINE__);

    if (ext->is_started == true) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d mesh service already started\n", __func__, __LINE__);
        return 0;
    }

    /* create STA vap's and install acl filters */
    vap_svc_start(svc);

    // initialize all extender specific structures
    memset(ext, 0, sizeof(vap_svc_ext_t));

    ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__, __LINE__);
    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                process_ext_connect_algorithm, svc,
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);

    ext->is_started = true;

    return 0;
}

int vap_svc_mesh_ext_clear_variable(vap_svc_t *svc)
{
    unsigned int  index = 0;
    unsigned char radio_index = 0;
    unsigned char num_of_radios = getNumberRadios();
    wifi_vap_info_map_t *map;

    for (radio_index = 0; radio_index < num_of_radios; radio_index++) {
        map = (wifi_vap_info_map_t *)get_wifidb_vap_map(radio_index);
        if (map == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s:%d failed to get vap map for radio index: %d\n", __func__, __LINE__, radio_index);
            return -1;
        }
        for (index = 0; index < map->num_vaps; index++) {
            if (svc->is_my_fn(map->vap_array[index].vap_index) == true) {
                map->vap_array[index].u.sta_info.conn_status = wifi_connection_status_disabled;
                memset(map->vap_array[index].u.sta_info.bssid, 0, sizeof(mac_address_t));
            }
        }
    }
    return 0;
}

int vap_svc_mesh_ext_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    vap_svc_ext_t *ext = &svc->u.ext;

    wifi_util_info_print(WIFI_CTRL, "%s:%d mesh service stop\n", __func__, __LINE__);

    if (ext->is_started == false) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d mesh service already stopped\n", __func__, __LINE__);
        return 0;
    }
    vap_svc_mesh_ext_disconnect(svc);
    cancel_all_running_timer(svc);
    vap_svc_stop(svc);
    vap_svc_mesh_ext_clear_variable(svc);
    ext->is_started = false;
    return 0;
}

static int process_ext_webconfig_set_data_sta_bssid(vap_svc_t *svc, void *arg)
{
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

    // Support only connected/wait_for_csa/connected_scan_list -> nb_in_progress state change
    if (ext->conn_state != connection_state_connected &&
        ext->conn_state != connection_state_connected_wait_for_csa &&
        ext->conn_state != connection_state_connected_scan_list) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d skip sta bssid change event: connection state: %s,"
            "vap: %s, bssid: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state),
            vap_info->vap_name, bssid_str);
        return 0;
    }

    // Clear old bssid
    if (candidate->vap_index == vap_info->vap_index) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d clear old sta bssid for vap %s\n", __func__,
            __LINE__, vap_info->vap_name);
        memset(candidate, 0, sizeof(bss_candidate_t));
    }

    // Skip zero bssid and disabled vaps
    if (!is_bssid_valid(vap_info->u.sta_info.bssid) || !vap_info->u.sta_info.enabled) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d skip sta bssid change event, vap: %s, bssid: %s, "
            "enabled: %d\n", __func__, __LINE__, vap_info->vap_name, bssid_str,
            vap_info->u.sta_info.enabled);
        return 0;
    }

    band = mgr->radio_config[vap_info->radio_index].oper.band;
    channel = mgr->radio_config[vap_info->radio_index].oper.channel;
    freq = convert_channel_to_freq(band, channel);
    if (freq == -1) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d failed to convert channel %d to frequency\n",
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

    wifi_util_info_print(WIFI_CTRL, "%s:%d new sta bssid: %s, ssid: %s, channel: %d, "
        "freq: %d, band: %d connection state: %s\n", __func__, __LINE__, bssid_str,
        candidate->external_ap.ssid, channel, candidate->external_ap.freq,
        candidate->radio_freq_band, ext_conn_state_to_str(ext->conn_state));

#if DML_SUPPORT
        apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_command, wifi_event_type_new_bssid, ext);
#endif

    if (ext->conn_state == connection_state_connected_wait_for_csa &&
        ext->ext_csa_wait_timeout_handler_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_csa_wait_timeout_handler_id);
        ext->ext_csa_wait_timeout_handler_id = 0;
    }

    if (ext->conn_state == connection_state_connected_scan_list &&
        ext->ext_connected_scan_result_timeout_handler_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_connected_scan_result_timeout_handler_id);
        ext->ext_connected_scan_result_timeout_handler_id = 0;
    }

    if (ext->ext_connect_algo_processor_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_connect_algo_processor_id);
        ext->ext_connect_algo_processor_id = 0;
    }

    ext_set_conn_state(ext, connection_state_connection_to_nb_in_progress, __func__,
        __LINE__);

    // If BSSID changed on the same band need to initiate disconnection before connection to avoid
    // HAL error. On different band try to connect to new BSSID before disconnection.
    if (ext->connected_vap_index == vap_info->vap_index) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d execute sta disconnect for vap index: %d\n",
            __func__, __LINE__, ext->connected_vap_index);
        if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d sta disconnect failed for vap index: %d\n",
                __func__, __LINE__, ext->connected_vap_index);
        }
        return 0;
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
        process_ext_connect_algorithm, svc,
        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);

    return 0;
}

int vap_svc_mesh_ext_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map,
    rdk_wifi_vap_info_t *rdk_vap_info)
{
    unsigned int i;
    wifi_vap_info_map_t tgt_vap_map;

    for (i = 0; i < map->num_vaps; i++) {
        memset((unsigned char *)&tgt_vap_map, 0, sizeof(tgt_vap_map));
        memcpy((unsigned char *)&tgt_vap_map.vap_array[0], (unsigned char *)&map->vap_array[i],
                    sizeof(wifi_vap_info_t));
        tgt_vap_map.num_vaps = 1;

        // avoid disabling mesh sta in extender mode
        if (tgt_vap_map.vap_array[0].u.sta_info.enabled == false && is_sta_enabled()) {
            wifi_util_info_print(WIFI_CTRL, "%s:%d vap_index:%d skip disabling sta\n", __func__,
                __LINE__, tgt_vap_map.vap_array[0].vap_index);
            tgt_vap_map.vap_array[0].u.sta_info.enabled = true;
        }

        if (wifi_hal_createVAP(radio_index, &tgt_vap_map) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s: wifi vap create failure: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
            continue;
        }
        wifi_util_info_print(WIFI_CTRL,"%s: wifi vap create success: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
        memcpy((unsigned char *)&map->vap_array[i], (unsigned char *)&tgt_vap_map.vap_array[0],
                    sizeof(wifi_vap_info_t));
        wifidb_update_wifi_vap_info(getVAPName(map->vap_array[i].vap_index), &map->vap_array[i],
            &rdk_vap_info[i]);
        wifidb_update_wifi_security_config(getVAPName(map->vap_array[i].vap_index),
            &map->vap_array[i].u.sta_info.security);
    }

    return 0;
}

int process_ext_webconfig_set_data(vap_svc_t *svc, void *arg)
{
    wifi_radio_operationParam_t *radio_oper_param = (wifi_radio_operationParam_t *)arg;
    bss_candidate_t         *candidate;
    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;
    unsigned int connected_radio_index = 0;

    if (radio_oper_param == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return 0;
    }

    ext = &svc->u.ext;
    ctrl = svc->ctrl;

    if (ext->conn_state == connection_state_connected) {
        candidate = &ext->last_connected_bss;
        if (candidate == NULL) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d last_connected_bss is NULL \n", __func__, __LINE__);
            return 0;
        }
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d Not in connected state no need to process event\n", __func__, __LINE__);
        return 0;
    }

    convert_freq_band_to_radio_index(candidate->radio_freq_band, (int *)&connected_radio_index);
    ext->go_to_channel = radio_oper_param->channel;
    ext->go_to_channel_width = radio_oper_param->channelWidth;
    ext_set_conn_state(ext, connection_state_connected_wait_for_csa, __func__, __LINE__);

    wifi_util_info_print(WIFI_CTRL, "%s:%d wait csa for channel: %u width: %u radio: %u\n",
        __func__, __LINE__, ext->go_to_channel, ext->go_to_channel_width, connected_radio_index);
    ext->channel_change_pending_map |= 1 << ext->connected_vap_index;

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
            process_ext_connect_algorithm, svc,
            EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    return 0;
}

static void process_ext_trigger_disconnection(vap_svc_t *svc, void *arg)
{
    int radio_index;
    unsigned int disconnection_type;
    wifi_ctrl_t *ctrl = svc->ctrl;
    vap_svc_ext_t *ext = &svc->u.ext;

    if (arg == NULL) {
        return;
    }

    disconnection_type = *(unsigned int *)arg;
    if (disconnection_type == EXT_DISCONNECTION_NO_ACTION) {
        return;
    }

    if (ext->conn_state != connection_state_connected) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d ignore disconnection event due to "
            "connection state: %s\n", __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        return;
    }

#if DML_SUPPORT
    apps_mgr_analytics_event(&ctrl->apps_mgr, wifi_event_type_command, wifi_event_type_trigger_disconnection_analytics, ext);
#endif

    radio_index = get_radio_index_for_vap_index(svc->prop, ext->connected_vap_index);
    if (radio_index == RETURN_ERR) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: failed to get radio index for vap_index: %d\n",
            __func__, __LINE__, ext->connected_vap_index);
        return;
    }

    if (disconnection_type == EXT_DISCONNECTION_DISCONNECT_AND_IGNORE_RADIO) {
        ext->is_radio_ignored = true;
        ext->ignored_radio_index = radio_index;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d execute sta disconnect for vap index: %d, "
        "ignore radio on scan: %s\n", __func__, __LINE__, ext->connected_vap_index,
        ext->is_radio_ignored ? "true" : "false");

    ext->disconn_retry++;
    if (wifi_hal_disconnect(ext->connected_vap_index) == RETURN_ERR) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d sta disconnect failed for vap index: %d, "
            "retry after timeout\n", __func__, __LINE__, ext->connected_vap_index);
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_trigger_disconnection_timeout_handler_id,
        process_trigger_disconnection_event_timeout, svc, EXT_DISCONNECTION_IND_TIMEOUT, 1, FALSE);
}

int process_ext_exec_timeout(vap_svc_t *svc, void *arg)
{
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    wifi_util_dbg_print(WIFI_CTRL,"%s:%d - start timeout timer\r\n", __func__, __LINE__);
    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                process_ext_connect_algorithm, svc,
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);

    return 0;
}

int scan_result_wait_timeout(vap_svc_t *svc)
{
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if (ext->conn_state == connection_state_disconnected_scan_list_in_progress) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - received only %u radio scan results\r\n", __func__,
            __LINE__, ext->scanned_radios);

        ext_set_conn_state(ext, connection_state_disconnected_scan_list_all, __func__, __LINE__);
        ext->scanned_radios = 0;
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, svc,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    }
    return 0;
}

void process_ext_connected_scan_results(vap_svc_t *svc, void *arg)
{
    if ((svc == NULL) || (arg == NULL)){
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Enter\n", __func__, __LINE__);
    
    unsigned int i = 0, num = 0, band = 0, channel = 0;
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;
    scan_results_t *results;
    wifi_bss_info_t *bss;
    wifi_bss_info_t *tmp_bss;
    bss_candidate_t *scan_list;
    bool found_candidate = false;
    
    results = (scan_results_t*)arg;
    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    num = results->num;
    bss = results->bss;

    if (ext->ext_connected_scan_result_timeout_handler_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_connected_scan_result_timeout_handler_id);
        ext->ext_connected_scan_result_timeout_handler_id = 0;
    }

    if ((num == 0) || (bss == NULL)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d No AP in the go to channel \n", __func__, __LINE__);
        ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                  process_ext_connect_algorithm, svc,
                  EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        return;
    }
    
    tmp_bss = bss;
    convert_radio_index_to_freq_band(svc->prop, results->radio_index, (int *)&band);
    if ((ext->candidates_list.scan_list == NULL) && num) {
        ext->candidates_list.scan_list = (bss_candidate_t *) malloc(num * sizeof(bss_candidate_t));
        scan_list = ext->candidates_list.scan_list;
        ext->candidates_list.scan_count = num;
    } else  {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d NULL scan list should not reach this condition\n", __func__, __LINE__);
        ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, svc,
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
                    process_ext_connect_algorithm, svc,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);

    return;
}

int process_ext_scan_results(vap_svc_t *svc, void *arg)
{
    wifi_bss_info_t *bss;
    wifi_bss_info_t *tmp_bss;
    unsigned int i, num = 0;
    scan_results_t *results;
    bss_candidate_t *scan_list;
    unsigned int band = 0;
    mac_addr_str_t bssid_str;
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;
    results = (scan_results_t *)arg;
    bss = results->bss;
    num = results->num;

    tmp_bss = bss;

    if (ext->conn_state == connection_state_connected_scan_list) {
        process_ext_connected_scan_results(svc, arg);
        return 0;
    }

    if (ext->conn_state >= connection_state_disconnected_scan_list_all) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Received scan resuts when already have result or connection in progress, should not happen\n",
                        __FUNCTION__,__LINE__);
        return 0;
    }

    convert_radio_index_to_freq_band(svc->prop, results->radio_index, (int *)&band);
    if (ext->ext_scan_result_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel wifi start scan timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_scan_result_timeout_handler_id);
        ext->ext_scan_result_timeout_handler_id = 0;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d Extender Mode radio:%u, num of scan results:%d,"
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
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: AP with ssid:%s, bssid:%s, rssi:%d, freq:%d\n",
            __func__, __LINE__, tmp_bss->ssid, to_mac_str(tmp_bss->bssid, bssid_str), tmp_bss->rssi, tmp_bss->freq);
        wifi_util_info_print(WIFI_CTRL, "%s:%d: AP with ssid:%s, bssid:%s, rssi:%d, freq:%d\n",
            __func__, __LINE__, scan_list->external_ap.ssid, to_mac_str(scan_list->external_ap.bssid, bssid_str), scan_list->external_ap.rssi, scan_list->external_ap.freq);
        tmp_bss++;
        scan_list++;
    }

    if (ext->candidates_list.scan_list && (ext->candidates_list.scan_count > 1))
        sort_bss_results_by_rssi(ext->candidates_list.scan_list, 0, ext->candidates_list.scan_count - 1);

    ext->scanned_radios++;
    if (ext->scanned_radios >= getNumberRadios()) {
        ext_set_conn_state(ext, connection_state_disconnected_scan_list_all, __func__, __LINE__);
        ext->scanned_radios = 0;

        if (ext->ext_scan_result_wait_timeout_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_scan_result_wait_timeout_handler_id);
            ext->ext_scan_result_wait_timeout_handler_id = 0;
        }
        // schedule extender connetion algorithm
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, svc,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    } else {
        ext_set_conn_state(ext, connection_state_disconnected_scan_list_in_progress, __func__,
            __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_scan_result_wait_timeout_handler_id,
                        scan_result_wait_timeout, svc,
                        EXT_SCAN_RESULT_WAIT_TIMEOUT, 1, FALSE);
    }

    return 0;
}

static bool is_connected_to_bssid(vap_svc_ext_t *ext)
{
    unsigned int i, j;
    wifi_vap_info_map_t *vap_map;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    for (i = 0; i < getNumberRadios(); i++) {
        vap_map = &mgr->radio_config[i].vaps.vap_map;
        for (j = 0; j < vap_map->num_vaps; j++) {
            wifi_vap_info_t *vap_info = &vap_map->vap_array[j];
            if (vap_svc_is_mesh_ext(vap_info->vap_index) &&
                    vap_info->vap_index == ext->connected_vap_index &&
                    vap_info->u.sta_info.conn_status == wifi_connection_status_connected) {
                return true;
            }
        }
    }

    return false;
}

// Channel change for connected STA may fail therefore need to re-apply it on disconnection.
// For example, STA is connected to 2.4 GHz. Optimization for extender is 1->11, 2.4 Ghz->5 Ghz.
// Gateway is left on channel 1 so extender will not receive CSA. One the other hand,
// driver cannot apply new channel while STA is connected.
static int apply_pending_channel_change(vap_svc_t *svc, int vap_index)
{
    int ret, radio_index;
    wifi_radio_operationParam_t *radio_params, temp_radio_params;
    vap_svc_ext_t *ext = &svc->u.ext;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    if ((ext->channel_change_pending_map & (1 << vap_index)) == 0) {
        return RETURN_OK;
    }
    ext->channel_change_pending_map &= ~(1 << vap_index);

    radio_index = get_radio_index_for_vap_index(svc->prop, vap_index);
    if (radio_index == RETURN_ERR) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: failed to get radio index for vap_index: %d\n",
            __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    radio_params = get_wifidb_radio_map(radio_index);
    if (radio_params == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: failed to get radio params for radio index: %d\n",
            __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d: change channel: %d radio index: %d\n", __func__,
        __LINE__, ext->go_to_channel, radio_index);

    // make a copy so actual radio parameters are updated by channel change callback
    pthread_mutex_lock(&mgr->data_cache_lock);
    memcpy(&temp_radio_params, radio_params, sizeof(wifi_radio_operationParam_t));
    pthread_mutex_unlock(&mgr->data_cache_lock);

    temp_radio_params.channel = ext->go_to_channel;
    temp_radio_params.channelWidth = ext->go_to_channel_width;
    ret = wifi_hal_setRadioOperatingParameters(radio_index, &temp_radio_params);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: failed to set channel %d for radio index: %d\n",
            __func__, __LINE__, radio_params->channel, radio_index);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int process_ext_sta_conn_status(vap_svc_t *svc, void *arg)
{
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *temp_vap_info = NULL;
    rdk_sta_data_t *sta_data = (rdk_sta_data_t *)arg;
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;
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

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    ext->conn_retry = 0;
    if (ext->ext_conn_status_ind_timeout_handler_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_conn_status_ind_timeout_handler_id);
        ext->ext_conn_status_ind_timeout_handler_id = 0;
    }

    /* first update the internal cache */
    index = get_radio_index_for_vap_index(svc->prop, sta_data->stats.vap_index);
    wifi_util_info_print(WIFI_CTRL,"%s:%d - radio index %d, VAP index %d connect_status : %s\n",
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
                wifi_util_info_print(WIFI_CTRL, "%s:%d: received duplicated wifi_event_hal_sta_conn_status event\n", __func__, __LINE__);
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
        wifi_util_error_print(WIFI_CTRL, "%s:%d: temp_vap_info is NULL \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (sta_data->stats.connect_status == wifi_connection_status_connected) {
        if ((ext->conn_state == connection_state_connection_in_progress) ||
            (ext->conn_state == connection_state_connection_to_lcb_in_progress) ||
            (ext->conn_state == connection_state_connection_to_nb_in_progress)) {
            int radio_freq_band = 0;
            // copy the bss info to lcb
            memset(&ext->last_connected_bss, 0, sizeof(bss_candidate_t));
            memcpy(&ext->last_connected_bss.external_ap, &sta_data->bss_info, sizeof(wifi_bss_info_t));
            ext->connected_vap_index = sta_data->stats.vap_index;

            // clear new bssid since it is not used for reconnection
            memset(&ext->new_bss, 0, sizeof(bss_candidate_t));

            convert_radio_index_to_freq_band(svc->prop, index, &radio_freq_band);
            ext->last_connected_bss.radio_freq_band = (wifi_freq_bands_t)radio_freq_band;
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d - connected radio_band:%d\r\n", __func__, __LINE__, ext->last_connected_bss.radio_freq_band);

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
                process_udhcp_ip_check, svc, EXT_UDHCP_IP_CHECK_INTERVAL,
                EXT_UDHCP_IP_CHECK_NUM + 1, FALSE);

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
                    start_wifi_sched_timer(index, ctrl, wifi_radio_sched);
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
                        wifi_util_info_print(WIFI_CTRL, "%s:%d more than one sta associated, "
                            "execute sta disconnect for vap index: %d\n", __func__, __LINE__,
                            vap_map->vap_array[j].vap_index);
                        if (wifi_hal_disconnect(vap_map->vap_array[j].vap_index) == RETURN_ERR) {
                            wifi_util_error_print(WIFI_CTRL, "%s:%d sta disconnect failed for "
                                "vap index: %d\n", __func__, __LINE__,
                                vap_map->vap_array[j].vap_index);
                        }
                        break;
                    }
                }
            }
        }
    } else if (sta_data->stats.connect_status == wifi_connection_status_ap_not_found || sta_data->stats.connect_status == wifi_connection_status_disconnected) {

        apply_pending_channel_change(svc, sta_data->stats.vap_index);

        if (ext->conn_state == connection_state_connected &&
            ext->connected_vap_index != sta_data->stats.vap_index) {
            wifi_util_info_print(WIFI_CTRL, "%s:%d: vap index %d is connected and received "
                "disconnection event on vap index %d\n", __func__, __LINE__,
                ext->connected_vap_index, sta_data->stats.vap_index);
            return 0;
        }

        if (ext->ext_udhcp_ip_check_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_udhcp_ip_check_id);
            ext->ext_udhcp_ip_check_id = 0;
        }

        ext->disconn_retry = 0;
        if (ext->ext_udhcp_disconnect_event_timeout_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched,
                ext->ext_udhcp_disconnect_event_timeout_handler_id);
            ext->ext_udhcp_disconnect_event_timeout_handler_id = 0;
        }

        if (ext->ext_trigger_disconnection_timeout_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched,
                ext->ext_trigger_disconnection_timeout_handler_id);
            ext->ext_trigger_disconnection_timeout_handler_id = 0;
        }

        if (ext->ext_disconnection_event_timeout_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched,
                ext->ext_disconnection_event_timeout_handler_id);
            ext->ext_disconnection_event_timeout_handler_id = 0;
        }

        if (ext->conn_state == connection_state_connection_to_nb_in_progress) {
            candidate = &ext->new_bss;
            found_candidate = true;
        } else if ((ext->conn_state == connection_state_connection_to_lcb_in_progress) ||
                (ext->conn_state == connection_state_connected)) {

            if (ext->is_radio_ignored == true) {
                candidate = NULL;
                found_candidate = false;
                ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__,
                    __LINE__);
            } else {
                candidate = &ext->last_connected_bss;
                found_candidate = true;
                ext_set_conn_state(ext, connection_state_connection_to_lcb_in_progress, __func__,
                    __LINE__);
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
            if (found_candidate == false) {
                candidate = NULL;
            }
        } else if (ext->conn_state == connection_state_disconnection_in_progress) {
            ext_set_conn_state(ext, connection_state_connection_in_progress, __func__, __LINE__);
            candidate = ext->candidates_list.scan_list;
            found_candidate = true;
        }
    }

    if (send_event == true) {
        sprintf(name, "Device.WiFi.STA.%d.Connection.Status", index + 1);

        wifi_util_dbg_print(WIFI_CTRL, "%s:%d Rbus name: %s connection status: %s\n", __func__,
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
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: rbusEvent_Publish Event failed\n", __func__, __LINE__);

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
                        process_ext_connect_algorithm, svc,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        } else {
            //ext_try_connecting(svc);
            wifi_util_info_print(WIFI_CTRL, "%s:%d connection state: %s\r\n", __func__,
                __LINE__, ext_conn_state_to_str(ext->conn_state));
            scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, svc,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        }
    } else if((found_candidate == false) && (ext->conn_state != connection_state_connected)) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d candidate null connection state: %s\r\n",
            __func__, __LINE__, ext_conn_state_to_str(ext->conn_state));
        ext_set_conn_state(ext, connection_state_disconnected_scan_list_none, __func__, __LINE__);

        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, svc,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: candidate null connection state: %s\r\n", __func__,
            __LINE__, ext_conn_state_to_str(ext->conn_state));
    }

    return 0;
}

int process_ext_channel_change(vap_svc_t *svc, void *arg)
{
    if ((svc == NULL) || (arg == NULL)) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: NULL pointers \n", __func__, __LINE__);
        return 0;
    }
    
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;
    wifi_channel_change_event_t *ch_chg;

    ext = &svc->u.ext;
    ctrl = svc->ctrl;
    ch_chg = (wifi_channel_change_event_t *) arg;

    if (ext->conn_state == connection_state_connected_wait_for_csa) {
        if (ch_chg->channel == ext->go_to_channel) {
            wifi_util_info_print(WIFI_CTRL, "%s:%d: csa channel: %u, width: %u, radio: %u\n",
                __func__, __LINE__, ch_chg->channel, ch_chg->channelWidth, ch_chg->radioIndex);
            ext->channel_change_pending_map &= ~(1 << ext->connected_vap_index);
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_csa_wait_timeout_handler_id);
            ext->ext_csa_wait_timeout_handler_id = 0;
            ext_set_conn_state(ext, connection_state_connected, __func__, __LINE__);
            scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, svc,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1, FALSE);
        }
    }

    return 0;
}

int process_ext_hal_ind(vap_svc_t *svc, wifi_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case wifi_event_scan_results:
            process_ext_scan_results(svc, arg);
            break;

        case wifi_event_hal_sta_conn_status:
            process_ext_sta_conn_status(svc, arg);
            break;

        case wifi_event_hal_channel_change:
            process_ext_channel_change(svc, arg);
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: assert - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            assert(sub_type >= wifi_event_hal_max);
        break;
    }

    return 0;
}

int process_ext_command(vap_svc_t *svc, wifi_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case wifi_event_type_device_network_mode:
            break;

        case wifi_event_type_trigger_disconnection:
            process_ext_trigger_disconnection(svc, arg);
            break;

        case wifi_event_type_eth_bh_status:
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: assert - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            assert(sub_type >= wifi_event_command_max);
            break;
    }

    return 0;
}

int process_ext_exec(vap_svc_t *svc, wifi_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case wifi_event_exec_timeout:
            process_ext_exec_timeout(svc, arg);
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: assert - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            assert(sub_type >= wifi_event_exec_max);
            break;
    }

    return 0;
}

int process_ext_webconfig(vap_svc_t *svc, wifi_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case wifi_event_webconfig_set_data:
            process_ext_webconfig_set_data(svc, arg);
            break;

        case wifi_event_webconfig_set_data_sta_bssid:
            process_ext_webconfig_set_data_sta_bssid(svc, arg);
            break;

        default:
            break;
    }

    return 0;
}

int vap_svc_mesh_ext_event(vap_svc_t *svc, wifi_event_type_t type, wifi_event_subtype_t sub_type, vap_svc_event_t event, void *arg)
{
    switch (type) {
        case wifi_event_type_exec:
            process_ext_exec(svc, sub_type, arg);
            break;

        case wifi_event_type_command:
            process_ext_command(svc, sub_type, arg);
            break;

        case wifi_event_type_hal_ind:
            process_ext_hal_ind(svc, sub_type, arg);
            break;

        case wifi_event_type_webconfig:
            process_ext_webconfig(svc, sub_type, arg);
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: default - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            break;
    }

    return 0;
}
