#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include "stdlib.h"
#include <sys/time.h>
#include <assert.h>
#include "vap_svc.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include <rbus.h>

#define PATH_TO_RSSI_NORMALIZER_FILE "/tmp/rssi_normalizer_2_4.cfg"
#define DEFAULT_RSSI_NORMALIZER_2_4_VALUE 20

int convert_radio_index_to_freq_band(int radio_index, int *band);

int convert_radio_index_to_freq_band(int radio_index, int *band)
{
    int status = RETURN_OK;

    if (radio_index == 0) {
        *band = WIFI_FREQUENCY_2_4_BAND;
    } else if (radio_index == 1) {
        *band = WIFI_FREQUENCY_5_BAND;
    } else if (radio_index == 2) {
        *band = WIFI_FREQUENCY_6_BAND;
    }

    return status;
}

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
    else {
        wifi_util_dbg_print(WIFI_CTRL, "%s():[%d] Unable to open file \'%s\' to get RSSI normalizer value [%s]. Setting default value.\r\n", 
            __FUNCTION__, __LINE__, path_to_file, strerror(errno));
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
}

void ext_incomplete_scan_list(vap_svc_t *svc)
{
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    ext->wait_scan_result++;
    if (ext->wait_scan_result > MAX_SCAN_RESULT_WAIT) {
        ext->conn_state = connection_state_disconnected_scan_list_all;
        ext->wait_scan_result = 0;

        // schedule extender connetion algorithm
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, svc,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);
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
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, svc,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);
    }
    return 0;
}

void cancel_scan_result_timer(wifi_ctrl_t *l_ctrl, vap_svc_ext_t *l_ext)
{
    if (l_ext->ext_scan_result_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel wifi start scan timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(l_ctrl->sched, l_ext->ext_scan_result_timeout_handler_id);
        l_ext->ext_scan_result_timeout_handler_id = 0;
    }
}

void ext_start_scan(vap_svc_t *svc)
{
    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;
    unsigned int radio_index;
    wifi_channels_list_t *channels;
    wifi_mgr_t *mgr = (wifi_mgr_t *)get_wifimgr_obj();

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if (ext->conn_state != connection_state_disconnected_scan_list_none) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi_scan completed, current state:%d\r\n",__func__, __LINE__, ext->conn_state);
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

    for (radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d start Scan on radio index %u\n", __func__, __LINE__,
            radio_index);

        channels = &mgr->hal_cap.wifi_prop.radiocap[radio_index].channel_list[0];
        wifi_hal_startScan(radio_index, WIFI_RADIO_SCAN_MODE_OFFCHAN, 0, channels->num_channels,
            channels->channels_list);
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_scan_result_timeout_handler_id,
                process_scan_result_timeout, svc,
                EXT_SCAN_RESULT_TIMEOUT, 0);
}

void ext_process_scan_list(vap_svc_t *svc)
{
    vap_svc_ext_t   *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if (ext->conn_state != connection_state_connection_in_progress) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d start wifi connection:%d scan_count:%d\n",__func__, __LINE__,
                    ext->conn_state, ext->candidates_list.scan_count);
        ext->wait_scan_result = 0;
        // process scan list, arrange candidates according to policies
        if (ext->candidates_list.scan_count != 0) {
            ext->conn_state = connection_state_connection_in_progress;
        } else {
            ext->conn_state = connection_state_disconnected_scan_list_none;
        }

        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, svc,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);
    } else {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d wifi connection already in process state\n",__func__, __LINE__);
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

    if (ext->conn_state == connection_state_connection_to_lcb_in_progress) {
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
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: assert - conn_state :%d\n", __func__, __LINE__, ext->conn_state);
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

        wifi_util_dbg_print(WIFI_CTRL,"%s:%d connecting to ssid:%s bssid:%s rssi:%d frequency:%d on vap:%d radio:%d\n",
                    __func__, __LINE__, candidate->external_ap.ssid,
                    to_mac_str(candidate->external_ap.bssid, bssid_str),
                    candidate->external_ap.rssi, candidate->external_ap.freq, vap_index, radio_index);
        wifi_hal_connect(vap_index, &candidate->external_ap);
        if (ext->ext_conn_status_ind_timeout_handler_id != 0) {
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d cancel wifi connect.. vap_index:%d\r\n", __func__, __LINE__, vap_index);
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_conn_status_ind_timeout_handler_id);
            ext->ext_conn_status_ind_timeout_handler_id = 0;
        }
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_conn_status_ind_timeout_handler_id,
                process_ext_connect_algorithm, svc,
                EXT_CONN_STATUS_IND_TIMEOUT, 1);
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d Triggered wifi connect.. vap_index:%d\r\n", __func__, __LINE__, vap_index);
    } else {
        ext->conn_state = connection_state_disconnected_scan_list_none;
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                process_ext_connect_algorithm, svc,
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);
    }
}

int process_ext_connect_algorithm(vap_svc_t *svc)
{
    vap_svc_ext_t   *ext;
    ext = &svc->u.ext;

    switch (ext->conn_state) {
        case connection_state_disconnected_scan_list_none:
            ext_start_scan(svc);
            break;

        case connection_state_disconnected_scan_list_2g:
        case connection_state_disconnected_scan_list_5g:
            ext_incomplete_scan_list(svc);
            break;

        case connection_state_disconnected_scan_list_all:
            ext_process_scan_list(svc);
            break;

        case connection_state_connection_in_progress:
        case connection_state_connection_to_lcb_in_progress:
            ext_try_connecting(svc);
            break;

        case connection_state_connected:
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
                    wifi_util_info_print(WIFI_CTRL, "%s:%d: wifi disconnect :%d\n", __func__, __LINE__, vap->vap_index);
                    wifi_hal_disconnect(vap->vap_index);
                    ext->conn_state = connection_state_disconnected_scan_list_none;
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

    /* create STA vap's and install acl filters */
    vap_svc_start(svc);

    // initialize all extender specific structures
    memset(ext, 0, sizeof(vap_svc_ext_t));

    ext->conn_state = connection_state_disconnected_scan_list_none;
    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                process_ext_connect_algorithm, svc,
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);

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
    vap_svc_mesh_ext_disconnect(svc);
    cancel_all_running_timer(svc);
    vap_svc_stop(svc);
    vap_svc_mesh_ext_clear_variable(svc);
    return 0;
}

int vap_svc_mesh_ext_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map)
{
    unsigned int i;
    wifi_vap_info_map_t tgt_vap_map;
    wifi_ctrl_t *ctrl;
    vap_svc_ext_t *ext;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    for (i = 0; i < map->num_vaps; i++) {
        memset((unsigned char *)&tgt_vap_map, 0, sizeof(tgt_vap_map));
        memcpy((unsigned char *)&tgt_vap_map.vap_array[0], (unsigned char *)&map->vap_array[i],
                    sizeof(wifi_vap_info_t));
        tgt_vap_map.num_vaps = 1;

        if (wifi_hal_createVAP(radio_index, &tgt_vap_map) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,"%s: wifi vap create failure: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
            continue;
        }
        wifi_util_info_print(WIFI_CTRL,"%s: wifi vap create success: radio_index:%d vap_index:%d\n",__FUNCTION__,
                                                radio_index, map->vap_array[i].vap_index);
        memcpy((unsigned char *)&map->vap_array[i], (unsigned char *)&tgt_vap_map.vap_array[0],
                    sizeof(wifi_vap_info_t));

        wifidb_update_wifi_vap_info(getVAPName(map->vap_array[i].vap_index), &map->vap_array[i]);
        wifidb_update_wifi_security_config(getVAPName(map->vap_array[i].vap_index),
            &map->vap_array[i].u.sta_info.security);
    }

    scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                process_ext_connect_algorithm, svc,
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);

    return 0;
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
                EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);

    return 0;
}

int scan_result_wait_timeout(vap_svc_t *svc)
{
    vap_svc_ext_t *ext;
    wifi_ctrl_t *ctrl;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if ((ext->conn_state == connection_state_disconnected_scan_list_2g) ||
            (ext->conn_state == connection_state_disconnected_scan_list_5g)) {
        ext->conn_state = connection_state_disconnected_scan_list_all;
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - received only one radio scan result\r\n", __func__, __LINE__);
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, svc,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);
    }
    return 0;
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
    
    if (ext->conn_state >= connection_state_disconnected_scan_list_all) {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d Received scan resuts when already have result or connection in progress, should not happen\n",
                        __FUNCTION__,__LINE__);
        return 0;
    }

    convert_radio_index_to_freq_band(results->radio_index, (int *)&band);
    if (ext->ext_scan_result_timeout_handler_id != 0) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d - cancel wifi start scan timer\r\n", __func__, __LINE__);
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_scan_result_timeout_handler_id);
        ext->ext_scan_result_timeout_handler_id = 0;
    }

    wifi_util_dbg_print(WIFI_CTRL, "%s:%d Extender Mode num of scan results:%d, conn_state:%d\n",
                __FUNCTION__,__LINE__, num, ext->conn_state);

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
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: AP with ssid:%s, bssid:%s, rssi:%d, freq:%d\n",
                __func__, __LINE__, scan_list->external_ap.ssid, to_mac_str(scan_list->external_ap.bssid, bssid_str), scan_list->external_ap.rssi, scan_list->external_ap.freq);
        tmp_bss++;
        scan_list++;
    }

    sort_bss_results_by_rssi(ext->candidates_list.scan_list, 0, ext->candidates_list.scan_count - 1);

    if (ext->conn_state == connection_state_disconnected_scan_list_none) {
        if (band == WIFI_FREQUENCY_2_4_BAND) {
            ext->conn_state = connection_state_disconnected_scan_list_2g;
        } else if (band == WIFI_FREQUENCY_5_BAND) {
            ext->conn_state = connection_state_disconnected_scan_list_5g;
        }
    } else {
        if (band == WIFI_FREQUENCY_2_4_BAND) {
            ext->conn_state |= connection_state_disconnected_scan_list_2g;
        } else if (band == WIFI_FREQUENCY_5_BAND) {
            ext->conn_state |= connection_state_disconnected_scan_list_5g;
        }
    }

    if (ext->conn_state == connection_state_disconnected_scan_list_all) {
        if (ext->ext_scan_result_wait_timeout_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, ext->ext_scan_result_wait_timeout_handler_id);
            ext->ext_scan_result_wait_timeout_handler_id = 0;
        }
        // schedule extender connetion algorithm
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, svc,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);
    } else {
        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_scan_result_wait_timeout_handler_id,
                        scan_result_wait_timeout, svc,
                        EXT_SCAN_RESULT_WAIT_TIMEOUT, 1);
    }

    return 0;
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
    unsigned int i, index;
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    char name[64];
    wifi_sta_conn_info_t sta_conn_info;

    ctrl = svc->ctrl;
    ext = &svc->u.ext;

    if (ext->ext_conn_status_ind_timeout_handler_id != 0) {
        scheduler_cancel_timer_task(ctrl->sched, ext->ext_conn_status_ind_timeout_handler_id);
        ext->ext_conn_status_ind_timeout_handler_id = 0;
    }

    /* first update the internal cache */
    index = get_radio_index_for_vap_index(svc->prop, sta_data->stats.vap_index);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d - radio index %d, VAP index %d\n", __func__, __LINE__, index, sta_data->stats.vap_index);
    vap_map = &mgr->radio_config[index].vaps.vap_map;

    for (i = 0; i < vap_map->num_vaps; i++) {
        if (vap_map->vap_array[i].vap_index == sta_data->stats.vap_index) {
            vap_map->vap_array[i].u.sta_info.conn_status = sta_data->stats.connect_status;
            memset(vap_map->vap_array[i].u.sta_info.bssid, 0, sizeof(vap_map->vap_array[i].u.sta_info.bssid));
            temp_vap_info = &vap_map->vap_array[i];
            break;
        }
    }

    if (sta_data->stats.connect_status == wifi_connection_status_connected) {
        if ((ext->conn_state == connection_state_connection_in_progress) ||
            (ext->conn_state == connection_state_connection_to_lcb_in_progress)) {

            // copy the bss info to lcb
            memset(&ext->last_connected_bss, 0, sizeof(bss_candidate_t));
            memcpy(&ext->last_connected_bss.external_ap, &sta_data->bss_info, sizeof(wifi_bss_info_t));
            ext->connected_vap_index = sta_data->stats.vap_index;
            convert_radio_index_to_freq_band(index, (int*)&ext->last_connected_bss.radio_freq_band);
            wifi_util_dbg_print(WIFI_CTRL,"%s:%d - connected radio_band:%d\r\n", __func__, __LINE__, ext->last_connected_bss.radio_freq_band);

            // copy the bss bssid info to global chache
            if (temp_vap_info != NULL) {
                memcpy (temp_vap_info->u.sta_info.bssid, sta_data->bss_info.bssid, sizeof(temp_vap_info->u.sta_info.bssid));
            }

            // change the state
            ext->conn_state = connection_state_connected;

            // send rbus connect indication
            send_event = true;
        }
    } else if (sta_data->stats.connect_status == wifi_connection_status_ap_not_found || sta_data->stats.connect_status == wifi_connection_status_disconnected) {
        // send rbus connect indication

        if ((ext->conn_state == connection_state_connection_to_lcb_in_progress) ||
                (ext->conn_state == connection_state_connected)) {
            candidate = &ext->last_connected_bss;
            found_candidate = true;
            ext->conn_state = connection_state_connection_to_lcb_in_progress;
            send_event = true;
        } else if (ext->conn_state == connection_state_connection_in_progress) {
            candidate = ext->candidates_list.scan_list;
            for (i = 0; i < ext->candidates_list.scan_count; i++) {
                if ((candidate->conn_attempt == connection_attempt_wait) && (candidate->conn_retry_attempt < STA_MAX_CONNECT_ATTEMPT)) {
                    found_candidate = true;
                    break;
                }
                candidate++;
            }
        }
    }

    if (send_event == true) {
        sprintf(name, "Device.WiFi.STA.%d.Connection.Status", index + 1);

        wifi_util_dbg_print(WIFI_CTRL,"%s:%d Rbus name:%s:connection status:%d\r\n", __func__, __LINE__,
                    name, sta_data->stats.connect_status);

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
            return RETURN_ERR;
        }

        rbusValue_Release(value);
        rbusObject_Release(rdata);
    }

    if (candidate != NULL) {
        if ((found_candidate == false && (ext->conn_state != connection_state_connected)) ||
                ((found_candidate == true) && (candidate->conn_retry_attempt >= STA_MAX_CONNECT_ATTEMPT))) {
            wifi_util_dbg_print(WIFI_CTRL, "{%s:%d}: change state to wifi start scan: [connection state:%d]\r\n", __func__, __LINE__, ext->conn_state);
            candidate->conn_attempt = connection_attempt_failed;
            ext->conn_state = connection_state_disconnected_scan_list_none;

            scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, svc,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);
        } else {
            //ext_try_connecting(svc);
            wifi_util_dbg_print(WIFI_CTRL, "{%s:%d}: [connection state:%d]\r\n", __func__, __LINE__, ext->conn_state);
            scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                        process_ext_connect_algorithm, svc,
                        EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);
        }
    } else if((found_candidate == false) && (ext->conn_state != connection_state_connected)) {
        wifi_util_dbg_print(WIFI_CTRL, "[%s:%d]: candidate null connection state:%d\r\n", __func__, __LINE__, ext->conn_state);
        ext->conn_state = connection_state_disconnected_scan_list_none;

        scheduler_add_timer_task(ctrl->sched, FALSE, &ext->ext_connect_algo_processor_id,
                    process_ext_connect_algorithm, svc,
                    EXT_CONNECT_ALGO_PROCESSOR_INTERVAL, 1);
    } else {
        wifi_util_dbg_print(WIFI_CTRL, "%s:%d: candidate null connection state:%d\r\n", __func__, __LINE__, ext->conn_state);
    }

    return 0;
}

int process_ext_hal_ind(vap_svc_t *svc, ctrl_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case ctrl_event_scan_results:
            process_ext_scan_results(svc, arg);
            break;

        case ctrl_event_hal_sta_conn_status:
            process_ext_sta_conn_status(svc, arg);
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: assert - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            assert(sub_type >= ctrl_event_hal_max);
        break;
    }

    return 0;
}

int process_ext_command(vap_svc_t *svc, ctrl_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case ctrl_event_type_device_network_mode:
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: assert - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            assert(sub_type >= ctrl_event_command_max);
            break;
    }

    return 0;
}

int process_ext_exec(vap_svc_t *svc, ctrl_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case ctrl_event_exec_timeout:
            process_ext_exec_timeout(svc, arg);
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: assert - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            assert(sub_type >= ctrl_event_exec_max);
            break;
    }

    return 0;
}

int vap_svc_mesh_ext_event(vap_svc_t *svc, ctrl_event_type_t type, ctrl_event_subtype_t sub_type, vap_svc_event_t event, void *arg)
{
    switch (type) {
        case ctrl_event_type_exec:
            process_ext_exec(svc, sub_type, arg);
            break;

        case ctrl_event_type_command:
            process_ext_command(svc, sub_type, arg);
            break;

        case ctrl_event_type_hal_ind:
            process_ext_hal_ind(svc, sub_type, arg);
            break;

        default:
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d: default - sub_type:%d\r\n", __func__, __LINE__, sub_type);
            break;
    }

    return 0;
}
