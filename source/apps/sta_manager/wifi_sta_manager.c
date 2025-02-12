#include "stdlib.h"
#include "wifi_ctrl.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_monitor.h"
#include "wifi_util.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include "common/ieee802_11_defs.h"
#include "wifi_sta_manager.h"

static int send_action_frame(sta_data_ts *sched_data)
{
    char client_mac[32];
    unsigned int ap_index = sched_data->ap_index;
    wifi_BeaconRequest_t *beacon_req = calloc(1, sizeof(wifi_BeaconRequest_t));
    to_mac_str((unsigned char *)sched_data->mac_addr, client_mac);
    wifi_util_info_print(WIFI_APPS, "%s:%d: Sending action frame for mac %s\n", __func__, __LINE__,
        client_mac);
    unsigned int radio_index = get_radio_index_for_vap_index(
        &(get_wifimgr_obj())->hal_cap.wifi_prop, ap_index);
    wifi_radio_operationParam_t *radio_oper_param =
        (wifi_radio_operationParam_t *)get_wifidb_radio_map(radio_index);
    ;
    if (radio_oper_param == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return 0;
    }

    unsigned int op_class;
    char country[8] = { 0 };

    if (RETURN_OK != get_coutry_str_from_code(radio_oper_param->countryCode, country)) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    op_class = radio_oper_param->op_class;
    unsigned int global_op_class = country_to_global_op_class(country, op_class);
    wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
    beacon_req->channel = radio_oper_param->channel;
    beacon_req->opClass = global_op_class;
    beacon_req->duration = 100;
    beacon_req->mode = 0;
    UCHAR out_dialog = 0;
    wifi_hal_setRMBeaconRequest(ap_index, sched_data->mac_addr, beacon_req, &out_dialog);
    sched_data->dialog_token = out_dialog;
    wifi_util_info_print(WIFI_APPS, "%s:%d: dialogue token is %d\n", __func__, __LINE__,
        out_dialog);
    free(beacon_req);
    return 0;
}

// Construct request for neighbor report.
static int push_request_to_monitor_queue(unsigned int ap_index,
    wifi_mon_stats_request_state_t state, uint8_t channel)
{
    wifi_monitor_data_t *data;
    wifi_event_route_t route;

    data = (wifi_monitor_data_t *)malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d data allocation failed\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(data, 0, sizeof(wifi_monitor_data_t));

    unsigned int radio_index = get_radio_index_for_vap_index(
        &(get_wifimgr_obj())->hal_cap.wifi_prop, ap_index);
    data->u.mon_stats_config.req_state = state;
    data->u.mon_stats_config.inst = wifi_app_inst_sta_mgr;
    data->u.mon_stats_config.args.radio_index = radio_index;
    wifi_util_error_print(WIFI_APPS, "%s:%d connected on radio_index %d vap_index %d\n", __func__,
        __LINE__, radio_index, ap_index);
    data->u.mon_stats_config.args.vap_index = ap_index;

    data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_ONCHAN;
    data->u.mon_stats_config.args.channel_list.num_channels = 0;
    data->u.mon_stats_config.args.channel_list.channels_list[0] = channel;

    if (data->u.mon_stats_config.interval_ms == 0) {
        data->u.mon_stats_config.interval_ms = 10 * 1000; // converting seconds to ms
    }

    data->u.mon_stats_config.args.app_info = sta_app_event_type_neighbor;
    data->u.mon_stats_config.start_immediately = true;
    data->u.mon_stats_config.req_state = state;
    data->u.mon_stats_config.delay_provider_sec = 5;
    data->u.mon_stats_config.data_type = mon_stats_type_neighbor_stats;
    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);

    return RETURN_OK;
}

// handle disassoc event
int handle_disassoc_device(wifi_app_t *app, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;
    char client_mac[32];
    mac_addr_str_t key;

    if (ctrl->network_mode == rdk_dev_mode_type_gw) {
        wifi_util_info_print(WIFI_APPS, "%s:%d : Got disassoc event \n", __func__, __LINE__);
        to_mac_str((unsigned char *)assoc_data->dev_stats.cli_MACAddress, client_mac);
        sta_data_ts *t_sta_data = (sta_data_ts *)hash_map_remove(
            app->data.u.sta_mgr.sta_mgr_map, client_mac);
        if (t_sta_data == NULL) {
            wifi_util_info_print(WIFI_APPS, "%s:%d: Mac %s not present in hash map\n", __func__,
                __LINE__, client_mac);
            return 0;
        }

        if (t_sta_data->bR_map != NULL) {
            bR_data_t *bR_data = (bR_data_t *)hash_map_get_first(t_sta_data->bR_map);
            while (bR_data != NULL) {
                to_mac_str(bR_data->bssid, key);
                bR_data = (bR_data_t *)hash_map_get_next(t_sta_data->bR_map, bR_data);
                bR_data_t *tmp_bR_data = (bR_data_t *)hash_map_remove(t_sta_data->bR_map, key);
                free(tmp_bR_data);
            }
        }

        if (t_sta_data->sched_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, t_sta_data->sched_handler_id);
            t_sta_data->sched_handler_id = 0;
        }
        free(t_sta_data);
    }
    return 0;
}

// handle assoc_device
int handle_assoc_device(wifi_app_t *app, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d : Got assoc event \n", __func__, __LINE__);
    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;
    char client_mac[32];

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);
    // Schedule onlyfor gw mode
    if (ctrl->network_mode == rdk_dev_mode_type_gw) {

        if (hash_map_get(app->data.u.sta_mgr.sta_mgr_map, client_mac) == NULL) {
            sta_data_ts *t_sta_data = (sta_data_ts *)malloc(sizeof(sta_data_ts));
            memset(t_sta_data, 0, sizeof(sta_data_ts));

            to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);
            memcpy(t_sta_data->mac_addr, assoc_data->dev_stats.cli_MACAddress,
                sizeof(mac_address_t));

            t_sta_data->ap_index = assoc_data->ap_index;
            wifi_util_info_print(WIFI_APPS, "%s:%d : Scheduling frame push for %s \n", __func__,
                __LINE__, client_mac);
            scheduler_add_timer_task(ctrl->sched, FALSE, &(t_sta_data->sched_handler_id),
                send_action_frame, t_sta_data, 2000, 0, FALSE);
            t_sta_data->bR_map = hash_map_create();
            hash_map_put(app->data.u.sta_mgr.sta_mgr_map, strdup(client_mac), t_sta_data);
        }
    }
    return 0;
}

typedef struct {
    unsigned int vapIndex;
    wifi_connection_status_t conn_status;
} sta_conn_state_t;

sta_conn_state_t g_sta_conn_state;
int handle_sta_conn_status(wifi_app_t *app, void *arg)
{
    if (!arg) {
        wifi_util_info_print(WIFI_APPS, "%s:%d : NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d : Inside  \n", __func__, __LINE__);
    rdk_sta_data_t *sta_data = (rdk_sta_data_t *)arg;
    if (sta_data->stats.connect_status == wifi_connection_status_connected) {
        g_sta_conn_state.conn_status = wifi_connection_status_connected;
        g_sta_conn_state.vapIndex = sta_data->stats.vap_index;
    } else if (sta_data->stats.connect_status == wifi_connection_status_disconnected) {
        g_sta_conn_state.conn_status = wifi_connection_status_disconnected;
        push_request_to_monitor_queue(g_sta_conn_state.vapIndex, mon_stats_request_state_stop, 0);
    }

    return 0;
}

typedef struct {
    unsigned char dialog_token;
    size_t size;
    wifi_BeaconReport_t *beacon_repo;
} wifi_hal_rrm_report_t;

void remove_bR_report(sta_data_ts *p_data)
{
    mac_addr_str_t key;
    if (p_data == NULL) {
        wifi_util_info_print(WIFI_APPS, "%s:%d : NULL pointer \n", __func__, __LINE__);
        return;
    }
    if (p_data->bR_map != NULL) {
        bR_data_t *bR_data = (bR_data_t *)hash_map_get_first(p_data->bR_map);
        while (bR_data != NULL) {
            to_mac_str(bR_data->bssid, key);
            bR_data = (bR_data_t *)hash_map_get_next(p_data->bR_map, bR_data);
            bR_data_t *tmp_bR_data = (bR_data_t *)hash_map_remove(p_data->bR_map, key);
            free(tmp_bR_data);
        }
    }
}

int publish_data(sta_data_ts *p_data)
{
    webconfig_subdoc_data_t *data;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_mgr_t *mgr = get_wifimgr_obj();
    data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS,
            "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", __func__,
            sizeof(webconfig_subdoc_data_t));
        return -1;
    }
    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    data->u.decoded.stamgr = *p_data;
    data->u.decoded.hal_cap = mgr->hal_cap;
    if (webconfig_encode(&ctrl->webconfig, data, webconfig_subdoc_type_sta_manager) ==
        webconfig_error_none) {
        wifi_util_info_print(WIFI_APPS, "%s: sta_manager encoded successfully  \n", __FUNCTION__);
        // push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig,
        // wifi_event_webconfig_set_data_dml, NULL);
    } else {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
        if (data != NULL) {
            free(data);
        }
        return -1;
    }

    return 0;
}

int process_beacon_rep(mac_address_t bssid, wifi_hal_rrm_report_t *rep, wifi_app_t *app)
{
    wifi_BeaconReport_t *data = rep->beacon_repo;
    mac_addr_str_t r_bssid, key;
    to_mac_str(bssid, key);
    sta_data_ts *p_data = (sta_data_ts *)hash_map_get(app->data.u.sta_mgr.sta_mgr_map, key);
    remove_bR_report(p_data);
    for (size_t itr = 0; itr < rep->size; itr++) {
        if (p_data != NULL) {
            to_mac_str(data->bssid, r_bssid);
            bR_data_t *bR_data = (bR_data_t *)malloc(sizeof(bR_data_t));
            memcpy(bR_data->bssid, data->bssid, ETH_ALEN);
            bR_data->op_class = data->opClass;
            bR_data->channel = data->channel;
            bR_data->rcpi = data->rcpi;
            bR_data->rssi = data->rsni;
            hash_map_put(p_data->bR_map, strdup(r_bssid), bR_data);
        } else {
            return -1;
        }
            data++;
    }
    publish_data(p_data);
    return 0;
}

int handle_mgmt_frame(wifi_app_t *apps, void *arg)
{
    frame_data_t *mgmt_frame = (frame_data_t *)arg;
    wifi_hal_rrm_request_t req;
    wifi_hal_rrm_report_t rep;
    mac_address_t mac_addr;
    mac_addr_str_t key;

    const struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)mgmt_frame->data;
    size_t len = mgmt_frame->frame.len;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    memcpy(mac_addr, mgmt->sa, ETH_ALEN);
    wifi_util_info_print(WIFI_APPS, "%s:%d: mgmt is %s\n", __func__, __LINE__,
        to_mac_str(mac_addr, key));
    if (mgmt->u.action.u.rrm.action == WLAN_RRM_RADIO_MEASUREMENT_REPORT) {
        if (ctrl->network_mode == rdk_dev_mode_type_gw) {
            wifi_hal_parse_rm_beaon_report(mgmt_frame->frame.ap_index, mgmt, len, &rep);
            process_beacon_rep(mac_addr, &rep, apps);
        }
    } else if (mgmt->u.action.u.rrm.action == WLAN_RRM_RADIO_MEASUREMENT_REQUEST) {

        if (ctrl->network_mode != rdk_dev_mode_type_gw) {
            wifi_hal_parse_rm_beacon_request(mgmt_frame->frame.ap_index, mgmt, len, &req);
            wifi_util_info_print(WIFI_APPS, "%s:%d: got duration as %d %d %d %d\n", __func__,
                __LINE__, req.duration, req.op_class, req.duration_mandatory, req.dialog_token);
            push_request_to_monitor_queue(mgmt_frame->frame.ap_index, mon_stats_request_state_start,
                req.channel);
        }
    }
    return 0;
}

int hal_event_sta_mgr(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d: event handled[%d]\r\n", __func__, __LINE__, sub_type);
    switch (sub_type) {
    case wifi_event_hal_unknown_frame:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_unknown_frame \n", __func__,
            __LINE__);
        break;
    case wifi_event_hal_dpp_public_action_frame:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_mgmt_frames \n", __func__, __LINE__);
        handle_mgmt_frame(apps, arg);
        break;
    case wifi_event_hal_probe_req_frame:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_probe_req_frame \n", __func__,
            __LINE__);
        break;
    case wifi_event_hal_auth_frame:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_auth_frame \n", __func__, __LINE__);
        break;
    case wifi_event_hal_assoc_req_frame:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_assoc_req_frame \n", __func__,
            __LINE__);
        break;
    case wifi_event_hal_assoc_rsp_frame:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_assoc_rsp_frame \n", __func__,
            __LINE__);
        break;
    case wifi_event_hal_reassoc_req_frame:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_reassoc_req_frame \n", __func__,
            __LINE__);
        break;
    case wifi_event_hal_reassoc_rsp_frame:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_reassoc_rsp_frame \n", __func__,
            __LINE__);
        break;
    case wifi_event_hal_sta_conn_status:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_sta_conn_status \n", __func__,
            __LINE__);
        // start_neigh_stats_collect(apps, arg);
        break;
    case wifi_event_hal_assoc_device:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_assoc_device \n", __func__,
            __LINE__);
        handle_assoc_device(apps, arg);
        break;
    case wifi_event_hal_disassoc_device:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_disassoc_device \n", __func__,
            __LINE__);
        handle_disassoc_device(apps, arg);
        break;
    case wifi_event_scan_results:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_scan_results \n", __func__, __LINE__);
        break;
    case wifi_event_hal_channel_change:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_channel_change \n", __func__,
            __LINE__);
        break;
    default:
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
        break;
    }

    return RETURN_OK;
}

static int neighbor_response(wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0, vap_index = 0;
    radio_index = provider_response->args.radio_index;
    vap_index = provider_response->args.vap_index;
    wifi_neighbor_ap2_t *neighbor_ap = NULL;

    neighbor_ap = (wifi_neighbor_ap2_t *)provider_response->stat_pointer;
    wifi_util_dbg_print(WIFI_APPS, "%s:%d: radio_index : %d stats_array_size : %d\r\n", __func__,
        __LINE__, radio_index, provider_response->stat_array_size);

    if (provider_response->stat_array_size > 0) {
        wifi_rrm_send_beacon_resp(vap_index, neighbor_ap, 1, 74,
            provider_response->stat_array_size);
    }
    push_request_to_monitor_queue(vap_index, mon_stats_request_state_stop, 0);
    return RETURN_OK;
}

static int handle_monitor_provider_response(wifi_app_t *app, wifi_event_t *event)
{
    wifi_provider_response_t *provider_response;
    provider_response = (wifi_provider_response_t *)event->u.provider_response;
    int ret = RETURN_ERR;

    if (provider_response == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: input event is NULL\r\n", __func__, __LINE__);
        return ret;
    }

    switch (provider_response->args.app_info) {
    case sta_app_event_type_neighbor:
        ret = neighbor_response(provider_response);
        break;
    default:
        wifi_util_error_print(WIFI_APPS, "%s:%d: event not handle[%d]\r\n", __func__, __LINE__,
            provider_response->args.app_info);
        break;
    }

    return ret;
}

int monitor_event_sta_manager(wifi_app_t *app, wifi_event_t *event)
{
    int ret = RETURN_ERR;

    if (event == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: input event is NULL\r\n", __func__, __LINE__);
        return ret;
    }

    switch (event->sub_type) {
    case wifi_event_monitor_provider_response:
        ret = handle_monitor_provider_response(app, event);
        break;
    default:
        wifi_util_error_print(WIFI_APPS, "%s:%d: event not handle[%d]\r\n", __func__, __LINE__,
            event->sub_type);
        break;
    }

    return ret;
}

int sta_mgr_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
    case wifi_event_type_hal_ind:
        hal_event_sta_mgr(app, event->sub_type, event->u.core_data.msg);
        break;

    case wifi_event_type_monitor:
        monitor_event_sta_manager(app, event);
        break;
    default:
        break;
    }

    return RETURN_OK;
}

int sta_mgr_init(wifi_app_t *app, unsigned int create_flag)
{

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: Init frame mgmt\n", __func__, __LINE__);

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_apps_mgr_t *apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (ctrl->network_mode == rdk_dev_mode_type_gw) {
        app->data.u.sta_mgr.sta_mgr_map = hash_map_create();
    }
    return 0;
}

int sta_mgr_deinit(wifi_app_t *app)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d: Called deinit\n", __func__, __LINE__);
    void *tmp_data = NULL;
    mac_addr_str_t mac_str;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (ctrl->network_mode == rdk_dev_mode_type_gw) {
        sta_data_ts *t_sta_data = (sta_data_ts *)hash_map_get_first(
            app->data.u.sta_mgr.sta_mgr_map);
        while (t_sta_data != NULL) {
            memset(mac_str, 0, sizeof(mac_addr_str_t));
            if (t_sta_data->sched_handler_id != 0) {
                scheduler_cancel_timer_task(ctrl->sched, t_sta_data->sched_handler_id);
                t_sta_data->sched_handler_id = 0;
            }
            to_mac_str((unsigned char *)t_sta_data->mac_addr, mac_str);
            tmp_data = (sta_data_ts *)hash_map_remove(app->data.u.sta_mgr.sta_mgr_map, mac_str);
            if (tmp_data != NULL) {
                free(tmp_data);
            }
            t_sta_data = hash_map_get_next(app->data.u.sta_mgr.sta_mgr_map, t_sta_data);
        }
        hash_map_destroy(app->data.u.sta_mgr.sta_mgr_map);
    }

    return 0;
}
