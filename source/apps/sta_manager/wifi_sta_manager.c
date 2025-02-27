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
#include "wifi_sta_manager.h"
#include "common/ieee802_11_defs.h"

#if TEST_CODE
//TODO: Test Data, remove later
unsigned int g_sched_id;
#endif

static int sta_mgr_send_action_frame(sta_beacon_report_reponse_t *sched_data)
{
    unsigned int op_class;
    char country[8] = { 0 };
    char client_mac[32];
    unsigned int global_op_class;
    UCHAR out_dialog = 0;
    unsigned int ap_index = sched_data->ap_index;

    wifi_BeaconRequest_t *beacon_req = calloc(1, sizeof(wifi_BeaconRequest_t));
    to_mac_str((unsigned char *)sched_data->mac_addr, client_mac);
    wifi_util_dbg_print(WIFI_APPS, "%s:%d: Sending action frame for mac %s\n", __func__, __LINE__,
        client_mac);
    unsigned int radio_index = get_radio_index_for_vap_index(
        &(get_wifimgr_obj())->hal_cap.wifi_prop, ap_index);
    wifi_radio_operationParam_t *radio_oper_param =
        (wifi_radio_operationParam_t *)get_wifidb_radio_map(radio_index);

    if (radio_oper_param == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Unable to get radio params\n", __func__, __LINE__);
        return 0;
    }

    if (RETURN_OK != get_coutry_str_from_code(radio_oper_param->countryCode, country)) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Unable to read country code\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    op_class = radio_oper_param->op_class;
    global_op_class = country_to_global_op_class(country, op_class);
    beacon_req->channel = radio_oper_param->channel;
    beacon_req->opClass = global_op_class;
    beacon_req->duration = 100;
    beacon_req->mode = 0;
    wifi_hal_setRMBeaconRequest(ap_index, sched_data->mac_addr, beacon_req, &out_dialog);
    sched_data->dialog_token = out_dialog;
    wifi_util_dbg_print(WIFI_APPS, "%s:%d: dialogue token is %d\n", __func__, __LINE__, out_dialog);
    free(beacon_req);
    return 0;
}

// Construct request for neighbor report.
static int sta_mgr_push_request_to_monitor_queue(unsigned int ap_index,
    wifi_mon_stats_request_state_t state, uint8_t channel)
{
    wifi_monitor_data_t *data;
    wifi_event_route_t route;
    unsigned int radio_index;

    data = (wifi_monitor_data_t *)malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d data allocation failed\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(data, 0, sizeof(wifi_monitor_data_t));

    radio_index = get_radio_index_for_vap_index(&(get_wifimgr_obj())->hal_cap.wifi_prop, ap_index);
    data->u.mon_stats_config.req_state = state;
    data->u.mon_stats_config.inst = wifi_app_inst_sta_mgr;
    data->u.mon_stats_config.args.radio_index = radio_index;
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
    wifi_util_dbg_print(WIFI_APPS, "%s:%d connected on radio_index %d vap_index %d\n", __func__,
        __LINE__, radio_index, ap_index);
    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);

    return RETURN_OK;
}

// handle disassoc event
static int sta_mgr_handle_disassoc_device(wifi_app_t *app, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;
    char client_mac[32];

    if (ctrl->network_mode == rdk_dev_mode_type_gw || ctrl->network_mode == rdk_dev_mode_type_em_colocated_node ||
        ctrl->network_mode == rdk_dev_mode_type_em_node) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d : Got disassoc event \n", __func__, __LINE__);
        to_mac_str((unsigned char *)assoc_data->dev_stats.cli_MACAddress, client_mac);
        sta_beacon_report_reponse_t *t_sta_data = (sta_beacon_report_reponse_t *)hash_map_remove(
            app->data.u.sta_mgr.sta_mgr_map, client_mac);
        if (t_sta_data == NULL) {
            wifi_util_error_print(WIFI_APPS, "%s:%d: Mac %s not present in hash map\n", __func__,
                __LINE__, client_mac);
            return 0;
        }
        if (t_sta_data->sched_handler_id != 0) {
            scheduler_cancel_timer_task(ctrl->sched, t_sta_data->sched_handler_id);
            t_sta_data->sched_handler_id = 0;
        }
        free(t_sta_data);
    }
    return 0;
}

bool sta_mgr_is_marker_present()
{
    return true;
}

// handle assoc_device
static int sta_mgr_handle_assoc_device(wifi_app_t *app, void *arg)
{
    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;
    char client_mac[32];
    unsigned int interval;

    wifi_util_dbg_print(WIFI_APPS, "%s:%d : Got assoc event \n", __func__, __LINE__);
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);
    // Schedule onlyfor gw mode
    if ((ctrl->network_mode == rdk_dev_mode_type_gw || ctrl->network_mode == rdk_dev_mode_type_em_colocated_node ||
        ctrl->network_mode == rdk_dev_mode_type_em_node) && (sta_mgr_is_marker_present())) {

        if (hash_map_get(app->data.u.sta_mgr.sta_mgr_map, client_mac) == NULL) {
            sta_beacon_report_reponse_t *t_sta_data = (sta_beacon_report_reponse_t *)malloc(
                sizeof(sta_beacon_report_reponse_t));
            memset(t_sta_data, 0, sizeof(sta_beacon_report_reponse_t));

            to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);
            memcpy(t_sta_data->mac_addr, assoc_data->dev_stats.cli_MACAddress,
                sizeof(mac_address_t));

            t_sta_data->ap_index = assoc_data->ap_index;
            wifi_util_dbg_print(WIFI_APPS, "%s:%d : Scheduling frame push for %s \n", __func__,
                __LINE__, client_mac);

            if (app->data.u.sta_mgr.ap_metrics_policy.interval < 0) {
                interval = 10;
            } else {
                interval = app->data.u.sta_mgr.ap_metrics_policy.interval;
            }
            scheduler_add_timer_task(ctrl->sched, FALSE, &(t_sta_data->sched_handler_id),
                sta_mgr_send_action_frame, t_sta_data, (interval * 1000), 0, FALSE);
            hash_map_put(app->data.u.sta_mgr.sta_mgr_map, strdup(client_mac), t_sta_data);
        }
    }
    return 0;
}

// For Station Mode
#if 0
typedef struct {
    unsigned int vapIndex;
    wifi_connection_status_t conn_status;
} sta_conn_state_t;

sta_conn_state_t g_sta_conn_state;
int sta_mgr_handle_sta_conn_status(wifi_app_t *app, void *arg)
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
        sta_mgr_push_request_to_monitor_queue(g_sta_conn_state.vapIndex, mon_stats_request_state_stop, 0);
    }

    return 0;
}

typedef struct {
    unsigned char dialog_token;
    size_t size;
    wifi_BeaconReport_t *beacon_repo;
} wifi_hal_rrm_report_t;
#endif

void sta_mgr_remove_br_report(sta_beacon_report_reponse_t *p_data)
{
    if (p_data == NULL) {
        wifi_util_info_print(WIFI_APPS, "%s:%d : NULL pointer \n", __func__, __LINE__);
        return;
    }

    memset(p_data->data, 0, sizeof(p_data->data));
    return;
}
#if TEST_ENCODE
// test Code.
int publish_data(sta_beacon_report_reponse_t *p_data)
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
    } else {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
        if (data != NULL) {
            free(data);
        }
        return -1;
    }
    const char *str = data->u.encoded.raw;
    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    data->u.decoded.hal_cap = mgr->hal_cap;
    if (webconfig_decode(&ctrl->webconfig, data, str) == webconfig_error_none) {
        wifi_util_info_print(WIFI_APPS, "%s:%d data->u.decoded.stamgr %d\n", __func__, __LINE__,
            data->u.decoded.stamgr.num_br_data);
    }
    return 0;
}
#endif

static int sta_mgr_process_beacon_rep(mac_address_t bssid, wifi_hal_rrm_report_t *rep,
    wifi_app_t *app, const struct ieee80211_mgmt *mgmt, size_t len)
{
    mac_addr_str_t key;
    sta_beacon_report_reponse_t *p_data = NULL;

    to_mac_str(bssid, key);
    p_data = (sta_beacon_report_reponse_t *)hash_map_get(app->data.u.sta_mgr.sta_mgr_map, key);
    if (p_data == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d Unknown client\n", __func__, __LINE__);
        return -1;
    }
    sta_mgr_remove_br_report(p_data);
    p_data->num_br_data = rep->size;

    p_data->data_len = len - IEEE80211_HDRLEN - 1 - sizeof(mgmt->u.action.u.rrm);
    memcpy(p_data->data, mgmt->u.action.u.rrm.variable, p_data->data_len);
    push_event_to_ctrl_queue(p_data, sizeof(sta_beacon_report_reponse_t), wifi_event_type_hal_ind,
        wifi_event_br_report, NULL);
#if TEST_ENCODE
    // to be removed
    publish_data(p_data);
#endif
    return 0;
}

static int sta_mgr_handle_action_frame(wifi_app_t *apps, void *arg)
{
    frame_data_t *mgmt_frame = (frame_data_t *)arg;
    wifi_hal_rrm_request_t req;
    wifi_hal_rrm_report_t rep;
    mac_address_t mac_addr;

    const struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)mgmt_frame->data;
    size_t len = mgmt_frame->frame.len;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (len <= 32) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d Invalid Beacon Report Not processing\n", __func__,
            __LINE__);
        return -1;
    }

    memcpy(mac_addr, mgmt->sa, ETH_ALEN);
    wifi_util_dbg_print(WIFI_APPS,
                "%s:%d: rrm.action:%d, mode:%d\n", __func__, __LINE__, mgmt->u.action.u.rrm.action, ctrl->network_mode);
    if (mgmt->u.action.u.rrm.action == WLAN_RRM_RADIO_MEASUREMENT_REPORT) {
        if (ctrl->network_mode == rdk_dev_mode_type_gw || ctrl->network_mode == rdk_dev_mode_type_em_colocated_node ||
        ctrl->network_mode == rdk_dev_mode_type_em_node) {
            if (wifi_hal_parse_rm_beaon_report(mgmt_frame->frame.ap_index, mgmt, len, &rep) ==
                RETURN_OK) {
                if (rep.size <= 5) {
                    sta_mgr_process_beacon_rep(mac_addr, &rep, apps, mgmt, len);
                }
            }
        }
    } else if (mgmt->u.action.u.rrm.action == WLAN_RRM_RADIO_MEASUREMENT_REQUEST) {

        if (ctrl->network_mode != rdk_dev_mode_type_gw && ctrl->network_mode != rdk_dev_mode_type_em_colocated_node &&
        ctrl->network_mode != rdk_dev_mode_type_em_node) {
            wifi_hal_parse_rm_beacon_request(mgmt_frame->frame.ap_index, mgmt, len, &req);
            wifi_util_dbg_print(WIFI_APPS,
                "%s:%d: got duration  %d  op_class %d  duration_mandatory %d dialog_token %d\n",
                __func__, __LINE__, req.duration, req.op_class, req.duration_mandatory,
                req.dialog_token);
            sta_mgr_push_request_to_monitor_queue(mgmt_frame->frame.ap_index,
                mon_stats_request_state_start, req.channel);
        }
    }
    return 0;
}

int sta_mgr_hal_event_sta_mgr(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
    case wifi_event_hal_dpp_public_action_frame:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_dpp_public_action_frame.\n", __func__,
            __LINE__);
        sta_mgr_handle_action_frame(apps, arg);
        break;
    case wifi_event_hal_assoc_device:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_assoc_device \n", __func__,
            __LINE__);
        sta_mgr_handle_assoc_device(apps, arg);
        break;
    case wifi_event_hal_disassoc_device:
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_disassoc_device \n", __func__,
            __LINE__);
        sta_mgr_handle_disassoc_device(apps, arg);
        break;
    default:
        wifi_util_info_print(WIFI_APPS, "%s:%d: sub_type:%d.\n", __func__,
            __LINE__, sub_type);
        break;
    }

    return RETURN_OK;
}

static int sta_mgr_neighbor_response(wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0, vap_index = 0;
    wifi_neighbor_ap2_t *neighbor_ap = NULL;

    radio_index = provider_response->args.radio_index;
    vap_index = provider_response->args.vap_index;

    neighbor_ap = (wifi_neighbor_ap2_t *)provider_response->stat_pointer;
    wifi_util_dbg_print(WIFI_APPS, "%s:%d: radio_index : %d stats_array_size : %d\r\n", __func__,
        __LINE__, radio_index, provider_response->stat_array_size);

    if (provider_response->stat_array_size > 0) {
        wifi_rrm_send_beacon_resp(vap_index, neighbor_ap, 1, 74,
            provider_response->stat_array_size);
    }
    sta_mgr_push_request_to_monitor_queue(vap_index, mon_stats_request_state_stop, 0);
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
        ret = sta_mgr_neighbor_response(provider_response);
        break;
    default:
        break;
    }

    return ret;
}

int sta_mgr_monitor_event(wifi_app_t *app, wifi_event_t *event)
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
        break;
    }

    return ret;
}

static void sta_mgr_req_kick_all_macs()
{
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    rdk_wifi_radio_t *radio;
    char tmp_str[120];
    unsigned i, j;

    wifi_util_info_print(WIFI_APPS, "%s:%d: Request to kick all clients\n", __func__, __LINE__);
    for (i = 0; i < getNumberRadios(); i++) {
        radio = find_radio_config_by_index(i);
        if (radio == NULL) {
            wifi_util_error_print(WIFI_APPS, "%s:%d: NULL Pointer\n", __func__, __LINE__);
            return;
        }
        vap_map = &radio->vaps.vap_map;
        if (!vap_map)
            continue;
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            vap = &vap_map->vap_array[j];
            if (!vap)
                continue;
            memset(tmp_str, 0, sizeof(tmp_str));
            snprintf(tmp_str, sizeof(tmp_str), "%d-ff:ff:ff:ff:ff:ff-0", vap->vap_index);
            push_event_to_ctrl_queue(tmp_str, (strlen(tmp_str) + 1), wifi_event_type_command,
                wifi_event_type_command_kick_assoc_devices, NULL);
        }
    }
    return;
}

static int handle_em_config_event(wifi_app_t *app, wifi_event_t *arg)
{
    em_config_t *em_config;
    wifi_event_t *event = NULL;
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;
    webconfig_subdoc_data_t *doc;

    if (!arg) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return -1;
    }

    event = arg;
    doc = (webconfig_subdoc_data_t *)event->u.webconfig_data;
    decoded_params = &doc->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Decoded data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    switch (doc->type) {
    case webconfig_subdoc_type_em_config:
        em_config = &decoded_params->em_config;
        if (em_config == NULL) {
            wifi_util_error_print(WIFI_APPS, "%s:%d NULL pointer \n", __func__, __LINE__);
            return RETURN_ERR;
        }

        wifi_util_info_print(WIFI_APPS, "%s:%d Received config Interval as %d and string as %s\n",
            __func__, __LINE__, em_config->ap_metric_policy.interval,
            em_config->ap_metric_policy.managed_client_marker);

        app->data.u.sta_mgr.ap_metrics_policy.interval = em_config->ap_metric_policy.interval;
        strncpy(app->data.u.sta_mgr.ap_metrics_policy.managed_client_marker,
            em_config->ap_metric_policy.managed_client_marker, sizeof(marker_name));
        sta_mgr_req_kick_all_macs();
        break;
    default:
        break;
    }

    return RETURN_OK;
}

static int sta_mgr_webconfig_event(wifi_app_t *app, wifi_event_t *event)
{
    int ret = RETURN_ERR;
    if (event == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: input event is NULL\r\n", __func__, __LINE__);
        return ret;
    }

    switch (event->sub_type) {
    case wifi_event_webconfig_set_data_ovsm:
        ret = handle_em_config_event(app, event);
        break;
    default:
        break;
    }

    return ret;
}

int sta_mgr_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
    case wifi_event_type_hal_ind:
        sta_mgr_hal_event_sta_mgr(app, event->sub_type, event->u.core_data.msg);
        break;
    case wifi_event_type_monitor:
        sta_mgr_monitor_event(app, event);
        break;
    case wifi_event_type_webconfig:
        sta_mgr_webconfig_event(app, event);
        break;
    default:
        break;
    }

    return RETURN_OK;
}

#if TEST_CODE
//TODO: Test Data, remove later
//Please replace with associated bssid and sta
unsigned char binaryData[] = {
        0x27, 0x39, 0x01, 0x00, 0x05, 0x01, 0x24, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x58, 0xbe, 0xd4, 0x52, 0xee, 0x0e,
        0x11, 0xcb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x53,
        0x4b, 0x59, 0x37, 0x39, 0x42, 0x35, 0x37, 0x02,
        0x02, 0x01, 0x80, 0x27, 0x39, 0x01, 0x00, 0x05,
        0x01, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0xc6, 0xd8,// d8:3a:dd:f1:6a:b1
        0x3a, 0xdd, 0xf1, 0x6a, 0xb1, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x08, 0x53, 0x4b, 0x59, 0x51, 0x5a, 0x52,
        0x39, 0x4a, 0x02, 0x02, 0x01, 0x80, 0x27, 0x39,
        0x01, 0x00, 0x05, 0x01, 0x24, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x86, 0xd5, 0xa0, 0xbd, 0xcd, 0xfe, 0x3a, 0x85,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x16, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x08, 0x53, 0x4b, 0x59,
        0x4e, 0x49, 0x39, 0x42, 0x52, 0x02, 0x02, 0x01,
        0x80, 0x27, 0x3e, 0x01, 0x00, 0x05, 0x01, 0x24,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x6a, 0xc7, 0x00, 0xa3, 0x88,
        0x78, 0x1d, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d,
        0x53, 0x4b, 0x59, 0x57, 0x49, 0x46, 0x49, 0x5f,
        0x5a, 0x58, 0x32, 0x4a, 0x5a, 0x02, 0x02, 0x01,
        0x80, 0x27, 0x39, 0x01, 0x00, 0x05, 0x01, 0x24,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x62, 0xc3, 0x78, 0x3e, 0x53,
        0xfe, 0x52, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x53, 0x4b, 0x59, 0x42, 0x42, 0x43, 0x34, 0x42,
        0x02, 0x02, 0x01, 0x80
};

static int send_em_test_data(void *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d Pushing to ctrl queue\n", __func__, __LINE__);
    unsigned char null_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    sta_beacon_report_reponse_t temp_data_t;
    temp_data_t.num_br_data = 5;
    temp_data_t.ap_index = 0;

    mac_addr_t sta_mac = {0x82,0x5c,0xec,0x20,0xc0,0xd9};
    memcpy(temp_data_t.mac_addr, sta_mac, sizeof(mac_addr_t));

    temp_data_t.data_len = sizeof(binaryData);

    wifi_util_info_print(WIFI_APPS, "%s:%d size of len %d\n", __func__, __LINE__, temp_data_t.data_len);

    memcpy(temp_data_t.data, binaryData, temp_data_t.data_len);

    push_event_to_ctrl_queue(&temp_data_t, sizeof(sta_beacon_report_reponse_t),
        wifi_event_type_hal_ind, wifi_event_br_report, NULL);

    return 0;
}
#endif

int sta_mgr_init(wifi_app_t *app, unsigned int create_flag)
{

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: Init sta manager\n", __func__, __LINE__);

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL ctrl Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_apps_mgr_t *apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL mgr Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (ctrl->network_mode == rdk_dev_mode_type_gw || ctrl->network_mode == rdk_dev_mode_type_em_colocated_node ||
        ctrl->network_mode == rdk_dev_mode_type_em_node) {
        app->data.u.sta_mgr.sta_mgr_map = hash_map_create();
    }

    //TODO: Test Data, for manual check without a real client
#if TEST_CODE
    scheduler_add_timer_task(ctrl->sched, FALSE, &(g_sched_id), send_em_test_data,
        NULL, 10000, 0, FALSE);
#endif
    return 0;
}

int sta_mgr_deinit(wifi_app_t *app)
{
    void *tmp_data = NULL;
    mac_addr_str_t mac_str;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_APPS, "%s:%d: deinit sta manager\n", __func__, __LINE__);
    if (ctrl->network_mode == rdk_dev_mode_type_gw || ctrl->network_mode == rdk_dev_mode_type_em_colocated_node ||
        ctrl->network_mode == rdk_dev_mode_type_em_node) {
        sta_beacon_report_reponse_t *t_sta_data = (sta_beacon_report_reponse_t *)hash_map_get_first(
            app->data.u.sta_mgr.sta_mgr_map);
        while (t_sta_data != NULL) {
            memset(mac_str, 0, sizeof(mac_addr_str_t));
            if (t_sta_data->sched_handler_id != 0) {
                scheduler_cancel_timer_task(ctrl->sched, t_sta_data->sched_handler_id);
                t_sta_data->sched_handler_id = 0;
            }
            to_mac_str((unsigned char *)t_sta_data->mac_addr, mac_str);
            tmp_data = (sta_beacon_report_reponse_t *)hash_map_remove(
                app->data.u.sta_mgr.sta_mgr_map, mac_str);
            if (tmp_data != NULL) {
                free(tmp_data);
            }
            t_sta_data = hash_map_get_next(app->data.u.sta_mgr.sta_mgr_map, t_sta_data);
        }
        hash_map_destroy(app->data.u.sta_mgr.sta_mgr_map);
    }

    return 0;
}
