#include "const.h"
#include "scheduler.h"
#include "wifi_em_utils.h"
#include "wifi_em.h"
#include "wifi_hal.h"
#include "wifi_hal_ap.h"
#include "wifi_mgr.h"
#include <stdbool.h>
#include <stdint.h>

#define DCA_TO_APP 1
#define APP_TO_DCA 2

#define EM_NEIGBOUR_SCAN_PROVIDER_DELAY_SEC 5 // 5 Seconds
#define EM_NEIGBOUR_SCAN_INTERVAL_MSEC 60000 // 60 Seconds
#define EM_DEF_LINK_METRICS_COLLECT_INTERVAL_MSEC 10000 // 10 Seconds

static bool is_monitor_done = false;

typedef struct {
    em_policy_req_type_t policy_type;
    mac_addr_t ruid;
    int radio_index;
    int vap_index;
    wifi_app_t *app;
    int sched_id;
    int current_interval;
} em_ap_report_callback_arg_t;

typedef struct {
    sta_data_t assoc_stats[BSS_MAX_NUM_STATIONS];
    bool threshold_hit[BSS_MAX_NUM_STATIONS];
    unsigned int hit_count;
    size_t stat_array_size;
} client_assoc_data_t;

typedef struct {
    sta_client_type_data_t sta_client_type;
} client_type_data_t;

typedef struct {
    client_assoc_data_t client_assoc_data[MAX_NUM_VAP_PER_RADIO];
    unsigned int assoc_stats_vap_presence_mask;
    unsigned int req_stats_vap_mask;
} client_assoc_stats_t;

typedef struct {
    int vap_index;
    ap_metrics_t ap_metrics;
    int sta_count;
    hash_map_t *client_stats_map; // wifi_associated_dev3_t
} ap_metrics_data_t;

typedef struct {
    int radio_index;
    em_ap_report_callback_arg_t args;
    ap_metrics_data_t ap_data[MAX_NUM_VAP_PER_RADIO];
} em_ap_metrics_report_cache_t;

em_ap_metrics_report_cache_t em_ap_metrics_report_cache[MAX_NUM_RADIOS] = { 0 };
client_assoc_stats_t client_assoc_stats[MAX_NUM_RADIOS] = { 0 };
client_type_data_t client_type_info = { 0 };

static int em_rssi_to_rcpi(int rssi)
{
    if (!rssi)
        return 255;
    if (rssi < -110)
        return 0;
    if (rssi > 0)
        return 220;
    return (rssi + 110) * 2;
}

static int em_get_radio_index_from_mac(mac_addr_t ruuid)
{
    unsigned int num_of_radios = getNumberRadios();
    wifi_vap_info_map_t *vap_map;
    mac_addr_str_t rad_str;
    mac_addr_str_t bss_str;

    to_mac_str(ruuid, rad_str);

    for (int i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        for (int j = 0; j < vap_map->num_vaps; j++) {
            to_mac_str(vap_map->vap_array[j].u.bss_info.bssid, bss_str);
            //wifi_util_dbg_print(WIFI_EM, "%s:%d comparing ruuid[%s] with bss mac: %s\n", __func__, __LINE__, rad_str, bss_str);
            if (memcmp(ruuid, vap_map->vap_array[j].u.bss_info.bssid, sizeof(mac_addr_t)) == 0) {
                //wifi_util_dbg_print(WIFI_EM, "%s:%d Radio Index: %d found for radio mac: %s\n", __func__, __LINE__, vap_map->vap_array[j].radio_index, rad_str);
                return vap_map->vap_array[j].radio_index;
            }
        }
    }

    wifi_util_error_print(WIFI_EM, "%s:%d Radio Index not found for radio mac: %s\n", __func__, __LINE__, rad_str);

    return RETURN_ERR;
}

static int em_match_radio_index_to_policy_index(radio_metrics_policies_t *radio_metrics_policies,
    int radio_index)
{
    int radio_count = radio_metrics_policies->radio_count;
    int found_index;
    mac_addr_t radio_mac;
    radio_interface_mapping_t *radio_iface_map = NULL;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;
    unsigned int i = 0, k = 0;

    // Testing the code for RCPI-based link metrics is required.
    // Will reassess this block during that process.
    /* for (int i = 0; i < radio_count; i++) {
        found_index = em_get_radio_index_from_mac(
            radio_metrics_policies->radio_metrics_policy[i].ruid);
        if (found_index == radio_index)
            return i;
    } */
    for (k = 0;
        k < (sizeof(wifi_prop->radio_interface_map) / sizeof(radio_interface_mapping_t)); k++) {
        if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
            radio_iface_map = &(wifi_prop->radio_interface_map[k]);
            break;
        }
    }

    if (radio_iface_map == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Unable to find the interface map entry\n", __func__,
           __LINE__);
        return RETURN_ERR;
    }

    mac_address_from_name(radio_iface_map->interface_name, radio_mac);
    for (int i = 0; i < radio_count; i++) {
        found_index = em_get_radio_index_from_mac(radio_mac);
        if (found_index == radio_index)
            return i;
    }

    wifi_util_error_print(WIFI_EM, "%s:%d Radio Index was not matched with policy\n", __func__,
        __LINE__);

    return RETURN_ERR;
}

int em_common_config_to_monitor_queue(wifi_monitor_data_t *data, em_config_t *em_config)
{
    int index = RETURN_ERR;
    int radio_count = em_config->radio_metrics_policies.radio_count;

    for (int i = 0; i < radio_count; i++) {
        data[i].u.mon_stats_config.inst = wifi_app_inst_easymesh;

        index = em_get_radio_index_from_mac(
            em_config->radio_metrics_policies.radio_metrics_policy[i].ruid);

        if (index == RETURN_ERR) {
            return RETURN_ERR;
        }
    }
    return RETURN_OK;
}

int em_route(wifi_event_route_t *route)
{
    memset(route, 0, sizeof(wifi_event_route_t));
    route->dst = wifi_sub_component_mon;
    route->u.inst_bit_map = wifi_app_inst_easymesh;
    return RETURN_OK;
}

int em_client_stats_store(unsigned int radio_index, unsigned int vap_index, int sta_cnt,
    wifi_associated_dev3_t *dev3)
{
    wifi_associated_dev3_t *stats = NULL;
    wifi_associated_dev3_t *new_stats = NULL;
    mac_addr_str_t mac_str = { 0 }, bss_str = { 0 };
    unsigned char key[64] = { 0 };
    int arr_vap_index = -1;
    unsigned int i = 0;
    wifi_vap_info_t *vap_info = NULL;

    if (dev3 == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d null stats=%d\n", __func__, __LINE__,
            radio_index);
        return RETURN_ERR;
    }

    if (radio_index >= MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_EM, "%s:%d invalid radio_index=%d\n", __func__, __LINE__,
            radio_index);
        return RETURN_ERR;
    }

    for (i = 0; i < MAX_NUM_VAP_PER_RADIO; i++) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d vap_index=%d, radio_index=%d and cache[%d]'s Vap index = %d\n",
            __func__, __LINE__, vap_index, radio_index, i, em_ap_metrics_report_cache[radio_index].ap_data[i].vap_index);
        if (vap_index == em_ap_metrics_report_cache[radio_index].ap_data[i].vap_index) {
            arr_vap_index = i;
            break;
        } else {
            arr_vap_index = -1;
        }
    }

    if (arr_vap_index == -1) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d Vap map not found for vapIndex: %d\n",
            __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    em_ap_metrics_report_cache[radio_index].ap_data[arr_vap_index].sta_count = sta_cnt;

    vap_info = getVapInfo(vap_index);
    if (vap_info == NULL) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d Vap not found for vap index:%d\n",
            __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }
    to_mac_str(vap_info->u.bss_info.bssid, bss_str);
    to_mac_str(dev3->cli_MACAddress, mac_str);
    snprintf(key, 64, "%s@%s", bss_str, mac_str);
    wifi_util_dbg_print(WIFI_EM, "%s:%d key while updating cache is =%s and arr_vap_index:%d\n",
        __func__, __LINE__, key, arr_vap_index);

    stats = (wifi_associated_dev3_t *)hash_map_get(
        em_ap_metrics_report_cache[radio_index].ap_data[arr_vap_index].client_stats_map, key);
    if (stats == NULL) {
        // add new entries
        new_stats = (wifi_associated_dev3_t *)malloc(sizeof(wifi_associated_dev3_t));
        if (new_stats == NULL) {
            wifi_util_error_print(WIFI_EM, "%s:%d null stats=%d\n", __func__, __LINE__,
                radio_index);
            return RETURN_ERR;
        }

        memcpy(new_stats, dev3, sizeof(wifi_associated_dev3_t));
        hash_map_put(em_ap_metrics_report_cache[radio_index].ap_data[arr_vap_index].client_stats_map,
            strdup(key), new_stats);
    } else {
        memcpy(stats, dev3, sizeof(wifi_associated_dev3_t));
    }

    wifi_util_dbg_print(WIFI_EM, "%s:%d added sample for radio_index=%d, vap_index=%d, client=%s\n",
        __func__, __LINE__, radio_index, vap_index, mac_str);

    return RETURN_OK;
}

static int prepare_sta_traffic_stats_data(assoc_sta_traffic_stats_t *data,
    wifi_associated_dev3_t *stats)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Error in allocating table for encode stats\n",
            __func__, __LINE__);
        free(data);
        return RETURN_ERR;
    }

    memcpy(data->sta_mac, stats->cli_MACAddress, sizeof(mac_address_t));
    data->bytes_sent = stats->cli_BytesSent;
    data->bytes_rcvd = stats->cli_BytesReceived;
    data->packets_sent = stats->cli_PacketsSent;
    data->packets_rcvd = stats->cli_PacketsReceived;
    data->tx_packtes_errs = stats->cli_ErrorsSent;
    data->rx_packtes_errs = stats->cli_RxErrors;
    data->retrans_cnt = stats->cli_RetransCount;
}

static int prepare_sta_lins_metrics_data(per_sta_metrics_t *data, wifi_associated_dev3_t *stats,
    unsigned int vap_index)
{
    sta_client_info_t *cli_data = NULL;
    mac_addr_str_t key = { 0 };
    wifi_vap_info_t *vap_info = NULL;

    vap_info = getVapInfo(vap_index);
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Vap not found\n", __func__, __LINE__);
        free(data);
        return RETURN_ERR;
    }

    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Error in allocating table for encode stats\n",
            __func__, __LINE__);
        free(data);
        return RETURN_ERR;
    }

    // Associated STA Link Metrics
    memcpy(data->sta_mac, stats->cli_MACAddress, sizeof(mac_address_t));
    // Retrive client type info
    to_mac_str(stats->cli_MACAddress, key);
    cli_data = hash_map_get(client_type_info.sta_client_type.client_type_map, key);
    if (cli_data != NULL) {
        strncpy(data->client_type, cli_data->client_type, sizeof(cli_data->client_type));
    }

    data->assoc_sta_link_metrics.num_bssid = 1; // must be changed for STA multiple associations
    memcpy(data->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].bssid,
        vap_info->u.bss_info.bssid, sizeof(mac_address_t));
    data->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].time_delta =
        0; // How to calculate time Delta (The time delta in ms between the time at
           // which the earliest measurement that contributed to the data rate estimates
           // were made, and the time at which this report was sent.)
    data->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].est_mac_rate_down =
        stats->cli_MaxDownlinkRate; // I'm not sure if cli_MaxXXXX is the same
                                    // as "Estimated MAC Data Rate in downlink"
    data->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].est_mac_rate_up =
        stats->cli_MaxUplinkRate;
    data->assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].rcpi = em_rssi_to_rcpi(
        stats->cli_RSSI);

    // Associated STA Extended Link Metrics
    data->assoc_sta_ext_link_metrics.num_bssid = 1; // must be changed for STA multiple associations
    memcpy(data->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].bssid,
        vap_info->u.bss_info.bssid, sizeof(mac_address_t));
    data->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].last_data_downlink_rate =
        stats->cli_LastDataDownlinkRate;
    data->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].last_data_uplink_rate =
        stats->cli_LastDataUplinkRate;
    data->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].utilization_receive =
        0; // do we have that data?
    data->assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0].utilization_transmit = 0;

    return RETURN_OK;
}

static int em_sta_stats_publish(wifi_app_t *app, client_assoc_data_t *stats, int stat_array_size,
    unsigned int vap_index)
{
    webconfig_subdoc_data_t *data;
    raw_data_t rdata;
    int rc;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM,
            "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", __func__,
            sizeof(webconfig_subdoc_data_t));
        return -1;
    }

    // need to specify how to pack all the metrics, send one by one or into array?
    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    memset(&rdata, 0, sizeof(raw_data_t));
    data->u.decoded.em_sta_link_metrics_rsp.vap_index = vap_index;
    data->u.decoded.em_sta_link_metrics_rsp.sta_count = stat_array_size;
    data->u.decoded.em_sta_link_metrics_rsp.vap_index = vap_index;
    data->u.decoded.em_sta_link_metrics_rsp.per_sta_metrics = (per_sta_metrics_t *)malloc(
        stat_array_size * sizeof(per_sta_metrics_t));

    for (int i = 0; i < MAX_NUM_VAP_PER_RADIO; i++) {
        stats[i].hit_count = 0;
        for (int j = 0; j < stats[i].stat_array_size; j++) {
            if (stats[i].threshold_hit[j] == true) {
                stats[i].threshold_hit[j] = false;
                prepare_sta_lins_metrics_data(
                    data->u.decoded.em_sta_link_metrics_rsp.per_sta_metrics,
                    &stats[i].assoc_stats[j].dev_stats, vap_index);
            }
        }
    }

    if (webconfig_encode(&ctrl->webconfig, data, webconfig_subdoc_type_em_ap_metrics_report) !=
        webconfig_error_none) {
        wifi_util_error_print(WIFI_EM, "%s:%d Error in encoding assocdev stats\n", __func__,
            __LINE__);
        free(data->u.decoded.em_sta_link_metrics_rsp.per_sta_metrics);
        free(data);
        return RETURN_ERR;
    }

    rdata.data_type = bus_data_type_string;
    rdata.raw_data.bytes = (void *)data->u.encoded.raw;
    rdata.raw_data_len = strlen(data->u.encoded.raw) + 1;

    rc = get_bus_descriptor()->bus_event_publish_fn(&app->ctrl->handle,
        WIFI_EM_STA_LINK_METRICS_REPORT, &rdata);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_EM, "%s:%d: bus: bus_event_publish_fn Event failed %d\n",
            __func__, __LINE__, rc);
        free(data->u.decoded.em_sta_link_metrics_rsp.per_sta_metrics);
        free(data);
        return RETURN_ERR;
    }

    for (int i = 0; i < MAX_NUM_VAP_PER_RADIO; i++) {
        for (int j = 0; j < stats[i].stat_array_size; j++) {
            stats[i].threshold_hit[j] = false;
        }
    }

    free(data->u.decoded.em_sta_link_metrics_rsp.per_sta_metrics);
    free(data);
}

static int handle_ready_client_stats(wifi_app_t *app, client_assoc_data_t *stats, size_t stats_num,
    unsigned int vap_mask, unsigned int radio_index, unsigned int vap_index, int app_etype,
    int sta_sze)
{
    unsigned int tmp_vap_index = 0;
    unsigned int hit_count = 0;
    int tmp_vap_array_index = 0;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    int RCPI;
    int policy_index = em_match_radio_index_to_policy_index(
        &app->data.u.em_data.em_config.radio_metrics_policies, radio_index);

    if (policy_index == RETURN_ERR) {
        return RETURN_ERR;
    }

    int RCPI_threshold = app->data.u.em_data.em_config.radio_metrics_policies
                             .radio_metrics_policy[policy_index]
                             .sta_rcpi_threshold;
    int RCPI_hysteresis = app->data.u.em_data.em_config.radio_metrics_policies
                              .radio_metrics_policy[policy_index]
                              .sta_rcpi_hysteresis;

    if (!stats) {
        wifi_util_error_print(WIFI_EM, "%s:%d: stats is NULL for radio_index: %d\r\n", __func__,
            __LINE__, radio_index);
        return RETURN_ERR;
    }

    while (vap_mask) {
        /* check all VAPs */
        if (vap_mask & 0x1) {
            tmp_vap_array_index = convert_vap_index_to_vap_array_index(&wifi_mgr->hal_cap.wifi_prop,
                tmp_vap_index);
            if (tmp_vap_array_index >= 0 && tmp_vap_array_index < (int)stats_num) {
                size_t stat_array_size = stats[tmp_vap_array_index].stat_array_size;
                stats[tmp_vap_array_index].hit_count = 0;
                for (size_t i = 0; i < stat_array_size; i++) {
                    sta_data_t *sta_data = &stats[tmp_vap_array_index].assoc_stats[i];
                    if (!sta_data) {
                        continue;
                    }
                    if (sta_data->dev_stats.cli_Active == false) {
                        continue;
                    }

                    switch (app_etype) {
                    case em_app_event_type_assoc_stats_rcpi_monitor:
                        RCPI = em_rssi_to_rcpi(sta_data->dev_stats.cli_RSSI);
                        wifi_util_dbg_print(WIFI_EM, "%s:%d: RCPI:%d \r\n", __func__, __LINE__,
                            RCPI);
                        wifi_util_dbg_print(WIFI_EM, "%s:%d: RCPI_threshold: %d \r\n", __func__,
                            __LINE__, RCPI_threshold);
                        if (RCPI < RCPI_threshold) {
                            stats[tmp_vap_array_index].threshold_hit[i] = true;
                            stats[tmp_vap_array_index].hit_count++;
                            hit_count++;
                        } else if (stats[tmp_vap_array_index].threshold_hit[i] == true &&
                            RCPI < (RCPI_threshold + RCPI_hysteresis)) {
                            stats[tmp_vap_array_index].threshold_hit[i] = true;
                            stats[tmp_vap_array_index].hit_count++;
                            hit_count++;
                        } else {
                            stats[tmp_vap_array_index].threshold_hit[i] = false;
                        }
                        break;

                    case em_app_event_type_assoc_dev_stats_periodic:
                        em_client_stats_store(radio_index, vap_index, stat_array_size,
                            &sta_data->dev_stats);
                        break;

                    default:
                        break;
                    }
                }
            }
        }
        tmp_vap_index++;
        vap_mask >>= 1;
    }

    if (hit_count > 0) {
        em_sta_stats_publish(app, stats, sta_sze, vap_index);
    }

    return RETURN_OK;
}

static int em_stop_metrics_report(int radio_index, wifi_app_t *app)
{
    wifi_monitor_data_t *data;
    wifi_event_route_t route;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    int interval = app->data.u.em_data.em_config.ap_metric_policy.interval;

    data = (wifi_monitor_data_t *)malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: data allocation failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(data, 0, sizeof(wifi_monitor_data_t));

    if (app->data.u.em_data.em_config.ap_metric_policy.interval == 0) {
        interval = EM_DEF_LINK_METRICS_COLLECT_INTERVAL_MSEC;
    } else {
        interval = app->data.u.em_data.em_config.ap_metric_policy.interval;
    }

    data->u.mon_stats_config.args.radio_index = radio_index;
    data->u.mon_stats_config.interval_ms = interval;
    data->u.mon_stats_config.data_type = mon_stats_type_associated_device_stats;
    data->u.mon_stats_config.args.app_info = em_app_event_type_assoc_stats_rcpi_monitor;
    data->u.mon_stats_config.inst = wifi_app_inst_easymesh;
    data->u.mon_stats_config.req_state = mon_stats_request_state_stop;
    data->u.mon_stats_config.start_immediately = true;
    data->u.mon_stats_config.delay_provider_sec = EM_NEIGBOUR_SCAN_PROVIDER_DELAY_SEC;

    em_route(&route);

    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);

    if (NULL != data) {
        free(data);
        data = NULL;
    }
}

int assoc_client_response(wifi_app_t *app, wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0;
    unsigned int vap_index = 0;
    int vap_array_index = 0;
    radio_index = provider_response->args.radio_index;
    vap_index = provider_response->args.vap_index;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    char vap_name[32];

    wifi_util_info_print(WIFI_EM, "%s:%d: provider_response is for radio index: %d and vap index: %d\n",
         __func__, __LINE__, radio_index, vap_index);

    if (provider_response->stat_array_size <= 0) {
        wifi_util_error_print(WIFI_EM, "%s:%d: provider_response is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (convert_vap_index_to_name(&wifi_mgr->hal_cap.wifi_prop, vap_index, vap_name) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,
            "%s:%d: convert_vap_index_to_name failed for vap_index : %d\r\n", __func__, __LINE__,
            vap_index);
        return RETURN_ERR;
    }

    vap_array_index = convert_vap_name_to_array_index(&wifi_mgr->hal_cap.wifi_prop, vap_name);
    if (vap_array_index == -1) {
        wifi_util_error_print(WIFI_EM,
            "%s:%d: convert_vap_name_to_array_index failed for vap_name: %s\r\n", __func__,
            __LINE__, vap_name);
        return RETURN_ERR;
    }

    memset(client_assoc_stats[radio_index].client_assoc_data[vap_array_index].assoc_stats, 0,
        sizeof(client_assoc_stats[radio_index].client_assoc_data[vap_array_index].assoc_stats));
    memcpy(client_assoc_stats[radio_index].client_assoc_data[vap_array_index].assoc_stats,
        provider_response->stat_pointer, (sizeof(sta_data_t) * provider_response->stat_array_size));
    client_assoc_stats[radio_index].client_assoc_data[vap_array_index].stat_array_size =
        provider_response->stat_array_size;
    client_assoc_stats[radio_index].assoc_stats_vap_presence_mask |= (1 << vap_index);

    wifi_util_dbg_print(WIFI_EM, "%s:%d: vap_index : %d client array size : %d \r\n", __func__,
        __LINE__, vap_index, provider_response->stat_array_size);

    if (client_assoc_stats[radio_index].assoc_stats_vap_presence_mask ==
            (client_assoc_stats[radio_index].req_stats_vap_mask & client_assoc_stats[radio_index].assoc_stats_vap_presence_mask)) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d: push stats for radio_index : %d \r\n", __func__,
            __LINE__, radio_index);
        handle_ready_client_stats(app, client_assoc_stats[radio_index].client_assoc_data,
            MAX_NUM_VAP_PER_RADIO, client_assoc_stats[radio_index].assoc_stats_vap_presence_mask,
            radio_index, vap_index, provider_response->args.app_info,
            provider_response->stat_array_size);
        client_assoc_stats[radio_index].assoc_stats_vap_presence_mask = 0;
    }

    return RETURN_OK;
}

static void config_em_neighbour_scan(wifi_monitor_data_t *data, unsigned int radioIndex)
{
    wifi_event_route_t route;
    em_route(&route);

    data->u.mon_stats_config.data_type = mon_stats_type_neighbor_stats;
    data->u.mon_stats_config.args.app_info = em_app_event_type_neighbor_stats;

    wifi_util_dbg_print(WIFI_EM, "%s:%d Pushing the event for app %d \n", __func__, __LINE__,
        route.u.inst_bit_map);
    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
}

static void config_em_chan_util(wifi_monitor_data_t *data, unsigned int radioIndex)
{
    wifi_event_route_t route;
    em_route(&route);

    data->u.mon_stats_config.data_type = mon_stats_type_radio_channel_stats;
    data->u.mon_stats_config.args.app_info = em_app_event_type_chan_stats;

    wifi_util_dbg_print(WIFI_EM, "%s:%d Pushing the event for app %d \n", __func__, __LINE__,
        route.u.inst_bit_map);

    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
}

static int em_prepare_scan_response_data(wifi_provider_response_t *provider_response,
    channel_scan_response_t *scan_response)
{

    unsigned int scan_count = 0, radio_index;
    mac_address_t radio_mac;
    mac_addr_str_t mac_str;
    wifi_neighbor_ap2_t *wifi_scan_data = NULL;
    radio_interface_mapping_t *radio_iface_map = NULL;
    char time_str[32] = { 0 };

    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;

    wifi_scan_data = (wifi_neighbor_ap2_t *)provider_response->stat_pointer;
    if (wifi_scan_data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: wifi_scan_data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (provider_response->stat_array_size <= 0) {
        wifi_util_error_print(WIFI_EM, "%s:%d: provider_response is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio_index = provider_response->args.radio_index;
    scan_count = provider_response->stat_array_size;
    wifi_util_dbg_print(WIFI_EM, "%s:%d radio_index : %d scan_count : %d\n", __func__, __LINE__,
        radio_index, scan_count);

    for (unsigned int k = 0;
         k < (sizeof(wifi_prop->radio_interface_map) / sizeof(radio_interface_mapping_t)); k++) {
        if (wifi_prop->radio_interface_map[k].radio_index == radio_index) {
            radio_iface_map = &(wifi_prop->radio_interface_map[k]);
            break;
        }
    }
    if (radio_iface_map == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Unable to find the interface map entry\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    memset(scan_response, 0, sizeof(channel_scan_response_t));

    mac_address_from_name(radio_iface_map->interface_name, radio_mac);
    memcpy(scan_response->ruid, radio_mac, sizeof(mac_address_t));

    get_formatted_time(time_str);

    for (int i = 0; i < scan_count; i++) {
        wifi_neighbor_ap2_t *src = &wifi_scan_data[i];

        int op_class = wifi_freq_to_op_class(src->ap_freq);
        if (op_class <= 0) {
            wifi_util_error_print(WIFI_EM, "%s:%d : Invalid op_class (%d). Skipping scan result.\n",
                __func__, __LINE__, op_class);
            continue;
        }

        if (strcmp(src->ap_SSID, "") == 0) {
            wifi_util_error_print(WIFI_EM, "%s:%d : Empty SSID found. Skipping scan result.\n",
                __func__, __LINE__);
            continue;
        }

        int res_index = -1;
        for (int j = 0; j < scan_response->num_results; j++) {
            if (scan_response->results[j].operating_class == op_class &&
                scan_response->results[j].channel == src->ap_Channel) {
                res_index = j;
                break;
            }
        }

        if (res_index == -1) {
            if (scan_response->num_results >= EM_MAX_RESULTS) {
                wifi_util_error_print(WIFI_EM,
                    "%s:%d : Maximum number of scan results reached. Skipping additional "
                    "results.\n",
                    __func__, __LINE__);
                continue;
            }
            res_index = scan_response->num_results;
            scan_response->results[res_index].operating_class = op_class;
            scan_response->results[res_index].channel = src->ap_Channel;
            scan_response->results[res_index].scan_status = 0;
            strncpy(scan_response->results[res_index].time_stamp, time_str,
                sizeof(scan_response->results[res_index].time_stamp));
            scan_response->results[res_index].utilization = src->ap_ChannelUtilization;
            scan_response->results[res_index].noise = src->ap_Noise;
            scan_response->results[res_index].num_neighbors = 0;
            scan_response->results[res_index].aggregate_scan_duration = 0;
            scan_response->results[res_index].scan_type = 0;
            scan_response->num_results++;
        }
        wifi_util_dbg_print(WIFI_EM, "%s:%d op_class : %d channel : %d\n", __func__, __LINE__,
            op_class, src->ap_Channel);

        channel_scan_result_t *res = &scan_response->results[res_index];
        if (res->num_neighbors < EM_MAX_NEIGHBORS) {
            neighbor_bss_t *neighbor = &res->neighbors[res->num_neighbors];
            sscanf(src->ap_BSSID, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &neighbor->bssid[0],
                &neighbor->bssid[1], &neighbor->bssid[2], &neighbor->bssid[3], &neighbor->bssid[4],
                &neighbor->bssid[5]);
            strncpy(neighbor->ssid, src->ap_SSID, sizeof(ssid_t));
            neighbor->signal_strength = src->ap_SignalStrength;
            strncpy(neighbor->channel_bandwidth, src->ap_OperatingChannelBandwidth,
                EM_MAX_CHANNEL_BW_LEN);
            neighbor->channel_utilization = src->ap_ChannelUtilization;
            neighbor->bss_load_element_present = 0;
            neighbor->bss_color = 0;
            neighbor->station_count = 0;
            res->num_neighbors++;
            wifi_util_dbg_print(WIFI_EM, "%s:%d BSSID: %s SSID: %s\n", __func__, __LINE__,
                src->ap_BSSID, src->ap_SSID);
        } else {
            wifi_util_error_print(WIFI_EM, "%s:%d : Maximum number of neighbors reached.\n",
                __func__, __LINE__);
        }
    }
    wifi_util_dbg_print(WIFI_EM, "%s:%d Scan results updated for radio mac : %s\n", __func__,
        __LINE__, to_mac_str(radio_mac, mac_str));

    return RETURN_OK;
}

static int em_publish_stats_data(channel_scan_response_t *scan_response)
{
    webconfig_subdoc_data_t *data;
    bus_error_t status;
    char eventName[MAX_EVENT_NAME_SIZE] = { 0 };
    webconfig_subdoc_type_t subdoc_type;
    time_t response_time;
    raw_data_t rdata;
    wifi_apps_mgr_t *apps_mgr = NULL;
    wifi_app_t *wifi_app = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Error in allocation memory\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(data, '\0', sizeof(webconfig_subdoc_data_t));
    data->u.decoded.collect_stats.stats = (struct channel_scan_response_t *)malloc(
        sizeof(channel_scan_response_t));
    if (data->u.decoded.collect_stats.stats == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Error in allocating memory\n", __func__, __LINE__);
        free(data);
        return RETURN_ERR;
    }

    (void)time(&response_time);

    memcpy(data->u.decoded.collect_stats.stats, scan_response, sizeof(channel_scan_response_t));

    subdoc_type = webconfig_subdoc_type_em_channel_stats;
    strncpy(eventName, "Device.WiFi.EM.ChannelScanReport", sizeof(eventName) - 1);

    wifi_util_dbg_print(WIFI_EM, "%s:%d subdoc_type is %d and eventName is %s at %ld\n", __func__,
        __LINE__, subdoc_type, eventName, response_time);

    if (webconfig_encode(&ctrl->webconfig, data, subdoc_type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_EM, "%s:%d Error in encoding channel scan stats\n", __func__,
            __LINE__);
        free(data->u.decoded.collect_stats.stats);
        free(data);
        return RETURN_ERR;
    }

    memset(&rdata, 0, sizeof(raw_data_t));
    rdata.data_type = bus_data_type_string;
    rdata.raw_data.bytes = (void *)data->u.encoded.raw;
    rdata.raw_data_len = strlen(data->u.encoded.raw) + 1;

    apps_mgr = &ctrl->apps_mgr;
    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_easymesh);

    status = get_bus_descriptor()->bus_event_publish_fn(&wifi_app->ctrl->handle, eventName, &rdata);

    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_EM, "%s:%d: bus: bus_event_publish_fn Event failed %d\n",
            __func__, __LINE__, status);
        free(data->u.decoded.collect_stats.stats);
        free(data);
        return RETURN_ERR;
    }
    free(data->u.decoded.collect_stats.stats);
    free(data);

    wifi_util_dbg_print(WIFI_EM, "%s:%d Scan results published\n", __func__, __LINE__);

    return RETURN_OK;
}

static int em_stop_neighbor_scan(wifi_provider_response_t *provider_response)
{
    wifi_monitor_data_t *data;
    unsigned int radio_index = provider_response->args.radio_index;

    data = (wifi_monitor_data_t *)malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: data allocation failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_EM, "%s:%d: Radio index: %d\n", __func__, __LINE__, radio_index);

    memset(data, 0, sizeof(wifi_monitor_data_t));

    data->u.mon_stats_config.args.radio_index = radio_index;
    data->u.mon_stats_config.interval_ms = EM_NEIGBOUR_SCAN_INTERVAL_MSEC;
    data->u.mon_stats_config.args.scan_mode = provider_response->args.scan_mode;
    data->u.mon_stats_config.inst = wifi_app_inst_easymesh;
    data->u.mon_stats_config.req_state = mon_stats_request_state_stop;
    data->u.mon_stats_config.start_immediately = false;
    data->u.mon_stats_config.delay_provider_sec = EM_NEIGBOUR_SCAN_PROVIDER_DELAY_SEC;

    config_em_neighbour_scan(data, radio_index);

    if (NULL != data) {
        free(data);
        data = NULL;
    }
}

static int em_process_neighbour_data(wifi_provider_response_t *provider_response)
{
    channel_scan_response_t scan_response;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    wifi_util_dbg_print(WIFI_EM, "%s:%d: Processing neighbour stats data\n", __func__, __LINE__);

    if (wifi_mgr == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: wifi_mgr or chan_scan_data is NULL\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    if (em_prepare_scan_response_data(provider_response, &scan_response) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM, "%s:%d Prepare neighbour scan response failed\r\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    if (em_publish_stats_data(&scan_response) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM, "%s:%d Publishing neighbour stats data failed\r\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    em_stop_neighbor_scan(provider_response);

    return RETURN_OK;
}

static int em_process_chan_stats_data(wifi_provider_response_t *provider_response)
{
    radio_chan_data_t *chan_scan_data = NULL;
    chan_scan_data = (radio_chan_data_t *)provider_response->stat_pointer;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    if (chan_scan_data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: chan_scan_data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    unsigned int radio_index = provider_response->args.radio_index;
    wifi_util_dbg_print(WIFI_EM, "%s:%d radio_index : %d stats_array_size : %d\r\n", __func__,
        __LINE__, radio_index, provider_response->stat_array_size);

    if (provider_response->stat_array_size <= 0) {
        wifi_util_error_print(WIFI_EM, "%s:%d: provider response is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    for (unsigned int count = 0; count < provider_response->stat_array_size; count++) {
        wifi_util_dbg_print(WIFI_EM,
            "%s:%d: radio_index : %d channel_num : %d ch_utilization : %d "
            "ch_utilization_total:%lld\r\n",
            __func__, __LINE__, radio_index, chan_scan_data[count].ch_number,
            chan_scan_data[count].ch_utilization, chan_scan_data[count].ch_utilization_total);
    }

    // ToDo the implementation later.

    return RETURN_OK;
}

static int radio_chan_stats_response(wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0;
    unsigned int count = 0;
    radio_chan_data_t *channel_stats = NULL;
    radio_interface_mapping_t *radio_iface_map = NULL;
    rdk_wifi_radio_t *radio = NULL;
    wifi_vap_info_map_t *vap_map = NULL;
    ap_metrics_data_t *ap_data = NULL;
    ap_metrics_t *ap_metrics = NULL;
    wifi_vap_info_t *vap = NULL;
    int j = 0;

    radio_index = provider_response->args.radio_index;
    if (radio_index > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_EM, "%s:%d Invalid radio index %d\n", __func__, __LINE__,
            radio_index);
        return RETURN_ERR;
    }

    if (provider_response->stat_array_size <= 0) {
        wifi_util_error_print(WIFI_EM, "%s:%d: provider_response is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    radio = find_radio_config_by_index(radio_index);
    if (radio == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return;
    }

    vap_map = &radio->vaps.vap_map;
    if (vap_map == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    channel_stats = (radio_chan_data_t *)provider_response->stat_pointer;

    wifi_util_dbg_print(WIFI_EM, "%s:%d radio_index : %d stats_array_size : %d\r\n", __func__,
        __LINE__, radio_index, provider_response->stat_array_size);
    for (count = 0; count < provider_response->stat_array_size; count++) {
        wifi_util_dbg_print(WIFI_EM, "\n\n%s:%d count : %d ch_utilization: %d\r\n", __func__, __LINE__,
            count, channel_stats[count].ch_utilization);
        // now save radio channel util for each vap
        for (j = 0; j < radio->vaps.num_vaps; j++) {
            vap = &vap_map->vap_array[j];
            if (vap == NULL) {
                wifi_util_dbg_print(WIFI_EM, "%s:%d NULL VAP\r\n", __func__, __LINE__);
                continue;
            }

            // very first time update of the cache
            if ((em_ap_metrics_report_cache[radio_index].ap_data[j].vap_index >= 0) &&
                (memcmp(em_ap_metrics_report_cache[radio_index].ap_data[j].ap_metrics.bssid, vap->u.bss_info.bssid,
                     sizeof(mac_addr_t)) != 0)) {
                ap_data = &em_ap_metrics_report_cache[radio_index].ap_data[j];
                ap_data->vap_index = vap->vap_index;

                ap_metrics = &ap_data->ap_metrics;
                if (ap_metrics != NULL) {
                    ap_metrics->channel_util = channel_stats[count].ch_utilization;
                } else {
                    wifi_util_dbg_print(WIFI_EM,
                        "%s:%d ap metrics report data update to cache error\r\n", __func__, __LINE__);
                }

                wifi_util_dbg_print(WIFI_EM, "%s:%d AP METRICS REPORT cache array Updated\n", __func__,
                    __LINE__);
            } else {
                ap_data = &em_ap_metrics_report_cache[radio_index].ap_data[j];
                if (ap_data->vap_index != vap->vap_index){
                    wifi_util_dbg_print(WIFI_EM,
                        "%s:%d vap index not mathing %d\r\n", __func__, __LINE__, vap->vap_index);
                    continue;
                }

                ap_metrics = &ap_data->ap_metrics;
                if (ap_metrics != NULL) {
                    ap_metrics->channel_util = channel_stats[count].ch_utilization;
                } else {
                    wifi_util_dbg_print(WIFI_EM,
                        "%s:%d ap metrics report data update to cache error\r\n", __func__, __LINE__);
                }

                wifi_util_dbg_print(WIFI_EM, "%s:%d AP METRICS REPORT cache array Updated for rad:%d and vap:%d into cache index:%d\n", __func__,
                    __LINE__, radio_index, vap->vap_index, j);
            }
        }
    }

    wifi_util_dbg_print(WIFI_EM, "%s:%d Process of radio chann stats response complete\r\n", __func__,
        __LINE__);

    return RETURN_OK;
}

int handle_monitor_provider_response(wifi_app_t *app, wifi_event_t *event)
{
    wifi_provider_response_t *provider_response;
    provider_response = (wifi_provider_response_t *)event->u.provider_response;
    int ret = RETURN_ERR;

    if (provider_response == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: input event is NULL\r\n", __func__, __LINE__);
        return ret;
    }

    switch (provider_response->args.app_info) {

    case em_app_event_type_assoc_stats_rcpi_monitor:
    case em_app_event_type_assoc_dev_stats_periodic:
        ret = assoc_client_response(app, provider_response);
        break;
    case em_app_event_type_neighbor_stats:
        ret = em_process_neighbour_data(provider_response);
        break;
    case em_app_event_type_chan_stats:
        ret = em_process_chan_stats_data(provider_response);
        break;
    case em_app_event_type_ap_metrics_rad_chan_stats:
        ret = radio_chan_stats_response(provider_response);
        break;
    default:
        wifi_util_error_print(WIFI_EM, "%s:%d: event not handle[%d]\r\n", __func__, __LINE__,
            provider_response->args.app_info);
    }

    return ret;
}

int handle_sta_client_info(wifi_app_t *app, void *data)
{
    sta_client_info_t *sta_info = (sta_client_info_t *)data;
    unsigned char client_mac[32] = { 0 };
    sta_client_info_t *cli_data = NULL;

    to_mac_str(sta_info->mac_addr, client_mac);

    if (hash_map_get(client_type_info.sta_client_type.client_type_map, client_mac) == NULL) {
        cli_data = (sta_client_info_t *)malloc(sizeof(sta_client_info_t));
        memset(cli_data, 0, sizeof(sta_client_info_t));
        memcpy(cli_data->mac_addr, sta_info->mac_addr, sizeof(mac_address_t));
        strncpy(cli_data->client_type, sta_info->client_type, sizeof(cli_data->client_type));
        cli_data->client_type[sizeof(cli_data->client_type) - 1] = '\0';

        hash_map_put(client_type_info.sta_client_type.client_type_map, strdup(client_mac),
            cli_data);
        wifi_util_dbg_print(WIFI_EM, "%s:%d Client Type Updated to stats cache [%s]\n",
            __func__, __LINE__, cli_data->client_type);
    }

    return RETURN_OK;
}

static int em_handle_disassoc_device(wifi_app_t *app, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;
    char client_mac[32];
    int vap_index = assoc_data->ap_index;
    unsigned char key[64] = { 0 };
    mac_addr_str_t sta_mac_str, bss_str;
    int i = 0;
    int radio_index = -1;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_platform_property_t *wifi_prop = &wifi_mgr->hal_cap.wifi_prop;
    int arr_vap_index = -1;
    wifi_vap_info_t *vap_info = NULL;
    wifi_associated_dev3_t *stats = NULL;

    wifi_util_dbg_print(WIFI_EM, "%s:%d : Sta disassoc event \n", __func__, __LINE__);

    radio_index = get_radio_index_for_vap_index(wifi_prop, vap_index);
    if (radio_index == RETURN_ERR) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d could not find radio_index=%d for vap index = %d\n",
            __func__, __LINE__, radio_index, vap_index);
        return 0;
    }

    for (i = 0; i < MAX_NUM_VAP_PER_RADIO; i++) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d vap_index=%d, radio_index=%d and cache[%d]'s Vap index = %d\n",
            __func__, __LINE__, vap_index, radio_index, i, em_ap_metrics_report_cache[radio_index].ap_data[i].vap_index);
        if (vap_index == em_ap_metrics_report_cache[radio_index].ap_data[i].vap_index) {
            arr_vap_index = i;
            break;
        } else {
            arr_vap_index = -1;
        }
    }

    if (arr_vap_index == -1) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d Vap map not found\n",
            __func__, __LINE__, key);
        return RETURN_ERR;
    }

    vap_info = getVapInfo(vap_index);
    if (vap_info == NULL) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d Vap not found for vap index:%d\n",
            __func__, __LINE__, vap_index);
        return RETURN_ERR;
    }
    to_mac_str(vap_info->u.bss_info.bssid, bss_str);
    to_mac_str(assoc_data->dev_stats.cli_MACAddress, sta_mac_str);
    snprintf(key, 64, "%s@%s", bss_str, sta_mac_str);
    stats = (wifi_associated_dev3_t *)hash_map_remove(
        em_ap_metrics_report_cache[radio_index].ap_data[arr_vap_index].client_stats_map, key);
    if (stats == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Sta Mac %s not present in hash map\n", __func__,
            __LINE__, sta_mac_str);
        return 0;
    }
    wifi_util_dbg_print(WIFI_EM, "%s:%d: Sta Mac %s disassociated\n", __func__,
        __LINE__, sta_mac_str);

    to_mac_str((unsigned char *)assoc_data->dev_stats.cli_MACAddress, client_mac);
    sta_client_info_t *t_sta_data = (sta_client_info_t *)hash_map_remove(
        client_type_info.sta_client_type.client_type_map, client_mac);

    if (t_sta_data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: Mac %s not present in hash map\n", __func__,
            __LINE__, client_mac);
        return 0;
    }

    free(t_sta_data);

    return 0;
}

static int em_handle_sta_conn_status(wifi_app_t *app, void *data)
{
    rdk_sta_data_t *sta_data = (rdk_sta_data_t *)data;
    if (sta_data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: NULL STA data!\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    // Publish the whole rdk_sta_data_t
    wifi_ctrl_t *wifi_ctrl = get_wifictrl_obj();
    raw_data_t rdata = {0};
    rdata.raw_data.bytes = malloc(sizeof(rdk_sta_data_t));
    if (rdata.raw_data.bytes == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Could not allocate for rdk_sta_data_t\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    rdata.data_type = bus_data_type_bytes;
    memcpy(rdata.raw_data.bytes, sta_data, sizeof(rdk_sta_data_t));
    rdata.raw_data_len = sizeof(rdk_sta_data_t);
    char path[256] = {0};
    snprintf(path, sizeof(path), WIFI_EM_ASSOCIATION_STATUS);
    get_bus_descriptor()->bus_event_publish_fn(&wifi_ctrl->handle, path, &rdata);
    free(rdata.raw_data.bytes);
}

int monitor_event_em(wifi_app_t *app, wifi_event_t *event)
{
    int ret = RETURN_ERR;

    if (event == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: input event is NULL\r\n", __func__, __LINE__);
        return ret;
    }

    switch (event->sub_type) {
    case wifi_event_monitor_provider_response:
        ret = handle_monitor_provider_response(app, event);
        break;

    default:
        wifi_util_error_print(WIFI_EM, "%s:%d: event not handle[%d]\r\n", __func__, __LINE__,
            event->sub_type);
        break;
    }

    return ret;
}

int generate_vap_mask_for_radio_index(unsigned int radio_index)
{
    rdk_wifi_vap_map_t *rdk_vap_map = NULL;
    unsigned int count = 0;
    rdk_vap_map = getRdkWifiVap(radio_index);
    if (rdk_vap_map == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: getRdkWifiVap failed for radio_index : %d\r\n",
            __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }
    for (count = 0; count < rdk_vap_map->num_vaps; count++) {
        if (!isVapSTAMesh(rdk_vap_map->rdk_vap_array[count].vap_index)) {
            client_assoc_stats[radio_index].req_stats_vap_mask |= (1
                << rdk_vap_map->rdk_vap_array[count].vap_index);
        }
    }

    return RETURN_OK;
}

int client_diag_config_to_monitor_queue(wifi_app_t *app, wifi_monitor_data_t *data,
    em_app_event_type_t app_etype)
{
    unsigned int vapArrayIndex = 0;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_event_route_t route;
    int radio_count = -1;
    unsigned int i = 0;

    em_route(&route);
    if (em_common_config_to_monitor_queue(app, data) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM, "%s:%d em Config creation failed %d\r\n", __func__, __LINE__,
            stats_type_client);
        return RETURN_ERR;
    }

    radio_count = app->data.u.em_data.em_config.radio_metrics_policies.radio_count;

    for (i = 0; i < radio_count; i++) {
        data[i].u.mon_stats_config.data_type = mon_stats_type_associated_device_stats;

        if (client_assoc_stats[data[i].u.mon_stats_config.args.radio_index].req_stats_vap_mask ==
            0) {
            if (generate_vap_mask_for_radio_index(data[i].u.mon_stats_config.args.radio_index) ==
                RETURN_ERR) {
                wifi_util_error_print(WIFI_EM,
                    "%s:%d generate_vap_mask_for_radio_index failed \r\n", __func__, __LINE__);
                return RETURN_ERR;
            }
        }

        switch (app_etype) {
        case em_app_event_type_assoc_stats_rcpi_monitor:
            // monitor stats every 10s for rcpi based link metrics sending
            // for rcpi based link metrics sending, dont bother interval. Just sample every 10s and
            // if crosses, send report to agent
            data[i].u.mon_stats_config.args.app_info = em_app_event_type_assoc_stats_rcpi_monitor;
            data->u.mon_stats_config.start_immediately = true;

            break;

        case em_app_event_type_assoc_dev_stats_periodic:
            data[i].u.mon_stats_config.args.app_info = em_app_event_type_assoc_dev_stats_periodic;
            data[i].u.mon_stats_config.interval_ms =
                app->data.u.em_data.em_config.ap_metric_policy.interval * 1000;
            data->u.mon_stats_config.start_immediately = true;
            break;

        default:
            break;
        }

        // for each vap push the event to monitor queue
        for (vapArrayIndex = 0;
             vapArrayIndex < getNumberVAPsPerRadio(data[i].u.mon_stats_config.args.radio_index);
             vapArrayIndex++) {
            data[i].u.mon_stats_config.args.vap_index =
                wifi_mgr->radio_config[data[i].u.mon_stats_config.args.radio_index]
                    .vaps.rdk_vap_array[vapArrayIndex]
                    .vap_index;
            if (!isVapSTAMesh(data[i].u.mon_stats_config.args.vap_index)) {
                push_event_to_monitor_queue(data + i, wifi_event_monitor_data_collection_config,
                    &route);
            }
        }
    }

    return RETURN_OK;
}

static int ap_report_push_cb(em_ap_report_callback_arg_t *args)
{
    int rc = RETURN_OK;
    int radio_index = 0;
    em_policy_req_type_t policy_type = em_ap_metrics_report_cache[radio_index].args.policy_type;
    webconfig_subdoc_data_t *data = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    em_vap_metrics_t *vap_report = NULL;
    wifi_associated_dev3_t *stats = NULL;
    mac_addr_str_t bss_str, bss_str1;
    em_ap_metrics_report_t *ap_metrics_report = NULL;
    ap_metrics_t *ap_metrics = NULL;
    rdk_wifi_radio_t *radio = NULL;
    wifi_vap_info_map_t *vap_map = NULL;
    wifi_vap_info_t *vap_info = NULL;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    raw_data_t rdata;
    unsigned int i = 0, j = 0, k = 0;
    int cache_vap_index = -1;

    data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM,
            "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", __func__,
            sizeof(webconfig_subdoc_data_t));
        return -1;
    }

    memset(data, 0, sizeof(webconfig_subdoc_data_t));

    radio_index = args->radio_index;
    radio = find_radio_config_by_index(radio_index);
    if (radio == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: NULL Pointer of radio_index %d\n", __func__,
            __LINE__, radio_index);
        free(data);
        return RETURN_ERR;
    }

    vap_map = &radio->vaps.vap_map;

    wifi_util_error_print(WIFI_EM, "%s:%d:\n\n Scheduled AP report create task for radio_index %d with total vaps: %d\n", __func__,
        __LINE__, radio_index, radio->vaps.num_vaps);

    ap_metrics_report = &data->u.decoded.em_ap_metrics_report;
    ap_metrics_report->radio_index = radio_index;

    // Report is configured to arrive per radio
    for (j = 0; j < radio->vaps.num_vaps; j++) {
        wifi_util_dbg_print(WIFI_EM,"%s:%d vap index: %d\n", __func__, __LINE__, j);
        vap_info = &vap_map->vap_array[j];
        if (vap_info == NULL) {
            continue;
        }
        // now search in the count of max_num_vaps_per_radio stored in cache
        // search for this bss in the ccahe and prep the data
        for (k = 0; k < MAX_NUM_VAP_PER_RADIO; k++) {
            ap_metrics = &em_ap_metrics_report_cache[radio_index].ap_data[k].ap_metrics;
            to_mac_str(ap_metrics->bssid, bss_str1);
            wifi_util_dbg_print(WIFI_EM, \
                "%s:%d Cache's Vap Data at k=%d, radio %d's vapIndex:%d and ap_metrics vap index: %d\n", \
                __func__, __LINE__, k, radio_index, vap_info->vap_index , em_ap_metrics_report_cache[radio_index].ap_data[k].vap_index);
            if (vap_info->vap_index == em_ap_metrics_report_cache[radio_index].ap_data[k].vap_index) {
                // in em_cache_store, dats is stored against the vapindex in the array
                cache_vap_index = k;
                break;
            }
        }

        if (cache_vap_index == -1) {
            wifi_util_dbg_print(WIFI_EM,"%s:%d Vap mapping not found for vap index: %d\n", __func__, __LINE__, vap_info->vap_index);
            continue;
        }

        vap_report = &data->u.decoded.em_ap_metrics_report.vap_reports[j];
        vap_report->sta_traffic_stats = NULL;
        vap_report->sta_link_metrics = NULL;

        //index cannot be vap index below right for cache retrieval, have to search in the all cache for each vaps and check vap index
        ap_metrics = &em_ap_metrics_report_cache[radio_index].ap_data[cache_vap_index].ap_metrics;
        ap_metrics->num_of_assoc_stas = hash_map_count(
            wifi_mgr->radio_config[radio_index].vaps.rdk_vap_array[j].associated_devices_map);
        vap_report->sta_cnt = ap_metrics->num_of_assoc_stas;
        memcpy(ap_metrics->bssid, vap_info->u.bss_info.bssid, sizeof(bssid_t));
        memcpy(&vap_report->vap_metrics, ap_metrics, sizeof(ap_metrics_t));
        to_mac_str(vap_info->u.bss_info.bssid, bss_str);
        wifi_util_dbg_print(WIFI_EM,
            "%s:%d Creating AP Metrics Report for vap-array-index:%d for radio :%d, Vap index :%d and Vap mac: %s\n",
            __func__, __LINE__, j, radio_index, vap_info->vap_index, bss_str);

        switch (policy_type) {
        case em_ap_metrics_only:
            break;

        case em_ap_metrics_link:
            //wifi_util_dbg_print(WIFI_EM, "%s:%d Include Link metrics only\n", __func__, __LINE__);
            vap_report->is_sta_link_metrics_enabled = true;
            if (vap_report->sta_cnt == 0)
            {
                continue;
            }
            vap_report->sta_link_metrics = (per_sta_metrics_t *)malloc(
                vap_report->sta_cnt * sizeof(per_sta_metrics_t));
            memset(vap_report->sta_link_metrics, 0, sizeof(per_sta_metrics_t));
            stats = hash_map_get_first(
                em_ap_metrics_report_cache[radio_index].ap_data[cache_vap_index].client_stats_map);
            i = 0;
            while (stats != NULL) {
                prepare_sta_lins_metrics_data(&vap_report->sta_link_metrics[i], stats,
                    vap_info->vap_index);
                stats = hash_map_get_next(
                    em_ap_metrics_report_cache[radio_index].ap_data[cache_vap_index].client_stats_map, stats);
                i++;
            }

            break;

        case em_ap_metrics_traffic:
           // wifi_util_dbg_print(WIFI_EM, "%s:%d Include Sta Traffic Stats\n", __func__, __LINE__);
            vap_report->is_sta_traffic_stats_enabled = true;
            if (vap_report->sta_cnt == 0)
            {
                continue;
            }
            vap_report->sta_traffic_stats = (assoc_sta_traffic_stats_t *)malloc(
                vap_report->sta_cnt * sizeof(assoc_sta_traffic_stats_t));
            memset(vap_report->sta_traffic_stats, 0, sizeof(assoc_sta_traffic_stats_t));

            stats = hash_map_get_first(
                em_ap_metrics_report_cache[radio_index].ap_data[cache_vap_index].client_stats_map);
            i = 0;
            while (stats != NULL) {
                prepare_sta_traffic_stats_data(&vap_report->sta_traffic_stats[i], stats);
                stats = hash_map_get_next(
                    em_ap_metrics_report_cache[radio_index].ap_data[cache_vap_index].client_stats_map, stats);
                i++;
            }
            break;

        case em_ap_metrics_link_and_traffic:
            wifi_util_dbg_print(WIFI_EM, "%s:%d Inlcude both Sta Link metrics and Traffic Stats\n",
                __func__, __LINE__);
            vap_report->is_sta_link_metrics_enabled = true;
            vap_report->is_sta_traffic_stats_enabled = true;
            if (vap_report->sta_cnt == 0) {
                continue;
            }
            vap_report->sta_link_metrics = (per_sta_metrics_t *)malloc(
                vap_report->sta_cnt * sizeof(per_sta_metrics_t));
            vap_report->sta_traffic_stats = (assoc_sta_traffic_stats_t *)malloc(
                vap_report->sta_cnt * sizeof(assoc_sta_traffic_stats_t));

            memset(vap_report->sta_link_metrics, 0, sizeof(per_sta_metrics_t));
            memset(vap_report->sta_traffic_stats, 0, sizeof(assoc_sta_traffic_stats_t));
            i = 0;

            stats = hash_map_get_first(
                em_ap_metrics_report_cache[radio_index].ap_data[cache_vap_index].client_stats_map);
            while (stats != NULL) {
                prepare_sta_traffic_stats_data(&vap_report->sta_traffic_stats[i], stats);
                prepare_sta_lins_metrics_data(&vap_report->sta_link_metrics[i], stats,
                    vap_info->vap_index);
                stats = hash_map_get_next(
                    em_ap_metrics_report_cache[radio_index].ap_data[cache_vap_index].client_stats_map, stats);
                i++;
            }
            break;

        default:
            break;
        }
    }

    data->u.decoded.hal_cap = wifi_mgr->hal_cap;
    data->u.decoded.radios[radio_index] = wifi_mgr->radio_config[radio_index];
    data->type = webconfig_subdoc_type_em_ap_metrics_report;

    if (webconfig_encode(&ctrl->webconfig, data, webconfig_subdoc_type_em_ap_metrics_report) ==
        webconfig_error_none) {
        wifi_util_info_print(WIFI_EM, "%s: ap report encoded successfully  \n", __FUNCTION__);
    } else {
        wifi_util_error_print(WIFI_EM, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
        rc = RETURN_ERR;
        goto cleanup;
    }

    rdata.data_type = bus_data_type_string;
    rdata.raw_data.bytes = (void *)data->u.encoded.raw;
    rdata.raw_data_len = strlen(data->u.encoded.raw) + 1;

    rc = get_bus_descriptor()->bus_event_publish_fn(&args->app->ctrl->handle,
        WIFI_EM_AP_METRICS_REPORT, &rdata);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_EM, "%s:%d: bus: bus_event_publish_fn Event failed %d\n",
            __func__, __LINE__, rc);
        rc = RETURN_ERR;
        goto cleanup;
    }

cleanup:
    // Cleanup allocated memory
    if (data != NULL) {
        for (i = 0; i < radio->vaps.num_vaps; i++) {
            vap_report = &data->u.decoded.em_ap_metrics_report.vap_reports[i];
            if (vap_report->sta_link_metrics != NULL) {
                free(vap_report->sta_link_metrics);
            }
            if (vap_report->sta_traffic_stats != NULL) {
                free(vap_report->sta_traffic_stats);
            }
        }
        free(data);
    }

    return rc;
}

int em_ap_report_config_task(wifi_app_t *app, em_config_t *em_config, wifi_mon_stats_request_state_t state,
    int radio_index, em_policy_req_type_t policy_type)
{
    int rc = RETURN_OK;
    int interval = em_config->ap_metric_policy.interval;
    em_ap_report_callback_arg_t *task_args = &em_ap_metrics_report_cache[radio_index].args;

    if (state == mon_stats_request_state_stop) {
        rc = scheduler_cancel_timer_task(app->ctrl->sched, em_ap_metrics_report_cache[radio_index].args.sched_id);
        if (rc != 0) {
            wifi_util_error_print(WIFI_EM, "%s:%d: Schedular task removal failure for sched id %d\n", __func__,
                __LINE__, em_ap_metrics_report_cache[radio_index].args.sched_id);
            return RETURN_ERR;
        }
        wifi_util_dbg_print(WIFI_EM, "%s:%d: Schedular task removal success for sched_id:%d\n", __func__,
            __LINE__, em_ap_metrics_report_cache[radio_index].args.sched_id);

        em_ap_metrics_report_cache[radio_index].args.sched_id = 0;

        return RETURN_OK;
    }

    task_args->app = app;
    task_args->radio_index = radio_index;
    task_args->policy_type = policy_type;

    rc = scheduler_add_timer_task(app->ctrl->sched, FALSE, &(em_ap_metrics_report_cache[radio_index].args.sched_id),
        ap_report_push_cb, task_args, interval * 1000, 0, FALSE);
    if (rc != RETURN_OK) {
        wifi_util_error_print(WIFI_EM, "%s:%d: failed to add timer task\n", __func__, __LINE__);
    }

    wifi_util_dbg_print(WIFI_EM, "%s:%d: added timer task %d with interval=%d for radio index %d\n",
        __func__, __LINE__, em_ap_metrics_report_cache[radio_index].args.sched_id, interval, task_args->radio_index);

    return RETURN_OK;
}

int ap_metrics_collector_config(wifi_app_t *app, wifi_monitor_data_t *data,
    wifi_mon_stats_request_state_t state, em_config_t *em_config, em_policy_req_type_t policy_type)
{
    wifi_event_route_t route;
    //int interval = app->data.u.em_data.em_config.ap_metric_policy.interval;
    radio_metrics_policy_t *metrics_pol = NULL;
    em_policy_req_type_t ap_metrics_inclusion;
    int radio_index = -1;
    int radio_count = -1;
    unsigned int i = 0;

    em_route(&route);

    if (em_common_config_to_monitor_queue(data, em_config) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM, "%s:%d em Config creation failed %d\r\n", __func__, __LINE__,
            stats_type_client);
        return RETURN_ERR;
    }

    // 1. configure collection task and push to monitor Q
    // 2. Start schedular to collect reports from cache and publish to agent every interval
    // requested by Agent
    radio_count = em_config->radio_metrics_policies.radio_count;

    for (i = 0; i < radio_count; i++) {
        radio_index = em_get_radio_index_from_mac(
            em_config->radio_metrics_policies.radio_metrics_policy[i].ruid);

        if (index == RETURN_ERR) {
            return RETURN_ERR;
        }

        data[i].u.mon_stats_config.data_type = mon_stats_type_radio_channel_stats;
        data[i].u.mon_stats_config.args.radio_index = radio_index;
        data[i].u.mon_stats_config.args.app_info = em_app_event_type_ap_metrics_rad_chan_stats;
        data[i].u.mon_stats_config.interval_ms =
            em_config->ap_metric_policy.interval * 1000;
        data->u.mon_stats_config.start_immediately = true;

        push_event_to_monitor_queue(data + i, wifi_event_monitor_data_collection_config, &route);

        if (em_config->ap_metric_policy.interval == 0 ||
            em_ap_metrics_report_cache[radio_index].args.sched_id == 0) {
            em_ap_report_config_task(app, em_config, state, radio_index, policy_type);
        } else if (em_config->ap_metric_policy.interval != em_ap_metrics_report_cache[radio_index].args.current_interval &&
                   em_ap_metrics_report_cache[radio_index].args.sched_id > 0) {
            if (scheduler_update_timer_task_interval(app->ctrl->sched,
                em_ap_metrics_report_cache[radio_index].args.sched_id,
                em_config->ap_metric_policy.interval * 1000) != 0) {

                wifi_util_error_print(WIFI_EM, "%s:%d scheduler_update_timer_task_interval failed for timer task %d of radio %d\r\n",
                    __func__, __LINE__,
                    em_ap_metrics_report_cache[radio_index].args.sched_id, radio_index);
            } else {
                wifi_util_error_print(WIFI_EM, "%s:%d scheduler_update_timer_task_interval success for timer task:%d with interval=%d for radio %d\n",
                    __func__, __LINE__, em_ap_metrics_report_cache[radio_index].args.sched_id,
                    em_config->ap_metric_policy.interval, radio_index);
            }
        }

        em_ap_metrics_report_cache[radio_index].args.policy_type = policy_type;
        em_ap_metrics_report_cache[radio_index].args.current_interval = em_config->ap_metric_policy.interval;
    }

    return RETURN_OK;
}

int ap_metrics_config_to_monitor_queue(wifi_app_t *app, wifi_monitor_data_t *data,
    wifi_mon_stats_request_state_t state, em_config_t *em_config)
{
    int interval = em_config->ap_metric_policy.interval;
    radio_metrics_policy_t *metrics_pol = NULL;
    em_policy_req_type_t ap_metrics_inclusion = em_ap_metrics_none;
    int rad_cnt = em_config->radio_metrics_policies.radio_count;
    int i = 0;

    if (em_config->ap_metric_policy.interval > 0) {
        for (i = 0; i < rad_cnt; i++) {
            metrics_pol = &em_config->radio_metrics_policies.radio_metrics_policy[i];
            // check further if other optional fields to be included
            if (metrics_pol->traffic_stats == true) {
                if (metrics_pol->link_metrics == true) {
                    ap_metrics_inclusion = em_ap_metrics_link_and_traffic;
                } else {
                    ap_metrics_inclusion = em_ap_metrics_traffic;
                }
            } else if (metrics_pol->link_metrics == true) {
                if (metrics_pol->traffic_stats == true) {
                    ap_metrics_inclusion = em_ap_metrics_link_and_traffic;
                } else {
                    ap_metrics_inclusion = em_ap_metrics_link;
                }
            } else {
                ap_metrics_inclusion = em_ap_metrics_only;
            }
        }
    }

    ap_metrics_collector_config(app, data, state, em_config, ap_metrics_inclusion);

    switch (ap_metrics_inclusion) {
    case em_ap_metrics_only:
        //  client_diag_config_to_monitor_queue(app, data, em_app_event_type_assoc_dev_sta_count);
        break;

    case em_ap_metrics_link:
    case em_ap_metrics_traffic:
    case em_ap_metrics_link_and_traffic:
        client_diag_config_to_monitor_queue(app, data, em_app_event_type_assoc_dev_stats_periodic);

        wifi_util_dbg_print(WIFI_EM, "%s:%d collect link/trafic/both as part of AP Metrics\r\n",
            __func__, __LINE__);
        break;

    default:
        break;
    }

    return RETURN_OK;
}

int push_em_config_event_to_monitor_queue(wifi_app_t *app, wifi_mon_stats_request_state_t state,
    em_policy_req_type_t policy, em_config_t *em_config)
{
    wifi_monitor_data_t *data = NULL;
    int ret = RETURN_ERR;
    int radio_count = em_config->radio_metrics_policies.radio_count;
    int i = 0;

    wifi_util_dbg_print(WIFI_EM, "%s:%d radio_count %d\r\n", __func__, __LINE__, radio_count);

    data = (wifi_monitor_data_t *)malloc(radio_count * sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d data allocation failed\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(data, 0, radio_count * sizeof(wifi_monitor_data_t));

    for (i = 0; i < radio_count; i++) {
        data[i].u.mon_stats_config.req_state = state;
    }

    switch (policy) {
    case em_policy_req_type_link_metrics:
        wifi_util_dbg_print(WIFI_EM, "%s:%d em_policy_req_type_link_metrics\n", __func__, __LINE__);
        ret = client_diag_config_to_monitor_queue(app, data,
            em_app_event_type_assoc_stats_rcpi_monitor);
        break;

    case em_policy_req_type_ap_metrics:
        wifi_util_dbg_print(WIFI_EM, "%s:%d em_policy_req_type_ap_metrics\n", __func__, __LINE__);
        ret = ap_metrics_config_to_monitor_queue(app, data, state, em_config);
        break;

    default:
        break;
    }

    if (ret == RETURN_ERR) {
        wifi_util_error_print(WIFI_EM, "%s:%d Event trigger failed for %d\r\n", __func__, __LINE__,
            stats_type_client);
        free(data);
        return RETURN_ERR;
    }

    free(data);

    return RETURN_OK;
}

static void ap_report_cache_init()
{
    for (int i = 0; i < MAX_NUM_RADIOS; i++) {
        for (int j = 0; j < MAX_NUM_VAP_PER_RADIO; j++) {
            em_ap_metrics_report_cache[i].ap_data[j].client_stats_map = hash_map_create();
            wifi_util_dbg_print(WIFI_EM, "%s:%d: Hash maps created\n", __func__, __LINE__);
        }
    }
}

int handle_em_webconfig_event(wifi_app_t *app, wifi_event_t *event)
{
    em_config_t *current_policy_cfg = &app->data.u.em_data.em_config;
    int temp_count = 0;
    bool size_change;
    webconfig_subdoc_data_t *webconfig_data = NULL;
    radio_metrics_policy_t *metrics_pol = NULL;
    em_config_t *new_policy_cfg = NULL;
    int rad_cnt = -1;
    em_policy_req_type_t ap_metrics_inclusion;
    bool interval_changed = false;
    bool metrics_different = false;

    if (event == NULL) {
        wifi_util_dbg_print(WIFI_EM, "%s %d input arguements are NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    webconfig_data = event->u.webconfig_data;
    if (webconfig_data == NULL) {
        wifi_util_dbg_print(WIFI_EM, "%s %d webconfig_data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (webconfig_data->type != webconfig_subdoc_type_em_config) {
        return RETURN_ERR;
    }

    new_policy_cfg = &webconfig_data->u.decoded.em_config;
    rad_cnt = new_policy_cfg->radio_metrics_policies.radio_count;

    /*  AP metrics:
        1. if currently policy interval is active, stop the time and reset timer. If not start
       afresh if > 0
        2. if interval is same, skip interval check, check other policy changes,
        3. if policy interval = 0 just stop
        4. Also RCPI/Threshhold for AP metrics - TBD
        5. channel util > 0, if recent collection has crossed limit - TBD*/

    // check for em_app_policy_req_type_ap_metrics
    // only update ap metrics related data to app data's config
    for (int i = 0; i < rad_cnt; i++) {
        metrics_pol = &new_policy_cfg->radio_metrics_policies.radio_metrics_policy[i];
        interval_changed = false;
        metrics_different = false;
        if (new_policy_cfg->ap_metric_policy.interval != current_policy_cfg->ap_metric_policy.interval) {
            interval_changed = true;
        }

        if (memcmp(&new_policy_cfg->radio_metrics_policies,
                   &current_policy_cfg->radio_metrics_policies,
                   sizeof(radio_metrics_policies_t)) != 0) {
            metrics_different = true;
        }

        if (new_policy_cfg->ap_metric_policy.interval >= 0 ||
            (interval_changed && metrics_different)) {
            wifi_util_dbg_print(WIFI_EM, "%s:%d New radio ap policy rcvd \n", __func__, __LINE__);
            temp_count = new_policy_cfg->radio_metrics_policies.radio_count;
            current_policy_cfg->radio_metrics_policies.radio_count = temp_count;
            if (temp_count != 0) {
                memcpy(current_policy_cfg->radio_metrics_policies.radio_metrics_policy,
                    new_policy_cfg->radio_metrics_policies.radio_metrics_policy,
                    temp_count * sizeof(radio_metrics_policy_t));

                current_policy_cfg->ap_metric_policy.interval =
                    new_policy_cfg->ap_metric_policy.interval;

                wifi_util_dbg_print(WIFI_EM, "%s:%d New radio ap policy updated \n", __func__,
                    __LINE__);
            }
        }
        if (current_policy_cfg->ap_metric_policy.interval == 0) {
            push_em_config_event_to_monitor_queue(app, mon_stats_request_state_stop,
                em_policy_req_type_ap_metrics, new_policy_cfg);
        } else {
            push_em_config_event_to_monitor_queue(app, mon_stats_request_state_start,
                em_policy_req_type_ap_metrics, new_policy_cfg);
        }
    }

    /*  1. STA Rcpi/threshold ==> send only link metrics
        2. sta link metrics = 1, then send as part of ap metrics, not covered here */
    // em_app_policy_req_type_link_metrics
    for (int i = 0; i < rad_cnt; i++) {
        if (new_policy_cfg->radio_metrics_policies.radio_metrics_policy[i].sta_rcpi_threshold > 0) {
            temp_count = new_policy_cfg->radio_metrics_policies.radio_count;
            current_policy_cfg->radio_metrics_policies.radio_count = temp_count;
            if (temp_count != 0) {
                //To be tested, commenting as this overrides the curre
                memcpy(current_policy_cfg->radio_metrics_policies.radio_metrics_policy,
                    new_policy_cfg->radio_metrics_policies.radio_metrics_policy,
                    temp_count * sizeof(radio_metrics_policy_t));
            }

            push_em_config_event_to_monitor_queue(app, mon_stats_request_state_start,
                em_policy_req_type_link_metrics, current_policy_cfg);
        } else {
            // stop monitoring if 0
            push_em_config_event_to_monitor_queue(app, mon_stats_request_state_stop,
                em_policy_req_type_link_metrics, current_policy_cfg);
        }
    }
#if 0
    current_policy_cfg->em_config.ap_metric_policy = new_policy_cfg->ap_metric_policy;
    current_policy_cfg->em_config.backhaul_bss_config_policy =
        new_policy_cfg->backhaul_bss_config_policy;

    temp_count = new_policy_cfg->btm_steering_dslw_policy.sta_count;
    current_policy_cfg->em_config.btm_steering_dslw_policy.sta_count = temp_count;

    if (temp_count != 0) {
        memcpy(current_policy_cfg->em_config.btm_steering_dslw_policy.disallowed_sta,
            new_policy_cfg->btm_steering_dslw_policy.disallowed_sta,
            temp_count * sizeof(mac_addr_t));
    }

    current_policy_cfg->em_config.channel_scan_reporting_policy =
        new_policy_cfg->channel_scan_reporting_policy;

    temp_count = new_policy_cfg->local_steering_dslw_policy.sta_count;
    current_policy_cfg->em_config.local_steering_dslw_policy.sta_count = temp_count;
    if (temp_count != 0) {
        memcpy(current_policy_cfg->em_config.local_steering_dslw_policy.disallowed_sta,
            new_policy_cfg->local_steering_dslw_policy.disallowed_sta,
            temp_count * sizeof(mac_addr_t));
    }

    temp_count = new_policy_cfg->radio_metrics_policies.radio_count;
    current_policy_cfg->em_config.radio_metrics_policies.radio_count = temp_count;
    if (temp_count != 0) {
        memcpy(current_policy_cfg->em_config.radio_metrics_policies.radio_metrics_policy,
            new_policy_cfg->radio_metrics_policies.radio_metrics_policy,
            temp_count * sizeof(radio_metrics_policy_t));
    }

    push_em_config_event_to_monitor_queue(app, mon_stats_request_state_start);
#endif
    return RETURN_OK;
}

static int em_process_scan_init_command(unsigned int radio_index, channel_scan_request_t *scan_req)
{
    wifi_mgr_t *mgr;
    wifi_ctrl_t *ctrl;
    wifi_monitor_data_t *data;
    int valid_chan_count = 0;
    char country[8] = { 0 };
    unsigned int global_op_class;

    wifi_util_dbg_print(WIFI_EM, "%s:%d radio_index: %d \n", __func__, __LINE__, radio_index);

    mgr = get_wifimgr_obj();
    if (mgr == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Mgr object is NULL \r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d: ctrl is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    data = (wifi_monitor_data_t *)malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d data allocation failed\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(data, 0, sizeof(wifi_monitor_data_t));

    get_coutry_str_from_code(mgr->radio_config[radio_index].oper.countryCode, country);
    global_op_class = country_to_global_op_class(country,
        mgr->radio_config[radio_index].oper.operatingClass);

    for (int i = 0; i < scan_req->num_operating_classes; i++) {
        if (scan_req->operating_classes[i].operating_class == global_op_class) {
            for (int j = 0; j < scan_req->operating_classes[i].num_channels; j++) {
                data->u.mon_stats_config.args.channel_list.channels_list[valid_chan_count] =
                    scan_req->operating_classes[i].channels[j];
                wifi_util_dbg_print(WIFI_EM, "%s:%d channel number:%u\n", __func__, __LINE__,
                    scan_req->operating_classes[i].channels[j]);
                valid_chan_count++;
            }
            break;
        }
    }

    data->u.mon_stats_config.args.radio_index = radio_index;
    // dummy value since it will be cancelled after first result
    data->u.mon_stats_config.interval_ms = EM_NEIGBOUR_SCAN_INTERVAL_MSEC;
    data->u.mon_stats_config.args.channel_list.num_channels = valid_chan_count;
    if (valid_chan_count > 0)
        data->u.mon_stats_config.args.scan_mode =
            WIFI_RADIO_SCAN_MODE_SELECT_CHANNELS; // Scan only requested channels.
    else
        data->u.mon_stats_config.args.scan_mode =
            WIFI_RADIO_SCAN_MODE_FULL; // Perform Full Scan since no channels in request.
    data->u.mon_stats_config.inst = wifi_app_inst_easymesh;
    data->u.mon_stats_config.args.dwell_time = 20;
    data->u.mon_stats_config.req_state = mon_stats_request_state_start;
    data->u.mon_stats_config.start_immediately = true;
    data->u.mon_stats_config.delay_provider_sec = EM_NEIGBOUR_SCAN_PROVIDER_DELAY_SEC;

    config_em_neighbour_scan(data, radio_index);
    // config_em_chan_util(data, radio_index);

    if (NULL != data) {
        free(data);
        data = NULL;
    }
    return RETURN_OK;
}

static void em_config_channel_scan(void *data, unsigned int len)
{
    mac_address_t radio_mac;
    mac_addr_str_t mac_str;
    radio_interface_mapping_t *radio_iface_map = NULL;
    channel_scan_request_t *scan_req;
    wifi_mgr_t *mgr;
    wifi_platform_property_t *wifi_prop;

    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d NUll data Pointer\n", __func__, __LINE__);
        return;
    }

    if (len < sizeof(channel_scan_request_t)) {
        wifi_util_error_print(WIFI_EM, "%s:%d Invalid parameter size \r\n", __func__, __LINE__);
        return;
    }

    mgr = get_wifimgr_obj();
    if (mgr == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Mgr object is NULL \r\n", __func__, __LINE__);
        return;
    }

    wifi_prop = &mgr->hal_cap.wifi_prop;
    scan_req = (channel_scan_request_t *)data;

    for (unsigned int k = 0;
         k < (sizeof(wifi_prop->radio_interface_map) / sizeof(radio_interface_mapping_t)); k++) {
        radio_iface_map = &(wifi_prop->radio_interface_map[k]);
        if (radio_iface_map == NULL) {
            printf("%s:%d: Unable to find the radio interface map entry \n", __func__, __LINE__);
            return;
        }
        mac_address_from_name(radio_iface_map->interface_name, radio_mac);
        if (memcmp(scan_req->ruid, radio_mac, sizeof(mac_addr_t)) == 0) {
            wifi_util_dbg_print(WIFI_EM, "%s:%d Processing channel scan for Radio : %s\n", __func__,
                __LINE__, to_mac_str(radio_mac, mac_str));
            em_process_scan_init_command(wifi_prop->radio_interface_map[k].radio_index, scan_req);
            break;
        }
    }
}
static void em_toggle_disconn_steady_state(void *data, unsigned int len)
{

    vap_svc_t* ext_svc = NULL;
    vap_svc_ext_t* ext = NULL;
    bool do_set;

    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d NUll data Pointer\n", __func__, __LINE__);
        return;
    }
    if (len < sizeof(bool)) {
        wifi_util_error_print(WIFI_EM, "%s:%d Invalid parameter size \r\n", __func__, __LINE__);
        return;
    }
    
    do_set = *(bool *)data;
    if (do_set) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d: Setting disconnected steady state\n", __func__,
            __LINE__);
    } else {
        wifi_util_dbg_print(WIFI_EM, "%s:%d: Unsetting disconnected steady state -> "
                                     "Setting disconnected scan list none state \n", __func__,
                                     __LINE__);
    }



    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    ext_svc = get_svc_by_type(ctrl, vap_svc_type_mesh_ext);
    ext = &ext_svc->u.ext;

    if (do_set){
        if (ext->conn_state == connection_state_connected ||
            ext->conn_state == connection_state_connected_scan_list ||
            ext->conn_state == connection_state_connected_wait_for_csa || 
            ext->conn_state == connection_state_connection_in_progress ||
            ext->conn_state == connection_state_connection_to_lcb_in_progress ||
            ext->conn_state == connection_state_connection_to_nb_in_progress) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d cannot transition from `connection_state_*` state "
                                             "(%d) to `connection_state_disconnected_steady`\r\n",
                                             __FUNCTION__, __LINE__, ext->conn_state);
            return bus_error_general;
        }
    
        ext->conn_state = connection_state_disconnected_steady;
    } else {
        if (ext->conn_state != connection_state_disconnected_steady) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d cannot selectively transition from any state "
                                             "besides `connection_state_disconnected_steady` to "
                                             "`connection_state_disconnected_scan_list_none`\r\n",
                                             __FUNCTION__, __LINE__);
            return bus_error_general;
        }
        ext->conn_state = connection_state_disconnected_scan_list_none;

        // Timeout to reset the SVC
        ext_svc->event_fn(ext_svc, wifi_event_type_exec, wifi_event_exec_timeout, vap_svc_event_none, NULL);
    }

    return bus_error_success;
}
void handle_em_command_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->sub_type) {
    case wifi_event_type_notify_monitor_done:
        is_monitor_done = TRUE;
        break;

    case wifi_event_type_start_channel_scan:
        if (is_monitor_done) {
            em_config_channel_scan(event->u.core_data.msg, event->u.core_data.len);
        }
        break;

    case wifi_event_type_sta_client_info:
        handle_sta_client_info(app, event->u.core_data.msg);
        break;

    case wifi_event_type_toggle_disconn_steady_state:
        em_toggle_disconn_steady_state(event->u.core_data.msg, event->u.core_data.len);
        break;
    default:
        break;
    }
}

static int em_beacon_report_publish(bus_handle_t *handle, void *msg_data)
{
    int rc;
    sta_beacon_report_reponse_t *temp_data_t = NULL;
    webconfig_subdoc_data_t *wb_data = NULL;
    wifi_ctrl_t *ctrl = NULL;
    raw_data_t p_data;
    wifi_mgr_t *mgr = NULL;

    if (msg_data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s %d NULL pointer \n", __func__, __LINE__);
        return 0;
    }

    wb_data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (wb_data == NULL) {
        wifi_util_error_print(WIFI_EM,
            "%s %d malloc failed to allocate webconfig_subdoc_data_t, size %d\n", __func__,
            sizeof(webconfig_subdoc_data_t));
        return bus_error_general;
    }

    memset(wb_data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy(&(wb_data->u.decoded.sta_beacon_report), msg_data, sizeof(sta_beacon_report_reponse_t));

    mgr = get_wifimgr_obj();
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wb_data->u.decoded.hal_cap = mgr->hal_cap;
    if (webconfig_encode(&ctrl->webconfig, wb_data, webconfig_subdoc_type_beacon_report) !=
        webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
        if (wb_data != NULL) {
            free(wb_data);
        }
        return bus_error_general;
    }

    memset(&p_data, 0, sizeof(raw_data_t));

    p_data.data_type = bus_data_type_string;
    p_data.raw_data.bytes = (void *)wb_data->u.encoded.raw;
    p_data.raw_data_len = strlen(wb_data->u.encoded.raw) + 1;

    rc = get_bus_descriptor()->bus_event_publish_fn(handle, WIFI_EM_BEACON_REPORT, &p_data);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_EM, "%s:%d: bus_event_publish_fn Event failed %d\n", __func__,
            __LINE__, rc);
        free(wb_data);
        return RETURN_ERR;
    } else {
        wifi_util_dbg_print(WIFI_EM, "%s:%d: bus_event_publish_fn Event for %s\n", __func__,
            __LINE__, WIFI_EM_BEACON_REPORT);
    }

    return RETURN_OK;
}

void em_beacon_report_frame_event(wifi_app_t *apps, void *data)
{
    wifi_app_t *wifi_app = NULL;

    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr;

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d NULL Pointer \n", __func__, __LINE__);
        free(data);
        return -1;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_easymesh);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    em_beacon_report_publish(&wifi_app->ctrl->handle, data);
}

int handle_em_hal_event(wifi_app_t *app, wifi_event_subtype_t sub_type, void *data)
{
    switch (sub_type) {
    case wifi_event_br_report:
        em_beacon_report_frame_event(app, data);
        break;

    case wifi_event_hal_disassoc_device:
        wifi_util_info_print(WIFI_EM, "%s:%d: wifi_event_hal_disassoc_device \n", __func__,
            __LINE__);
        em_handle_disassoc_device(app, data);
        break;
    
    case wifi_event_hal_sta_conn_status:
        em_handle_sta_conn_status(app, data);
        break;

    default:
        wifi_util_dbg_print(WIFI_EM, "%s:%d app sub_event:%s not handled\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
        break;
    }
    return RETURN_OK;
}

bus_error_t start_channel_scan(char *name, raw_data_t *p_data)
{
    unsigned int len = 0;
    char *pTmp = NULL;

    if (!name) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d property name is not found\r\n", __FUNCTION__,
            __LINE__);
        return bus_error_element_name_missing;
    }

    pTmp = (char *)p_data->raw_data.bytes;
    if ((p_data->data_type != bus_data_type_bytes) || (pTmp == NULL)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d wrong bus data_type:%x\n", __func__, __LINE__,
            p_data->data_type);
        return bus_error_invalid_input;
    }

    len = p_data->raw_data_len;
    push_event_to_ctrl_queue((char *)pTmp, len, wifi_event_type_command,
        wifi_event_type_start_channel_scan, NULL);

    return bus_error_success;
}

bus_error_t set_disconn_steady_state(char *name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    (void)p_data;
    (void)user_data;
    
    if (!name) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d property name is not found\r\n", __FUNCTION__,
            __LINE__);
        return bus_error_element_name_missing;
    }

    bool do_set_disconn_steady_state = true;
    push_event_to_ctrl_queue((char *)&do_set_disconn_steady_state, (unsigned int)sizeof(bool), 
                              wifi_event_type_command, wifi_event_type_toggle_disconn_steady_state, NULL);

    return bus_error_success;
}

bus_error_t set_disconn_scan_none_state(char *name, raw_data_t *p_data, bus_user_data_t *user_data)
{

    (void)p_data;
    (void)user_data;
    if (!name) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d property name is not found\r\n", __FUNCTION__,
            __LINE__);
        return bus_error_element_name_missing;
    }

    bool do_set_disconn_steady_state = false;
    push_event_to_ctrl_queue((char *)&do_set_disconn_steady_state, (unsigned int)sizeof(bool), 
                              wifi_event_type_command, wifi_event_type_toggle_disconn_steady_state, NULL);

    return bus_error_success;
}

int em_init(wifi_app_t *app, unsigned int create_flag)
{
    int rc = RETURN_OK;
    char *component_name = "WifiEM";
    int num_elements;
    em_config_t *policy_config = &app->data.u.em_data.em_config;

    bus_data_element_t dataElements[] = {
        { WIFI_EM_CHANNEL_SCAN_REQUEST, bus_element_type_method,
            { NULL, start_channel_scan, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, true, 0, 0, 0, NULL } },
        { WIFI_SET_DISCONN_STEADY_STATE, bus_element_type_method,
            { NULL, set_disconn_steady_state, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_none, true, 0, 0, 0, NULL } },
        { WIFI_SET_DISCONN_SCAN_NONE_STATE, bus_element_type_method,
            { NULL, set_disconn_scan_none_state, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_none, true, 0, 0, 0, NULL } },
        { WIFI_EM_CHANNEL_SCAN_REPORT, bus_element_type_event,
            { NULL, NULL, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, false, 0, 0, 0, NULL } },
        { WIFI_EM_BEACON_REPORT, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { WIFI_EM_STA_LINK_METRICS_REPORT, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { WIFI_EM_ASSOCIATION_STATUS, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_byte, false, 0, 0, 0, NULL } } ,
        { WIFI_EM_AP_METRICS_REPORT, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } }
    };

    policy_config->btm_steering_dslw_policy.sta_count = 0;
    policy_config->local_steering_dslw_policy.sta_count = 0;
    policy_config->radio_metrics_policies.radio_count = 0;

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    client_type_info.sta_client_type.client_type_map = hash_map_create();

    ap_report_cache_init();

    rc = get_bus_descriptor()->bus_open_fn(&app->handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_EM,
            "%s:%d bus: bus_open_fn open failed for component:%s, rc:%d\n", __func__, __LINE__,
            component_name, rc);
        return RETURN_ERR;
    }

    num_elements = (sizeof(dataElements) / sizeof(bus_data_element_t));

    rc = get_bus_descriptor()->bus_reg_data_element_fn(&app->ctrl->handle, dataElements,
        num_elements);
    if (rc != bus_error_success) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d bus_reg_data_element_fn failed, rc:%d\n", __func__,
            __LINE__, rc);
    } else {
        wifi_util_info_print(WIFI_EM, "%s:%d Apps bus_regDataElement success\n", __func__,
            __LINE__);
    }

    wifi_util_info_print(WIFI_EM, "%s:%d: Init em app %s\n", __func__, __LINE__,
        rc ? "failure" : "success");

    return rc;
}
  
int em_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
    case wifi_event_type_hal_ind:
        handle_em_hal_event(app, event->sub_type, event->u.core_data.msg);
        break;
    case wifi_event_type_webconfig:
        handle_em_webconfig_event(app, event);
        break;
    case wifi_event_type_monitor:
        monitor_event_em(app, event);
        break;
    case wifi_event_type_command:
        handle_em_command_event(app, event);
        break;
    default:
        break;
    }
    return RETURN_OK;
}

int em_deinit(wifi_app_t *app)
{
    void *tmp_data = NULL;
    mac_addr_str_t mac_str;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_EM, "%s:%d: em-app deinit\n", __func__, __LINE__);

    sta_client_info_t *t_sta_data = (sta_client_info_t *)hash_map_get_first(
        client_type_info.sta_client_type.client_type_map);
    while (t_sta_data != NULL) {
        memset(mac_str, 0, sizeof(mac_addr_str_t));
        to_mac_str((unsigned char *)t_sta_data->mac_addr, mac_str);
        tmp_data = (sta_client_info_t *)hash_map_remove(
            client_type_info.sta_client_type.client_type_map, mac_str);
        if (tmp_data != NULL) {
            free(tmp_data);
        }
        t_sta_data = hash_map_get_next(client_type_info.sta_client_type.client_type_map,
            t_sta_data);
    }
    hash_map_destroy(client_type_info.sta_client_type.client_type_map);

    return RETURN_OK;
}