#include "const.h"
#include "scheduler.h"
#include "wifi_em_utils.h"
#include "wifi_em.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include <stdbool.h>
#include <stdint.h>

#define DCA_TO_APP 1
#define APP_TO_DCA 2

#define EM_NEIGBOUR_SCAN_PROVIDER_DELAY_SEC 5 // 5 Seconds
#define EM_NEIGBOUR_SCAN_INTERVAL_MSEC 60000 // 60 Seconds
#define EM_LINK_METRICS_COLLECT_INTERVAL_MSEC 10000 // 10 Seconds

static bool is_monitor_done = false;

#define em_app_event_type_chan_stats 1
#define em_app_event_type_neighbor_stats 2

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

    for (int i = 0; i < num_of_radios; i++) {
        vap_map = (wifi_vap_info_map_t *)get_wifidb_vap_map(i);
        for (int j = 0; j < vap_map->num_vaps; j++) {
            if (memcmp(ruuid, vap_map->vap_array[j].u.bss_info.bssid, sizeof(mac_addr_t)) == 0)
                return vap_map->vap_array[j].radio_index;
        }
    }

    wifi_util_error_print(WIFI_EM, "%s:%d Radio Index not found\n", __func__, __LINE__);

    return RETURN_ERR;
}

static int em_match_radio_index_to_policy_index(radio_metrics_policies_t *radio_metrics_policies,
    int radio_index)
{
    int radio_count = radio_metrics_policies->radio_count;
    int found_index;
    for (int i = 0; i < radio_count; i++) {
        found_index = em_get_radio_index_from_mac(
            radio_metrics_policies->radio_metrics_policy[i].ruid);
        if (found_index == radio_index)
            return i;
    }

    wifi_util_error_print(WIFI_EM, "%s:%d Radio Index was not matched with policy\n", __func__,
        __LINE__);

    return RETURN_ERR;
}

int em_common_config_to_monitor_queue(wifi_app_t *app, wifi_monitor_data_t *data)
{
    int index = RETURN_ERR;
    int radio_count = app->data.u.em_data.em_config.radio_metrics_policies.radio_count;
    for (int i = 0; i < radio_count; i++) {
        data[i].u.mon_stats_config.inst = wifi_app_inst_easymesh;

        index = em_get_radio_index_from_mac(
            app->data.u.em_data.em_config.radio_metrics_policies.radio_metrics_policy[i].ruid);

        if (index == RETURN_ERR)
            return RETURN_ERR;

        data[i].u.mon_stats_config.args.radio_index = index;
        data[i].u.mon_stats_config.interval_ms =
            app->data.u.em_data.em_config.ap_metric_policy.interval *
            1000; // converting seconds to ms
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

static int prepare_sta_lins_metrics_data(wifi_app_t *app, webconfig_subdoc_data_t *data,
    client_assoc_data_t *stats, unsigned int vap_index)
{
    int sta_count = 0;
    int sta_it = 0;
    sta_client_info_t *cli_data;
    mac_addr_str_t key;

    for (int i = 0; i < MAX_NUM_VAP_PER_RADIO; i++) {
        sta_count += stats[i].hit_count;
        stats[i].hit_count = 0;
    }

    data->u.decoded.em_sta_link_metrics_rsp.sta_count = sta_count;
    data->u.decoded.em_sta_link_metrics_rsp.vap_index = vap_index;
    data->u.decoded.em_sta_link_metrics_rsp.per_sta_metrics = (per_sta_metrics_t *)malloc(
        sta_count * sizeof(per_sta_metrics_t));
    if (data->u.decoded.em_sta_link_metrics_rsp.per_sta_metrics == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d Error in allocating table for encode stats\n",
            __func__, __LINE__);
        free(data);
        return RETURN_ERR;
    }

    per_sta_metrics_t *param = data->u.decoded.em_sta_link_metrics_rsp.per_sta_metrics;
    for (int i = 0; i < MAX_NUM_VAP_PER_RADIO; i++) {
        for (int j = 0; j < stats[i].stat_array_size; j++) {
            if (stats[i].threshold_hit[j] == true) {

                stats[i].threshold_hit[j] = false;

                // Associated STA Link Metrics
                memcpy(param[sta_it].assoc_sta_link_metrics.sta_mac,
                    stats[i].assoc_stats[j].sta_mac, sizeof(mac_address_t));
                // Retrive client type info
                to_mac_str(stats[i].assoc_stats[j].sta_mac, key);
                cli_data = hash_map_get(client_type_info.sta_client_type.client_type_map, key);
                if (cli_data != NULL) {
                    strncpy(param[sta_it].assoc_sta_link_metrics.client_type, cli_data->client_type,
                        sizeof(cli_data->client_type));
                }
                param[sta_it].assoc_sta_link_metrics.num_bssid =
                    1; // must be changed for STA multiple associations
                memcpy(param[sta_it].assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].bssid,
                    stats[i].assoc_stats[j].link_mac,
                    sizeof(mac_address_t)); // where bssid can be found?
                param[sta_it].assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].time_delta =
                    0; // How to calculate time Delta (The time delta in ms between the time at
                       // which the earliest measurement that contributed to the data rate estimates
                       // were made, and the time at which this report was sent.)
                param[sta_it]
                    .assoc_sta_link_metrics.assoc_sta_link_metrics_data[0]
                    .est_mac_rate_down =
                    stats[i]
                        .assoc_stats[j]
                        .dev_stats.cli_MaxDownlinkRate; // I'm not sure if cli_MaxXXXX is the same
                                                        // as "Estimated MAC Data Rate in downlink"
                param[sta_it]
                    .assoc_sta_link_metrics.assoc_sta_link_metrics_data[0]
                    .est_mac_rate_up = stats[i].assoc_stats[j].dev_stats.cli_MaxUplinkRate;
                param[sta_it].assoc_sta_link_metrics.assoc_sta_link_metrics_data[0].rcpi =
                    em_rssi_to_rcpi(stats[i].assoc_stats[j].dev_stats.cli_RSSI);

                // Associated STA Extended Link Metrics
                memcpy(param[sta_it].assoc_sta_ext_link_metrics.sta_mac,
                    stats[i].assoc_stats[j].sta_mac, sizeof(mac_address_t));
                param[sta_it].assoc_sta_ext_link_metrics.num_bssid =
                    1; // must be changed for STA multiple associations
                memcpy(param[sta_it]
                           .assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0]
                           .bssid,
                    stats[i].assoc_stats[j].link_mac, sizeof(mac_address_t));
                param[sta_it]
                    .assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0]
                    .last_data_downlink_rate =
                    stats[i].assoc_stats[j].dev_stats.cli_LastDataDownlinkRate;
                param[sta_it]
                    .assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0]
                    .last_data_uplink_rate =
                    stats[i].assoc_stats[j].dev_stats.cli_LastDataUplinkRate;
                param[sta_it]
                    .assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0]
                    .utilization_receive = 0; // do we have that data?
                param[sta_it]
                    .assoc_sta_ext_link_metrics.assoc_sta_ext_link_metrics_data[0]
                    .utilization_transmit = 0;
                sta_it++;
            }
        }
    }
    return RETURN_OK;
}

static int em_sta_stats_publish(wifi_app_t *app, client_assoc_data_t *stats, unsigned int vap_index)
{
    webconfig_subdoc_data_t *data;
    raw_data_t rdata;
    int rc;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS,
            "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", __func__,
            sizeof(webconfig_subdoc_data_t));
        return -1;
    }

    // need to specify how to pack all the metrics, send one by one or into array?
    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    memset(&rdata, 0, sizeof(raw_data_t));
    data->u.decoded.em_sta_link_metrics_rsp.vap_index = vap_index;
    prepare_sta_lins_metrics_data(app, data, stats, vap_index);

    if (webconfig_encode(&ctrl->webconfig, data, webconfig_subdoc_type_em_sta_link_metrics) !=
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

    free(data->u.decoded.em_sta_link_metrics_rsp.per_sta_metrics);
    free(data);
}

static int handle_ready_client_stats(wifi_app_t *app, client_assoc_data_t *stats, size_t stats_num,
    unsigned int vap_mask, unsigned int radio_index, unsigned int vap_index)
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
                    RCPI = em_rssi_to_rcpi(sta_data->dev_stats.cli_RSSI);
                    wifi_util_dbg_print(WIFI_EM, "%s:%d: RCPI:%d \r\n", __func__, __LINE__, RCPI);
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
                }
            }
        }
        tmp_vap_index++;
        vap_mask >>= 1;
    }

    if (hit_count > 0)
        em_sta_stats_publish(app, stats, vap_index);

    return RETURN_OK;
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

    if ((client_assoc_stats[radio_index].assoc_stats_vap_presence_mask ==
            client_assoc_stats[radio_index].req_stats_vap_mask)) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d: push stats for radio_index : %d \r\n", __func__,
            __LINE__, radio_index);
        handle_ready_client_stats(app, client_assoc_stats[radio_index].client_assoc_data,
            MAX_NUM_VAP_PER_RADIO, client_assoc_stats[radio_index].assoc_stats_vap_presence_mask,
            radio_index, vap_index);
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

    case em_app_event_type_assoc_dev_stats:
        ret = assoc_client_response(app, provider_response);
        break;
    case em_app_event_type_neighbor_stats:
        ret = em_process_neighbour_data(provider_response);
        break;
    case em_app_event_type_chan_stats:
        ret = em_process_chan_stats_data(provider_response);
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
    unsigned char client_mac[32];
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
        printf("    Client Type Updated to stats cache [%s]\n", cli_data->client_type);
    }

    return RETURN_OK;
}

static int em_handle_disassoc_device(wifi_app_t *app, void *arg)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;
    char client_mac[32];

    wifi_util_dbg_print(WIFI_APPS, "%s:%d : Got disassoc event \n", __func__, __LINE__);
    to_mac_str((unsigned char *)assoc_data->dev_stats.cli_MACAddress, client_mac);
    sta_client_info_t *t_sta_data = (sta_client_info_t *)hash_map_remove(
        client_type_info.sta_client_type.client_type_map, client_mac);

    if (t_sta_data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Mac %s not present in hash map\n", __func__,
            __LINE__, client_mac);
        return 0;
    }

    free(t_sta_data);

    return 0;
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

int client_diag_config_to_monitor_queue(wifi_app_t *app, wifi_monitor_data_t *data)
{
    unsigned int vapArrayIndex = 0;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_event_route_t route;
    em_route(&route);
    if (em_common_config_to_monitor_queue(app, data) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM, "%s:%d em Config creation failed %d\r\n", __func__, __LINE__,
            stats_type_client);
        return RETURN_ERR;
    }

    int radio_count = app->data.u.em_data.em_config.radio_metrics_policies.radio_count;

    for (int i = 0; i < radio_count; i++) {
        data[i].u.mon_stats_config.data_type = mon_stats_type_associated_device_stats;
        data[i].u.mon_stats_config.interval_ms = EM_LINK_METRICS_COLLECT_INTERVAL_MSEC;

        if (client_assoc_stats[data[i].u.mon_stats_config.args.radio_index].req_stats_vap_mask ==
            0) {
            if (generate_vap_mask_for_radio_index(data[i].u.mon_stats_config.args.radio_index) ==
                RETURN_ERR) {
                wifi_util_error_print(WIFI_EM,
                    "%s:%d generate_vap_mask_for_radio_index failed \r\n", __func__, __LINE__);
                return RETURN_ERR;
            }
        }

        data[i].u.mon_stats_config.args.app_info = em_app_event_type_assoc_dev_stats;

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

int push_em_config_event_to_monitor_queue(wifi_app_t *app, wifi_mon_stats_request_state_t state)
{
    wifi_monitor_data_t *data;
    int ret = RETURN_ERR;
    int radio_count = app->data.u.em_data.em_config.radio_metrics_policies.radio_count;

    data = (wifi_monitor_data_t *)malloc(radio_count * sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM, "%s:%d data allocation failed\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(data, 0, radio_count * sizeof(wifi_monitor_data_t));

    for (int i = 0; i < radio_count; i++) {
        data[i].u.mon_stats_config.req_state = state;
    }

    ret = client_diag_config_to_monitor_queue(app, data);

    if (ret == RETURN_ERR) {
        wifi_util_error_print(WIFI_EM, "%s:%d Event trigger failed for %d\r\n", __func__, __LINE__,
            stats_type_client);
        free(data);
        return RETURN_ERR;
    }

    free(data);

    return RETURN_OK;
}

int handle_em_webconfig_event(wifi_app_t *app, wifi_event_t *event)
{
    webconfig_subdoc_data_t *webconfig_data = NULL;
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

    em_config_t *new_policy_cfg = &webconfig_data->u.decoded.em_config;
    em_data_t *current_policy_cfg = &app->data.u.em_data;
    int temp_count = 0;
    bool size_change;

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
        wifi_util_info_print(WIFI_APPS, "%s:%d: wifi_event_hal_disassoc_device \n", __func__,
            __LINE__);
        em_handle_disassoc_device(app, data);
        break;

    default:
        wifi_util_dbg_print(WIFI_EM, "%s:%d app sub_event:%s not handled\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
        break;
    }
    return RETURN_OK;
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
        { WIFI_EM_CHANNEL_SCAN_REPORT, bus_element_type_event,
            { NULL, NULL, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, false, 0, 0, 0, NULL } },
        { WIFI_EM_BEACON_REPORT, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } },
        { WIFI_EM_STA_LINK_METRICS_REPORT, bus_element_type_method,
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

int em_deinit(wifi_app_t *app)
{
    void *tmp_data = NULL;
    mac_addr_str_t mac_str;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    wifi_util_info_print(WIFI_APPS, "%s:%d: em-app deinit\n", __func__, __LINE__);

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