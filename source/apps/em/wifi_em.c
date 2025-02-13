#include <stdbool.h>
#include <stdint.h>
#include "scheduler.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_em.h"
#include "wifi_em_utils.h"
#include "const.h"

#define DCA_TO_APP 1
#define APP_TO_DCA 2

typedef struct {
    sta_data_t  assoc_stats[BSS_MAX_NUM_STATIONS];
    size_t      stat_array_size;
} client_assoc_data_t;

typedef struct {
    client_assoc_data_t client_assoc_data[MAX_NUM_VAP_PER_RADIO];
    unsigned int    assoc_stats_vap_presence_mask;
    unsigned int    req_stats_vap_mask;
} client_assoc_stats_t;

client_assoc_stats_t client_assoc_stats[MAX_NUM_RADIOS];

int em_survey_type_conversion(wifi_neighborScanMode_t *halw_scan_type, survey_type_t *app_stat_type, unsigned int conv_type)
{
    //is RADIO_SCAN_TYPE_NONE is required? as None survey type is not present
    unsigned int i = 0;
    wifi_neighborScanMode_t halw_scan_enum[] = {WIFI_RADIO_SCAN_MODE_FULL, WIFI_RADIO_SCAN_MODE_ONCHAN, WIFI_RADIO_SCAN_MODE_OFFCHAN};
    survey_type_t app_stat_enum[] = {survey_type_full, survey_type_on_channel, survey_type_off_channel};

    if ((halw_scan_type == NULL) || (app_stat_type == NULL)) {
        return RETURN_ERR;
    }

    if (conv_type == APP_TO_DCA) {
        for (i = 0; i < ARRAY_SIZE(app_stat_enum); i++) {
            if (*app_stat_type == app_stat_enum[i]) {
                *halw_scan_type = halw_scan_enum[i];
                return RETURN_OK;
            }
        }
    } else if (conv_type == DCA_TO_APP) {
        for (i = 0; i < ARRAY_SIZE(halw_scan_enum); i++) {
            if (*halw_scan_type == halw_scan_enum[i]) {
                *app_stat_type = app_stat_enum[i];
                return RETURN_OK;
            }
        }
    }

    return RETURN_ERR;
}

int em_common_config_to_monitor_queue(wifi_monitor_data_t *data, stats_config_t *stat_config_entry)
{
    data->u.mon_stats_config.inst = wifi_app_inst_easymesh;
    int index;
    if (convert_freq_band_to_radio_index(stat_config_entry->radio_type, &index) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,"%s:%d: convert freq_band %d  to radio_index failed \r\n",__func__, __LINE__, stat_config_entry->radio_type);
        return RETURN_ERR;
    }
    data->u.mon_stats_config.args.radio_index = index;
    data->u.mon_stats_config.interval_ms =  stat_config_entry->sampling_interval*1000; //converting seconds to ms

    return RETURN_OK;
}

static int em_stats_to_monitor_set(wifi_app_t *app)
{
    stats_config_t *cur_stats_cfg = NULL;
    hash_map_t *stats_cfg_map = NULL;

    if (!app) {
        wifi_util_error_print(WIFI_EM,"%s:%d: app is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    stats_cfg_map = app->data.u.em_data.em_stats_config_map;
    if (!stats_cfg_map) {
        wifi_util_error_print(WIFI_EM,"%s:%d: stats_cfg_map is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    cur_stats_cfg = hash_map_get_first(stats_cfg_map);
    while (cur_stats_cfg != NULL) {
        wifi_util_dbg_print(WIFI_EM,"%s:%d: Stopping the scan id='%s'\n", __func__, __LINE__, cur_stats_cfg->stats_cfg_id);
        push_em_config_event_to_monitor_queue(app, mon_stats_request_state_stop, cur_stats_cfg);
        cur_stats_cfg = hash_map_get_next(stats_cfg_map, cur_stats_cfg);
    }

    return RETURN_OK;
}

int free_em_stats_config_map(wifi_app_t *app)
{
    stats_config_t *stats_config = NULL, *temp_stats_config = NULL;
    char key[64] = {0};

    if (app->data.u.em_data.em_stats_config_map != NULL) {
        stats_config = hash_map_get_first(app->data.u.em_data.em_stats_config_map);
        while (stats_config != NULL) {
            memset(key, 0, sizeof(key));
            snprintf(key, sizeof(key), "%s", stats_config->stats_cfg_id);
            stats_config = hash_map_get_next(app->data.u.em_data.em_stats_config_map, stats_config);
            temp_stats_config = hash_map_remove(app->data.u.em_data.em_stats_config_map, key);
            if (temp_stats_config != NULL) {
                free(temp_stats_config);
            }
        }
        hash_map_destroy(app->data.u.em_data.em_stats_config_map);
        app->data.u.em_data.em_stats_config_map = NULL;
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

int neighbor_config_to_monitor_queue(wifi_monitor_data_t *data, stats_config_t *stat_config_entry)
{
    int i = 0;
    wifi_event_route_t route;
    wifi_neighborScanMode_t halw_scan_type;
    em_route(&route);

    if (em_common_config_to_monitor_queue(data, stat_config_entry) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,"%s:%d em Config creation failed %d\r\n", __func__, __LINE__, stat_config_entry->stats_type);
        return RETURN_ERR;
    }

    if (em_survey_type_conversion(&halw_scan_type, &stat_config_entry->survey_type, APP_TO_DCA) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,"%s:%d Invalid survey type %d\r\n", __func__, __LINE__, stat_config_entry->survey_type);
        return RETURN_ERR;
    }
    data->u.mon_stats_config.args.scan_mode = halw_scan_type;

    data->u.mon_stats_config.data_type = mon_stats_type_neighbor_stats;

    if (stat_config_entry->survey_type == survey_type_on_channel) {
        data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_ONCHAN;
        data->u.mon_stats_config.args.channel_list.num_channels = 0;
    } else {
        data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_OFFCHAN;
        data->u.mon_stats_config.args.channel_list.num_channels = stat_config_entry->channels_list.num_channels;
        for (i = 0;i < stat_config_entry->channels_list.num_channels; i++) {
            data->u.mon_stats_config.args.channel_list.channels_list[i] = stat_config_entry->channels_list.channels_list[i];
        }
    }

    if (data->u.mon_stats_config.interval_ms == 0) {
        data->u.mon_stats_config.interval_ms = stat_config_entry->reporting_interval * 1000; //converting seconds to ms
    }

    data->u.mon_stats_config.args.app_info = em_app_event_type_neighbor;

    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);

    return RETURN_OK;
}

int survey_config_to_monitor_queue(wifi_monitor_data_t *data, stats_config_t *stat_config_entry)
{
    int i = 0;
    wifi_neighborScanMode_t halw_scan_type;
    wifi_event_route_t route;
    em_route(&route);
    if (em_common_config_to_monitor_queue(data, stat_config_entry) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,"%s:%d em Config creation failed %d\r\n", __func__, __LINE__, stat_config_entry->stats_type);
        return RETURN_ERR;
    }

    if (em_survey_type_conversion(&halw_scan_type, &stat_config_entry->survey_type, APP_TO_DCA) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,"%s:%d Invalid survey type %d\r\n", __func__, __LINE__, stat_config_entry->survey_type);
        return RETURN_ERR;
    }
    data->u.mon_stats_config.args.scan_mode = halw_scan_type;

    data->u.mon_stats_config.data_type = mon_stats_type_radio_channel_stats;

    if (stat_config_entry->survey_type == survey_type_on_channel) {
        data->u.mon_stats_config.args.channel_list.num_channels = 0;
        data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_ONCHAN;
    } else {
        data->u.mon_stats_config.args.channel_list.num_channels = stat_config_entry->channels_list.num_channels;
        for (i = 0;i < stat_config_entry->channels_list.num_channels; i++) {
            data->u.mon_stats_config.args.channel_list.channels_list[i] = stat_config_entry->channels_list.channels_list[i];
        }
        data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_OFFCHAN;
    }
    data->u.mon_stats_config.args.app_info = em_app_event_type_survey;

    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);

    return RETURN_OK;
}

int neighbor_response(wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0;
    radio_index = provider_response->args.radio_index;
    unsigned int count = 0;
    wifi_neighbor_ap2_t *neighbor_ap = NULL;
    survey_type_t survey_type;
    wifi_neighborScanMode_t halw_scan_type = provider_response->args.scan_mode;

    if (em_survey_type_conversion(&halw_scan_type, &survey_type, DCA_TO_APP) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,"%s:%d: failed to convert scan_mode %d to survey_type for radio_index : %d\r\n",
            __func__, __LINE__, provider_response->args.scan_mode, radio_index);
        return RETURN_ERR;
    }

    neighbor_ap =  (wifi_neighbor_ap2_t *)provider_response->stat_pointer;

    wifi_util_dbg_print(WIFI_EM, "%s:%d: radio_index : %d stats_array_size : %d\r\n", __func__,
        __LINE__, radio_index, provider_response->stat_array_size);
    if (provider_response->stat_array_size == 0) {
        wifi_util_dbg_print(WIFI_EM, "%s:%d: No neighbor APs found in %s on %s\r\n", __func__,
            __LINE__, survey_type_to_str(survey_type), radio_index_to_radio_type_str(radio_index));
    } else {
        for (count = 0; count < provider_response->stat_array_size; count++) {
            wifi_util_dbg_print(WIFI_EM, "%s:%d: count : %d ap_SSID : %s\r\n", __func__, __LINE__,
                count, neighbor_ap[count].ap_SSID);
            //em_neighbor_sample_store(radio_index, survey_type, &neighbor_ap[count]);//are we interested in caching responses? we don't need contructing reports and sedning it over pipeline as it is opensync specific?
        }
    }
    return RETURN_OK;
}

int capacity_response(wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0;
    radio_index = provider_response->args.radio_index;
    radio_chan_data_t *channelStats = NULL;
    unsigned int count = 0;

    wifi_util_dbg_print(WIFI_EM,"%s:%d: radio_index : %d stats_array_size : %d\r\n",__func__, __LINE__, radio_index, provider_response->stat_array_size);

    channelStats = (radio_chan_data_t *)provider_response->stat_pointer;
    for (count = 0; count < provider_response->stat_array_size; count++) {
        wifi_util_dbg_print(WIFI_EM,"%s:%d: radio_index : %d channel_num : %d ch_utilization : %d\r\n",__func__, __LINE__, radio_index, channelStats[count].ch_number, channelStats[count].ch_utilization);
    }

    return RETURN_OK;
}

int survey_response(wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0;
    unsigned int count = 0;
    radio_index = provider_response->args.radio_index;
    radio_chan_data_t *channelStats = NULL;
    survey_type_t survey_type;
    wifi_neighborScanMode_t halw_scan_type = provider_response->args.scan_mode;

    if (em_survey_type_conversion(&halw_scan_type, &survey_type, DCA_TO_APP) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,"%s:%d: failed to convert scan_mode %d to survey_type for radio_index : %d\r\n",
                              __func__, __LINE__, provider_response->args.scan_mode, radio_index);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_EM,"%s:%d: radio_index : %d stats_array_size : %d\r\n",__func__, __LINE__, radio_index, provider_response->stat_array_size);

    channelStats = provider_response->stat_pointer;
    for (count = 0; count < provider_response->stat_array_size; count++) {
        wifi_util_dbg_print(WIFI_EM,"%s:%d: radio_index : %d channel_num : %d ch_utilization : %d ch_utilization_total:%lld survey_type : %d\r\n",
                            __func__, __LINE__, radio_index, channelStats[count].ch_number, channelStats[count].ch_utilization, channelStats[count].ch_utilization_total, survey_type);
        //sm_survey_sample_store(radio_index, survey_type, &channelStats[count]);//here
    }

    return RETURN_OK;
}

static int handle_ready_client_stats(client_assoc_data_t *stats, size_t stats_num, unsigned int vap_mask, unsigned int radio_index)
{
    unsigned int tmp_vap_index = 0;
    int tmp_vap_array_index = 0;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();

    if (!stats) {
        wifi_util_error_print(WIFI_EM,"%s:%d: stats is NULL for radio_index: %d\r\n",__func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    while (vap_mask) {
        /* check all VAPs */
        if (vap_mask & 0x1) {
            tmp_vap_array_index = convert_vap_index_to_vap_array_index(&wifi_mgr->hal_cap.wifi_prop, tmp_vap_index);
            if (tmp_vap_array_index >= 0 && tmp_vap_array_index < (int)stats_num) {
                size_t stat_array_size = stats[tmp_vap_array_index].stat_array_size;
                for (size_t i = 0; i < stat_array_size; i++) {
                    sta_data_t *sta_data = &stats[tmp_vap_array_index].assoc_stats[i];
                    if (!sta_data) {
                        continue;
                    }
                    if (sta_data->dev_stats.cli_Active == false) {
                        continue;
                    }
                    //sm_client_sample_store(radio_index, tmp_vap_index,
                        //&sta_data->dev_stats, &conn_info);
                }
            }
        }
        tmp_vap_index++;
        vap_mask >>= 1;
    }

    return RETURN_OK;
}

int assoc_client_response(wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0;
    unsigned int vap_index = 0;
    int vap_array_index = 0;
    radio_index = provider_response->args.radio_index;
    vap_index = provider_response->args.vap_index;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    char vap_name[32];

    if (convert_vap_index_to_name(&wifi_mgr->hal_cap.wifi_prop, vap_index, vap_name) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,"%s:%d: convert_vap_index_to_name failed for vap_index : %d\r\n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    vap_array_index = convert_vap_name_to_array_index(&wifi_mgr->hal_cap.wifi_prop, vap_name);
    if (vap_array_index == -1) {
        wifi_util_error_print(WIFI_EM,"%s:%d: convert_vap_name_to_array_index failed for vap_name: %s\r\n",__func__, __LINE__, vap_name);
        return RETURN_ERR;
    }

    memset(client_assoc_stats[radio_index].client_assoc_data[vap_array_index].assoc_stats, 0, sizeof(client_assoc_stats[radio_index].client_assoc_data[vap_array_index].assoc_stats));
    memcpy(client_assoc_stats[radio_index].client_assoc_data[vap_array_index].assoc_stats, provider_response->stat_pointer, (sizeof(sta_data_t)*provider_response->stat_array_size));
    client_assoc_stats[radio_index].client_assoc_data[vap_array_index].stat_array_size = provider_response->stat_array_size;
    client_assoc_stats[radio_index].assoc_stats_vap_presence_mask |= (1 << vap_index);

    wifi_util_dbg_print(WIFI_EM,"%s:%d: vap_index : %d client array size : %d \r\n",__func__, __LINE__, vap_index, provider_response->stat_array_size);

    if ((client_assoc_stats[radio_index].assoc_stats_vap_presence_mask == client_assoc_stats[radio_index].req_stats_vap_mask)) {
        wifi_util_dbg_print(WIFI_EM,"%s:%d: push to dpp for radio_index : %d \r\n",__func__, __LINE__, radio_index);
        handle_ready_client_stats(client_assoc_stats[radio_index].client_assoc_data,
                                  MAX_NUM_VAP_PER_RADIO,
                                  client_assoc_stats[radio_index].assoc_stats_vap_presence_mask,
                                  radio_index);
        client_assoc_stats[radio_index].assoc_stats_vap_presence_mask = 0;
    }

    return RETURN_OK;
}

int handle_monitor_provider_response(wifi_app_t *app, wifi_event_t *event)
{
    wifi_provider_response_t    *provider_response;
    provider_response = (wifi_provider_response_t *)event->u.provider_response;
    int ret = RETURN_ERR;

    if (provider_response == NULL) {
        wifi_util_error_print(WIFI_EM,"%s:%d: input event is NULL\r\n",__func__, __LINE__);
        return ret;
    }

    switch (provider_response->args.app_info) {
        case em_app_event_type_neighbor:
            ret = neighbor_response(provider_response);
        break;
        case em_app_event_type_capacity:
            ret = capacity_response(provider_response);
        break;
        case em_app_event_type_survey:
            ret = survey_response(provider_response);
        break;
        case em_app_event_type_assoc_dev_diag:
            ret = assoc_client_response(provider_response);
        break;
        default:
            wifi_util_error_print(WIFI_EM,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, provider_response->args.app_info);
    }

    return ret;
}

int monitor_event_em(wifi_app_t *app, wifi_event_t *event)
{
    int ret = RETURN_ERR;

    if (event == NULL) {
        wifi_util_error_print(WIFI_EM,"%s:%d: input event is NULL\r\n",__func__, __LINE__);
        return ret;
    }

    switch (event->sub_type) {
        case wifi_event_monitor_provider_response:
            ret = handle_monitor_provider_response(app, event);
        break;
        default:
            wifi_util_error_print(WIFI_EM,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, event->sub_type);
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
       wifi_util_error_print(WIFI_EM,"%s:%d: getRdkWifiVap failed for radio_index : %d\r\n",__func__, __LINE__, radio_index);
       return RETURN_ERR;
   }
   for (count = 0; count < rdk_vap_map->num_vaps; count++) {
       if (!isVapSTAMesh(rdk_vap_map->rdk_vap_array[count].vap_index)) {
           client_assoc_stats[radio_index].req_stats_vap_mask |= (1 << rdk_vap_map->rdk_vap_array[count].vap_index);
       }
   }

    return RETURN_OK;
}

int client_diag_config_to_monitor_queue(wifi_monitor_data_t *data, stats_config_t *stat_config_entry)
{
    unsigned int vapArrayIndex = 0;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    wifi_event_route_t route;
    em_route(&route);
    if (em_common_config_to_monitor_queue(data, stat_config_entry) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,"%s:%d em Config creation failed %d\r\n", __func__, __LINE__, stat_config_entry->stats_type);
        return RETURN_ERR;
    }

    data->u.mon_stats_config.data_type = mon_stats_type_associated_device_stats;

    if (client_assoc_stats[data->u.mon_stats_config.args.radio_index].req_stats_vap_mask == 0) {
        if(generate_vap_mask_for_radio_index(data->u.mon_stats_config.args.radio_index) == RETURN_ERR) {
            wifi_util_error_print(WIFI_EM,"%s:%d generate_vap_mask_for_radio_index failed \r\n", __func__, __LINE__);
            return RETURN_ERR;
        }
    }

    data->u.mon_stats_config.args.app_info = em_app_event_type_assoc_dev_diag;

    //for each vap push the event to monitor queue
    for (vapArrayIndex = 0; vapArrayIndex < getNumberVAPsPerRadio(data->u.mon_stats_config.args.radio_index); vapArrayIndex++) {
        data->u.mon_stats_config.args.vap_index = wifi_mgr->radio_config[data->u.mon_stats_config.args.radio_index].vaps.rdk_vap_array[vapArrayIndex].vap_index;
        if (!isVapSTAMesh(data->u.mon_stats_config.args.vap_index)) {
            push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
        }
    }

    return RETURN_OK;
}

int capacity_config_to_monitor_queue(wifi_monitor_data_t *data, stats_config_t *stat_config_entry)
{
    wifi_event_route_t route;
    em_route(&route);
    if (em_common_config_to_monitor_queue(data, stat_config_entry) != RETURN_OK) {
        wifi_util_error_print(WIFI_EM,"%s:%d em Config creation failed %d\r\n", __func__, __LINE__, stat_config_entry->stats_type);
        return RETURN_ERR;
    }

    data->u.mon_stats_config.data_type = mon_stats_type_radio_channel_stats;
    //for capacity its on channel
    data->u.mon_stats_config.args.channel_list.num_channels = 0;
    data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_ONCHAN;

    data->u.mon_stats_config.args.app_info = em_app_event_type_capacity;

    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
    return RETURN_OK;
}

int push_em_config_event_to_monitor_queue(wifi_app_t *app, wifi_mon_stats_request_state_t state, stats_config_t *stat_config_entry)
{
    wifi_monitor_data_t *data;
    int ret = RETURN_ERR;

    if (stat_config_entry == NULL) {
        wifi_util_error_print(WIFI_EM,"%s:%d input config entry is NULL\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    data = (wifi_monitor_data_t *)malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_EM,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    memset(data, 0, sizeof(wifi_monitor_data_t));

    data->u.mon_stats_config.req_state = state;

    switch (stat_config_entry->stats_type) {
        case stats_type_neighbor:
            ret = neighbor_config_to_monitor_queue(data, stat_config_entry);
        break;
        case stats_type_survey:
            ret = survey_config_to_monitor_queue(data, stat_config_entry);
        break;
        case stats_type_client:
            ret = client_diag_config_to_monitor_queue(data, stat_config_entry); // wifi_getApAssociatedDeviceDiagnosticResult3
        break;
        case stats_type_capacity:
            ret = capacity_config_to_monitor_queue(data, stat_config_entry);
        break;
        default:
            wifi_util_error_print(WIFI_EM,"%s:%d: stats_type not handled[%d]\r\n",__func__, __LINE__, stat_config_entry->stats_type);
            free(data);
            return RETURN_ERR;
    }

    if (ret == RETURN_ERR) {
        wifi_util_error_print(WIFI_EM,"%s:%d Event trigger failed for %d\r\n", __func__, __LINE__, stat_config_entry->stats_type);
        free(data);
        return RETURN_ERR;
    }

    free(data);

    return RETURN_OK;
}

int handle_em_webconfig_event(wifi_app_t *app, wifi_event_t *event)
{

    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    bool off_scan_rfc = g_wifi_mgr->rfc_dml_parameters.wifi_offchannelscan_sm_rfc;
    webconfig_subdoc_data_t *webconfig_data = NULL;
    if (event == NULL) {
        wifi_util_dbg_print(WIFI_EM,"%s %d input arguements are NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    webconfig_data = event->u.webconfig_data;
    if (webconfig_data == NULL) {
        wifi_util_dbg_print(WIFI_EM,"%s %d webconfig_data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (webconfig_data->type != webconfig_subdoc_type_em_config) {
        return RETURN_ERR;
    }


    hash_map_t *new_ctrl_stats_cfg_map = webconfig_data->u.decoded.stats_config_map;
    hash_map_t *cur_app_stats_cfg_map = app->data.u.em_data.em_stats_config_map;
    stats_config_t *cur_stats_cfg, *new_stats_cfg, *tmp_stats_cfg;
    stats_config_t *temp_stats_config;
    char key[64] = {0};

    if (new_ctrl_stats_cfg_map == NULL) {
        wifi_util_dbg_print(WIFI_EM,"%s %d input ctrl stats map is null, Nothing to update\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    //update neigbour sampling_interval to survey interval if value is 0
    new_stats_cfg = hash_map_get_first(new_ctrl_stats_cfg_map);
    while (new_stats_cfg != NULL) {
        if (new_stats_cfg->stats_type == stats_type_neighbor && new_stats_cfg->sampling_interval == 0 ) {
            //search survey configuration.
            tmp_stats_cfg = hash_map_get_first(new_ctrl_stats_cfg_map);
            while (tmp_stats_cfg != NULL) {
                if (tmp_stats_cfg->stats_type == stats_type_survey && tmp_stats_cfg->radio_type == new_stats_cfg->radio_type
                    && tmp_stats_cfg->survey_type == new_stats_cfg->survey_type && tmp_stats_cfg->sampling_interval != 0) {
                        new_stats_cfg->sampling_interval = tmp_stats_cfg->sampling_interval;
                        wifi_util_dbg_print(WIFI_EM,"%s %d update sampling_interval for neighbor stats_type_neighbor(radio_type %d, survey_type %d) to %u\n", __func__, __LINE__,
                                        new_stats_cfg->radio_type, new_stats_cfg->survey_type, new_stats_cfg->sampling_interval);
                        break;
                }
                tmp_stats_cfg = hash_map_get_next(new_ctrl_stats_cfg_map, tmp_stats_cfg);
            }
        }
        new_stats_cfg = hash_map_get_next(new_ctrl_stats_cfg_map, new_stats_cfg);
    }

    //search for the deleted elements if any in new_ctrl_stats_cfg
    if (cur_app_stats_cfg_map != NULL) {
        cur_stats_cfg = hash_map_get_first(cur_app_stats_cfg_map);
        while (cur_stats_cfg != NULL) {
            if (hash_map_get(new_ctrl_stats_cfg_map, cur_stats_cfg->stats_cfg_id) == NULL) {
                //send the delete and remove elem from cur_stats_cfg
                memset(key, 0, sizeof(key));
                snprintf(key, sizeof(key), "%s", cur_stats_cfg->stats_cfg_id);
                push_em_config_event_to_monitor_queue(app, mon_stats_request_state_stop, cur_stats_cfg);
                cur_stats_cfg = hash_map_get_next(cur_app_stats_cfg_map, cur_stats_cfg);

                //Temporary removal, need to uncomment it
                temp_stats_config = hash_map_remove(cur_app_stats_cfg_map, key);
                if (temp_stats_config != NULL) {
                    free(temp_stats_config);
                }
            } else {
                cur_stats_cfg = hash_map_get_next(cur_app_stats_cfg_map, cur_stats_cfg);

            }
        }
    }

    //search for the newly added/updated elements
    if (new_ctrl_stats_cfg_map != NULL) {
        new_stats_cfg = hash_map_get_first(new_ctrl_stats_cfg_map);
        while (new_stats_cfg != NULL) {
            cur_stats_cfg = hash_map_get(cur_app_stats_cfg_map, new_stats_cfg->stats_cfg_id);
            if (cur_stats_cfg == NULL) {
                cur_stats_cfg = (stats_config_t *)malloc(sizeof(stats_config_t));
                if (cur_stats_cfg == NULL) {
                    wifi_util_error_print(WIFI_EM,"%s %d NULL pointer \n", __func__, __LINE__);
                    return RETURN_ERR;
                }
                memset(cur_stats_cfg, 0, sizeof(stats_config_t));
                memcpy(cur_stats_cfg, new_stats_cfg, sizeof(stats_config_t));
                hash_map_put(cur_app_stats_cfg_map, strdup(cur_stats_cfg->stats_cfg_id), cur_stats_cfg);
                //Notification for new entry.
                if(!(!off_scan_rfc && cur_stats_cfg->survey_type == survey_type_off_channel && ( cur_stats_cfg->radio_type == WIFI_FREQUENCY_5_BAND || cur_stats_cfg->radio_type == WIFI_FREQUENCY_5L_BAND || cur_stats_cfg->radio_type == WIFI_FREQUENCY_5H_BAND ))) {
                     push_em_config_event_to_monitor_queue(app, mon_stats_request_state_start, cur_stats_cfg);
                }
            } else {
                if (memcmp(cur_stats_cfg, new_stats_cfg, sizeof(stats_config_t)) != 0) {
                    memcpy(cur_stats_cfg, new_stats_cfg, sizeof(stats_config_t));
                    if(!off_scan_rfc && cur_stats_cfg->survey_type == survey_type_off_channel && ( cur_stats_cfg->radio_type == WIFI_FREQUENCY_5_BAND || cur_stats_cfg->radio_type == WIFI_FREQUENCY_5L_BAND || cur_stats_cfg->radio_type == WIFI_FREQUENCY_5H_BAND )) {

                        push_em_config_event_to_monitor_queue(app, mon_stats_request_state_stop, cur_stats_cfg);
                        
                    } else {
                        //Notification for update entry.
                        push_em_config_event_to_monitor_queue(app, mon_stats_request_state_start, cur_stats_cfg);
                    }
                }
            }

            new_stats_cfg = hash_map_get_next(new_ctrl_stats_cfg_map, new_stats_cfg);
        }
    }

    return RETURN_OK;
}

int em_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
        case wifi_event_type_webconfig:
            handle_em_webconfig_event(app, event);
        break;
        case wifi_event_type_monitor:
            monitor_event_em(app, event);
        break;
        default:
        break;
    }
    return RETURN_OK;
}

int em_init(wifi_app_t *app, unsigned int create_flag)
{
    int rc = RETURN_OK;
    char *component_name = "WifiEM";
    int num_elements;

        bus_data_element_t dataElements[] = {
        /*{ RADIO_LEVL_TEMPERATURE_EVENT, bus_element_type_event,
            { NULL, NULL, NULL, NULL, levl_event_handler, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_uint32, false, 0, 0, 0, NULL } }*///what kind of dataElements we want?
    };

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    rc = get_bus_descriptor()->bus_open_fn(&app->handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_EM, "%s:%d bus: bus_open_fn open failed for component:%s, rc:%d\n",
            __func__, __LINE__, component_name, rc);
        return RETURN_ERR;
    }

    num_elements = (sizeof(dataElements)/sizeof(bus_data_element_t));

    rc = get_bus_descriptor()->bus_reg_data_element_fn(&app->handle, dataElements, num_elements);
    if (rc != bus_error_success) {
        wifi_util_dbg_print(WIFI_EM,"%s:%d bus_reg_data_element_fn failed, rc:%d\n", __func__, __LINE__, rc);
    } else {
        wifi_util_info_print(WIFI_EM,"%s:%d Apps bus_regDataElement success\n", __func__, __LINE__);
    }

    app->data.u.em_data.em_stats_config_map  = hash_map_create();

    wifi_util_info_print(WIFI_EM, "%s:%d: Init em app %s\n", __func__, __LINE__, rc ? "failure" : "success");

    return rc;
}

int em_deinit(wifi_app_t *app)
{
    em_stats_to_monitor_set(app);
    free_em_stats_config_map(app);
    return RETURN_OK;
}