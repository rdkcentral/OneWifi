#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_apps.h"
#include "wifi_analytics.h"
#include "wifi_hal_rdk_framework.h"
#include "wifi_monitor.h"
#include <rbus.h>
#include <sys/resource.h>

const char *subdoc_type_to_string(webconfig_subdoc_type_t type)
{
#define	DOC2S(x) case x: return #x;
    switch (type) {
        DOC2S(webconfig_subdoc_type_private)
        DOC2S(webconfig_subdoc_type_null)
        DOC2S(webconfig_subdoc_type_home)
        DOC2S(webconfig_subdoc_type_xfinity)
        DOC2S(webconfig_subdoc_type_radio)
        DOC2S(webconfig_subdoc_type_mesh)
        DOC2S(webconfig_subdoc_type_mesh_backhaul)
        DOC2S(webconfig_subdoc_type_mesh_sta)
        DOC2S(webconfig_subdoc_type_lnf)
        DOC2S(webconfig_subdoc_type_dml)
        DOC2S(webconfig_subdoc_type_associated_clients)
        DOC2S(webconfig_subdoc_type_wifiapiradio)
        DOC2S(webconfig_subdoc_type_wifiapivap)
        DOC2S(webconfig_subdoc_type_mac_filter)
        DOC2S(webconfig_subdoc_type_blaster)
        DOC2S(webconfig_subdoc_type_harvester)
        DOC2S(webconfig_subdoc_type_wifi_config)
        DOC2S(webconfig_subdoc_type_csi)
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, type);
            break;
    }

    return "unknown subdoc";
}

int analytics_event_exec_start(wifi_apps_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_mgr_core, "start", "");
    return 0;
}

int analytics_event_exec_stop(wifi_apps_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_mgr_core, "end", "");
    return 0;
}

int analytics_event_exec_timeout(wifi_apps_t *apps, void *arg)
{
    hash_map_t   *sta_map;
    char         temp_str[128];
    unsigned int radio_index = 0;
    radio_data_t radio_stats;
    char   client_mac[32], sta_stats_str[256];
    analytics_sta_info_t    *sta_info;
    wifi_associated_dev3_t  *dev_stats;
    sta_data_t *sta_data;
    struct rusage usage;
    float user, system;
    analytics_data_t        *data;

    data = &apps->u.analytics;
    data->tick_demultiplexer++;

    /* We process every 60 seconds. Since this function will be executed every QUEUE_WIFI_CTRL_TASK_TIMEOUT
       seconds, the following equation should do the trick */

    if ((data->tick_demultiplexer % (ANAYLYTICS_PERIOD/QUEUE_WIFI_CTRL_TASK_TIMEOUT)) != 0) {
        return 0;
    }

    getrusage(RUSAGE_SELF, &usage);
    data->minutes_alive++;

    user = (usage.ru_utime.tv_sec - data->last_usage.ru_utime.tv_sec) +
                               1e-6*(usage.ru_utime.tv_usec - data->last_usage.ru_utime.tv_usec);
    system = (usage.ru_stime.tv_sec - data->last_usage.ru_stime.tv_sec) +
                               1e-6*(usage.ru_stime.tv_usec - data->last_usage.ru_stime.tv_usec);

    sprintf(temp_str, "minutes:%d user:%f system:%f", data->minutes_alive, user, system);
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_mgr_core, "keep-alive", temp_str);

    memcpy(&data->last_usage, &usage, sizeof(struct rusage));

    memset(client_mac, 0, sizeof(client_mac));
    memset(sta_stats_str, 0, sizeof(sta_stats_str));

    for (radio_index = 0; radio_index < getNumberRadios(); radio_index++) {
        memset(&radio_stats, 0, sizeof(radio_stats));
        memset(temp_str, 0, sizeof(temp_str));
        if (get_dev_stats_for_radio(radio_index, (radio_data_t *)&radio_stats) == RETURN_OK) {
            sprintf(temp_str, "Radio%d_Stats noise_floor:%d channel_util:%d channel_interference:%d", radio_index,
                        radio_stats.NoiseFloor, radio_stats.channelUtil, radio_stats.channelInterference);
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "radio_stats", temp_str);
        }
    }

    sta_map = data->sta_map;
    sta_info = hash_map_get_first(sta_map);
    while (sta_info != NULL) {
        memset(temp_str, 0, sizeof(temp_str));
        memset(client_mac, 0, sizeof(client_mac));
        memset(sta_stats_str, 0, sizeof(sta_stats_str));
        sta_data = (sta_data_t *)get_stats_for_sta(sta_info->ap_index, sta_info->sta_mac);
        if (sta_data != NULL) {
            dev_stats = &sta_data->dev_stats;
            to_mac_str(sta_info->sta_mac, client_mac);
            sprintf(sta_stats_str, "rssi:%ddbm good/bad rssi:%d/%d rapid reconnects:%d vap index:%d",
                               dev_stats->cli_RSSI, sta_data->good_rssi_time, sta_data->bad_rssi_time,
                               sta_data->rapid_reconnects, sta_info->ap_index);
            sprintf(temp_str, "\"%s\"", client_mac);
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_generic, temp_str, "CORE", "stats", sta_stats_str);
        }
        sta_info = hash_map_get_next(sta_map, sta_info);
    }

    data->tick_demultiplexer = 0;
    return 0;
}

int analytics_event_webconfig_set_data(wifi_apps_t *apps, void *arg)
{
    webconfig_subdoc_data_t *doc = (webconfig_subdoc_data_t *)arg;
    char temp_str[512];
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    int out_bytes = 0;
    unsigned int i = 0, j = 0;
    int  radio_index = 0;

    if (doc == NULL) {
       /*Note : This is not error case, but this check is used to denote webconfig_set_data event
        * is received by the handle_webconfig_event() function and decode is not happened yet
        * to determine the subdoc type.
        */
        wifi_util_info_print(WIFI_ANALYTICS, analytics_format_ovsm_core, "set", "webconfig");
        return 0;
    }

    decoded_params = &doc->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d: decoded data is NULL : %p\n", __func__, __LINE__, decoded_params);
        return -1;
    }
    memset(temp_str, 0, sizeof(temp_str));
    switch (doc->type) {
        case webconfig_subdoc_type_private:
        case webconfig_subdoc_type_home:
        case webconfig_subdoc_type_xfinity:
        case webconfig_subdoc_type_lnf:
        case webconfig_subdoc_type_mesh_backhaul:
            out_bytes += snprintf(&temp_str[out_bytes], (sizeof(temp_str)-out_bytes), "%s:", subdoc_type_to_string(doc->type));
            for (i = 0; i < getNumberRadios(); i++) {
                radio = &decoded_params->radios[i];
                vap_map = &radio->vaps.vap_map;
                for (j = 0; j < radio->vaps.num_vaps; j++) {
                    vap = &vap_map->vap_array[j];

                    if(vap->vap_name[0] != '\0') {
                        out_bytes += snprintf(&temp_str[out_bytes], (sizeof(temp_str)-out_bytes)," %d,%s,%s",
                                vap->vap_index, vap->u.bss_info.ssid, (vap->u.bss_info.enabled==TRUE)?"enb":"dis");
                    }
                }
            }
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_core_core, "set", temp_str);
        break;
        case webconfig_subdoc_type_mesh_sta:
            out_bytes += snprintf(&temp_str[out_bytes], (sizeof(temp_str)-out_bytes), "%s:", subdoc_type_to_string(doc->type));
            for (i = 0; i < getNumberRadios(); i++) {
                radio = &decoded_params->radios[i];
                vap_map = &radio->vaps.vap_map;
                for (j = 0; j < radio->vaps.num_vaps; j++) {
                    vap = &vap_map->vap_array[j];

                    if(vap->vap_name[0] != '\0') {
                        out_bytes += snprintf(&temp_str[out_bytes], (sizeof(temp_str)-out_bytes)," %d,%s,%s",
                                vap->vap_index, vap->u.sta_info.ssid, (vap->u.sta_info.conn_status==wifi_connection_status_connected)?"con":"discon");

                    }
                }
            }
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_core_core, "set", temp_str);
        break;
        case webconfig_subdoc_type_radio:
            out_bytes += snprintf(&temp_str[out_bytes], (sizeof(temp_str)-out_bytes), "%s:", subdoc_type_to_string(doc->type));
            for (i = 0; i < getNumberRadios(); i++) {
                radio = &decoded_params->radios[i];
                radio_index = convert_radio_name_to_radio_index(radio->name);
                out_bytes += snprintf(&temp_str[out_bytes], (sizeof(temp_str)-out_bytes)," %d,%s,%d",
                        radio_index, (radio->oper.enable==TRUE)?"enb":"dis", radio->oper.channel);
            }
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_core_core, "set", temp_str);
        break;
        default:
            out_bytes += snprintf(&temp_str[out_bytes], (sizeof(temp_str)-out_bytes), "%s:", subdoc_type_to_string(doc->type));
            wifi_util_info_print(WIFI_ANALYTICS, analytics_format_core_core, "set", temp_str);
        break;
    }

    return 0;
}

int analytics_event_webconfig_hal_result(wifi_apps_t *apps, void *arg)
{
    char *hal_result = (char *)arg;

    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "result", hal_result);

    return 0;
}

int analytics_event_webconfig_set_status(wifi_apps_t *apps, void *arg)
{
    webconfig_subdoc_type_t *type = (webconfig_subdoc_type_t *)arg;

    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_core_ovsm, "status", subdoc_type_to_string(*type));

    return 0;
}

int analytics_event_webconfig_get_data(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_webconfig_set_data_tunnel(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_hal_unknown_frame(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_hal_mgmt_frame(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_hal_probe_req_frame(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_hal_auth_frame(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_hal_assoc_req_frame(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_hal_assoc_rsp_frame(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_hal_sta_conn_status(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_hal_assoc_device(wifi_apps_t *apps, void *arg)
{
    char client_mac[32];
    char temp_str[64];
    hash_map_t           *sta_map;
    analytics_sta_info_t *sta_info;
    char *tmp;

    memset(client_mac, 0, sizeof(client_mac));
    memset(temp_str, 0, sizeof(temp_str));

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;

    tmp = (char *)to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);

    sprintf(temp_str, "\"%s\" vap index:%d", client_mac, assoc_data->ap_index);

    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "connect", temp_str);

    sta_map = apps->u.analytics.sta_map;

    if ((sta_info = (analytics_sta_info_t *)hash_map_get(sta_map, tmp)) == NULL) {
        sta_info = malloc(sizeof(analytics_sta_info_t));
        sta_info->ap_index = assoc_data->ap_index;
        memcpy(sta_info->sta_mac, assoc_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
        hash_map_put(sta_map, strdup(client_mac), sta_info);
    } else {
        sta_info->ap_index = assoc_data->ap_index;
        memcpy(sta_info->sta_mac, assoc_data->dev_stats.cli_MACAddress, sizeof(mac_address_t));
    }

    return 0;
}

int analytics_event_hal_disassoc_device(wifi_apps_t *apps, void *arg)
{
    char client_mac[32];
    char temp_str[64];
    hash_map_t            *sta_map;
    analytics_sta_info_t  *sta_info;
    char *tmp;
    memset(client_mac, 0, sizeof(client_mac));
    memset(temp_str, 0, sizeof(temp_str));

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *)arg;

    sta_map = apps->u.analytics.sta_map;

    tmp = (char *)to_mac_str(assoc_data->dev_stats.cli_MACAddress, client_mac);
    sprintf(temp_str, "\"%s\" vap index:%d reason:%d", client_mac, assoc_data->ap_index, assoc_data->reason);
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "disconnect", temp_str);

    sta_info = (analytics_sta_info_t *)hash_map_get(sta_map, tmp);
    if (sta_info != NULL) {
        sta_info = hash_map_remove(sta_map, tmp);
        if (sta_info != NULL) {
            free(sta_info);
        }
    }

    return 0;
}

int analytics_event_hal_scan_results(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_hal_channel_change(wifi_apps_t *apps, void *arg)
{
    char    desc[128] = { 0 };
    wifi_channel_change_event_t *ch = (wifi_channel_change_event_t *)arg;

    sprintf(desc, "ch:%d bw:%d radio:%d", ch->channel, ch->channelWidth, ch->radioIndex);

    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_hal_core, "channel change", desc);

    return 0;
}

int analytics_event_hal_radius_greylist(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_command_sta_connect(wifi_apps_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_other_core, "sta connect", (*(bool *)arg == true) ? "true":"false");
    return 0;
}

int analytics_event_command_factory_reset(wifi_apps_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_core_core, "factory reset", "");
    return 0;
}

int analytics_event_command_kickmac(wifi_apps_t *apps, void *arg)
{
    return 0;
}

int analytics_event_command_kick_assoc_devices(wifi_apps_t *apps, void *arg)
{
    char *str = (char *)arg;

    wifi_util_info_print(WIFI_ANALYTICS, analytics_format_dml_core, "kick_mac", str);
    return 0;
}

int exec_event_analytics(wifi_apps_t *apps, ctrl_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case ctrl_event_exec_start:
            analytics_event_exec_start(apps, arg);
            break;

        case ctrl_event_exec_stop:
            analytics_event_exec_stop(apps, arg);
            break;

        case ctrl_event_exec_timeout:
            analytics_event_exec_timeout(apps, arg);
            break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, sub_type);
            break;
    }
    return 0;
}

int webconfig_event_analytics(wifi_apps_t *apps, ctrl_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case ctrl_event_webconfig_set_data:
            analytics_event_webconfig_set_data(apps, arg);
            break;

        case ctrl_event_webconfig_set_status:
            analytics_event_webconfig_set_status(apps, arg);
            break;

        case ctrl_event_webconfig_hal_result:
            analytics_event_webconfig_hal_result(apps, arg);
            break;

        case ctrl_event_webconfig_get_data:
            analytics_event_webconfig_get_data(apps, arg);
            break;

        case ctrl_event_webconfig_set_data_tunnel:
            analytics_event_webconfig_set_data_tunnel(apps, arg);
            break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, sub_type);
            break;
    }

    return 0;
}

int hal_event_analytics(wifi_apps_t *apps, ctrl_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case ctrl_event_hal_unknown_frame:
            analytics_event_hal_unknown_frame(apps, arg);
            break;

        case ctrl_event_hal_mgmt_farmes:
            analytics_event_hal_mgmt_frame(apps, arg);
            break;

        case ctrl_event_hal_probe_req_frame:
            analytics_event_hal_probe_req_frame(apps, arg);
            break;

        case ctrl_event_hal_auth_frame:
            analytics_event_hal_auth_frame(apps, arg);
            break;

        case ctrl_event_hal_assoc_req_frame:
            analytics_event_hal_assoc_req_frame(apps, arg);
            break;

        case ctrl_event_hal_assoc_rsp_frame:
            analytics_event_hal_assoc_rsp_frame(apps, arg);
            break;

        case ctrl_event_hal_sta_conn_status:
            analytics_event_hal_sta_conn_status(apps, arg);
            break;

        case ctrl_event_hal_assoc_device:
            analytics_event_hal_assoc_device(apps, arg);
            break;

        case ctrl_event_hal_disassoc_device:
            analytics_event_hal_disassoc_device(apps, arg);
            break;

        case ctrl_event_scan_results:
            analytics_event_hal_scan_results(apps, arg);
            break;

        case ctrl_event_hal_channel_change:
            analytics_event_hal_channel_change(apps, arg);
            break;

        case ctrl_event_radius_greylist:
            analytics_event_hal_radius_greylist(apps, arg);
            break;

        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, sub_type);
            break;
    }

    return 0;
}

int command_event_analytics(wifi_apps_t *apps, ctrl_event_subtype_t sub_type, void *arg)
{
    switch (sub_type) {
        case ctrl_event_type_command_sta_connect:
            analytics_event_command_sta_connect(apps, arg);
            break;

        case ctrl_event_type_command_factory_reset:
            analytics_event_command_factory_reset(apps, arg);
            break;

        case ctrl_event_type_radius_grey_list_rfc:
            break;

        case ctrl_event_type_wifi_passpoint_rfc:
            break;

        case ctrl_event_type_wifi_interworking_rfc:
            break;

        case ctrl_event_type_wpa3_rfc:
            break;

        case ctrl_event_type_ow_core_thread_rfc:
            break;

        case ctrl_event_type_dfs_rfc:
            break;

        case ctrl_event_type_dfs_atbootup_rfc:
            break;

        case ctrl_event_type_command_kickmac:
            analytics_event_command_kickmac(apps, arg);
            break;

        case ctrl_event_type_command_kick_assoc_devices:
            analytics_event_command_kick_assoc_devices(apps, arg);
            break;

        case ctrl_event_type_command_wps:
            break;

        case ctrl_event_type_command_wifi_host_sync:
            break;

        case ctrl_event_type_device_network_mode:
            break;

        case ctrl_event_type_twoG80211axEnable_rfc:
            break;

        case ctrl_event_type_command_wifi_neighborscan:
            break;

        case ctrl_event_type_command_mesh_status:
            break;

        case ctrl_event_type_normalized_rssi:
            break;

        case ctrl_event_type_snr:
            break;

        case ctrl_event_type_cli_stat:
            break;

        case ctrl_event_type_txrx_rate:
            break;
        default:
            wifi_util_error_print(WIFI_APPS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, sub_type);
            break;
    }
    return 0;
}

int wifi_apps_analytics_event(wifi_apps_t *apps, ctrl_event_type_t type, ctrl_event_subtype_t sub_type, void *arg)
{
    switch (type) {
        case ctrl_event_type_exec:
            exec_event_analytics(apps, sub_type, arg);
            break;

        case ctrl_event_type_webconfig:
            webconfig_event_analytics(apps, sub_type, arg);
            break;

        case ctrl_event_type_hal_ind:
            hal_event_analytics(apps, sub_type, arg);
            break;

        case ctrl_event_type_command:
            command_event_analytics(apps, sub_type, arg);
            break;

        default:
            break;
    }

    return 0;
}

int wifi_apps_analytics_init(wifi_apps_t *apps)
{
    apps->u.analytics.tick_demultiplexer = 0;
    apps->u.analytics.minutes_alive = 0;
    memset(&apps->u.analytics.last_usage, 0, sizeof(struct rusage));
    apps->u.analytics.sta_map = hash_map_create();
    apps->event_fn = wifi_apps_analytics_event;

    wifi_util_info_print(WIFI_ANALYTICS, "@startuml\n");
    wifi_util_info_print(WIFI_ANALYTICS, "hide footbox\n");
    wifi_util_info_print(WIFI_ANALYTICS, "skinparam SequenceMessageAlign center\n");
    wifi_util_info_print(WIFI_ANALYTICS, "\n");
    wifi_util_info_print(WIFI_ANALYTICS, "participant OVSM as \"Ctrl/Ovsm\"\n");
    wifi_util_info_print(WIFI_ANALYTICS, "participant MGR as \"Mgr\"\n");
    wifi_util_info_print(WIFI_ANALYTICS, "participant CORE as \"Core\"\n");
    wifi_util_info_print(WIFI_ANALYTICS, "participant HAL as \"HAL\"\n");
    wifi_util_info_print(WIFI_ANALYTICS, "participant HOSTAP as \"LibHostap\"\n");

    return 0;
}