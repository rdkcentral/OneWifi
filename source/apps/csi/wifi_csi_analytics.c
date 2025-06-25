#include "wifi_csi_analytics.h"
#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_analytics.h"

#ifdef ONEWIFI_CSI_APP_SUPPORT
void process_csi_analytics_data(wifi_app_t *app, wifi_csi_dev_t *csi_dev_data)
{
    if (app == NULL && csi_dev_data == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    } else if(app->data.u.csi_analytics.csi_analytics_map == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d csi analytics map is NULL\n", __func__, __LINE__);
        return;
    }

    uint8_t *p_mac = csi_dev_data->sta_mac;
    wifi_csi_data_t *p_csi_data = &csi_dev_data->csi;
    mac_addr_str_t mac_str = { 0 };
    csi_analytics_data_t *csi_info;
    hash_map_t *csi_analytics_handle = app->data.u.csi_analytics.csi_analytics_map;
    long long int current_time_sec = get_current_time_in_sec();
    bool print_log_msg = false;
    bool is_csi_data_mismatch;

    uint8_mac_to_string_mac(p_mac, mac_str);
    csi_info = hash_map_get(csi_analytics_handle, mac_str);
    if (csi_info == NULL) {
        csi_info = calloc(1, sizeof(csi_analytics_data_t));
        if (csi_info == NULL) {
            wifi_util_error_print(WIFI_APPS,"%s:%d csi analytics calloc failed\n", __func__, __LINE__);
            return;
        }
        csi_info->csi_data_capture_time_sec = current_time_sec;
        csi_info->num_sc = p_csi_data->frame_info.num_sc;
        csi_info->decimation = p_csi_data->frame_info.decimation;
        csi_info->skip_mismatch_data_num = 0;
        hash_map_put(csi_analytics_handle, strdup(mac_str), csi_info);
        return;
    }

    is_csi_data_mismatch = ((csi_info->num_sc != p_csi_data->frame_info.num_sc) ||
        (csi_info->decimation != p_csi_data->frame_info.decimation));

    if (csi_info->skip_mismatch_data_num || is_csi_data_mismatch) {
        if (current_time_sec - csi_info->csi_data_capture_time_sec >= MAX_LOG_MSG_PRINT_TIME_SEC) {
            print_log_msg = true;
        }
        if (print_log_msg) {
            if (csi_info->num_sc != p_csi_data->frame_info.num_sc) {
                wifi_util_info_print(WIFI_APPS,"%s:%d number of subcarriers old:%d -> new:%d\n",
                    __func__, __LINE__, csi_info->num_sc, p_csi_data->frame_info.num_sc);
            }

            if (csi_info->decimation != p_csi_data->frame_info.decimation) {
                wifi_util_info_print(WIFI_APPS,"%s:%d number of decimation old:%d -> new:%d\n",
                    __func__, __LINE__, csi_info->decimation, p_csi_data->frame_info.decimation);
            }
            wifi_util_info_print(WIFI_APPS,"previous csi data mismatch skip cnt:%d\n",
                    csi_info->skip_mismatch_data_num);
            csi_info->skip_mismatch_data_num = 0;
        } else if(is_csi_data_mismatch) {
            csi_info->skip_mismatch_data_num++;
        }
    }

    csi_info->csi_data_capture_time_sec = current_time_sec;
    csi_info->num_sc = p_csi_data->frame_info.num_sc;
    csi_info->decimation = p_csi_data->frame_info.decimation;
}

void csi_analytics_disassoc_device_event(wifi_app_t *apps, void *data)
{
    if (apps == NULL || data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer - app:%p\n",
            __func__, __LINE__, apps);
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;
    mac_addr_str_t mac_str = { 0 };
    hash_map_t *csi_analytics_handle = app->data.u.csi_analytics.csi_analytics_map;
    csi_analytics_data_t *csi_info;

    uint8_mac_to_string_mac(assoc_data->dev_stats.cli_MACAddress, mac_str);
    csi_info = hash_map_remove(csi_analytics_handle, mac_str);
    if (csi_info != NULL) {
        free(csi_info);
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d STA:%s DisAssoc\n", __func__, __LINE__, mac_str);
}

void csi_analytics_assoc_device_event(void *data)
{   
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }
    
    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;
    mac_addr_str_t mac_str = { 0 };
    
    uint8_mac_to_string_mac(assoc_data->dev_stats.cli_MACAddress, mac_str);
    wifi_util_info_print(WIFI_APPS, "%s:%d STA:%s Assoc\n", __func__, __LINE__, mac_str);
}

int csi_data_events(wifi_app_t *app, wifi_event_subtype_t sub_type, wifi_csi_dev_t *csi)
{
    switch (sub_type) {
        case wifi_event_type_csi_data:
            process_csi_analytics_data(app, csi);
        break;
        default:
            break;
    }
    return RETURN_OK;
}

int csi_analytics_hal_events(wifi_app_t *app, wifi_event_subtype_t sub_type, void *data)
{
    switch (sub_type) {
        case wifi_event_hal_assoc_device:
            csi_analytics_assoc_device_event(data);
            break;
        case wifi_event_hal_disassoc_device:
            csi_analytics_disassoc_device_event(app, data);
            break;
        default:
            break;
    }
    return RETURN_OK;
}

int csi_analytics_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
        case wifi_event_type_csi:
            csi_data_events(app, event->sub_type, event->u.csi);
            break;
        case wifi_event_type_hal_ind:
            csi_analytics_hal_events(app, event->sub_type, event->u.core_data.msg);
            break;
        default:
        break;
    }
    return RETURN_OK;
}

int csi_analytics_deinit(wifi_app_t *app)
{
    if (app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: app obj is NULL"
            " for Csi Analytics\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    app_deinit(app, app->desc.create_flag);

    hash_map_destroy(app->data.u.csi_analytics.csi_analytics_map);
    wifi_util_info_print(WIFI_APPS, "%s:%d:Deinit Csi Analytics App\n", __func__, __LINE__);
    return RETURN_OK;
}

int csi_analytics_init(wifi_app_t *app, unsigned int create_flag)
{
    if (app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: app obj is NULL"
            " for Csi Analytics\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    app->data.u.csi_analytics.csi_analytics_map = hash_map_create();
    if (app->data.u.csi_analytics.csi_analytics_map == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: hash_map Init failure"
            " for Csi Analytics\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d: Init Csi Analytics App\n", __func__, __LINE__);
    return RETURN_OK;
}

int csi_analytics_update(wifi_app_t *app)
{
    if (app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    //Only handling RFC as of NOW
    if (app->desc.inst != wifi_app_inst_csi_analytics) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Unknown app:%x instance\n",
            __func__, __LINE__, app->desc.inst);
        return RETURN_ERR;
    }
    if (app->desc.enable != app->desc.rfc) {
        app->desc.enable = app->desc.rfc;
        if (app->desc.enable) {
            csi_analytics_init(app, app->desc.create_flag);
        } else {
            csi_analytics_deinit(app);
        }
    }
    return 0;
}
#endif
