#include "wifi_base.h"
#include "wifi_events.h"
#include "wifi_hal.h"

#include "wifi_analytics.h"
#include "wifi_apps_mgr.h"
#include "wifi_ctrl.h"
#include "wifi_easyconnect.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif // MAC2STR

#ifndef MACSTRFMT
#define MACSTRFMT "%02x:%02x:%02x:%02x:%02x:%02x"
#endif // MACSTRFMT

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof(*(a)))
#endif // ARRAYSIZE

#define SCAN_DWELL_MS 50

static void publish_bss_info(const uint8_t *bss_buffer, int count, unsigned radio_idx)
{
    if (count == 0) {
        wifi_util_dbg_print(WIFI_EC, "%s:%d publishing 0 length buffer since no bsses match\n",
            __func__, __LINE__);
    }
    wifi_ctrl_t *ctrl = get_wifictrl_obj();
    raw_data_t rdata = { 0 };
    rdata.raw_data.bytes = (uint8_t *)bss_buffer;
    rdata.data_type = bus_data_type_bytes;
    rdata.raw_data_len = count * sizeof(wifi_bss_info_t);

    get_bus_descriptor()->bus_event_publish_fn(&ctrl->handle, WIFI_EASYCONNECT_BSS_INFO, &rdata);
}

static void handle_wifi_event_scan_results(wifi_app_t *app, void *data)
{
    scan_results_t *scan_results = (scan_results_t *)data;
    if (!scan_results) {
        wifi_util_error_print(WIFI_EC, "%s:%d: NULL scan data!\n", __func__, __LINE__);
        return;
    }
    wifi_util_dbg_print(WIFI_EC, "%s:%d: Got scan results on radio %d\n", __func__, __LINE__,
        scan_results->radio_index);

    uint8_t *bss_info_buffer = calloc(scan_results->num, sizeof(wifi_bss_info_t));
    
    if (bss_info_buffer == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d: BSS Info failed to allocate!\n", 
                            __func__, __LINE__);
        return;
    }

    for (int i = 0; i < scan_results->num; i++) {
        wifi_bss_info_t *bss_info = &scan_results->bss[i];
        memcpy(bss_info_buffer + (i * sizeof(wifi_bss_info_t)), bss_info, sizeof(wifi_bss_info_t));
    }
    // According to EasyConnect 6.5.2, for Reconfiguration,
    // an Enrollee must broadcast a Reconfiguration Annoncement
    // on each channel where the Configuration Response's SSID is heard.
    // So, publish the whole BSS info to a different path for
    // subscribers to work with.
    publish_bss_info(bss_info_buffer, scan_results->num, scan_results->radio_index);
    free(bss_info_buffer);
    
    wifi_util_dbg_print(WIFI_EC, "%s:%d parsed and published %d frames\n",
        __func__, __LINE__, scan_results->num);
}

static void handle_hal_event(wifi_app_t *app, wifi_event_subtype_t event_subtype, void *data)
{
    switch (event_subtype) {
    case wifi_event_scan_results:
        handle_wifi_event_scan_results(app, data);
        break;
    default:
        wifi_util_dbg_print(WIFI_EC, "%s:%d: unhandled event sub_type=%d\n", __func__, __LINE__,
            event_subtype);
        break;
    }
}

static bus_error_t event_sub_handler(char *eventName, bus_event_sub_action_t action,
    int32_t interval, bool *autoPublish)
{
    uint32_t radio_idx = 0;
    wifi_app_t *wifi_app = NULL;
    wifi_ctrl_t *wifi_ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (!wifi_ctrl) {
        wifi_util_error_print(WIFI_EC, "%s:%d: Wi-Fi control is NULL!\n", __func__, __LINE__);
        return bus_error_general;
    }

    wifi_apps_mgr_t *apps_mgr = &wifi_ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return bus_error_general;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_easyconnect);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return bus_error_general;
    }

    *autoPublish = false;
    return bus_error_success;
}

static void start_sta_channel_scan(void *data, unsigned int len)
{
    mac_address_t radio_mac;
    wifi_platform_property_t *wifi_prop;
    wifi_radio_capabilities_t *wifi_cap = NULL;
    wifi_radio_operationParam_t *radioOperation = NULL;
    int num_channels = 0;
    int channels[64] = { 0 };
    unsigned int global_op_class = 0;
    char country[8] = { 0 };

    radio_interface_mapping_t *radio_iface_map = NULL;
    channel_scan_request_t *scan_req = (channel_scan_request_t *)data;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    bool found_radio = false;

    if (scan_req == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d NUll data Pointer\n", __func__, __LINE__);
        return;
    }

    if (len < sizeof(channel_scan_request_t)) {
        wifi_util_error_print(WIFI_EC, "%s:%d Invalid parameter size \n", __func__, __LINE__);
        return;
    }

    if (mgr == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d Mgr object is NULL \n", __func__, __LINE__);
        return;
    }

    wifi_prop = &mgr->hal_cap.wifi_prop;

    for (unsigned int k = 0;
         k < (sizeof(wifi_prop->radio_interface_map) / sizeof(radio_interface_mapping_t)); k++) {
        radio_iface_map = &(wifi_prop->radio_interface_map[k]);
        if (radio_iface_map == NULL) {
            wifi_util_error_print(WIFI_EC, "%s:%d: Unable to find the radio interface map entry \n",
                __func__, __LINE__);
            return;
        }
        mac_address_from_name(radio_iface_map->interface_name, radio_mac);
        if (memcmp(scan_req->ruid, radio_mac, sizeof(mac_addr_t)) == 0) {
            wifi_util_dbg_print(WIFI_EC,
                "%s:%d Processing channel scan for Radio : " MACSTRFMT "\n", __func__, __LINE__,
                MAC2STR(radio_mac));
            found_radio = true;
            break;
        }
    }

    if (!found_radio) {
        wifi_util_dbg_print(WIFI_EC, "%s:%d Failed to find radio for MAC : " MACSTRFMT "\n",
            __func__, __LINE__, MAC2STR(radio_mac));
        return;
    }

    radioOperation = getRadioOperationParam(radio_iface_map->radio_index);
    if (radioOperation == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d NULL radioOperation pointer for radio : %d\n",
            __func__, __LINE__, radio_iface_map->radio_index);
        return;
    }

    wifi_cap = getRadioCapability(radio_iface_map->radio_index);

    if (scan_req->num_operating_classes == 0) {
        if (get_allowed_channels(radioOperation->band, wifi_cap, channels, &num_channels,
                radioOperation->DfsEnabled) != RETURN_OK) {
            wifi_util_error_print(WIFI_EC, "%s:%d get allowed channels failed for the radio : %d\n",
                __func__, __LINE__, radio_iface_map->radio_index);
            return;
        }
    } else {
        get_coutry_str_from_code(mgr->radio_config[radio_iface_map->radio_index].oper.countryCode,
            country);
        global_op_class = country_to_global_op_class(country,
            mgr->radio_config[radio_iface_map->radio_index].oper.operatingClass);

        for (int i = 0; i < scan_req->num_operating_classes; i++) {
            if (scan_req->operating_classes[i].operating_class == global_op_class) {
                for (int j = 0; j < scan_req->operating_classes[i].num_channels; j++) {
                    channels[num_channels] = scan_req->operating_classes[i].channels[j];
                    wifi_util_dbg_print(WIFI_EC, "%s:%d channel number:%u\n", __func__, __LINE__,
                        scan_req->operating_classes[i].channels[j]);
                    num_channels++;
                }
                break;
            }
        }
    }

    if (wifi_hal_startScan(radio_iface_map->radio_index, WIFI_RADIO_SCAN_MODE_OFFCHAN, SCAN_DWELL_MS,
            num_channels, channels) != RETURN_OK) {
        wifi_util_error_print(WIFI_EC, "%s:%d Failed to start station scan on radio: %d\n",
            __func__, __LINE__, radio_iface_map->radio_index);
        return;
    }
    wifi_util_dbg_print(WIFI_EC, "%s:%d Successfully started scan on radio: %d\n", __func__,
        __LINE__, radio_iface_map->radio_index);
}

static bus_error_t start_sta_channel_scan_cmd(char *name, raw_data_t *p_data,
    bus_user_data_t *user_data)
{
    unsigned int len = 0;
    char *tmp = NULL;
    (void)user_data;

    if (name == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d property name is not found\r\n", __FUNCTION__,
            __LINE__);
        return bus_error_element_name_missing;
    }

    tmp = (char *)p_data->raw_data.bytes;
    if ((p_data->data_type != bus_data_type_bytes) || (tmp == NULL)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d wrong bus data_type:%x\n", __func__, __LINE__,
            p_data->data_type);
        return bus_error_invalid_input;
    }

    len = p_data->raw_data_len;
    push_event_to_ctrl_queue((char *)tmp, len, wifi_event_type_command,
        wifi_event_type_start_sta_channel_scan, NULL);

    return bus_error_success;
}

static void handle_ec_command_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->sub_type) {
    case wifi_event_type_start_sta_channel_scan:
        start_sta_channel_scan(event->u.core_data.msg, event->u.core_data.len);
        break;
    default:
        break;
    }
}

int easyconnect_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
    case wifi_event_type_hal_ind:
        handle_hal_event(app, event->sub_type, event->u.core_data.msg);
        break;
    case wifi_event_type_command:
        handle_ec_command_event(app, event);
        break;
    default:
        wifi_util_dbg_print(WIFI_EC, "%s:%d: unhandled event_type=%d\n", __func__, __LINE__,
            event->event_type);
        break;
    }
}

int easyconnect_init(wifi_app_t *app, unsigned int create_flags)
{
    wifi_util_dbg_print(WIFI_EC, "%s called.", __func__);
    char *app_name = "WifiAppsEasyConnect";

    // clang-format off
    bus_data_element_t data_elements[] = {
        { WIFI_EASYCONNECT_BSS_INFO, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_bytes, false, 0, 0, 0, NULL } } ,
        { WIFI_TRIGGER_STA_SCAN_REQ, bus_element_type_method,
            { NULL, start_sta_channel_scan_cmd, NULL, NULL, NULL, NULL}, slow_speed, ZERO_TABLE,
            { bus_data_type_none, true, 0, 0, 0, NULL } },
    };
    // clang-format on

    if (app_init(app, create_flags) != 0) {
        wifi_util_error_print(WIFI_EC, "%s:%d: Failed to register app!\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_EC, "%s:%d: EasyConnect app init'd\n", __func__, __LINE__);
    if (get_bus_descriptor()->bus_reg_data_element_fn(&app->ctrl->handle, data_elements,
            ARRAYSIZE(data_elements)) != bus_error_success) {
        wifi_util_error_print(WIFI_EC, "%s:%d: failed to register data elements\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_EC, "%s:%d: EasyConnect app data elems registered\n", __func__,
        __LINE__);
    return RETURN_OK;
}

int easyconnect_deinit(wifi_app_t *app)
{
    wifi_util_info_print(WIFI_EC, "%s:%d: %s called.", __func__, __LINE__, __func__);
    app_deinit(app, app->desc.create_flag);
    return 0;
}
