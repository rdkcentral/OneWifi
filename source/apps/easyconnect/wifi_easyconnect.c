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

bus_error_t easyconnect_radio_addrowhandler(const char *tableName, const char *aliasName,
    uint32_t *instNum)
{
    static unsigned int instanceCounter = 1;
    *instNum = instanceCounter;
    wifi_util_dbg_print(WIFI_EC, "%s:%d: tableName=%s aliasName=%s instNum=%d\n", __func__,
        __LINE__, tableName, aliasName, *instNum);
    instanceCounter = (instanceCounter % MAX_NUM_RADIOS) + 1;
    return bus_error_success;
}

bus_error_t easyconnect_radio_removerowhandler(const char *rowName)
{
    wifi_util_dbg_print(WIFI_EC, "%s(): %s\n", __func__, rowName);
    return bus_error_success;
}

int easyconnect_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
    case wifi_event_type_hal_ind:
        handle_hal_event(app, event->sub_type, event->u.core_data.msg);
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
