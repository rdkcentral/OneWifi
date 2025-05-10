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

/**
 * @brief Is this IE a Wi-Fi Alliance CCE IE?
 *
 * @param ie The information element in question
 * @param ie_len Length of the information element in bytes.
 * @return true if this IE is a WFA CCE IE, otherwise false
 */
static bool is_cce_ie(const uint8_t *const ie, size_t ie_len)
{
    static const uint8_t OUI_WFA[3] = { 0x50, 0x6F, 0x9A };
    static const uint8_t CCE_CONSTANT = 0x1E;
    if (ie_len < 4)
        return false;
    return memcmp(ie, OUI_WFA, sizeof(OUI_WFA)) == 0 && *(ie + 3) == CCE_CONSTANT;
}

static void publish_cce_ie_info(const wifi_bss_info_t *bss_info, unsigned radio_idx)
{
    if (bss_info == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d: NULL BSS info!\n", __func__, __LINE__);
        return;
    }
    wifi_ctrl_t *ctrl = get_wifictrl_obj();
    raw_data_t rdata = { 0 };
    rdata.raw_data.bytes = malloc(sizeof(wifi_bss_info_t));
    if (rdata.raw_data.bytes == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d: Failed to malloc for wifi_bss_info_t!\n", __func__,
            __LINE__);
        return;
    }
    rdata.data_type = bus_data_type_bytes;
    memcpy(rdata.raw_data.bytes, bss_info, sizeof(*bss_info));
    rdata.raw_data_len = sizeof(*bss_info);
    char path[256] = { 0 };
    snprintf(path, sizeof(path), "Device.WiFi.Radio.%d.CCEInd", radio_idx + 1);
    get_bus_descriptor()->bus_event_publish_fn(&ctrl->handle, path, &rdata);
    free(rdata.raw_data.bytes);
}

static void publish_bss_info(const wifi_bss_info_t *bss_info)
{
    if (bss_info == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d: NULL BSS info!\n", __func__, __LINE__);
        return;
    }
    wifi_ctrl_t *ctrl = get_wifictrl_obj();
    raw_data_t rdata = { 0 };
    rdata.raw_data.bytes = malloc(sizeof(wifi_bss_info_t));
    if (rdata.raw_data.bytes == NULL) {
        wifi_util_error_print(WIFI_EC, "%s:%d: Failed to malloc for wifi_bss_info_t!\n", __func__,
            __LINE__);
        return;
    }
    rdata.data_type = bus_data_type_bytes;
    memcpy(rdata.raw_data.bytes, bss_info, sizeof(*bss_info));
    rdata.raw_data_len = sizeof(*bss_info);
    char path[256] = { 0 };
    get_bus_descriptor()->bus_event_publish_fn(&ctrl->handle, WIFI_EASYCONNECT_BSS_INFO, &rdata);
    free(rdata.raw_data.bytes);
}

static void handle_wifi_event_scan_results(wifi_app_t *app, void *data)
{
    int i;
    int n = 0;
    scan_results_t *scan_results = (scan_results_t *)data;
    if (!scan_results) {
        wifi_util_error_print(WIFI_EC, "%s:%d: NULL scan data!\n", __func__, __LINE__);
        return;
    }
    wifi_util_dbg_print(WIFI_EC, "%s:%d: Got scan results on radio %d\n", __func__, __LINE__,
        scan_results->radio_index);
    if (app->data.u.ec.subscriptions[scan_results->radio_index] == false) {
        wifi_util_dbg_print(WIFI_EC,
            "%s:%d: Got a scan result on radio %d but there are no subscribers, skipping...\n",
            __func__, __LINE__, scan_results->radio_index);
        return;
    }
    for (i = 0; i < scan_results->num; i++) {
        wifi_bss_info_t *bss_info = &scan_results->bss[i];
        if (!bss_info || !bss_info->ie || bss_info->ie_len == 0) {
            wifi_util_dbg_print(WIFI_EC, "%s:%d: Invalid BSS info! #%d\n", __func__, __LINE__, i);
            continue;
        }
        uint8_t *ie_pos = bss_info->ie;
        size_t ie_len_remaining = bss_info->ie_len;
        while (ie_len_remaining > 2) {
            uint8_t id = ie_pos[0];
            uint8_t ie_len = ie_pos[1];
            if (ie_len + 2 > ie_len_remaining)
                break;
            // 0xdd == Vendor IE
            if (id == 0xdd && is_cce_ie(ie_pos + 2, ie_len)) {
                wifi_util_dbg_print(WIFI_EC,
                    "%s:%d: BSS %s Beacon and/or Probe Response from BSSID " MACSTRFMT
                    " contains WFA CCE IE!\n",
                    __func__, __LINE__, bss_info->ssid, MAC2STR(bss_info->bssid));
                publish_cce_ie_info(bss_info, scan_results->radio_index);
                n++;
            }
            // next IE
            ie_len_remaining -= (ie_len + 2);
            ie_pos += (ie_len + 2);
        }
    }
    wifi_util_dbg_print(WIFI_EC, "%s:%d parsed and published %d frames containing CCE IE\n",
        __func__, __LINE__, n);

    // According to EasyConnect 6.5.2, for Reconfiguration,
    // an Enrollee must broadcast a Reconfiguration Annoncement
    // on each channel where the Configuration Response's SSID is heard.
    // So, publish the whole BSS info to a different path for
    // subscribers to work with.
    for (i = 0; i < scan_results->num; i++) {
        wifi_bss_info_t *bss_info = &scan_results->bss[i];
        if (!bss_info) continue;
        publish_bss_info(bss_info);
    }

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
    if (sscanf(eventName, "Device.WiFi.Radio.%d.CCEInd", &radio_idx) != 1) {
        wifi_util_error_print(WIFI_EC,
            "%s:%d: sscanf failed for event %s, searching on bus path %s\n", __func__, __LINE__,
            eventName, WIFI_EASYCONNECT_RADIO_CCE_IND);
        return bus_error_general;
    }
    // ensure radio index is valid
    if (radio_idx < 0 || radio_idx > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_EC, "%s:%d: invalid radio index: %d\n", __func__, __LINE__,
            radio_idx);
        return bus_error_general;
    }
    if (action == bus_event_action_subscribe) {
        wifi_util_info_print(WIFI_EC, "%s:%d: Adding subscrption for radio %d\n", __func__,
            __LINE__, radio_idx);
        wifi_app->data.u.ec.subscriptions[radio_idx - 1] = true;
    } else if (action == bus_event_action_unsubscribe) {
        wifi_app->data.u.ec.subscriptions[radio_idx - 1] = false;
        wifi_util_info_print(WIFI_EC, "%s:%d: Removing subscription for radio %d\n", __func__,
            __LINE__, radio_idx);
    } else {
        wifi_util_dbg_print(WIFI_EC, "%s:%d: unhandled action %d for radio %d\n", __func__,
            __LINE__, action, radio_idx);
        return bus_error_invalid_event;
    }
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
    for (int i = 0; i < ARRAYSIZE(app->data.u.ec.subscriptions); i++) {
        app->data.u.ec.subscriptions[i] = false;
    }
    // clang-format off
    bus_data_element_t data_elements[] = {
        { WIFI_EASYCONNECT_RADIO_TABLE,   bus_element_type_table,
         { NULL, NULL, easyconnect_radio_addrowhandler, easyconnect_radio_removerowhandler, NULL,
          NULL }, slow_speed, MAX_NUM_RADIOS, { bus_data_type_object, false, 0, 0, 0, NULL } },
        { WIFI_EASYCONNECT_RADIO_CCE_IND, bus_element_type_event,
         { NULL, NULL, NULL, NULL, event_sub_handler, NULL }, slow_speed, ZERO_TABLE,
         { bus_data_type_bytes, false, 0, 0, 0, NULL } },
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
    for (int i = 0; i < ARRAYSIZE(app->data.u.ec.subscriptions); i++) {
        app->data.u.ec.subscriptions[i] = false;
    }
    app_deinit(app, app->desc.create_flag);
    return 0;
}
