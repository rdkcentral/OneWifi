
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common_web_gui.h"
#include "wifi_util.h"
#include "wifi_events.h"
#include "wifi_apps_mgr.h"
#include "wifi_ctrl.h"

web_gui_obj_t *get_web_gui_obj(void)
{
    wifi_app_t *app =  NULL;
    wifi_apps_mgr_t *apps_mgr;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_WEB_GUI, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }

    apps_mgr = &ctrl->apps_mgr;
    app = get_app_by_inst(apps_mgr, wifi_app_inst_web_gui);
    if (app == NULL) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }

    return &app->data.u.web_obj;
}

int save_json_to_file(const char *filename, cJSON *json)
{
    char *json_string = cJSON_Print(json);
    if (!json_string) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d json:%p parse failed\n",
            __func__, __LINE__, json);
        return -1;
    }

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d file:%s open failed\n json_msg:%s\n",
            __func__, __LINE__, filename, json_string);
        free(json_string);
        return -1;
    }

    fputs(json_string, fp);
    fclose(fp);
    free(json_string);
    wifi_util_info_print(WIFI_WEB_GUI,"%s:%d json:%s\n file:%s save success\n",
        __func__, __LINE__, json_string, filename);

    return 0;
}

int add_sta_mac_from_json(cJSON *json_assoc_sta_list, const char *str_sta_mac)
{
    if (!json_assoc_sta_list || !str_sta_mac) {
        wifi_util_error_print(WIFI_WEB_GUI, "%s:%d input obj are null\n", __func__, __LINE__);
        return -1;
    }

    cJSON *clients = cJSON_GetObjectItem(json_assoc_sta_list, "AssociatedClients");
    if (!cJSON_IsArray(clients)) {
        clients = cJSON_CreateArray();
        if (!clients) {
            wifi_util_error_print(WIFI_WEB_GUI, "%s:%d Failed to create array\n", __func__, __LINE__);
            return -1;
        }
        cJSON_AddItemToObject(json_assoc_sta_list, "AssociatedClients", clients);
    }

    int size = cJSON_GetArraySize(clients);

    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(clients, i);
        if (cJSON_IsString(item) && strcmp(item->valuestring, str_sta_mac) == 0) {
            wifi_util_info_print(WIFI_WEB_GUI,"%s:%d sta_mac:%s is already present\n", __func__, __LINE__, str_sta_mac);
            return -1;
        }
    }

    cJSON_AddItemToArray(clients, cJSON_CreateString(str_sta_mac));
    wifi_util_info_print(WIFI_WEB_GUI,"%s:%d sta_mac:%s is set in json\n", __func__, __LINE__, str_sta_mac);
    return 0;
}

int remove_sta_mac_from_json(cJSON *json_assoc_sta_list, const char *str_sta_mac)
{
    if (!json_assoc_sta_list || !str_sta_mac) {
        wifi_util_error_print(WIFI_WEB_GUI, "%s:%d input obj are null\n", __func__, __LINE__);
        return -1;
    }

    cJSON *clients = cJSON_GetObjectItem(json_assoc_sta_list, "AssociatedClients");
    if (!cJSON_IsArray(clients)) {
        wifi_util_error_print(WIFI_WEB_GUI, "%s:%d Failed to get json AssociatedClients element\n",
            __func__, __LINE__);
        return -1;
    }

    int size = cJSON_GetArraySize(clients);

    for (int i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(clients, i);
        if (cJSON_IsString(item) && strcmp(item->valuestring, str_sta_mac) == 0) {
            cJSON_DeleteItemFromArray(clients, i);
            wifi_util_info_print(WIFI_WEB_GUI,"%s:%d sta_mac:%s is remove from json\n",
                __func__, __LINE__, str_sta_mac);
            return 0;
        }
    }

    wifi_util_info_print(WIFI_WEB_GUI,"%s:%d sta_mac:%s is not found from json\n",
        __func__, __LINE__, str_sta_mac);
    return -1;
}

void web_gui_assoc_device_event(wifi_app_t *apps, void *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;
    web_gui_obj_t *p_web_gui = &apps->data.u.web_obj;

    if (isVapPrivate(assoc_data->ap_index)) {
        mac_addr_str_t str_sta_mac = { 0 };

        to_mac_str(assoc_data->dev_stats.cli_MACAddress, str_sta_mac);
        add_sta_mac_from_json(p_web_gui->json_assoc_sta_list, str_sta_mac);
    }
}

void web_gui_disassoc_device_event(wifi_app_t *apps, void *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;
    web_gui_obj_t *p_web_gui = &apps->data.u.web_obj;

    if (isVapPrivate(assoc_data->ap_index)) {
        mac_addr_str_t str_sta_mac = { 0 };

        to_mac_str(assoc_data->dev_stats.cli_MACAddress, str_sta_mac);
        remove_sta_mac_from_json(p_web_gui->json_assoc_sta_list, str_sta_mac);
    }
}

int hal_event_for_web_gui(wifi_app_t *app, wifi_event_subtype_t sub_type, void *data)
{
    switch (sub_type) {
    case wifi_event_hal_assoc_device:
        web_gui_assoc_device_event(app, data);
        break;
    case wifi_event_hal_disassoc_device:
        web_gui_disassoc_device_event(app, data);
        break;
    default:
        break;
    }
    return RETURN_OK;
}

int init_web_gui_param(wifi_app_t *app)
{
    web_gui_obj_t *p_web_mgr = &app->data.u.web_obj;

    if (!p_web_mgr->json_assoc_sta_list) {
        p_web_mgr->json_assoc_sta_list = cJSON_CreateObject();
        wifi_util_info_print(WIFI_WEB_GUI,"%s:%d json_assoc_sta_list:%p\n",
            __func__, __LINE__, p_web_mgr->json_assoc_sta_list);
    }
    init_web_server_param(p_web_mgr);
    init_gui_csi_mgr_param(p_web_mgr);

    return 0;
}

int web_gui_app_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
        case wifi_event_type_webconfig:
            break;

        case wifi_event_type_exec:
            break;

        case wifi_event_type_hal_ind:
            hal_event_for_web_gui(app, event->sub_type, event->u.core_data.msg);
            break;

        default:
            break;
    }

    return RETURN_OK;
}

int web_gui_app_init(wifi_app_t *app, unsigned int create_flag)
{
    init_web_gui_param(app);
    motion_core_init();

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }

    return 0;
}

int web_gui_app_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}
