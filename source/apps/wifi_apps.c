#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_apps.h"
#include <rbus.h>

int wifi_apps_frame_dist_event(wifi_apps_t *apps, ctrl_event_type_t type, ctrl_event_subtype_t sub_type, void *arg)
{
    return 0;
}

int wifi_apps_init(wifi_apps_t *apps, wifi_apps_type_t type)
{
    int rc = RBUS_ERROR_SUCCESS;
    char *component_name = "WifiApps";
    rbusDataElement_t dataElements[] = {
                                { WIFI_ANALYTICS_FRAME_EVENTS, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, NULL, NULL, NULL, NULL, NULL }},
    };
    wifi_mgr_t *wifi_mgr_obj = get_wifimgr_obj();

    memset(apps, 0, sizeof(wifi_apps_t));

    apps->type = type;
    apps->ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    apps->prop = &wifi_mgr_obj->hal_cap.wifi_prop;

    switch (type) {
        case wifi_apps_type_frame_dist:
            apps->event_fn = wifi_apps_frame_dist_event;
            apps->u.probe_req_map = hash_map_create();
            rc = rbus_open(&apps->rbus_handle, component_name);
            if (rc != RBUS_ERROR_SUCCESS) {
                return RETURN_ERR;
            }

            rc = rbus_regDataElements(apps->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
            if (rc != RBUS_ERROR_SUCCESS) {
                wifi_util_dbg_print(WIFI_ANALYTICS,"%s:%d rbus_regDataElements failed\n", __func__, __LINE__);
                rbus_unregDataElements(apps->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
                rbus_close(apps->rbus_handle);
                return RETURN_ERR;
            } else {
                wifi_util_info_print(WIFI_ANALYTICS,"%s:%d Apps rbus_regDataElement success\n", __func__, __LINE__);
            }
            break;
        case wifi_apps_type_analytics:
            apps->u.analytics.tick_demultiplexer = 0;
            apps->u.analytics.sta_map = hash_map_create();
            apps->event_fn = wifi_apps_analytics_event;
            break;
        default:
            wifi_util_error_print(WIFI_ANALYTICS,"%s:%d: event not handle[%d]\r\n",__func__, __LINE__, type);
            break;
    }

    return ((rc == RBUS_ERROR_SUCCESS) ? RETURN_OK : RETURN_ERR);
}

wifi_apps_t *get_app_by_type(wifi_ctrl_t *ct, wifi_apps_type_t type)
{
    unsigned int i;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)ct;

    for (i = 0; i < wifi_apps_type_max; i++) {
        if (ctrl->fi_apps[i].type == type) {
            return &ctrl->fi_apps[i];
        }
    }

    return NULL;
}
