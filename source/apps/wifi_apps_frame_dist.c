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
//#include <ieee80211.h>
#include "common/ieee802_11_defs.h"

#if 0
void update_probe_map(hash_map_t *probe_map)
{
    probe_req_elem_t *elem, *tmp;
    struct ieee80211_mgmt *frame;
    mac_addr_str_t mac_str;
    char *str;

    elem = (probe_req_elem_t *)hash_map_get_first(probe_map);
    while (elem != NULL) {
        tmp = elem;
        elem->curr_time_alive++;
        elem = (probe_req_elem_t *)hash_map_get_next(probe_map, elem);

        if (tmp->curr_time_alive > MAX_PROBE_MAP_TTL) {
            frame = (struct ieee80211_mgmt *)tmp->data.data;
            str = to_mac_str(frame->sa, mac_str);
            hash_map_remove(probe_map, str);
            free(tmp);
        }
    }
}

void apps_unknown_frame_event(wifi_apps_t *apps, frame_data_t *msg, uint32_t msg_length)
{
    //printf("%s:%d unknown wifi mgmt frame message\r\n", __FUNCTION__, __LINE__);
}

void apps_probe_req_frame_event(wifi_apps_t *apps, frame_data_t *msg, uint32_t msg_length)
{
    struct ieee80211_mgmt *frame;
    mac_addr_str_t mac_str;
    char *str;
    probe_req_elem_t *elem;

    update_probe_map(apps->u.probe_req_map);

    frame = (struct ieee80211_mgmt *)msg->data;
    str = to_mac_str(frame->sa, mac_str);
    printf("%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d src mac:%s\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir, str);

    if ((elem = (probe_req_elem_t *)hash_map_get(apps->u.probe_req_map, mac_str)) == NULL) {
        elem = (probe_req_elem_t *)malloc(sizeof(probe_req_elem_t));
        memset(elem, 0, sizeof(probe_req_elem_t));
        memcpy(&elem->data, msg, sizeof(frame_data_t));
        hash_map_put(apps->u.probe_req_map, strdup(mac_str), elem);
    }
}

void apps_auth_frame_event(wifi_apps_t *apps, frame_data_t *msg, uint32_t msg_length)
{
    //printf("%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}

void apps_assoc_req_frame_event(wifi_apps_t *apps, frame_data_t *msg, uint32_t msg_length)
{
    struct ieee80211_mgmt *frame;
    mac_addr_str_t mac_str;
    char *str;
    probe_req_elem_t *elem;

    frame = (struct ieee80211_mgmt *)msg->data;
    str = to_mac_str(frame->sa, mac_str);

    if ((elem = (probe_req_elem_t *)hash_map_get(apps->u.probe_req_map, mac_str)) == NULL) {
        printf("%s:%d:probe not found for mac address:%s\n", __func__, __LINE__, str);
        //assert(1);
    } else {
        printf("%s:%d Send probe and assoc ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
        printf("%s:%d curr_time_alive:%d\r\n", __func__, __LINE__, elem->curr_time_alive);
    }
}

void apps_assoc_rsp_frame_event(wifi_apps_t *apps, frame_data_t *msg, uint32_t msg_length)
{
    //printf("%s:%d wifi mgmt frame message: ap_index:%d length:%d type:%d dir:%d\r\n", __FUNCTION__, __LINE__, msg->frame.ap_index, msg->frame.len, msg->frame.type, msg->frame.dir);
}
#endif

int wifi_apps_frame_dist_event(wifi_apps_t *apps, ctrl_event_type_t type, ctrl_event_subtype_t sub_type, void *arg)
{
    return 0;
}

int wifi_apps_frame_dist_init(wifi_apps_t *apps)
{
    int rc = RBUS_ERROR_SUCCESS;
    char *component_name = "WifiApps";
    rbusDataElement_t dataElements[] = {
                                { WIFI_ANALYTICS_FRAME_EVENTS, RBUS_ELEMENT_TYPE_METHOD,
                                { NULL, NULL, NULL, NULL, NULL, NULL }},
    };

    apps->event_fn = wifi_apps_frame_dist_event;
    apps->u.probe_req_map = hash_map_create();
    rc = rbus_open(&apps->rbus_handle, component_name);
    if (rc != RBUS_ERROR_SUCCESS) {
        return RETURN_ERR;
    }

    rc = rbus_regDataElements(apps->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d rbus_regDataElements failed\n", __func__, __LINE__);
        rbus_unregDataElements(apps->rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
        rbus_close(apps->rbus_handle);
        return RETURN_ERR;
    } else {
        wifi_util_info_print(WIFI_APPS,"%s:%d Apps rbus_regDataElement success\n", __func__, __LINE__);
    }

    return ((rc == RBUS_ERROR_SUCCESS) ? RETURN_OK : RETURN_ERR);
}
