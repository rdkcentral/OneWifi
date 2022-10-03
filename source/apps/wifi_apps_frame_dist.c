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
#include <ieee80211.h>

void update_probe_map(hash_map_t *probe_map)
{
    probe_req_elem_t *elem, *tmp;
    struct ieee80211_frame *frame;
    mac_addr_str_t mac_str;
    char *str;

    elem = (probe_req_elem_t *)hash_map_get_first(probe_map);
    while (elem != NULL) {
        tmp = elem;
        elem->curr_time_alive++;
        elem = (probe_req_elem_t *)hash_map_get_next(probe_map, elem);

        if (tmp->curr_time_alive > MAX_PROBE_MAP_TTL) {
            frame = (struct ieee80211_frame *)tmp->data.data;
            str = to_mac_str(frame->i_addr2, mac_str);
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
    struct ieee80211_frame *frame;
    mac_addr_str_t mac_str;
    char *str;
    probe_req_elem_t *elem;

    update_probe_map(apps->u.probe_req_map);

    frame = (struct ieee80211_frame *)msg->data;
    str = to_mac_str(frame->i_addr2, mac_str);
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
    struct ieee80211_frame *frame;
    mac_addr_str_t mac_str;
    char *str;
    probe_req_elem_t *elem;

    frame = (struct ieee80211_frame *)msg->data;
    str = to_mac_str(frame->i_addr2, mac_str);

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

