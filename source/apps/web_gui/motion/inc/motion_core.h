#ifndef MOTION_CORE_H
#define MOTION_CORE_H

#include "wifi_csi.h"
#include "bus.h"
#include <cjson/cJSON.h>
#include "wifi_ctrl.h"
#include "collection.h"
#include "common_web_gui.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CSI_MOTION_CORE_INTERVAL 100
#define MAX_CFG_MAC 5

#define ARR_SIZE(x) ((unsigned int)(sizeof(x) / sizeof(x[0])))

typedef struct motion_whitelist_info {
    char *sta_mac;
    bool enable_status;
    double last_motion_detected_time;
    sounder_t *sounder_obj;
} motion_whitelist_info_t;

typedef struct session_conn_info {
    int32_t pipe_read_fd;
    bool is_read_oper_thread_enabled;
} session_conn_info_t;

typedef struct motion_core_param {
    bus_handle_t handle;
    wifi_ctrl_t *ctrl;
    uint32_t csi_session_index;
    uint32_t motion_interval_in_ms;
    session_conn_info_t s_conn_info;
    bool motion_enabled;
    char sta_mac_list[MAX_MACLIST_SIZE];
    mac_addr_str_t gw_mac_str;
    hash_map_t *motion_sta_map; //contain motion_whitelist_info_t
} motion_core_param_t;


motion_whitelist_info_t *create_new_motion_sta_info(hash_map_t *motion_sta_map,
    bool enable_status, char *key);

#ifdef __cplusplus
}
#endif

#endif //MOTION_CORE_H
