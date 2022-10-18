#ifndef WIFI_APPS_H
#define WIFI_APPS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi_hal.h"
#include "wifi_base.h"
#include <sys/resource.h>

#define MAX_PROBE_MAP_TTL    64

typedef struct {
    unsigned int    max_probe_ttl_cnt;
    mac_addr_str_t  mac_str;
} __attribute__((__packed__)) probe_ttl_data_t;

typedef enum {
    wifi_apps_type_frame_dist,
    wifi_apps_type_analytics,
    wifi_apps_type_max
} wifi_apps_type_t;

typedef struct {
    unsigned int       curr_time_alive;
    frame_data_t       msg_data;
} __attribute__((__packed__)) probe_req_elem_t;

typedef struct wifi_ctrl wifi_ctrl_t;
typedef struct wifi_apps wifi_apps_t;

typedef int (* wifi_apps_event_fn_t)(wifi_apps_t *apps, ctrl_event_type_t type, ctrl_event_subtype_t sub_type, void *arg);

typedef struct {
    unsigned int    ap_index;
    mac_address_t   sta_mac;
} analytics_sta_info_t;

typedef struct {
    unsigned int    minutes_alive;
    unsigned int    tick_demultiplexer;
    hash_map_t      *sta_map;
    struct rusage   last_usage;
} analytics_data_t;

typedef struct wifi_apps {
    wifi_apps_type_t         type;
    wifi_ctrl_t              *ctrl;
    wifi_platform_property_t *prop;
    rbusHandle_t             rbus_handle;
    union {
        hash_map_t           *probe_req_map;
        analytics_data_t     analytics;
    } u;
    wifi_apps_event_fn_t     event_fn;
} __attribute__((__packed__)) wifi_apps_t;

wifi_apps_t *get_app_by_type(wifi_ctrl_t *ctrl, wifi_apps_type_t type);

// frame distributer
int wifi_apps_frame_dist_event(wifi_apps_t *apps, ctrl_event_type_t type, ctrl_event_subtype_t sub_type, void *arg);
// analytics
int wifi_apps_analytics_event(wifi_apps_t *apps, ctrl_event_type_t type, ctrl_event_subtype_t sub_type, void *arg);

#ifdef __cplusplus
}
#endif

#endif // WIFI_APPS_H
