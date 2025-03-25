#ifndef WIFI_STA_MGR_H
#define WIFI_STA_MGR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    sta_app_event_type_neighbor = 1,
} sta_app_event_type_t;

typedef struct {
    hash_map_t *sta_mgr_map;
    ap_metrics_policy_t ap_metrics_policy;
} sta_mgr_data_t;

#ifdef __cplusplus
}
#endif

#endif