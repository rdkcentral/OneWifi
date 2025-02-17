#ifndef WIFI_STA_MANAGER_H
#define WIFI_STA_MANAGER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    sta_app_event_type_neighbor = 1,
} sta_app_event_type_t;

typedef struct {
    hash_map_t *sta_mgr_map;
} sta_mgr_data_t;

#endif
