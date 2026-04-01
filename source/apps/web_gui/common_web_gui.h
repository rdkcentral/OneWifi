#ifndef COMMON_WEB_GUI_H
#define COMMON_WEB_GUI_H

#include <cjson/cJSON.h>
#include "wifi_base.h"
#include "collection.h"
#include "wifi_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WEB_SERVER_PATH "/www/data"

typedef struct web_t web_t;
typedef struct csimgr_t csimgr_t;
typedef struct sounder_t sounder_t;

typedef struct web_event web_event_t;
typedef unsigned int gestures_t;

typedef struct web_gui_obj {
    csimgr_t *gui_csi_mgr;
    web_t *web_server;
    cJSON *json_assoc_sta_list;
} web_gui_obj_t;

int init_web_server_param(web_gui_obj_t *p_web_mgr);
int init_gui_csi_mgr_param(web_gui_obj_t *p_web_mgr);
int motion_core_init(void);

web_gui_obj_t *get_web_gui_obj(void);
int save_json_to_file(const char *filename, cJSON *json);

sounder_t* get_or_create_sounder_from_map(hash_map_t *map,
                                 const char *mac_str,
                                 const uint8_t *sta_mac);

void process_csi_motion_data(sounder_t *sd, wifi_csi_dev_t *csi_dev, gestures_t gestures);

#ifdef __cplusplus
}
#endif

#endif // COMMON_WEB_GUI_H
