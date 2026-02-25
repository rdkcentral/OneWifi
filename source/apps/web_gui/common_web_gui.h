#ifndef COMMON_WEB_GUI_H
#define COMMON_WEB_GUI_H

#include <cjson/cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WEB_SERVER_PATH "/www/data"

typedef struct web_t web_t;
typedef struct csimgr_t csimgr_t;

typedef struct web_event web_event_t;

typedef struct web_gui_obj {
    csimgr_t *gui_csi_mgr;
    web_t *web_server;
    cJSON *json_assoc_sta_list;
} web_gui_obj_t;

int init_web_server_param(web_gui_obj_t *p_web_mgr);
int init_gui_csi_mgr_param(web_gui_obj_t *p_web_mgr);

web_gui_obj_t *get_web_gui_obj(void);
int save_json_to_file(const char *filename, cJSON *json);

#ifdef __cplusplus
}
#endif

#endif // COMMON_WEB_GUI_H
