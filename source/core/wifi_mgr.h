#ifndef WIFI_MGR_H
#define WIFI_MGR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include "ssp_main.h"
#include "wifi_base.h"
#include "wifi_db.h"
#include "wifi_blaster.h"
#include "wifi_ctrl.h"

typedef struct {
    wifi_db_t                       wifidb;
    pthread_mutex_t                 data_cache_lock;
    pthread_mutex_t                 lock;
    wifi_ssp_t                      ssp;
    wifi_ctrl_t                     ctrl;
    wifi_global_config_t            global_config;
    wifi_hal_capability_t           hal_cap;
    queue_t                         *csi_data_queue;
    rdk_wifi_radio_t                radio_config[MAX_NUM_RADIOS];
    wifi_dml_parameters_t           dml_parameters;
    wifi_rfc_dml_parameters_t       rfc_dml_parameters;
    pthread_cond_t                  dml_init_status;
} wifi_mgr_t;

wifi_mgr_t *get_wifimgr_obj();

#ifdef __cplusplus
}
#endif

#endif //WIFI_MGR_H
