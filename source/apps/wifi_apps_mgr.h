/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the  
  following copyright and licenses apply:

  Copyright 2018 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#ifndef WIFI_APPS_MGR_H
#define WIFI_APPS_MGR_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi_hal.h"
#include "wifi_base.h"

#ifdef CCSP_COMMON
#include "wifi_analytics.h"
#include "wifi_levl.h"
#ifdef ONEWIFI_CAC_APP_SUPPORT
#include "wifi_cac.h"
#endif
#include "wifi_sm.h"
#include "wifi_motion.h"
#include "wifi_csi.h"
#include "wifi_whix.h"
#include "wifi_harvester.h"
#include "wifi_ocs.h"
#endif  //CCSP_COMMON

#ifdef ONEWIFI_BLASTER_APP_SUPPORT
#include "wifi_blaster.h"
#endif

#define MAX_APP_INIT_DATA 1024
#define APP_DETACHED 0x01

#define unicast_event_to_apps(x)	\
    ((x->route.dst == wifi_sub_component_apps) && (x->route.u.inst_bit_map >= wifi_app_inst_base) \
     && (x->route.u.inst_bit_map < wifi_app_inst_max))

typedef queue_t *wifi_app_event_queue_t;
typedef hash_map_t *wifi_registered_apps_t;

typedef char wifi_app_name_t[256];

typedef struct wifi_ctrl wifi_ctrl_t;
typedef struct wifi_apps_mgr wifi_apps_mgr_t;
typedef struct wifi_app wifi_app_t;

typedef int (* wifi_app_event_fn_t)(wifi_app_t *app, wifi_event_t *event);
typedef int (* wifi_app_init_fn_t)(wifi_app_t *app, unsigned int create_flag);
typedef int (* wifi_app_deinit_fn_t)(wifi_app_t *app);
typedef int (* wifi_app_update_fn_t)(wifi_app_t *app);
typedef struct {
    union {
#ifdef CCSP_COMMON
        levl_data_t          levl;
#ifdef ONEWIFI_CAC_APP_SUPPORT
        cac_data_t           cac;
#endif
        analytics_data_t     analytics;
        sm_data_t            sm_data;
        motion_data_t        motion;
        csi_app_t            csi;
        whix_data_t          whix;
#endif  //CCSP_COMMON
#ifdef ONEWIFI_BLASTER_APP_SUPPORT
        blaster_data_t       blaster;
#endif
#if defined (FEATURE_OFF_CHANNEL_SCAN_5G)
        off_channel_param_t  ocs[MAX_NUM_RADIOS];
#endif //FEATURE_OFF_CHANNEL_SCAN_5G
    } u;
} wifi_app_data_t;

typedef struct {
    wifi_app_inst_t inst;
    unsigned int create_flag;
    unsigned int reg_events_types; // but mask of registered event types
    bool rfc;
    bool enable;
    wifi_app_name_t         desc;
    wifi_app_init_fn_t init_fn;
    wifi_app_event_fn_t     event_fn;
    wifi_app_deinit_fn_t deinit_fn;
    wifi_hal_frame_hook_fn_t mgmt_frame_hook_fn;
    wifi_app_update_fn_t update_fn;
} wifi_app_descriptor_t;

typedef struct wifi_app {
    wifi_app_descriptor_t desc;
    pthread_mutex_t     lock;
    pthread_cond_t         cond;
    wifi_app_event_queue_t     queue;
    pthread_t             tid;
    wifi_app_data_t    data;
    rbusHandle_t                rbus_handle;
    bool exit_app;
    unsigned int        poll_period;
    struct timespec     last_signalled_time;
    struct timespec     last_polled_time;
    wifi_ctrl_t         *ctrl;
} wifi_app_t;

typedef struct wifi_apps_mgr {
    wifi_ctrl_t              *ctrl;
    wifi_platform_property_t *prop;
    rbusHandle_t             rbus_handle;
    wifi_registered_apps_t apps_map;
} __attribute__((__packed__)) wifi_apps_mgr_t;

int apps_mgr_init(wifi_ctrl_t *ctrl, wifi_app_descriptor_t *desc, unsigned int num);
int apps_mgr_event(wifi_apps_mgr_t *apps_mgr, wifi_event_t *event);
wifi_app_t *get_app_by_inst(wifi_apps_mgr_t *apps, wifi_app_inst_t inst);

wifi_app_descriptor_t* get_app_desc(int *);
#ifdef __cplusplus
}
#endif

#endif // WIFI_APPS_MGR_H
