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

#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_apps_mgr.h"
#include <rbus.h>

#ifdef ONEWIFI_CSI_APP_SUPPORT
extern int csi_init(wifi_app_t *app, unsigned int create_flag);
#else
int csi_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}
#endif

#ifdef ONEWIFI_CAC_APP_SUPPORT
extern int cac_init(wifi_app_t *app, unsigned int create_flag);
extern int cac_deinit(wifi_app_t *app);
extern int cac_mgmt_frame_hook(int ap_index, wifi_mgmtFrameType_t type);
extern int cac_event(wifi_app_t *app, wifi_event_t *event);
#else
int cac_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int cac_deinit(wifi_app_t *app)
{
    return 0;
}

int cac_mgmt_frame_hook(int ap_index, wifi_mgmtFrameType_t type)
{
    return 0;
}

int cac_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}
#endif

#ifdef ONEWIFI_MOTION_APP_SUPPORT
extern int motion_init(wifi_app_t *app, unsigned int create_flag);
extern int motion_event(wifi_app_t *app, wifi_event_t *event);
#else
int motion_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int motion_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}
#endif

#ifdef ONEWIFI_HARVESTER_APP_SUPPORT
extern int harvester_init(wifi_app_t *app, unsigned int create_flag);
extern int harvester_event(wifi_app_t *app, wifi_event_t *event);
extern int harvester_deinit(wifi_app_t *app);
#else
int harvester_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int harvester_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}

int harvester_deinit(wifi_app_t *app)
{
    return 0;
}
#endif

#ifdef ONEWIFI_LEVL_APP_SUPPORT
extern int levl_init(wifi_app_t *app, unsigned int create_flag);
extern int levl_deinit(wifi_app_t *app);
extern int levl_update(wifi_app_t *app);
extern int levl_event(wifi_app_t *app, wifi_event_t *event);
#else
int levl_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int levl_deinit(wifi_app_t *app)
{
    return 0;
}

int levl_update(wifi_app_t *app)
{
    return 0;
}

int levl_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}

#endif

#ifdef ONEWIFI_WHIX_APP_SUPPORT
extern int whix_init(wifi_app_t *app, unsigned int create_flag);
extern int whix_deinit(wifi_app_t *app);
extern int whix_event(wifi_app_t *app, wifi_event_t *event);
#else
int whix_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int whix_deinit(wifi_app_t *app)
{
    return 0;
}

int whix_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}

#endif

#ifdef ONEWIFI_BLASTER_APP_SUPPORT
extern int blaster_init(wifi_app_t *app, unsigned int create_flag);
extern int blaster_deinit(wifi_app_t *app);
extern int blaster_event(wifi_app_t *app, wifi_event_t *event);
#else
int blaster_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int blaster_deinit(wifi_app_t *app)
{
    return 0;
}

int blaster_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}

#endif


wifi_app_descriptor_t app_desc[] = {
    #ifdef CCSP_COMMON
    {
        wifi_app_inst_analytics, 0,
        wifi_event_type_exec | wifi_event_type_webconfig | wifi_event_type_hal_ind | wifi_event_type_command | wifi_event_type_monitor | wifi_event_type_net | wifi_event_type_wifiapi,
        true, true,
        "Analytics of Real Time Events",
        analytics_init, analytics_event, analytics_deinit,
        NULL,NULL
    },
#ifdef ONEWIFI_CAC_APP_SUPPORT
    {
        wifi_app_inst_cac, 0,
        wifi_event_type_hal_ind | wifi_event_type_exec | wifi_event_type_webconfig,
        true,true,
        "Connection Admission Control for VAPs",
        cac_init, cac_event, cac_deinit,
        cac_mgmt_frame_hook,NULL
    },
#endif
#if SM_APP
    {
        wifi_app_inst_sm, 0,
        wifi_event_type_monitor | wifi_event_type_webconfig | wifi_event_type_command,
        true, true,
        "Stats Manager",
        sm_init, sm_event, sm_deinit,
        NULL,NULL
    },
#endif
    {
        wifi_app_inst_csi, 0, 0,
        true, true,
        "CSI Application",
        csi_init, NULL, NULL,
        NULL, NULL
    },
    {
        wifi_app_inst_levl, 0,
        wifi_event_type_hal_ind | wifi_event_type_webconfig | wifi_event_type_monitor | wifi_event_type_csi ,
        true, true,
        "Levl Finger Printing",
        levl_init, levl_event, levl_deinit,
        NULL, levl_update
    },
    {
        wifi_app_inst_motion, 0,
        wifi_event_type_hal_ind | wifi_event_type_webconfig | wifi_event_type_monitor | wifi_event_type_csi | wifi_event_type_speed_test,
        true, true,
        "Motion Application",
        motion_init, motion_event, NULL,
        NULL, NULL
    },
    {
        wifi_app_inst_whix, 0,
        wifi_event_type_webconfig | wifi_event_type_monitor | wifi_event_type_command,
        true, true,
        "WHIX telemetry",
        whix_init, whix_event, whix_deinit,
        NULL, NULL
    },
    {
        wifi_app_inst_harvester, 0,
        wifi_event_type_monitor | wifi_event_type_webconfig | wifi_event_type_hal_ind,
        true, true,
        "Harvester",
        harvester_init, harvester_event, harvester_deinit,
        NULL, NULL
    },
#if defined (FEATURE_OFF_CHANNEL_SCAN_5G)
    {
        wifi_app_inst_ocs, 0,
        wifi_event_type_monitor | wifi_event_type_webconfig | wifi_event_type_command,
        true, true,
        "ocs",
        ocs_init, ocs_event, ocs_deinit,
        NULL, NULL
    },
#endif // (FEATURE_OFF_CHANNEL_SCAN_5G)
#endif
    {
        wifi_app_inst_blaster, 0,
        wifi_event_type_monitor | wifi_event_type_webconfig | wifi_event_type_hal_ind,
        true, true,
        "Blaster",
        blaster_init, blaster_event, blaster_deinit,
        NULL, NULL
    }

};

wifi_app_descriptor_t* get_app_desc(int *size){
    *size = (sizeof(app_desc)/sizeof(wifi_app_descriptor_t));
    return app_desc;
}
