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

#ifdef ONEWIFI_ANALYTICS_APP_SUPPORT
extern int analytics_init(wifi_app_t *app, unsigned int create_flag);
extern int analytics_deinit(wifi_app_t *app);
extern int analytics_event(wifi_app_t *app, wifi_event_t *event);
#else
int analytics_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int analytics_deinit(wifi_app_t *app)
{
    return 0;
}

int analytics_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}
#endif

#ifdef ONEWIFI_CSI_APP_SUPPORT
extern int csi_init(wifi_app_t *app, unsigned int create_flag);
extern int csi_analytics_init(wifi_app_t *app, unsigned int create_flag);
extern int csi_analytics_event(wifi_app_t *app, wifi_event_t *event);
extern int csi_analytics_deinit(wifi_app_t *app);
extern int csi_analytics_update(wifi_app_t *app);
#else
int csi_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int csi_analytics_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int csi_analytics_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}

int csi_analytics_deinit(wifi_app_t *app)
{
    return 0;
}

int csi_analytics_update(wifi_app_t *app)
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

#ifdef ONEWIFI_MEMWRAPTOOL_APP_SUPPORT
extern int memwraptool_init(wifi_app_t *app, unsigned int create_flag);
extern int memwraptool_deinit(wifi_app_t *app);
extern int memwraptool_event(wifi_app_t *app, wifi_event_t *event);
#else
int memwraptool_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int memwraptool_deinit(wifi_app_t *app)
{
    return 0;
}

int memwraptool_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}

#endif // ONEWIFI_MEMWRAPTOOL_APP_SUPPORT

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

#endif // ONEWIFI_BLASTER_APP_SUPPORT

#ifdef ONEWIFI_EASYCONNECT_APP_SUPPORT
extern int easyconnect_init(wifi_app_t *app, unsigned int create_flag);
extern int easyconnect_deinit(wifi_app_t *app);
extern int easyconnect_event(wifi_app_t *app, wifi_event_t *event);
#else
int easyconnect_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int easyconnect_deinit(wifi_app_t *app)
{
    return 0;
}

int easyconnect_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}
#endif // ONEWIFI_EASYCONNECT_APP_SUPPORT

#ifdef EM_APP
extern int em_init(wifi_app_t *app, unsigned int create_flag);
extern int em_deinit(wifi_app_t *app);
extern int em_update(wifi_app_t *app);
extern int em_event(wifi_app_t *app, wifi_event_t *event);
#else
int em_init(wifi_app_t *app, unsigned int create_flag)
{
    return 0;
}

int em_deinit(wifi_app_t *app)
{
    return 0;
}

int em_update(wifi_app_t *app)
{
    return 0;
}

int em_event(wifi_app_t *app, wifi_event_t *event)
{
    return 0;
}
#endif // EM_APP

#ifdef ONEWIFI_STA_MGR_APP_SUPPORT
extern int sta_mgr_init(wifi_app_t *app, unsigned int create_flag);
extern int sta_mgr_deinit(wifi_app_t *app);
extern int sta_mgr_event(wifi_app_t *app, wifi_event_t *event);
#endif

wifi_app_descriptor_t app_desc[] = {
#ifdef ONEWIFI_ANALYTICS_APP_SUPPORT
    {
        wifi_app_inst_analytics, 0,
        wifi_event_type_exec | wifi_event_type_webconfig | wifi_event_type_hal_ind | wifi_event_type_command | wifi_event_type_monitor | wifi_event_type_net | wifi_event_type_wifiapi,
        true, true,
        "Analytics of Real Time Events",
        analytics_init, analytics_event, analytics_deinit,
        NULL,NULL
    },
#endif
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
#if EM_APP
    {
        wifi_app_inst_easymesh, 0,
        wifi_event_type_monitor | wifi_event_type_webconfig | wifi_event_type_hal_ind | wifi_event_type_command,
        true, true,
        "Easy Mesh",
        em_init, em_event, em_deinit,
        NULL,NULL
    },
#endif
#if ONEWIFI_CSI_APP_SUPPORT
    {
        wifi_app_inst_csi, 0, 0,
        true, true,
        "CSI Application",
        csi_init, NULL, NULL,
        NULL, NULL
    },
#endif
#if ONEWIFI_LEVL_APP_SUPPORT
    {
        wifi_app_inst_levl, 0,
        wifi_event_type_hal_ind | wifi_event_type_webconfig | wifi_event_type_monitor | wifi_event_type_csi ,
        true, true,
        "Levl Finger Printing",
        levl_init, levl_event, levl_deinit,
        NULL, levl_update
    },
#endif
#if ONEWIFI_MOTION_APP_SUPPORT
    {
        wifi_app_inst_motion, 0,
        wifi_event_type_hal_ind | wifi_event_type_webconfig | wifi_event_type_monitor | wifi_event_type_csi | wifi_event_type_speed_test,
        true, true,
        "Motion Application",
        motion_init, motion_event, NULL,
        NULL, NULL
    },
#endif
#if ONEWIFI_CSI_APP_SUPPORT
    {
        wifi_app_inst_csi_analytics, 0,
        wifi_event_type_webconfig,
        true, true,
        "CSI analytics App",
        csi_analytics_init, csi_analytics_event, csi_analytics_deinit,
        NULL, csi_analytics_update
    },
#endif
#if ONEWIFI_WHIX_APP_SUPPORT
    {
        wifi_app_inst_whix, 0,
        wifi_event_type_webconfig | wifi_event_type_monitor | wifi_event_type_command | wifi_event_type_hal_ind,
        true, true,
        "WHIX telemetry",
        whix_init, whix_event, whix_deinit,
        NULL, NULL
    },
#endif
#if ONEWIFI_HARVESTER_APP_SUPPORT
    {
        wifi_app_inst_harvester, 0,
        wifi_event_type_monitor | wifi_event_type_webconfig | wifi_event_type_hal_ind,
        true, true,
        "Harvester",
        harvester_init, harvester_event, harvester_deinit,
        NULL, NULL
    },
#endif
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
#if ONEWIFI_BLASTER_APP_SUPPORT
    {
        wifi_app_inst_blaster, 0,
        wifi_event_type_monitor | wifi_event_type_webconfig | wifi_event_type_hal_ind,
        true, true,
        "Blaster",
        blaster_init, blaster_event, blaster_deinit,
        NULL, NULL
    },
#endif
#ifdef ONEWIFI_MEMWRAPTOOL_APP_SUPPORT
    {
        wifi_app_inst_memwraptool, 0,
        wifi_event_type_webconfig | wifi_event_type_command,
        true, true,
        "Memwraptool",
        memwraptool_init, memwraptool_event, memwraptool_deinit,
        NULL, NULL
    },
#endif // ONEWIFI_MEMWRAPTOOL_APP_SUPPORT
#ifdef ONEWIFI_STA_MGR_APP_SUPPORT
    {
        wifi_app_inst_sta_mgr, 0,
        wifi_event_type_hal_ind | wifi_event_type_exec | wifi_event_type_webconfig,
        true, true,
        "Station Manager",
        sta_mgr_init, sta_mgr_event, sta_mgr_deinit,
        NULL, NULL
    },
#endif//ONEWIFI_STA_MGR_APP_SUPPORT
#ifdef ONEWIFI_EASYCONNECT_APP_SUPPORT
    {
        wifi_app_inst_easyconnect, 0,
        wifi_event_type_hal_ind,
        true, true,
        "EasyConnect",
        easyconnect_init, easyconnect_event, easyconnect_deinit,
        NULL, NULL
    },
#endif // ONEWIFI_EASYCONNECT_APP_SUPPORT
};

wifi_app_descriptor_t* get_app_desc(int *size){
    *size = (sizeof(app_desc)/sizeof(wifi_app_descriptor_t));
    return app_desc;
}
