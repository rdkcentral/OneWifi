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
#include <pthread.h>
#include <ev.h>
#include <sys/time.h>
#include <assert.h>
#include "wifi_data_plane.h"
#include "wifi_monitor.h"
#include "wifi_db.h"
#include "wifi_mgr.h"
#include "wifi_stubs.h"
#include "wifi_ctrl.h"
#include <stdlib.h>
#include "wifi_util.h"
#include <execinfo.h>
#include "util.h"
#include "misc.h"

wifi_mgr_t g_wifi_mgr;
wifi_misc_t g_misc;

wifi_misc_t *get_wifimisc_obj(void)
{
    return &g_misc;
}

wifi_misc_desc_t *get_misc_descriptor(void)
{
    return &g_misc.desc;
}

wifi_ccsp_t *get_wificcsp_obj(void)
{
    return &g_wifi_mgr.wifi_ccsp;
}

wifi_dml_t *get_wifidml_obj(void)
{
    return &g_wifi_mgr.wifidml;
}

wifi_db_t *get_wifidb_obj(void)
{
    return &g_wifi_mgr.wifidb;
}

wifi_ctrl_t *get_wifictrl_obj(void)
{
    return &g_wifi_mgr.ctrl;
}

wifi_mgr_t *get_wifimgr_obj(void)
{
    return &g_wifi_mgr;
}

webconfig_t *get_webconfig_obj(void)
{
    return &g_wifi_mgr.ctrl.webconfig;
}

bool is_db_consolidated()
{
    return g_wifi_mgr.ctrl.db_consolidated;
}

bool is_db_backup_required()
{
    return (g_wifi_mgr.ctrl.dev_type != dev_subtype_pod);
}

int init_wifi_hal()
{
    int ret = RETURN_OK;

    wifi_util_info_print(WIFI_CTRL,"%s: start wifi hal init\n",__FUNCTION__);

    ret = wifi_hal_init();
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL,"%s wifi_init failed:ret :%d\n",__FUNCTION__, ret);
        return RETURN_ERR;
    }

    /* Get the wifi capabilities from from hal*/
    ret = wifi_hal_getHalCapability(&g_wifi_mgr.hal_cap);
    wifi_util_dbg_print(WIFI_MGR,"%s():%d: return:%d from wifi_hal_getHalCapability.\n", __func__, __LINE__, ret);

    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_CTRL,"RDK_LOG_ERROR, %s wifi_getHalCapability returned with error %d\n", __FUNCTION__, ret);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int init_global_radio_config(rdk_wifi_radio_t *radios_cfg, UINT radio_index)
{
    UINT vap_array_index = 0;
    UINT i;
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();

    if (radios_cfg == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    snprintf(radios_cfg->name, sizeof(radios_cfg->name),"radio%d", radio_index+1);
    for (i = 0; i < (sizeof(wifi_hal_cap_obj->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); i++)
    {
        if (wifi_hal_cap_obj->wifi_prop.interface_map[i].vap_name[0] != '\0' && wifi_hal_cap_obj->wifi_prop.interface_map[i].rdk_radio_index == radio_index) {
            radios_cfg->vaps.rdk_vap_array[vap_array_index].vap_index = wifi_hal_cap_obj->wifi_prop.interface_map[i].index;
            radios_cfg->vaps.vap_map.vap_array[vap_array_index].vap_index = wifi_hal_cap_obj->wifi_prop.interface_map[i].index;
            radios_cfg->vaps.vap_map.vap_array[vap_array_index].radio_index = radio_index;
            strcpy((char *)radios_cfg->vaps.rdk_vap_array[vap_array_index].vap_name, (char *)wifi_hal_cap_obj->wifi_prop.interface_map[i].vap_name);
            strcpy((char *)radios_cfg->vaps.vap_map.vap_array[vap_array_index].vap_name, (char *)wifi_hal_cap_obj->wifi_prop.interface_map[i].vap_name);

            radios_cfg->vaps.rdk_vap_array[vap_array_index].associated_devices_map = hash_map_create();
            if (radios_cfg->vaps.rdk_vap_array[vap_array_index].associated_devices_map == NULL) {
                wifi_util_info_print(WIFI_CTRL,"%s:%d hash_map_create (associated_devices_hash_map) failed\n",__FUNCTION__, __LINE__);
            }

            radios_cfg->vaps.rdk_vap_array[vap_array_index].associated_devices_diff_map = NULL;

            radios_cfg->vaps.rdk_vap_array[vap_array_index].acl_map = hash_map_create();
            if (radios_cfg->vaps.rdk_vap_array[vap_array_index].acl_map == NULL) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d hash_map_create(acl_map) failed\n",__FUNCTION__, __LINE__);
            }
            vap_array_index++;
            if (vap_array_index >= MAX_NUM_VAP_PER_RADIO) {
                break;
            }
        }
    }
    radios_cfg->vaps.radio_index = radio_index;
    radios_cfg->vaps.num_vaps = vap_array_index;
    radios_cfg->vaps.vap_map.num_vaps = vap_array_index;
    return RETURN_OK;
}

bool is_supported_gateway_device(const char *model)
{
    FILE *fp = NULL;
    char box_type[64] = {0};

    memset(box_type, '\0', sizeof(box_type)-1);
    fp = popen("cat /etc/device.properties | grep MODEL_NUM | cut -f 2 -d\"=\"", "r");
    if (fp != NULL) {
         while (fgets(box_type, sizeof(box_type), fp) != NULL) {
                wifi_util_dbg_print(WIFI_MGR,"%s:%d:box_type is %s\n", __func__, __LINE__, box_type);
        }
        pclose(fp);
    }

    return (strncmp(box_type, model, strlen(box_type)-1)) ? false : true;
}

bool is_device_type_cmxb7(void)
{
    return is_supported_gateway_device("TG4482A");
}

bool is_device_type_xb7(void)
{
    return is_supported_gateway_device("CGM4331COM");
}

bool is_device_type_xb8(void)
{
    return is_supported_gateway_device("CGM4981COM");
}
bool is_device_type_vbvxb10(void)
{
    return is_supported_gateway_device("CGM601TCOM");
}
bool is_device_type_sercommxb10(void)
{
    return is_supported_gateway_device("SG417DBCT");
}
bool is_device_type_sr213(void)
{
    return is_supported_gateway_device("SR213");
}
bool is_device_type_cbr2(void)
{
    return is_supported_gateway_device("CGA4332COM");
}
bool is_device_type_scxer10(void)
{
    return is_supported_gateway_device("SCER11BEL");
}

int init_wifimgr()
{
    if (!get_stubs_descriptor()->drop_root_fn()) {
        wifi_util_error_print(WIFI_MGR,"%s: drop_root function failed!\n", __func__);
        get_stubs_descriptor()->gain_root_privilege_fn();
    }
    struct stat sb;
    char db_file[128];
    int hal_initialized = RETURN_ERR;

    if(wifi_hal_pre_init() != RETURN_OK) {
        wifi_util_error_print(WIFI_MGR,"%s wifi hal pre_init failed\n", __func__);
        return -1;
    }

    //Initialize HAL and get Capabilities
    hal_initialized = init_wifi_hal();
    if (hal_initialized != RETURN_OK) {
        get_stubs_descriptor()->v_secure_system_fn("touch /tmp/hal_initialize_failed");
        wifi_util_info_print(WIFI_MGR,"Hal initialization failed rebooting the device\n");
    }
    assert(hal_initialized == RETURN_OK);

    int itr=0;
    for (itr=0; itr < (int)getNumberRadios(); itr++) {
        init_global_radio_config(&g_wifi_mgr.radio_config[itr], itr);
    }

    /* Initialize DML initial data */
    get_wifidml_obj()->desc.set_dml_init_status_fn(false);

    sprintf(db_file, "%s/rdkb-wifi.db", WIFIDB_DIR);
    if (stat(db_file, &sb) != 0) {
        wifi_util_info_print(WIFI_MGR,"WiFiDB file not present FRcase\n");
        g_wifi_mgr.ctrl.factory_reset = true;
        wifi_util_info_print(WIFI_MGR,"WiFiDB  FRcase factory_reset is true\n");
    } else {
        g_wifi_mgr.ctrl.factory_reset = false;
        wifi_util_info_print(WIFI_MGR,"WiFiDB FRcase factory_reset is false\n");
    }

    if (init_wifi_ctrl(&g_wifi_mgr.ctrl) != 0) {
        wifi_util_error_print(WIFI_MGR,"%s: wifi ctrl init failed\n", __func__);
        return -1;
    } else {
        wifi_util_info_print(WIFI_MGR,"%s: wifi ctrl initalization success\n", __func__);
    }

    //Init csi_data_queue
    if (g_wifi_mgr.csi_data_queue == NULL) {
        g_wifi_mgr.csi_data_queue = queue_create();
    }

    if (g_wifi_mgr.stats_config_map == NULL) {
        g_wifi_mgr.stats_config_map = hash_map_create();
    }

    if (g_wifi_mgr.steering_config_map == NULL) {
        g_wifi_mgr.steering_config_map = hash_map_create();
    }

    if (g_wifi_mgr.steering_client_map == NULL) {
        g_wifi_mgr.steering_client_map = hash_map_create();
    }


    if (g_wifi_mgr.vif_neighbors_map == NULL) {
        g_wifi_mgr.vif_neighbors_map = hash_map_create();
    }

    wifidb_init(get_wifidb_obj());

    /* Initialize SSP loop */
    get_wifidml_obj()->desc.ssp_init_fn();

    //Start Wifi DB server, and Initialize data Cache
    get_wifidb_obj()->desc.init_fn();

    return 0;
}

int start_wifimgr()
{
    get_wifidml_obj()->desc.start_dml_fn();

    wifi_ctrl_t *ctrl =  NULL;
    int WIFI_APPS_NUM;
    wifi_app_descriptor_t *app_desc = get_app_desc(&WIFI_APPS_NUM);
    // initialize wifi apps mgr after wifidb init
    ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl != NULL) {
        apps_mgr_init(ctrl, app_desc, WIFI_APPS_NUM);
    } else {
        wifi_util_error_print(WIFI_MGR,"%s:%d NULL Ctrl Pointer Unable to init app\n", __func__, __LINE__);
    }

    if (start_wifi_ctrl(&g_wifi_mgr.ctrl) != 0) {
        wifi_util_error_print(WIFI_MGR,"%s: wifi ctrl start failed\n", __func__);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    bool run_daemon = true;
    int  idx = 0;

    for (idx = 1; idx < argc; idx++) {
        if (strcmp(argv[idx], "-c" ) == 0) {
            run_daemon = false;
        }
    }

    platform_init(&g_wifi_mgr.ctrl.handle);

    if (run_daemon) {
        get_misc_descriptor()->daemonize_fn();
    }

    if (init_wifimgr() != 0) {
        wifi_util_error_print(WIFI_MGR,"%s: wifimgr init failed\n", __func__);
        return -1;
    }

    bus_get_vap_init_parameter(WIFI_DEVICE_MODE, &g_wifi_mgr.ctrl.network_mode);
    if (start_wifimgr() != 0) {
        wifi_util_error_print(WIFI_MGR,"%s: wifimgr start failed\n", __func__);
        return -1;
    }

    wifi_util_info_print(WIFI_MGR,"%s: Exiting Wifi mgr\n", __func__);
    return 0;
}
