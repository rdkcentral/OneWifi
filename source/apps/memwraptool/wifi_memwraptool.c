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

#include "wifi_events.h"
#include "wifi_util.h"
#include "wifi_stubs.h"
#include "wifi_memwraptool.h"
#include "wifi_apps_mgr.h"
#include "wifi_mgr.h"
#include "wifi_base.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#define MAX_EVENT_NAME_SIZE 200

static bus_error_t memwraptool_get_handler(char *event_name, raw_data_t *p_data,
    bus_user_data_t *user_data);
static bus_error_t memwraptool_set_handler(char *event_name, raw_data_t *p_data,
    bus_user_data_t *user_data);

bus_data_element_t dataElements[] = {
    { WIFI_MEMWRAPTOOL_RSSCHECKINTERVAL, bus_element_type_property,
     { memwraptool_get_handler, memwraptool_set_handler, NULL, NULL, NULL, NULL }, slow_speed,
     ZERO_TABLE, { bus_data_type_uint32, true, 0, 0, 0, NULL }  },
    { WIFI_MEMWRAPTOOL_RSSTHRESHOLD,     bus_element_type_property,
     { memwraptool_get_handler, memwraptool_set_handler, NULL, NULL, NULL, NULL }, slow_speed,
     ZERO_TABLE, { bus_data_type_uint32, true, 0, 0, 0, NULL }  },
    { WIFI_MEMWRAPTOOL_RSSMAXLIMIT,      bus_element_type_property,
     { memwraptool_get_handler, memwraptool_set_handler, NULL, NULL, NULL, NULL }, slow_speed,
     ZERO_TABLE, { bus_data_type_uint32, true, 0, 0, 0, NULL }  },
    { WIFI_MEMWRAPTOOL_HEAPWALKDURATION, bus_element_type_property,
     { memwraptool_get_handler, memwraptool_set_handler, NULL, NULL, NULL, NULL }, slow_speed,
     ZERO_TABLE, { bus_data_type_uint32, true, 0, 0, 0, NULL }  },
    { WIFI_MEMWRAPTOOL_HEAPWALKINTERVAL, bus_element_type_property,
     { memwraptool_get_handler, memwraptool_set_handler, NULL, NULL, NULL, NULL }, slow_speed,
     ZERO_TABLE, { bus_data_type_uint32, true, 0, 0, 0, NULL }  },
    { WIFI_MEMWRAPTOOL_ENABLE,           bus_element_type_property,
     { memwraptool_get_handler, memwraptool_set_handler, NULL, NULL, NULL, NULL }, slow_speed,
     ZERO_TABLE, { bus_data_type_boolean, true, 0, 0, 0, NULL } }
};

static int push_memwrap_data_dml_to_ctrl_queue(memwraptool_config_t *memwraptool)
{
    webconfig_subdoc_data_t *data;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    char *str = NULL;

    if (memwraptool == NULL) {
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d NULL pointer\n", __func__, __LINE__);
        return bus_error_general;
    }

    data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d malloc failed\n", __func__, __LINE__);
        return bus_error_general;
    }

    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy(&data->u.decoded.config.global_parameters.memwraptool, memwraptool,
        sizeof(memwraptool_config_t));

    if (webconfig_encode(&ctrl->webconfig, data, webconfig_subdoc_type_memwraptool) ==
        webconfig_error_none) {
        str = data->u.encoded.raw;
        wifi_util_info_print(WIFI_MEMWRAPTOOL, "%s:%d Memwraptool data encoded successfully\n",
            __func__, __LINE__);
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig,
            wifi_event_webconfig_set_data_dml, NULL);
    } else {
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d Webconfig set failed\n", __func__, __LINE__);
        if (data != NULL) {
            free(data);
        }
        return bus_error_general;
    }
    wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d Memwraptool pushed to queue. Encoded data is %s\n",
        __func__, __LINE__, str);
    webconfig_data_free(data);
    if (data != NULL) {
        free(data);
    }
    return bus_error_success;
}

static int memwraptool_event_webconfig_set_data(wifi_app_t *apps, void *arg, wifi_event_subtype_t sub_type)
{
    char cmd[256];
    memwraptool_config_t *memwraptool_config = NULL;
    webconfig_subdoc_data_t *doc = (webconfig_subdoc_data_t *)arg;
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;
    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();

    decoded_params = &doc->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d Decoded data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d Entering and subdoc type is %d\n", __func__,
        __LINE__, doc->type);
    switch (doc->type) {
    case webconfig_subdoc_type_memwraptool:
        memwraptool_config = (memwraptool_config_t *)malloc(sizeof(memwraptool_config_t));
        if (memwraptool_config == NULL) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d memwraptool_config is NULL\n", __func__,
                __LINE__);
            return RETURN_ERR;
        }
        memcpy(memwraptool_config, &decoded_params->config.global_parameters.memwraptool,
            sizeof(memwraptool_config_t));
        wifi_util_dbg_print(WIFI_MEMWRAPTOOL,
            "%s:%d Received memwraptool configurations rss_threshold %d, rss_check_interval %d, "
            "rss_maxlimit %d, heapwalk_duration %d, heapwalk_interval %d\n",
            __func__, __LINE__, memwraptool_config->rss_threshold,
            memwraptool_config->rss_check_interval, memwraptool_config->rss_maxlimit,
            memwraptool_config->heapwalk_duration, memwraptool_config->heapwalk_interval);
        if (apps->data.u.memwraptool.rss_threshold != memwraptool_config->rss_threshold) {
            apps->data.u.memwraptool.rss_threshold = memwraptool_config->rss_threshold;
        }
        if (apps->data.u.memwraptool.rss_check_interval != memwraptool_config->rss_check_interval) {
            apps->data.u.memwraptool.rss_check_interval = memwraptool_config->rss_check_interval;
        }
        if (apps->data.u.memwraptool.rss_maxlimit != memwraptool_config->rss_maxlimit) {
            apps->data.u.memwraptool.rss_maxlimit = memwraptool_config->rss_maxlimit;
        }
        if (apps->data.u.memwraptool.heapwalk_duration != memwraptool_config->heapwalk_duration) {
            apps->data.u.memwraptool.heapwalk_duration = memwraptool_config->heapwalk_duration;
        }
        if (apps->data.u.memwraptool.heapwalk_interval != memwraptool_config->heapwalk_interval) {
            if (memwraptool_config->heapwalk_duration < memwraptool_config->heapwalk_interval) {
                wifi_util_error_print(WIFI_MEMWRAPTOOL,
                    "%s:%d heapwalk_duration %d is less than heapwalk_interval %d\n", __func__,
                    __LINE__, memwraptool_config->heapwalk_duration,
                    memwraptool_config->heapwalk_interval);
                free(memwraptool_config);
                return RETURN_ERR;
            }
            apps->data.u.memwraptool.heapwalk_interval = memwraptool_config->heapwalk_interval;
        }
        if (apps->data.u.memwraptool.enable != memwraptool_config->enable) {
            if (memwraptool_config->enable == true) {
                if (rfc_pcfg->memwraptool_app_rfc == false) {
                    wifi_util_error_print(WIFI_MEMWRAPTOOL,
                        "%s:%d memwraptool_app_rfc is disabled\n", __func__, __LINE__);
                    free(memwraptool_config);
                    return RETURN_ERR;
                }
                snprintf(cmd, sizeof(cmd), "/usr/ccsp/wifi/Heapwalkcheckrss.sh %d %d %d %d %d &",
                    memwraptool_config->rss_check_interval, memwraptool_config->rss_threshold,
                    memwraptool_config->rss_maxlimit, memwraptool_config->heapwalk_duration,
                    memwraptool_config->heapwalk_interval);
                int ret = get_stubs_descriptor()->v_secure_system_fn(cmd);
                if (ret == 0) {
                    wifi_util_info_print(WIFI_MEMWRAPTOOL,
                        "%s:%d Heapwalkscheckrss.sh script executed successfully\r\n", __func__,
                        __LINE__);
                }
            } else {
                int ret = get_stubs_descriptor()->v_secure_system_fn("killall Heapwalkcheckrss.sh");
                int ret1 = get_stubs_descriptor()->v_secure_system_fn("killall HeapwalkField.sh");
                if ((ret == 0) && (ret1 == 0)) {
                    wifi_util_info_print(WIFI_MEMWRAPTOOL,
                        "%s:%d Heapwalkcheckrss.sh and HeapwalkField.sh script killed "
                        "successfully\r\n",
                        __func__, __LINE__);
                }
            }
            apps->data.u.memwraptool.enable = memwraptool_config->enable;
        }
        break;
    default:
        wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d Invalid subdoc type %d\n", __func__, __LINE__,
            doc->type);
        break;
    }
    free(memwraptool_config);
    return RETURN_OK;
}

static int handle_memwraptool_webconfig_event(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *data)
{
    switch (sub_type) {
    case wifi_event_webconfig_set_data_dml:
        wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d Entering and subdoc type is %d\n", __func__,
            __LINE__, ((webconfig_subdoc_data_t *)data)->type);
        memwraptool_event_webconfig_set_data(apps, data, sub_type);
        break;
    default:
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d Invalid event type %d\n", __func__, __LINE__,
            sub_type);
        break;
    }
    return RETURN_OK;
}

static int memwraptool_monitor_done_event(wifi_app_t *apps)
{
    char cmd[256];
    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
    int ret = 0;

    if (rfc_pcfg->memwraptool_app_rfc == FALSE) {
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d memwraptool_app_rfc is disabled\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }
    snprintf(cmd, sizeof(cmd), "/usr/ccsp/wifi/Heapwalkcheckrss.sh %d %d %d %d %d &",
        apps->data.u.memwraptool.rss_check_interval, apps->data.u.memwraptool.rss_threshold,
        apps->data.u.memwraptool.rss_maxlimit, apps->data.u.memwraptool.heapwalk_duration,
        apps->data.u.memwraptool.heapwalk_interval);
    ret = get_stubs_descriptor()->v_secure_system_fn(cmd);
    if (ret == 0) {
        wifi_util_info_print(WIFI_MEMWRAPTOOL,
            "%s:%d Heapwalkscheckrss.sh script executed successfully\r\n", __func__, __LINE__);
    } else {
        wifi_util_error_print(WIFI_MEMWRAPTOOL,
            "%s:%d Heapwalkscheckrss.sh script execution failed after monitor init\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

static int handle_memwraptool_command_event(wifi_app_t *apps, wifi_event_subtype_t sub_type)
{
    switch (sub_type) {
    case wifi_event_type_notify_monitor_done:
        if (apps->data.u.memwraptool.enable != TRUE) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d memwraptool is not enabled\n", __func__,
                __LINE__);
            return RETURN_ERR;
        } else {
            memwraptool_monitor_done_event(apps);
        }
        break;
    default:
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d Invalid event type %d\n", __func__, __LINE__,
            sub_type);
        break;
    }
    return RETURN_OK;
}

#ifdef ONEWIFI_MEMWRAPTOOL_APP_SUPPORT
int memwraptool_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
    case wifi_event_type_webconfig:
        handle_memwraptool_webconfig_event(app, event->sub_type, event->u.webconfig_data);
        break;
    case wifi_event_type_command:
        handle_memwraptool_command_event(app, event->sub_type);
        break;
    default:
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d Invalid event type %d\n", __func__, __LINE__,
            event->event_type);
        break;
    }
    return RETURN_OK;
}
#endif

static bus_error_t memwraptool_get_handler(char *event_name, raw_data_t *p_data,
    bus_user_data_t *user_data)
{
    (void)user_data;
    bus_error_t ret = bus_error_success;
    char parameter[MAX_EVENT_NAME_SIZE];
    wifi_app_t *wifi_app = NULL;
    wifi_apps_mgr_t *apps_mgr = NULL;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return bus_error_general;
    }
    memset(parameter, 0, sizeof(parameter));
    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return bus_error_general;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_memwraptool);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d wifi_app_inst_memwraptool not registered\n",
            __func__, __LINE__);
        return bus_error_general;
    }

    if (event_name == NULL) {
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d invalid bus property name %s\n", __func__,
            __LINE__, event_name);
        return bus_error_invalid_input;
    }

    wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d Event name: %s\n", __func__, event_name);
    sscanf(event_name, "Device.WiFi.MemwrapTool.%199s", parameter);

    if (strcmp(parameter, "RSSThreshold") == 0) {
        p_data->data_type = bus_data_type_uint32;
        p_data->raw_data.u32 = wifi_app->data.u.memwraptool.rss_threshold;
    } else if (strcmp(parameter, "RSSCheckInterval") == 0) {
        p_data->data_type = bus_data_type_uint32;
        p_data->raw_data.u32 = wifi_app->data.u.memwraptool.rss_check_interval;
    } else if (strcmp(parameter, "RSSMaxLimit") == 0) {
        p_data->data_type = bus_data_type_uint32;
        p_data->raw_data.u32 = wifi_app->data.u.memwraptool.rss_maxlimit;
    } else if (strcmp(parameter, "HeapWalkDuration") == 0) {
        p_data->data_type = bus_data_type_uint32;
        p_data->raw_data.u32 = wifi_app->data.u.memwraptool.heapwalk_duration;
    } else if (strcmp(parameter, "HeapWalkInterval") == 0) {
        p_data->data_type = bus_data_type_uint32;
        p_data->raw_data.u32 = wifi_app->data.u.memwraptool.heapwalk_interval;
    } else if (strcmp(parameter, "Enable") == 0) {
        p_data->data_type = bus_data_type_boolean;
        p_data->raw_data.b = wifi_app->data.u.memwraptool.enable;
    }
    return ret;
}

static bus_error_t memwraptool_set_handler(char *event_name, raw_data_t *p_data,
    bus_user_data_t *user_data)
{
    (void)user_data;
    char const *name = event_name;
    char parameter[MAX_EVENT_NAME_SIZE];
    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
    memwraptool_config_t *memwraptool_cfg = NULL;
    wifi_app_t *wifi_app = NULL;
    wifi_apps_mgr_t *apps_mgr = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    if (event_name == NULL) {
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s %d: invalid bus property name %s\n", __func__,
            __LINE__, event_name);
        return bus_error_invalid_input;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return bus_error_general;
    }
    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_memwraptool);
    if (wifi_app == NULL) {
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d wifi_app_inst_memwraptool not registered\n",
            __func__, __LINE__);
        return bus_error_general;
    }
    memset(parameter, 0, sizeof(parameter));
    memwraptool_cfg = (memwraptool_config_t *)malloc(sizeof(memwraptool_config_t));
    if (memwraptool_cfg == NULL) {
        wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s %d: failed to allocate memory\n", __func__,
            __LINE__);
        return bus_error_general;
    }
    memcpy(memwraptool_cfg, &wifi_app->data.u.memwraptool, sizeof(memwraptool_config_t));
    wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d Event name :%s\n", __func__, __LINE__, event_name);
    sscanf(name, "Device.WiFi.MemwrapTool.%199s", parameter);

    if (strcmp(parameter, "RSSCheckInterval") == 0) {
        if ((p_data->data_type != bus_data_type_uint32) || (p_data->raw_data.u32 == 0)) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL,
                "%s:%d-%s invalid bus data_type:%x or value: %u\n", __func__, __LINE__, name,
                p_data->data_type, p_data->raw_data.u32);
            free(memwraptool_cfg);
            return bus_error_invalid_input;
        }
        wifi_util_info_print(WIFI_MEMWRAPTOOL, "%s:%d-%s RSSCheckInterval is changed \n", __func__,
            __LINE__, name);
        memwraptool_cfg->rss_check_interval = p_data->raw_data.u32;
    } else if (strcmp(parameter, "RSSThreshold") == 0) {
        if ((p_data->data_type != bus_data_type_uint32) || (p_data->raw_data.u32 == 0)) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL,
                "%s:%d-%s invalid bus data_type:%x or value: %u\n", __func__, __LINE__, name,
                p_data->data_type, p_data->raw_data.u32);
            free(memwraptool_cfg);
            return bus_error_invalid_input;
        }
        wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d-%s RSSThreshold is changed \n", __func__,
            __LINE__, name);
        memwraptool_cfg->rss_threshold = p_data->raw_data.u32;
    } else if (strcmp(parameter, "RSSMaxLimit") == 0) {
        if ((p_data->data_type != bus_data_type_uint32) || (p_data->raw_data.u32 == 0)) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL,
                "%s:%d-%s invalid bus data_type:%x or value: %u\n", __func__, __LINE__, name,
                p_data->data_type, p_data->raw_data.u32);
            free(memwraptool_cfg);
            return bus_error_invalid_input;
        }
        wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d-%s RSSMaxLimit is changed \n", __func__,
            __LINE__, name);
        memwraptool_cfg->rss_maxlimit = p_data->raw_data.u32;
    } else if (strcmp(parameter, "HeapWalkDuration") == 0) {
        if ((p_data->data_type != bus_data_type_uint32) || (p_data->raw_data.u32 == 0)) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL,
                "%s:%d-%s invalid bus data_type:%x or value: %u\n", __func__, __LINE__, name,
                p_data->data_type, p_data->raw_data.u32);
            free(memwraptool_cfg);
            return bus_error_invalid_input;
        }

        if (p_data->raw_data.u32 < (unsigned int)DEFAULT_HEAPWALK_INTERVAL) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL,
                "%s:%d-%s HeapwalkDuration should be greater than HeapWalkInterval\n", __func__,
                __LINE__, name);
            free(memwraptool_cfg);
            return bus_error_invalid_input;
        }
        wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d-%s HeapwalkDuration is changed\n", __func__,
            __LINE__, name);
        memwraptool_cfg->heapwalk_duration = p_data->raw_data.u32;
    } else if (strcmp(parameter, "HeapWalkInterval") == 0) {
        if ((p_data->data_type != bus_data_type_uint32) || (p_data->raw_data.u32 == 0)) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL,
                "%s:%d-%s invalid bus data_type:%x or value: %u\n", __func__, __LINE__, name,
                p_data->data_type, p_data->raw_data.u32);
            free(memwraptool_cfg);
            return bus_error_invalid_input;
        }
        if (p_data->raw_data.u32 > memwraptool_cfg->heapwalk_duration) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL,
                "%s:%d-%s HeapwalkDuration should be greater than HeapWalkInterval\n", __func__,
                __LINE__, name);
            free(memwraptool_cfg);
            return bus_error_invalid_input;
        }
        memwraptool_cfg->heapwalk_interval = p_data->raw_data.u32;
    } else if (strcmp(parameter, "Enable") == 0) {
        if (p_data->data_type != bus_data_type_boolean) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d-%s invalid bus data_type:%x\n", __func__,
                __LINE__, name, p_data->data_type);
            free(memwraptool_cfg);
            return bus_error_invalid_input;
        }

        if (rfc_pcfg->memwraptool_app_rfc == FALSE) {
            wifi_util_error_print(WIFI_MEMWRAPTOOL, "%s:%d-%s RFC is not enabled\n", __func__,
                __LINE__, name);
            free(memwraptool_cfg);
            return bus_error_invalid_input;
        }
        if (memwraptool_cfg->enable == p_data->raw_data.b) {
            wifi_util_dbg_print(WIFI_MEMWRAPTOOL, "%s:%d-%s No change in Memwraptool Enable\n",
                __func__, __LINE__, name);
            free(memwraptool_cfg);
            return bus_error_success;
        }
        memwraptool_cfg->enable = p_data->raw_data.b;
        wifi_util_info_print(WIFI_MEMWRAPTOOL, "%s:%d-%s Enable is changed\n", __func__, __LINE__,
            name);
    }
    wifi_util_info_print(WIFI_MEMWRAPTOOL,
        "%s:%d values are pushed to push_memwrap_data_dml_to_ctrl_queue\n", __func__, __LINE__);
    push_memwrap_data_dml_to_ctrl_queue(memwraptool_cfg);
    free(memwraptool_cfg);
    return bus_error_success;
}

#ifdef ONEWIFI_MEMWRAPTOOL_APP_SUPPORT
int memwraptool_init(wifi_app_t *app, unsigned int create_flag)
{
    bus_error_t rc = bus_error_success;
    char *component_name = "WifiAppsMemwrapTool";
    int num_elements;
    wifi_app_t *memwraptool_app = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr = &ctrl->apps_mgr;
    wifi_global_param_t *pcfg = (wifi_global_param_t *)get_wifidb_wifi_global_param();

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: Init Memwraptool\n", __func__, __LINE__);

    if (apps_mgr == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memwraptool_app = get_app_by_inst(apps_mgr, wifi_app_inst_memwraptool);
    if (memwraptool_app == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: NULL MEMWRAPTOOL app instance\n", __func__,
            __LINE__);
        return RETURN_ERR;
    }

    app->data.u.memwraptool.rss_check_interval = pcfg->memwraptool.rss_check_interval;
    app->data.u.memwraptool.rss_threshold = pcfg->memwraptool.rss_threshold;
    app->data.u.memwraptool.rss_maxlimit = pcfg->memwraptool.rss_maxlimit;
    app->data.u.memwraptool.heapwalk_duration = pcfg->memwraptool.heapwalk_duration;
    app->data.u.memwraptool.heapwalk_interval = pcfg->memwraptool.heapwalk_interval;
    app->data.u.memwraptool.enable = pcfg->memwraptool.enable;

    rc = get_bus_descriptor()->bus_open_fn(&app->handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS,
            "%s:%d bus: bus_open_fn open failed for component:%s, rc:%d\n", __func__, __LINE__,
            component_name, rc);
        return RETURN_ERR;
    }

    num_elements = (sizeof(dataElements) / sizeof(bus_data_element_t));

    rc = get_bus_descriptor()->bus_reg_data_element_fn(&app->handle, dataElements, num_elements);
    if (rc != bus_error_success) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d bus_reg_data_element_fn failed, rc:%d\n", __func__,
            __LINE__, rc);
    } else {
        wifi_util_info_print(WIFI_APPS, "%s:%d Apps bus_regDataElement success\n", __func__,
            __LINE__);
    }
    return RETURN_OK;
}

int memwraptool_deinit(wifi_app_t *app)
{
    bus_error_t rc = bus_error_success;
    int num_elements;

    wifi_util_info_print(WIFI_APPS, "%s:%d: Deinit Memwraptool\n", __func__, __LINE__);
    num_elements = (sizeof(dataElements) / sizeof(bus_data_element_t));

    rc = get_bus_descriptor()->bus_unreg_data_element_fn(&app->handle, num_elements, dataElements);
    if (rc != bus_error_success) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d bus_unreg_data_element_fn failed, rc:%d\n", __func__,
            __LINE__, rc);
    } else {
        wifi_util_info_print(WIFI_APPS, "%s:%d Apps bus_unregDataElement success\n", __func__,
            __LINE__);
    }

    rc = get_bus_descriptor()->bus_close_fn(&app->handle);
    if (rc != bus_error_success) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d: Unable to close memwraptool bus handle\n", __func__,
            __LINE__);
    }
    return RETURN_OK;
}
#endif
