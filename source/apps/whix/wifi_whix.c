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

#ifdef CCSP_COMMON
#include <telemetry_busmessage_sender.h>
#include "cosa_wifi_apis.h"
#include "ccsp_psm_helper.h"
#endif // CCSP_COMMON
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include "collection.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_whix.h"
#include <sys/sysinfo.h>
#include <time.h>
#include <sys/un.h>
#include <assert.h>
#include <limits.h>
#ifdef CCSP_COMMON
#include "ansc_status.h"
#include <sysevent/sysevent.h>
#include "ccsp_base_api.h"
#include "wifi_passpoint.h"
#include "ccsp_trace.h"
#include "safec_lib_common.h"
#include "ccsp_WifiLog_wrapper.h"
#endif // CCSP_COMMON


#ifndef  UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(_p_)         (void)(_p_)
#endif

#define TIMER_TASK_COMPLETE     0
#define TIMER_TASK_CONTINUE     1
#define TIMER_TASK_ERROR        -1

static wifi_monitor_t g_monitor_module;

static const char *wifi_health_log = "/rdklogs/logs/wifihealth.txt";

int radio_health_telemetry_logger_whix(unsigned int radio_index, int ch_util)
{
    char buff[256] = {0}, tmp[128] = {0}, telemetry_buf[64] = {0}, t_string[5] = {0};
    unsigned long int itr = 0;
    char *t_str = NULL;

    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    if (g_monitor_module.radio_presence[radio_index] == false) {
        wifi_util_error_print(WIFI_APPS, "%s:%d Radio presence is false\n", __func__, __LINE__);
        return TIMER_TASK_ERROR;
    }
    memset(buff, 0, sizeof(buff));
    memset(tmp, 0, sizeof(tmp));
    get_formatted_time(tmp);
    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio_index);
    if (radioOperation != NULL) {
        wifi_util_dbg_print(WIFI_APPS, "Radio operation param is not null\n");
        //Printing the utilization of Radio if and only if the radio is enabled
        if (radioOperation->enable) {
            snprintf(buff, 256, "%s WIFI_BANDUTILIZATION_%d:%d\n", tmp, radio_index+1, ch_util);
            memset(tmp, 0, sizeof(tmp));
            t_str = convert_radio_index_to_band_str_g(radio_index);
            if (t_str != NULL) {
                strncpy(t_string, t_str, sizeof(t_string) - 1);
                for (itr=0; itr<strlen(t_string); itr++) {
                    t_string[itr] = toupper(t_string[itr]);
                }
                snprintf(tmp, sizeof(tmp), "Wifi_%s_utilization_split", t_string);
            } else {
                wifi_util_dbg_print(WIFI_MON, "%s:%d Failed to get band for radio Index %d\n", __func__, __LINE__, radio_index);
                return TIMER_TASK_ERROR;
            }

            //updating T2 Marker here
            memset(telemetry_buf, 0, sizeof(telemetry_buf));
            snprintf(telemetry_buf, sizeof(telemetry_buf), "%d", ch_util);
            t2_event_s(tmp, telemetry_buf);
        } else {
            snprintf(buff, 256, "%s Radio_%d is down, so not printing WIFI_BANDUTILIZATION marker", tmp, radio_index + 1);
        }

        wifi_util_error_print(WIFI_APPS, "buff is %s\n", buff);
        write_to_file(wifi_health_log, buff);
    }
    return TIMER_TASK_COMPLETE;
}

int radio_channel_stats_response(wifi_provider_response_t *provider_response)
{
    unsigned int radio_index = 0;
    radio_index = provider_response->args.radio_index;
    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    unsigned int count = 0;
    wifi_channelStats_t *channel_stats = NULL;

    channel_stats = (wifi_channelStats_t*) provider_response->stat_pointer;

    wifi_util_dbg_print(WIFI_APPS,"%s:%d radio_index : %d stats_array_size : %d\r\n",__func__, __LINE__, radio_index, provider_response->stat_array_size);
    for (count = 0; count < provider_response->stat_array_size; count++) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d count : %d provider_response->ch_utilization: %d\r\n",__func__, __LINE__, count, channel_stats[count].ch_utilization);
        radio_health_telemetry_logger_whix(radio_index, channel_stats[count].ch_utilization);
    }
    return RETURN_OK;
}

void update_clientdiagdata(unsigned int num_devs, int vap_idx, sta_data_t *assoc_stats)
{
    //add code of events_update_clientdiagdata
    wifi_util_dbg_print(WIFI_APPS, "Entering %s for vap_idx : %d\n", __func__, vap_idx);
    return;
}

int associated_device_stats_response(wifi_provider_response_t *provider_response)
{
    unsigned int vap_index = 0;
    vap_index = provider_response->args.vap_index;
    sta_data_t *assoc_stats = NULL;
    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);

    assoc_stats = (sta_data_t *) provider_response->stat_pointer;

    wifi_util_dbg_print(WIFI_APPS,"%s:%d: vap_index : %d stats_array_size : %d\r\n",__func__, __LINE__, vap_index, provider_response->stat_array_size);
    update_clientdiagdata(provider_response->stat_array_size, vap_index, assoc_stats);

    return RETURN_OK;
}

int handle_whix_provider_response(wifi_app_t *app, wifi_event_t *event)
{
    // Handle the response for stats, radio confs
    wifi_provider_response_t    *provider_response;
    provider_response = (wifi_provider_response_t *)event->u.provider_response;
    int ret = RETURN_ERR;
    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    if (provider_response == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d input event is NULL\r\n", __func__, __LINE__);
        return ret;
    }

    switch (provider_response->data_type) {
        case mon_stats_type_radio_channel_stats:
            wifi_util_error_print(WIFI_APPS, "collect channel stats %s\n", __func__);
            ret = radio_channel_stats_response(provider_response);
        break;
        /*	case mon_stats_type_neighbor_stats:
          ret = neighbor_stats_response(provider_response);
          break;
          */
        case mon_stats_type_associated_device_stats:
            ret = associated_device_stats_response(provider_response);
        break;
        default:
            wifi_util_error_print(WIFI_MON, "%s:%d Data type %d is not supported.\n", __func__,__LINE__, provider_response->args.app_info);
            return RETURN_ERR;
    }
    return RETURN_OK;
}

int monitor_whix_event(wifi_app_t *app, wifi_event_t *event)
{
    int ret = RETURN_ERR;
    unsigned int radio;

    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    if (event == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d input event is NULL\r\n", __func__, __LINE__);
        return ret;
    }
    wifi_mgr_t *mgr = get_wifimgr_obj();
    for (radio = 0; radio < getNumberRadios(); radio++) {
        g_monitor_module.radio_presence[radio] = mgr->hal_cap.wifi_prop.radio_presence[radio];
    }
    switch (event->sub_type) {
        case wifi_event_monitor_provider_response:
            wifi_util_dbg_print(WIFI_APPS, "Inside wifi_event_monitor_data_collection_response %s\n", __func__);
            ret = handle_whix_provider_response(app, event);
        break;
        default:
            wifi_util_error_print(WIFI_APPS, "%s:%d Inside default\n", __func__, __LINE__);
        break;
    }
    return ret;
}

int whix_event(wifi_app_t *app, wifi_event_t *event)
{
    switch(event->event_type) {
        case wifi_event_type_monitor:
            monitor_whix_event(app, event);
        break;
        default:
        break;
    }
    return RETURN_OK;
}

int whix_init(wifi_app_t *app, unsigned int create_flag)
{
    wifi_util_dbg_print(WIFI_APPS, "Entering %s\n", __func__);
    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int whix_deinit(wifi_app_t *app)
{
    push_whix_config_event_to_monitor_queue(app, mon_stats_request_state_stop);
    return RETURN_OK;
}

