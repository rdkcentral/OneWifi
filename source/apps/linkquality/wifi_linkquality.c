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
#include "wifi_stubs.h"
#include "wifi_util.h"
#include "wifi_apps_mgr.h"
#include "wifi_linkquality.h"
#include "wifi_hal_rdk_framework.h"
#include "wifi_monitor.h"

/* Register callback BEFORE starting qmgr */
void publish_qmgr_subdoc(const report_batch_t* report)
{
    webconfig_subdoc_type_t subdoc_type;
    webconfig_subdoc_data_t *data;
    //webconfig_subdoc_data_t data_decode = {0};
    bus_error_t status;
    raw_data_t rdata;
    wifi_util_error_print(WIFI_CTRL,"[C CALLBACK] %s:%d link_count=%d\n",__func__,__LINE__,report->link_count);
    #if 1
    link_report_t *lr = report->links;
    for (size_t i = 0; i < report->link_count; i++) {
        wifi_util_error_print(WIFI_CTRL,"[C CALLBACK] %s:%d link_count=%d\n",__func__,__LINE__,i);

        wifi_util_error_print(
            WIFI_CTRL,
            "MAC=%s Alarm=%d Samples=%zu\n",
            lr->mac,
            lr->alarm,
            lr->sample_count
        );

        sample_t *s = lr->samples;
        for (size_t j = 0; j < lr->sample_count; j++) {
            wifi_util_error_print(
                WIFI_CTRL,
                " [%s] Score=%.2f SNR=%.2f PER=%.2f PHY=%.2f\n",
                s->time, s->score, s->snr, s->per, s->phy
            );
            s++;
        }
        lr++;
    }
    #endif
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    data = (webconfig_subdoc_data_t *)malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
          wifi_util_error_print(WIFI_CTRL, "%s:%d Error in allocation memory\n", __func__, __LINE__);
          return ;
    }
 
    memset(data, '\0', sizeof(webconfig_subdoc_data_t));
    data->u.decoded.qmgr_report =  (report_batch_t *)report;
    subdoc_type = webconfig_subdoc_type_link_report;
    if (webconfig_encode(&ctrl->webconfig, data, subdoc_type) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Error in encoding link report\n", __func__,
              __LINE__);
        free(data);
        return;
    }
    memset(&rdata, 0, sizeof(raw_data_t));
    rdata.data_type = bus_data_type_string;
    rdata.raw_data.bytes = (void *)data->u.encoded.raw;
    wifi_util_error_print(WIFI_CTRL,"raw data=%s\n",(char*)rdata.raw_data.bytes);
    rdata.raw_data_len = strlen(data->u.encoded.raw) + 1;
    status = get_bus_descriptor()->bus_event_publish_fn(&ctrl->handle, WIFI_QUALITY_LINKREPORT, &rdata);
    if (status != bus_error_success) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d: bus: bus_event_publish_fn Event failed %d\n",
            __func__, __LINE__, status);
        free(data);
        return ;
    }
   #if 0
    char *str =  (char *) data->u.encoded.raw;
    wifi_util_error_print(WIFI_CTRL,"raw data=%s\n",str);
    if (webconfig_decode(&ctrl->webconfig, &data_decode, str) != webconfig_error_none) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Error in decoding link report\n", __func__,
              __LINE__);
        return;
    }
    report_batch_t *report1 = data_decode.u.decoded.qmgr_report;

    for (size_t i = 0; i < report1->link_count; i++) {
        link_report_t *lr = &report1->links[i];

        wifi_util_error_print(
            WIFI_CTRL,
           "[C CALLBACK] %s:%d link=%zu\n",
            __func__, __LINE__, i
        );

        wifi_util_error_print(
            WIFI_CTRL,
            "MAC=%s Alarm=%d Samples=%zu\n",
           lr->mac,
           lr->alarm,
           lr->sample_count
        );

       for (size_t j = 0; j < lr->sample_count; j++) {

            sample_t *s = &lr->samples[j];

            wifi_util_error_print(
                WIFI_CTRL,
                "  [%zu] time=%s score=%f snr=%f per=%f phy=%f\n",
                j,
                s->time,
                s->score,
                s->snr,
                s->per,
                s->phy
            );
        }
    }
    #endif

    free(data);
}

int link_quality_event_exec_start(wifi_app_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    qmgr_register_callback(publish_qmgr_subdoc);
    start_link_metrics();
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

int link_quality_event_exec_stop(wifi_app_t *apps, void *arg)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}
int link_quality_hal_disconnect(wifi_app_t *apps, void *arg, int len)
{
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    linkquality_data_t *data = (linkquality_data_t *)arg;
    stats_arg_t *stats = &data->stats;
    wifi_util_error_print(
        WIFI_CTRL,
        "%s:%d  mac=%s per=%f snr=%d phy=%d\n",
        __func__, __LINE__,
        stats->mac_str,
        stats->per,
        stats->snr,
        stats->phy
    );

    remove_link_stats(stats);
    return RETURN_OK;

}
int link_quality_param_reinit(wifi_app_t *apps, void *arg, int len)
{
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    linkquality_data_t *data = (linkquality_data_t *)arg;

     server_arg_t *server_arg = &data->server_arg;
        wifi_util_dbg_print(
            WIFI_APPS,
            "%s:%d  threshold=%f reporting=%d\n",
            __func__, __LINE__,
            server_arg->threshold,
            server_arg->reporting
        );
        reinit_link_metrics(server_arg);

    return RETURN_OK;
}

int link_quality_event_exec_timeout(wifi_app_t *apps, void *arg, int len)
{
    if (!arg) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL arg\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    linkquality_data_t *data = (linkquality_data_t *)arg;

    /* The number of devices is stored in the first element */
    int num_devs = len;
    wifi_util_dbg_print(WIFI_APPS, "%s:%d num_devs =%d\n", __func__, __LINE__,num_devs);

    for (int i = 0; i < num_devs; i++) {

        stats_arg_t *stats = &data[i].stats;
        wifi_util_dbg_print(
            WIFI_APPS,
            "%s:%d idx=%d mac=%s per=%f snr=%d phy=%d\n",
            __func__, __LINE__,
            i,
            stats->mac_str,
            stats->per,
            stats->snr,
            stats->phy,
            stats->vap_index
        );

        add_stats_metrics(stats);
    }

    return RETURN_OK;
}

int exec_event_link_quality(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg, int len)
{
    switch (sub_type) {
        case wifi_event_exec_start:
            link_quality_event_exec_start(apps, arg);
            break;

        case wifi_event_exec_stop:
            link_quality_event_exec_stop(apps, arg);
            break;

        case wifi_event_exec_timeout:
            link_quality_event_exec_timeout(apps, arg,len);
            break;
        default:
            wifi_util_error_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
            break;
    }
    return RETURN_OK;
}

int exec_event_webconfig_event(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg, int len)
{
    wifi_util_info_print(WIFI_APPS,"Enter %s:%d\n",__func__,__LINE__);
    switch (sub_type) {
        case wifi_event_exec_start:
            break;

        case wifi_event_exec_stop:
            break;

        case wifi_event_exec_timeout:
            link_quality_param_reinit(apps, arg,len);
            break;
        default:
            wifi_util_error_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
            break;
    }
    return RETURN_OK;
}
int exec_event_hal_ind(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *arg, int len)
{
    wifi_util_info_print(WIFI_APPS,"Enter %s:%d\n",__func__,__LINE__);
    switch (sub_type) {
        case wifi_event_exec_start:
            break;

        case wifi_event_exec_stop:
            break;

        case wifi_event_exec_timeout:
            link_quality_hal_disconnect(apps, arg,len);
            break;
        default:
            wifi_util_error_print(WIFI_APPS, "%s:%d: event not handle %s\r\n", __func__, __LINE__,
            wifi_event_subtype_to_string(sub_type));
            break;
    }
    return RETURN_OK;
}

int link_quality_event(wifi_app_t *app, wifi_event_t *event)
{
    switch (event->event_type) {
        case wifi_event_type_webconfig:
            exec_event_webconfig_event(app, event->sub_type, event->u.core_data.msg, event->u.core_data.len);
            break;

        case wifi_event_type_exec:
            exec_event_link_quality(app, event->sub_type, event->u.core_data.msg, event->u.core_data.len);
            break;

        case wifi_event_type_hal_ind:
            exec_event_hal_ind(app, event->sub_type, event->u.core_data.msg, event->u.core_data.len);
            break;

        default:
            break;
    }

    return RETURN_OK;
}


int link_quality_init(wifi_app_t *app, unsigned int create_flag)
{
    char *component_name = "WifiLinkReport";
    int num_elements = 0;
    int rc = bus_error_success;

    bus_data_element_t dataElements[] = {
        { WIFI_QUALITY_LINKREPORT, bus_element_type_method,
            { NULL, NULL, NULL, NULL, NULL, NULL }, slow_speed, ZERO_TABLE,
            { bus_data_type_string, false, 0, 0, 0, NULL } } ,
    };

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    rc = get_bus_descriptor()->bus_open_fn(&app->handle, component_name);
    if (rc != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d bus: bus_open_fn open failed for component:%s, rc:%d\n",
            __func__, __LINE__, component_name, rc);
        return RETURN_ERR;
    }
    num_elements = (sizeof(dataElements)/sizeof(bus_data_element_t));
    if (get_bus_descriptor()->bus_reg_data_element_fn(&app->ctrl->handle, dataElements,
        num_elements) != bus_error_success) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: failed to register Linkstats app data elements\n", __func__,
        __LINE__);
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: Linkstats app data elems registered\n", __func__,__LINE__);
    return RETURN_OK;
}

int link_quality_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}
