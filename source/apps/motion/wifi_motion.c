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
#include "wifi_motion.h"
#if DML_SUPPORT
#include "wifi_analytics.h"
#endif
#include <rbus.h>
#include <telemetry_busmessage_sender.h>
#include <fcntl.h>
#include <errno.h>

#define UNREFERENCED_PARAMETER(_p_)         (void)(_p_)

const char *wifi_log = "/rdklogs/logs/WiFilog.txt.0";
bool csi_check_timeout(csi_session_t *csi, int client_idx, struct timeval* t_now)
{
    struct timeval interval;
    int  interval_ms_margin;
    struct timeval timeout;

    if (csi == NULL || t_now == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s: Invalid arguments. csi %p, t_now %p\n",__func__, csi, t_now);
        return FALSE;
    }
    //Need to support the fluctuation of csi interval coming from the driver
    interval_ms_margin = csi->csi_time_interval - (MIN_CSI_INTERVAL/2);

    interval.tv_sec = (interval_ms_margin / 1000);
    interval.tv_usec = (interval_ms_margin % 1000) * 1000;
    timeradd(&(csi->last_publish_time[client_idx]), &interval, &timeout);
    if (timercmp(t_now, &timeout, >)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

queue_t *get_csi_session_queue()
{
    wifi_app_t *wifi_app =  NULL;
    wifi_apps_mgr_t *apps_mgr;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_motion);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }
    queue_t *csi_queue = wifi_app->data.u.motion.csi_session_queue;
    return csi_queue;
}

queue_t *get_csi_data_queue()
{
    wifi_app_t *wifi_app =  NULL;
    wifi_apps_mgr_t *apps_mgr;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_motion);
    if (wifi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return NULL;
    }
    queue_t *csi_queue = wifi_app->data.u.motion.csi_data_queue;
    return csi_queue;
}


static void csi_disable_client(csi_session_t *r_csi)
{
    int count = 0;
    int i = 0, j = 0, k = 0;
    csi_session_t *csi = NULL;
    bool client_in_diff_subscriber = FALSE;
    wifi_app_t *app = NULL;

    if (r_csi == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s: r_csi is NULL\n",__func__);
        return;
    }

    wifi_apps_mgr_t *apps_mgr;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }
    app = get_app_by_inst(apps_mgr, wifi_app_inst_motion);
    queue_t *csi_queue = get_csi_session_queue();
    count = queue_count(csi_queue);

    for (j =0 ; j< r_csi->no_of_mac; j++) {
        client_in_diff_subscriber = FALSE;
        for (i = 0; i<count; i++) {
            csi = queue_peek(csi_queue, i);

            if (csi == NULL || csi == r_csi) {
                continue;
            }
            if (!(csi->enable && csi->subscribed && !(app->data.u.motion.paused))) {
                continue;
            }

            for (k = 0; k < csi->no_of_mac; k++) {
                if (memcmp(r_csi->mac_list[j], csi->mac_list[k], sizeof(mac_addr_t))== 0) {
                    //Client is also monitored by a different subscriber
                    wifi_util_info_print(WIFI_APPS, "%s: Not Disabling csi for client mac %02x..%02x\n",__func__,r_csi->mac_list[j][0],r_csi->mac_list[j][5]);
                    client_in_diff_subscriber = TRUE;
                    break;
                }
            }
            if (client_in_diff_subscriber)
                break;
        }
        if ((client_in_diff_subscriber == FALSE) && (r_csi->mac_is_connected[j] == TRUE)) {
            wifi_util_info_print(WIFI_APPS, "%s: Disabling for client mac %02x..%02x\n",__func__,r_csi->mac_list[j][0],r_csi->mac_list[j][5]);

            //need to call csi stop function to stop CSIENgine
            wifi_app_t *csi_app = app->data.u.motion.csi_app;
            if (csi_app == NULL) {
                wifi_util_info_print(WIFI_APPS, "%s:%d NULL Pointer Unable to stop CSI \n", __func__, __LINE__);
                return;
            }
            csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, r_csi->ap_index[j], r_csi->mac_list[j], wifi_app_inst_motion);
        }
    }
}

static csi_session_t* csi_get_session(bool create, int csi_session_number) {
    csi_session_t *csi = NULL;
    int count = 0, i = 0;
    queue_t *csi_queue = get_csi_session_queue();
    char fifo_path[64] = {0};

    count = queue_count(csi_queue);
    for (i = 0; i<count; i++) {
        csi = queue_peek(csi_queue, i);
        if (csi == NULL){
            continue;
        }
        if (csi->csi_sess_number == csi_session_number) {
            return csi;
        }
    }

    if (create == FALSE) {
        return NULL;
    }


    csi = (csi_session_t *) malloc(sizeof(csi_session_t));
    if (csi == NULL) {
        return NULL;
    }

    memset(csi, 0, sizeof(csi_session_t));
    csi->csi_time_interval = MIN_CSI_INTERVAL;
    csi->csi_sess_number = csi_session_number;
    csi->enable = FALSE;
    csi->subscribed = FALSE;
    csi->csi_fd = -1;

    //Create FIFO fr the session.
    snprintf(fifo_path, sizeof(fifo_path), "/tmp/csi_motion_pipe%d", csi_session_number);
    mkfifo(fifo_path, 0777);

    queue_push(csi_queue, csi);
    return csi;
}

static void csi_update_client_mac_status(mac_addr_t mac, bool connected, int ap_idx) {
    csi_session_t *csi = NULL;
    int count = 0;
    int i = 0, j = 0;
    bool client_csi_monitored = FALSE;
    wifi_apps_mgr_t *apps_mgr;
    wifi_app_t *app = NULL;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    queue_t *csi_queue = get_csi_session_queue();
    if (csi_queue == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    app = get_app_by_inst(apps_mgr, wifi_app_inst_motion);
    count = queue_count(csi_queue);
    wifi_util_info_print(WIFI_APPS, "%s: Received Mac %d %d %02x %02x\n",__func__, connected, count, mac[0], mac[5]);
    for (i = 0; i<count; i++) {
        csi = queue_peek(csi_queue, i);
        if (csi == NULL) {
            continue;
        }

        wifi_util_dbg_print(WIFI_APPS, "%s: Received Mac  %d %d %d %02x %02x\n",__func__, connected, csi->subscribed, csi->enable, mac[0], mac[5]);
        for (j =0 ;j < csi->no_of_mac; j++) {
            wifi_util_dbg_print(WIFI_APPS, "%s: checking with Mac  %d %d %d %02x %02x\n",__func__, connected, csi->subscribed, csi->enable, csi->mac_list[j][0], csi->mac_list[j][5]);
            if (memcmp(mac, csi->mac_list[j], sizeof(mac_addr_t)) == 0) {
                csi->mac_is_connected[j] = connected;
                if (csi->enable && csi->subscribed && !(app->data.u.motion.paused)) {
                    client_csi_monitored = TRUE;
                }
                if (connected == FALSE) {
                    csi->ap_index[j] = -1;
                }
                else {
                    csi->ap_index[j] = ap_idx;
                }
                break;
            }
        }
    }

    wifi_app_t *csi_app = app->data.u.motion.csi_app;
    if (csi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }

    if (client_csi_monitored) {
        wifi_util_dbg_print(WIFI_APPS, "%s: Updating csi collection for Mac %02x %02x %d\n",__func__, mac[0], mac[5], connected);
        if (connected) {
            csi_app->data.u.csi.csi_fns.csi_start_fn(csi_app, ap_idx, (unsigned char*)mac, wifi_app_inst_motion);
        } else {
            csi_app->data.u.csi.csi_fns.csi_stop_fn((void *)csi_app, ap_idx, (unsigned char*)mac, wifi_app_inst_motion);
        }
    }
}

void csi_set_client_mac(char *r_mac_list, int csi_session_number)
{
    csi_session_t *csi = NULL;
    int ap_index = -1, mac_ctr = 0;
    int i = 0;
    char *mac_tok=NULL;
    char* rest = NULL;
    char mac_list[MAX_CSI_CLIENTMACLIST_STR] = {0};
    struct timeval t_now = {0};
    wifi_apps_mgr_t *apps_mgr = NULL;
    wifi_app_t *app  = NULL;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    if (r_mac_list == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s: mac_list is NULL \n",__func__);
        return;
    }
    app = get_app_by_inst(apps_mgr, wifi_app_inst_motion);
    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    csi = csi_get_session(FALSE, csi_session_number);
    if (!csi) {
        wifi_util_error_print(WIFI_APPS, "%s: csi session not present \n",__func__);
        return;
    }
    if (csi->no_of_mac > 0) {
        wifi_util_info_print(WIFI_APPS, "%s: Mac already configured %d\n",__func__, csi->no_of_mac);
        csi_disable_client(csi);
        for(i = 0; i<csi->no_of_mac; i++) {
            csi->mac_is_connected[i] = FALSE;
            csi->ap_index[mac_ctr] = -1;
            memset(&csi->mac_list[i], 0, sizeof(mac_addr_t));
        }
        csi->no_of_mac = 0;
    }

    strncpy(mac_list, r_mac_list, MAX_CSI_CLIENTMACLIST_STR);
    rest = mac_list;
    if (strlen(mac_list) > 0)  {
        gettimeofday(&t_now, NULL);
        while ((mac_tok = strtok_r(rest, ",", &rest))) {

            wifi_util_dbg_print(WIFI_APPS, "%s: Mac %s\n",__func__, mac_tok);
            str_to_mac_bytes(mac_tok,(unsigned char*)&csi->mac_list[mac_ctr]);
            csi->no_of_mac++;
            ap_index= getApIndexfromClientMac((char *)&csi->mac_list[mac_ctr]);
            if (ap_index >= 0) {
                csi->ap_index[mac_ctr] = ap_index;
                csi->mac_is_connected[mac_ctr] = TRUE;
                if (csi->enable && csi->subscribed) {
                    wifi_util_info_print(WIFI_APPS, "%s: Enabling csi collection for Mac %s\n",__func__, mac_tok);
                    wifi_app_t *csi_app = app->data.u.motion.csi_app;
                    if (csi_app != NULL) {
                        csi_app->data.u.csi.csi_fns.csi_start_fn((void *)csi_app, ap_index, csi->mac_list[mac_ctr], wifi_app_inst_motion);
                    }
                }
            } else {
                wifi_util_info_print(WIFI_APPS, "%s: Not Enabling csi collection for Mac %s\n",__func__, mac_tok);
                csi->ap_index[mac_ctr] = -1;
                csi->mac_is_connected[mac_ctr] = FALSE;
            }
            mac_ctr++;
        }
        for (i = 0; i<csi->no_of_mac; i++) {
            memcpy(&csi->last_publish_time[i], &t_now, sizeof(struct timeval));
        }
    }
    wifi_util_info_print(WIFI_APPS, "%s: Total mac's present -  %d %s\n",__func__, csi->no_of_mac, r_mac_list);
}

static void csi_enable_client(csi_session_t *csi)
{
    int i =0;
    int ap_index = -1;
    if ((csi == NULL) || !(csi->enable && csi->subscribed)) {
        return;
    }

    wifi_apps_mgr_t *apps_mgr;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    wifi_app_t *app = get_app_by_inst(apps_mgr, wifi_app_inst_motion);
    if (app == NULL) {
        wifi_util_info_print(WIFI_APPS, "%s:%d NULL Pointer Unable to start CSI\n", __func__, __LINE__);
        return;
    }

    wifi_app_t *csi_app = app->data.u.motion.csi_app;
    if (csi_app == NULL) {
        wifi_util_info_print(WIFI_APPS, "%s:%d NULL Pointer Unable to start CSI\n", __func__, __LINE__);
        return;
    }

    for (i =0; i<csi->no_of_mac; i++) {
        if ((csi->ap_index[i] != -1) && (csi->mac_is_connected[i] == TRUE)) {
            wifi_util_info_print(WIFI_APPS, "%s: Enabling csi collection for Mac %02x..%02x\n",__func__, csi->mac_list[i][0] , csi->mac_list[i][5]  );
            csi_app->data.u.csi.csi_fns.csi_start_fn((void *)csi_app, csi->ap_index[i], csi->mac_list[i], wifi_app_inst_motion);
        }
        //check if client is connected now
        else {
            ap_index= getApIndexfromClientMac((char *)&csi->mac_list[i]);
            if (ap_index >= 0) {
                csi->ap_index[i] = ap_index;
                csi->mac_is_connected[i] = TRUE;
                wifi_util_info_print(WIFI_APPS, "%s: Enabling csi collection for Mac %02x..%02x\n",__func__, csi->mac_list[i][0] , csi->mac_list[i][5]  );
                csi_app->data.u.csi.csi_fns.csi_start_fn((void *)csi_app, csi->ap_index[i], csi->mac_list[i], wifi_app_inst_motion);
            }
        }
    }
}

void csi_enable_session(bool enable, int csi_session_number)
{
    csi_session_t *csi = NULL;

    csi = csi_get_session(FALSE, csi_session_number);
    if (csi) {
        wifi_util_dbg_print(WIFI_APPS, "%s: Enable session %d enable - %d\n",__func__, csi_session_number, enable);
        if (enable) {
            csi->enable = enable;
            csi_enable_client(csi);
        }  else {
            csi_disable_client(csi);
            csi->enable = enable;
        }
    }
}

void csi_enable_subscription(bool subscribe, int csi_session_number)
{
    csi_session_t *csi = NULL;
    wifi_app_t *app =  NULL;
    wifi_apps_mgr_t *apps_mgr;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    app = get_app_by_inst(apps_mgr, wifi_app_inst_motion);
    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    pthread_mutex_lock(&app->data.u.motion.lock);
    csi = csi_get_session(TRUE, csi_session_number);
    if (csi) {
        wifi_util_info_print(WIFI_APPS, "%s: subscription for session %d\n",__func__, csi_session_number);
        if (subscribe) {
            csi->subscribed = subscribe;
            csi_enable_client(csi);
        } else {
            csi_disable_client(csi);
            csi->subscribed = subscribe;
        }
    }
    pthread_mutex_unlock(&app->data.u.motion.lock);
}

void csi_create_session(int csi_session_number)
{
    csi_get_session(TRUE, csi_session_number);
}

void csi_set_interval(int interval, int csi_session_number)
{
    csi_session_t *csi = NULL;
    wifi_app_t *app =  NULL;
    wifi_apps_mgr_t *apps_mgr;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    app = get_app_by_inst(apps_mgr, wifi_app_inst_motion);
    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    pthread_mutex_lock(&app->data.u.motion.lock);
    csi = csi_get_session(FALSE, csi_session_number);
    if (csi) {
        csi->csi_time_interval = interval;
    }
    pthread_mutex_unlock(&app->data.u.motion.lock);
}

static int push_csi_data_dml_to_ctrl_queue(queue_t *csi_queue)
{
    webconfig_subdoc_data_t *data;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    char *str = NULL;

    if ((csi_queue == NULL)) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Error, queue is NULL\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }
    data = (webconfig_subdoc_data_t *) malloc(sizeof(webconfig_subdoc_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s: malloc failed to allocate webconfig_subdoc_data_t, size %d\n", \
                __func__, sizeof(webconfig_subdoc_data_t));
        return RBUS_ERROR_BUS_ERROR;
    }
    memset(data, 0, sizeof(webconfig_subdoc_data_t));
    wifi_util_dbg_print(WIFI_APPS, "%s: queue count is %lu\n", __func__, queue_count(csi_queue));
    data->u.decoded.csi_data_queue = csi_queue;

    if (webconfig_encode(&ctrl->webconfig, data, webconfig_subdoc_type_csi) == webconfig_error_none) {
        str = data->u.encoded.raw;
        wifi_util_info_print(WIFI_APPS, "%s: CSI cache encoded successfully  \n", __FUNCTION__);
        push_event_to_ctrl_queue(str, strlen(str), wifi_event_type_webconfig, wifi_event_webconfig_set_data_dml, NULL);
    } else {
        wifi_util_error_print(WIFI_APPS, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
        if (data != NULL) {
            free(data);
        }
        return RBUS_ERROR_BUS_ERROR;
    }

    wifi_util_info_print(WIFI_APPS, "%s:  CSI cache pushed to queue encoded data is %s\n", __FUNCTION__, str);
    webconfig_data_free(data);
    if (data != NULL) {
        free(data);
    }
    return RBUS_ERROR_SUCCESS;
}

void csi_del_session(int csi_sess_number)
{
    int count = 0;
    int i = 0;
    char fifo_path[64] = {0};
    csi_session_t *csi = NULL;

    queue_t *csi_queue = get_csi_session_queue();
    if (csi_queue == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: NULL Pointer Unable to delete session\n", __func__, __LINE__);
        return;
    }
    count = queue_count(csi_queue);
    wifi_util_info_print(WIFI_APPS, "%s: Deleting Element %d\n",__func__, csi_sess_number);
    for (i = 0; i<count; i++) {
        csi = queue_peek(csi_queue, i);

        if (csi == NULL){
            continue;
        }

        if (csi->csi_sess_number == csi_sess_number) {
            wifi_util_dbg_print(WIFI_APPS, "%s: Found Element\n",__func__);
            queue_remove(csi_queue, i);

            //Close FIFO
            snprintf(fifo_path, sizeof(fifo_path), "/tmp/csi_motion_pipe%d", csi_sess_number);
            close(csi->csi_fd);
            csi->csi_fd = -1;
            unlink(fifo_path);

            csi_disable_client(csi);
            free(csi);
            break;
        }
    }
}

queue_t *update_csi_local_queue_from_motion_queue()
{
    csi_data_t *tmp_csi_data;
    unsigned int itr;
    queue_t *local_csi_queue;

    queue_t *csi_queue = get_csi_data_queue();

    if (csi_queue == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s %d: mgr csi queue is NULL\n", __FUNCTION__, __LINE__);
        return NULL;
    }

    local_csi_queue = queue_create();
    if (local_csi_queue == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s %d: csi queue create failed\n", __FUNCTION__, __LINE__);
        return NULL;
    }


    //update the local queue from app csi queue
    for (itr=0; itr<queue_count(csi_queue); itr++) {
        tmp_csi_data = (csi_data_t *)queue_peek(csi_queue, itr);
        if (tmp_csi_data != NULL) {
            csi_data_t *to_queue = (csi_data_t *)malloc(sizeof(csi_data_t));
            if (to_queue == NULL) {
                wifi_util_error_print(WIFI_APPS, "%s %d: malloc failed for itr : %d\n", __FUNCTION__, __LINE__, itr);
                queue_destroy(local_csi_queue);
                return NULL;
            }
            memcpy(to_queue, tmp_csi_data, sizeof(csi_data_t));
            queue_push(local_csi_queue, to_queue);
        }
    }


    return local_csi_queue;
}

rbusError_t csi_table_addrowhandler(rbusHandle_t handle, char const* tableName, char const* aliasName, uint32_t* instNum)
{
    static int instanceCounter = 1;
    queue_t *local_csi_queue = NULL;
    csi_data_t *csi_data;
    *instNum = instanceCounter++;

    wifi_util_dbg_print(WIFI_APPS, "%s(): %s %d\n", __FUNCTION__, tableName, *instNum);

    local_csi_queue = update_csi_local_queue_from_motion_queue();
    if (local_csi_queue == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d update csi Queue from mgr Queue failed\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    csi_data = (csi_data_t *)malloc(sizeof(csi_data_t));
    if (csi_data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer\n", __func__, __LINE__);
        queue_destroy(local_csi_queue);
        return RBUS_ERROR_BUS_ERROR;
    }
    memset(csi_data, 0, sizeof(csi_data_t));
    csi_data->csi_session_num = *instNum;

    queue_push(local_csi_queue, csi_data);
    push_csi_data_dml_to_ctrl_queue(local_csi_queue);
    queue_destroy(local_csi_queue);

    wifi_util_dbg_print(WIFI_APPS, "%s(): exit\n", __FUNCTION__);
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(aliasName);
    return RBUS_ERROR_SUCCESS;
}

rbusError_t csi_table_removerowhandler(rbusHandle_t handle, char const *rowName)
{
    csi_data_t *tmp_csi_data =  NULL;
    unsigned int itr, qcount;
    int idx;
    queue_t *local_csi_queue = NULL;

    wifi_util_dbg_print(WIFI_APPS, "%s(): %s\n", __FUNCTION__, rowName);

    local_csi_queue = update_csi_local_queue_from_motion_queue();
    if (local_csi_queue == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d update csi Queue from mgr Queue failed\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    sscanf(rowName, "Device.WiFi.X_RDK_CSI.%d.", &idx);
    qcount = queue_count(local_csi_queue);
    for (itr=0; itr<qcount; itr++) {
        tmp_csi_data = queue_peek(local_csi_queue, itr);
        if (tmp_csi_data->csi_session_num == (unsigned long) idx) {
            tmp_csi_data = queue_remove(local_csi_queue, itr);
            if (tmp_csi_data) {
                free(tmp_csi_data);
            }
            break;
        }
    }

    push_csi_data_dml_to_ctrl_queue(local_csi_queue);
    queue_destroy(local_csi_queue);

    UNREFERENCED_PARAMETER(handle);

    return RBUS_ERROR_SUCCESS;
}

rbusError_t csi_set_handler(rbusHandle_t handle, rbusProperty_t property, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    char const* name;
    rbusValue_t value;
    rbusValueType_t type;
    unsigned int idx = 0;
    int ret, apply = false;
    char parameter[MAX_EVENT_NAME_SIZE];
    unsigned int itr, i, j, k, qcount, num_unique_mac=0;
    csi_data_t *csi_data =  NULL, *tmp_csi_data;
    mac_address_t unique_mac_list[MAX_NUM_CSI_CLIENTS];
    bool found = false;
    unsigned int csi_client_count;
    mac_address_t csi_client_list[MAX_NUM_CSI_CLIENTS];

    name = rbusProperty_GetName(property);
    value = rbusProperty_GetValue(property);
    type = rbusValue_GetType(value);

    if (!name) {
        wifi_util_error_print(WIFI_APPS, "%s %d: invalid rbus property name %s\n", __FUNCTION__, __LINE__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }
    wifi_util_dbg_print(WIFI_APPS, "%s(): %s\n", __FUNCTION__, name);

    queue_t *local_csi_queue = NULL;

    local_csi_queue = update_csi_local_queue_from_motion_queue();
    if (local_csi_queue == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d update csi Queue from mgr Queue failed\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    ret = sscanf(name, "Device.WiFi.X_RDK_CSI.%4d.%200s", &idx, parameter);
    if (ret==2) {
        qcount = queue_count(local_csi_queue);
        for (itr=0; itr<qcount; itr++) {
            csi_data = queue_peek(local_csi_queue, itr);
            if (csi_data->csi_session_num == idx) {
                break;
            }
        }

        if (csi_data == NULL) {
            wifi_util_error_print(WIFI_APPS,"%s:%d Could not find entry\n", __func__, __LINE__);
            queue_destroy(local_csi_queue);
            return RBUS_ERROR_BUS_ERROR;
        }
        if (strcmp(parameter, "ClientMaclist") == 0) {

            if (type != RBUS_STRING) {
                wifi_util_error_print(WIFI_APPS,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
                queue_destroy(local_csi_queue);
                return RBUS_ERROR_INVALID_INPUT;
            } else {
                char *str, *cptr, *str_dup;
                mac_address_t l_client_list[MAX_NUM_CSI_CLIENTS];
                char const* pTmp = NULL;
                int len = 0;
                memset(l_client_list, 0, MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));

                pTmp = rbusValue_GetString(value, &len);
                str_dup = strdup(pTmp);
                if (str_dup == NULL) {
                    wifi_util_error_print(WIFI_APPS,"%s:%d strdup failed\n", __func__, __LINE__);
                    queue_destroy(local_csi_queue);
                    return RBUS_ERROR_BUS_ERROR;
                }
                itr = 0;
                str = strtok_r(str_dup, ",", &cptr);
                while (str != NULL) {
                    str_to_mac_bytes(str, l_client_list[itr]);
                    str = strtok_r(NULL, ",", &cptr);
                    itr++;
                    if (itr > MAX_NUM_CSI_CLIENTS) {
                        wifi_util_error_print(WIFI_APPS,"%s:%d client list is big %d\n", __func__, __LINE__, itr);
                        if (str_dup) {
                            free(str_dup);
                        }
                        queue_destroy(local_csi_queue);
                        return RBUS_ERROR_BUS_ERROR;
                    }
                }
                if (memcmp(csi_data->csi_client_list, l_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t)) != 0) {
                    //check new configuration did not exceed the max number of csi clients
                    num_unique_mac = 0;
                    for (i=0; i<qcount; i++) {
                        tmp_csi_data = (csi_data_t *)queue_peek(local_csi_queue, i);
                        if ((tmp_csi_data != NULL) && (tmp_csi_data->enabled)) {
                            if (tmp_csi_data->csi_session_num == csi_data->csi_session_num) {
                                csi_client_count = itr;
                                memcpy(csi_client_list, l_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));
                            } else {
                                csi_client_count = tmp_csi_data->csi_client_count;
                                memcpy(csi_client_list, tmp_csi_data->csi_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));
                            }
                            for (j=0; j < csi_client_count; j++) {
                                found  = false;
                                for (k=0; k < num_unique_mac; k++) {
                                    if (memcmp(csi_client_list[j], unique_mac_list[k], sizeof(mac_address_t)) == 0) {
                                        found  = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    num_unique_mac++;
                                    if (num_unique_mac > MAX_NUM_CSI_CLIENTS) {
                                        wifi_util_error_print(WIFI_APPS, "%s %d MAX_NUM_CSI_CLIENTS reached\n", __func__, __LINE__);
                                        if (str_dup) {
                                            free(str_dup);
                                        }
                                        queue_destroy(local_csi_queue);
                                        return RBUS_ERROR_BUS_ERROR;
                                    } else {
                                        memcpy(unique_mac_list[num_unique_mac-1], csi_client_list[j], sizeof(mac_address_t));
                                    }
                                }
                            }
                        }
                    }

                    memcpy(csi_data->csi_client_list, l_client_list,  MAX_NUM_CSI_CLIENTS*sizeof(mac_address_t));
                    csi_data->csi_client_count = itr;
                    apply = true;
                } else {
                    wifi_util_error_print(WIFI_APPS,"%s:%d config not change\n", __func__, __LINE__);
                }
                if (str_dup) {
                    free(str_dup);
                }
            }
        } else if (strcmp(parameter, "Enable") == 0) {
            if (type != RBUS_BOOLEAN)
            {
                wifi_util_error_print(WIFI_APPS,"%s:%d '%s' Called Set handler with wrong data type\n", __func__, __LINE__, name);
                queue_destroy(local_csi_queue);
                return RBUS_ERROR_INVALID_INPUT;
            } else {
                bool enabled = rbusValue_GetBoolean(value);
                if (enabled != csi_data->enabled) {
                    //check new configuration did not exceed the max number of csi clients
                    num_unique_mac = 0;
                    if (enabled == true) {
                        for (i=0; i<qcount; i++) {
                            tmp_csi_data = (csi_data_t *)queue_peek(local_csi_queue, i);
                            if (tmp_csi_data != NULL) {
                                if (tmp_csi_data->csi_session_num != csi_data->csi_session_num) {
                                    if (tmp_csi_data->enabled == false) {
                                        continue;
                                    }
                                }
                                for (j=0; j < tmp_csi_data->csi_client_count; j++) {
                                    found  = false;
                                    for (k=0; k < num_unique_mac; k++) {
                                        if (memcmp(tmp_csi_data->csi_client_list[j], unique_mac_list[k], sizeof(mac_address_t)) == 0) {
                                            found  = true;
                                            break;
                                        }
                                    }
                                    if (!found) {
                                        num_unique_mac++;
                                        if (num_unique_mac > MAX_NUM_CSI_CLIENTS) {
                                            wifi_util_error_print(WIFI_APPS,"%s %d MAX_NUM_CSI_CLIENTS reached\n", __func__, __LINE__);
                                            queue_destroy(local_csi_queue);
                                            return RBUS_ERROR_BUS_ERROR;
                                        } else {
                                            memcpy(unique_mac_list[num_unique_mac-1], tmp_csi_data->csi_client_list[j], sizeof(mac_address_t));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    csi_data->enabled = enabled;
                    apply = true;
                }
            }
        }
        if (apply) {
            push_csi_data_dml_to_ctrl_queue(local_csi_queue);
        }
        queue_destroy(local_csi_queue);
        return RBUS_ERROR_SUCCESS;
    }
    queue_destroy(local_csi_queue);
    return RBUS_ERROR_INVALID_INPUT;
}

rbusError_t csi_get_handler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(opts);
    char const* name;
    rbusValue_t value;
    unsigned int idx = 0;
    int ret;
    char parameter[MAX_EVENT_NAME_SIZE];
    unsigned int itr, count, qcount;
    csi_data_t *csi_data =  NULL;
    queue_t *csi_data_queue = get_csi_data_queue();

    name = rbusProperty_GetName(property);
    if (!name) {
        wifi_util_dbg_print(WIFI_APPS, "%s(): invalid property name : %s \n", __FUNCTION__, name);
        return RBUS_ERROR_INVALID_INPUT;
    }

    if (csi_data_queue == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d queue pointer is NULL\n", __func__, __LINE__);
        return RBUS_ERROR_BUS_ERROR;
    }

    wifi_util_dbg_print(WIFI_APPS, "%s(): %s\n", __FUNCTION__, name);
    if (strcmp(name, "Device.WiFi.X_RDK_CSINumberOfEntries") == 0) {
        count = queue_count(csi_data_queue);
        rbusValue_Init(&value);
        rbusValue_SetUInt32(value, count);
        rbusProperty_SetValue(property, value);
        rbusValue_Release(value);

        return RBUS_ERROR_SUCCESS;
    }

    ret = sscanf(name, "Device.WiFi.X_RDK_CSI.%4d.%200s", &idx, parameter);
    if (ret==2) {
        qcount = queue_count(csi_data_queue);
        for (itr=0; itr<qcount; itr++) {
            csi_data = queue_peek(csi_data_queue, itr);
            if (csi_data->csi_session_num == idx) {
                break;
            }
        }

        if (csi_data == NULL) {
            wifi_util_error_print(WIFI_APPS,"%s:%d Could not find entry\n", __func__, __LINE__);
            return RBUS_ERROR_BUS_ERROR;
        }

        rbusValue_Init(&value);
        if (strcmp(parameter, "ClientMaclist") == 0) {
            char tmp_cli_list[128];
            mac_addr_str_t mac_str;
            memset(tmp_cli_list, 0, sizeof(tmp_cli_list));
            if (csi_data->csi_client_count > 0) {
                for (itr=0; itr<csi_data->csi_client_count; itr++) {
                    snprintf(mac_str, sizeof(mac_str), "%02x%02x%02x%02x%02x%02x",
                            csi_data->csi_client_list[itr][0], csi_data->csi_client_list[itr][1],
                            csi_data->csi_client_list[itr][2], csi_data->csi_client_list[itr][3],
                            csi_data->csi_client_list[itr][4], csi_data->csi_client_list[itr][5]);
                    strncat(tmp_cli_list, mac_str, strlen(tmp_cli_list)-1);
                    strncat(tmp_cli_list, ",", strlen(tmp_cli_list)-1);
                }
                int len  = strlen(tmp_cli_list);
                tmp_cli_list[len-1] = '\0';
            }
            rbusValue_SetString(value, tmp_cli_list);
        } else if (strcmp(parameter, "Enable") == 0) {
            rbusValue_SetBoolean(value, csi_data->enabled);
        }
        rbusProperty_SetValue(property, value);
        rbusValue_Release(value);

        return RBUS_ERROR_SUCCESS;
    }

    return RBUS_ERROR_INVALID_INPUT;
}

int webconfig_hal_csi_apply(webconfig_subdoc_decoded_data_t *data)
{
    queue_t *new_config, *current_config;
    new_config = data->csi_data_queue;
    char *tmp_cli_list;
    unsigned int tmp_cli_list_size = (19*MAX_NUM_CSI_CLIENTS)+1;
    unsigned int itr, i, current_config_count, new_config_count, itrj, num_unique_mac=0;
    csi_data_t *current_csi_data = NULL, *new_csi_data;
    bool found = false, data_change = false;
    mac_addr_str_t mac_str;
    mac_address_t unique_mac_list[MAX_NUM_CSI_CLIENTS];
    current_config = get_csi_data_queue();

    if (current_config == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s %d NULL pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    tmp_cli_list = (char *) malloc(tmp_cli_list_size);
    if (tmp_cli_list == NULL) {
        wifi_util_error_print(WIFI_MGR,"%s %d malloc failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    //check new configuration did not exceed the max number of csi clients
    if (new_config != NULL) {
        new_config_count = queue_count(new_config);
        for (itr=0; itr<new_config_count; itr++) {
            new_csi_data = (csi_data_t *)queue_peek(new_config, itr);
            if ((new_csi_data != NULL) && (new_csi_data->enabled)) {
                for (itrj=0; itrj<new_csi_data->csi_client_count; itrj ++) {
                    found  = false;
                    for (i=0; i<num_unique_mac; i++) {
                        if (memcmp(new_csi_data->csi_client_list[itrj], unique_mac_list[i], sizeof(mac_address_t)) == 0) {
                            found  = true;
                            break;
                        }
                    }
                    if (!found) {
                        num_unique_mac++;
                        if (num_unique_mac > MAX_NUM_CSI_CLIENTS) {
                            wifi_util_error_print(WIFI_APPS,"%s %d MAX_NUM_CSI_CLIENTS reached\n", __func__, __LINE__);
                            goto free_csi_data;
                        } else {
                            memcpy(unique_mac_list[num_unique_mac-1], new_csi_data->csi_client_list[itrj], sizeof(mac_address_t));
                        }
                    }
                }
            }
        }
    }

    current_config_count = queue_count(current_config);
    for (itr=0; itr<current_config_count; itr++) {
        current_csi_data = (csi_data_t *)queue_peek(current_config, itr);
        found = false;
        if (new_config != NULL) {
            new_config_count = queue_count(new_config);
            for (itrj=0; itrj<new_config_count; itrj++) {
                new_csi_data = (csi_data_t *)queue_peek(new_config, itrj);
                if (new_csi_data != NULL) {
                    if (new_csi_data->csi_session_num == current_csi_data->csi_session_num) {
                        found = true;
                    }
               }
            }
        }
        if (!found) {
            csi_del_session(current_csi_data->csi_session_num);
            current_csi_data = (csi_data_t *)queue_remove(current_config, itr);
            if (current_csi_data != NULL) {
                free(current_csi_data);
            }
            current_config_count = queue_count(current_config);
        }
    }


    if (new_config != NULL) {
        new_config_count = queue_count(new_config);
        for (itr=0; itr<new_config_count; itr++) {
            new_csi_data = (csi_data_t *)queue_peek(new_config, itr);
            memset(tmp_cli_list, 0, tmp_cli_list_size);
            found = false;
            data_change = false;
            if (current_config != NULL) {
                current_config_count = queue_count(current_config);
                for (itrj=0; itrj<current_config_count; itrj++) {
                    current_csi_data = (csi_data_t *)queue_peek(current_config, itrj);
                    if (current_csi_data != NULL) {
                        if (new_csi_data->csi_session_num == current_csi_data->csi_session_num) {
                            found = true;
                            if (memcmp(new_csi_data, current_csi_data, sizeof(csi_data_t)) != 0) {
                                data_change = true;
                            }
                            break;
                        }
                    }
                }
            }

            //Change client macarray to comma seperarted string.
            for (i=0; i<new_csi_data->csi_client_count; i++) {
                to_mac_str(new_csi_data->csi_client_list[i], mac_str);
                strcat(tmp_cli_list, mac_str);
                strcat(tmp_cli_list, ",");
            }
            int len  = strlen(tmp_cli_list);
            if (len > 0) {
                tmp_cli_list[len-1] = '\0';
            }

            if (!found) {
                csi_create_session(new_csi_data->csi_session_num);
                csi_data_t *to_queue = (csi_data_t *)malloc(sizeof(csi_data_t));
                memcpy(to_queue, new_csi_data, sizeof(csi_data_t));
                queue_push(current_config, to_queue);
                csi_enable_session(new_csi_data->enabled, new_csi_data->csi_session_num);
                csi_set_client_mac(tmp_cli_list, new_csi_data->csi_session_num);
            }

            if (found && data_change) {
                csi_enable_session(new_csi_data->enabled, new_csi_data->csi_session_num);
                csi_set_client_mac(tmp_cli_list, new_csi_data->csi_session_num);
                memcpy(current_csi_data, new_csi_data, sizeof(csi_data_t));
            }
        }
    }

free_csi_data:
    if (new_config != NULL) {
        queue_destroy(new_config);
    }
    if (tmp_cli_list != NULL) {
        free(tmp_cli_list);
    }
    return RETURN_OK;
}

csi_session_t *get_csi_session_from_session_num(int session_num) 
{
    unsigned int itr;
    csi_session_t *tmp_csi_session = NULL;

    queue_t *csi_queue = get_csi_session_queue();
    if (csi_queue == NULL) 
    {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return NULL;
    }

    for (itr=0; itr<queue_count(csi_queue); itr++) {
        tmp_csi_session = (csi_session_t *)queue_peek(csi_queue, itr);
        if (session_num == tmp_csi_session->csi_sess_number) {
            return tmp_csi_session;
        }
    }
    return NULL;
}

rbusError_t eventHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    UNREFERENCED_PARAMETER(handle);
    UNREFERENCED_PARAMETER(filter);
    char tmp[128] = {0};

    int idx = -1;

    *autoPublish = false;
    wifi_util_dbg_print(WIFI_APPS,"%s:%d eventHandler called: action=%s\n eventName=%s autoPublish:%d\n",
            __func__, __LINE__, action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe",
            eventName, *autoPublish);

    sscanf(eventName, "Device.WiFi.X_RDK_CSI.%d.data", &idx);
    int csi_session = idx;
    csi_session_t *csi_data = (csi_session_t *)get_csi_session_from_session_num(idx);
    if (csi_data == NULL) {
        if (action == RBUS_EVENT_ACTION_SUBSCRIBE) {
            wifi_util_dbg_print(WIFI_APPS, "WiFi_Motion_SubscriptionStarted %d\n", csi_session);
            memset(tmp, 0, sizeof(tmp));
            get_formatted_time(tmp);
            write_to_file(wifi_log,  "%s WiFi_CSI_SubscriptionStarted %d\n", tmp,csi_session);

            csi_set_interval(interval, csi_session);
            csi_enable_subscription(TRUE, csi_session);
            wifi_util_dbg_print(WIFI_APPS, "Exit %s: Event %s\n", __FUNCTION__, eventName);
            return RBUS_ERROR_SUCCESS;
        }
    }
    if (action == RBUS_EVENT_ACTION_SUBSCRIBE) {
        /* TODO: interval needs to be multiple of WifiMonitor basic interval */
        if (interval > MAX_CSI_INTERVAL || interval < MIN_CSI_INTERVAL
                ||  csi_data->subscribed == TRUE) {
            //telemetry
            printf("WiFi_Motion_SubscriptionFailed %d\n", csi_session);
            memset(tmp, 0, sizeof(tmp));
            get_formatted_time(tmp);
            wifi_util_dbg_print(WIFI_APPS, "WiFi_Motion_SubscriptionFailed %d\n", csi_session);
            write_to_file(wifi_log,  "%s WiFi_CSI_SubscriptionFailed %d\n", tmp,csi_session);
            wifi_util_dbg_print(WIFI_APPS, "Exit %s: Event %s\n", __FUNCTION__, eventName);
            return RBUS_ERROR_BUS_ERROR;
        }
        wifi_util_dbg_print(WIFI_APPS, "WiFi_Motion_SubscriptionStarted %d\n", csi_session);
        memset(tmp, 0, sizeof(tmp));
        get_formatted_time(tmp);
        write_to_file(wifi_log,  "%s WiFi_CSI_SubscriptionStarted %d\n", tmp,csi_session);

        csi_set_interval(interval, csi_session);
        csi_enable_subscription(TRUE, csi_session);
        wifi_util_dbg_print(WIFI_APPS, "Exit %s: Event %s\n", __FUNCTION__, eventName);
        return RBUS_ERROR_SUCCESS;
    } else {
        wifi_util_dbg_print(WIFI_APPS, "WiFi_Motion_SubscriptionStopped %d\n", csi_session);
        memset(tmp, 0, sizeof(tmp));
        get_formatted_time(tmp);
        write_to_file(wifi_log,  "%s WiFi_CSI_SubscriptionCancelled %d\n", tmp,csi_session);
        csi_enable_subscription(FALSE, csi_session);
        wifi_util_dbg_print(WIFI_APPS, "Exit %s: Event %s\n", __FUNCTION__, eventName);
        return RBUS_ERROR_SUCCESS;
    }
}

static void csi_vap_down_update(int ap_idx)
{
    csi_session_t *csi = NULL;
    int count = 0, i = 0, j=0;
    wifi_apps_mgr_t *apps_mgr;

    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    queue_t *csi_queue = get_csi_session_queue();
    wifi_app_t *app = get_app_by_inst(apps_mgr, wifi_app_inst_motion);
    if (app == NULL)
    {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Unable to fetch csi app instance\n", __func__, __LINE__);
        return;
    }

    wifi_app_t *csi_app = app->data.u.motion.csi_app;
    if (csi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    count = queue_count(csi_queue);
    for (i = 0; i<count; i++) {
        csi = queue_peek(csi_queue, i);
        if (csi == NULL) {
            continue;
        }
        for (j =0; j<csi->no_of_mac; j++) {
            if (csi->ap_index[j] == ap_idx) {
                csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, csi->ap_index[j], csi->mac_list[j], wifi_app_inst_motion);
                csi->ap_index[j] = -1;
                csi->mac_is_connected[j] = FALSE;
            }
        }
    }
}

int motion_event_webconfig_set_data(wifi_app_t *apps, void *arg, wifi_event_subtype_t sub_type)
{
    rdk_wifi_radio_t *radio;
    wifi_vap_info_map_t *vap_map;
    wifi_vap_info_t *vap;
    unsigned int i = 0, j = 0;
    webconfig_subdoc_data_t *doc = (webconfig_subdoc_data_t *)arg;
    webconfig_subdoc_decoded_data_t *decoded_params = NULL;

    decoded_params = &doc->u.decoded;
    if (decoded_params == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Decoded data is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    switch (doc->type) {
        case webconfig_subdoc_type_csi:
           webconfig_hal_csi_apply(decoded_params); 
            break;
        case webconfig_subdoc_type_private:
        case webconfig_subdoc_type_home:
        case webconfig_subdoc_type_xfinity:
        case webconfig_subdoc_type_lnf:
        case webconfig_subdoc_type_mesh_backhaul:
            for (i = 0; i < getNumberRadios(); i++) {
                radio = &decoded_params->radios[i];
                vap_map = &radio->vaps.vap_map;
                for (j = 0; j < radio->vaps.num_vaps; j++) {
                    vap = &vap_map->vap_array[j];

                    if(vap->vap_name[0] != '\0') {
                        if (vap->u.bss_info.enabled == false) {
                            csi_vap_down_update(vap->vap_index);
                        }
                    }
                }
            }
        break;
        default:
            break;
    }

    return RETURN_OK;
}

int webconfig_event_motion(wifi_app_t *apps, wifi_event_subtype_t sub_type, void *data)
{
    switch(sub_type) {
        case wifi_event_webconfig_set_data:
        case wifi_event_webconfig_set_data_dml:
            motion_event_webconfig_set_data(apps, data, sub_type);
            break;
        default:
            break;
    }
    return RETURN_OK;
}

void motion_assoc_device_event(wifi_app_t *apps, void *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;
    csi_update_client_mac_status(assoc_data->dev_stats.cli_MACAddress, TRUE, assoc_data->ap_index);
}

void motion_disassoc_device_event(wifi_app_t *apps, void *data)
{
    if (data == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return;
    }

    assoc_dev_data_t *assoc_data = (assoc_dev_data_t *) data;
    csi_update_client_mac_status(assoc_data->dev_stats.cli_MACAddress, FALSE, assoc_data->ap_index);
}

int hal_event_motion(wifi_app_t *app, wifi_event_subtype_t sub_type, void *data)
{
    switch (sub_type) {
        case wifi_event_hal_assoc_device:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Got Assoc device for Levl\n", __func__, __LINE__);
            motion_assoc_device_event(app, data);
            break;
        case wifi_event_hal_disassoc_device:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d Got DisAssoc device for Levl\n", __func__, __LINE__);
            motion_disassoc_device_event(app, data);
            break;
        default:
            wifi_util_dbg_print(WIFI_APPS,"%s:%d app sub_event:%d not handle\r\n", __func__, __LINE__, sub_type);
            break;
    }
    return RETURN_OK;
}

int do_pipe_publish(char *buffer, size_t len, csi_session_t *csi)
{
    char fifo_path[64] = {0};

    if (csi == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    if (csi->csi_fd < 0) {
        sprintf(fifo_path, "/tmp/csi_motion_pipe%d", csi->csi_sess_number);
        csi->csi_fd = open(fifo_path, O_WRONLY);
        if (csi->csi_fd < 0) {
            wifi_util_error_print(WIFI_APPS, "%s(): Failed to open pipe reason %s\n", __func__, strerror(errno));
            return RETURN_ERR;
        }
    }
    if (csi->csi_fd > 0)
    {
        if ((write(csi->csi_fd, buffer, len) < 0)) {
            wifi_util_dbg_print(WIFI_APPS, "%s:%d Messed up write error is %s\n", __func__, __LINE__, strerror(errno));
            return RETURN_ERR;
        }
    }
    return RETURN_OK;

}

void motion_csi_publish(mac_address_t mac_address, wifi_csi_dev_t *csi_dev_data, csi_session_t *csi)
{
    if (csi == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }

    //Construct Header.
    unsigned int total_length, num_csi_clients, csi_data_length, curr_length = 0;
    time_t datetime;
    char *header = csi_dev_data->header;

    memcpy(header,"CSI", (strlen("CSI") + 1));
    curr_length = curr_length + strlen("CSI") + 1;

    total_length = sizeof(time_t) + (sizeof(unsigned int)) + (1 *(sizeof(mac_addr_t) + sizeof(unsigned int) + sizeof(wifi_csi_data_t)));
    memcpy((header + curr_length), &total_length, sizeof(unsigned int));
    curr_length = curr_length + sizeof(unsigned int);

    datetime = time(NULL);
    memcpy((header + curr_length), &datetime, sizeof(time_t));
    curr_length = curr_length + sizeof(time_t);

    num_csi_clients = 1;
    memcpy((header + curr_length), &num_csi_clients, sizeof(unsigned int));
    curr_length = curr_length + sizeof(unsigned int);

    memcpy((header + curr_length), csi_dev_data->sta_mac, sizeof(mac_addr_t));
    curr_length = curr_length + sizeof(mac_addr_t);

    csi_data_length = sizeof(wifi_csi_data_t);
    memcpy((header + curr_length), &csi_data_length, sizeof(unsigned int));

    size_t buffer_len = CSI_HEADER_SIZE + sizeof(wifi_csi_data_t);

    do_pipe_publish(csi_dev_data->header, buffer_len, csi);
    return;
}

void process_csi_data(wifi_app_t *app, wifi_csi_dev_t *csi_dev_data)
{
    int i = 0, j = 0;
    struct timeval t_now = {0};
    bool mac_found;
    csi_session_t *csi = NULL;

    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }

    queue_t *csi_queue = get_csi_session_queue();
    if (csi_queue == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return;
    }

    mac_addr_t mac_addr;
    memcpy(mac_addr, csi_dev_data->sta_mac, sizeof(mac_addr_t));

    int csi_subscribers_count = queue_count(csi_queue);
    gettimeofday(&t_now, NULL);

    for (i =0; i < csi_subscribers_count; i++) {
        mac_found = FALSE;
        csi = (csi_session_t *)queue_peek(csi_queue, i);
        if (csi == NULL || !(csi->enable && csi->subscribed && !(app->data.u.motion.paused))) {
            continue;
        }
        for (j = 0; j < csi->no_of_mac; j++) {
            if (csi->mac_is_connected[j] == FALSE) {
                continue;
            }
            if (memcmp(csi_dev_data->sta_mac, csi->mac_list[j], sizeof(mac_addr_t)) == 0) {
                mac_found = TRUE;
                break;
            }
        }
        if (mac_found == TRUE) {
            //check interval
            if (csi->csi_time_interval == MIN_CSI_INTERVAL || csi_check_timeout(csi, j, &t_now)) {
                wifi_util_dbg_print(WIFI_APPS, "%s: Publish CSI Event - MAC  %02x:%02x:%02x:%02x:%02x:%02x Session %d\n",__func__, mac_addr[0], mac_addr[1],
                                                        mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5], csi->csi_sess_number);
                motion_csi_publish(csi_dev_data->sta_mac, csi_dev_data, csi);
                csi->last_publish_time[j] = t_now;
            }
        }
    }
}

int process_csi_stop_motion(wifi_app_t *app)
{
    csi_session_t *csi = NULL;
    int count = 0, i = 0, j=0;

    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    queue_t *csi_queue = get_csi_session_queue();
    wifi_app_t *csi_app = app->data.u.motion.csi_app;
    if (csi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d Unable to fetch csi app instance\n", __func__, __LINE__);
        return -1;
    }
    wifi_util_dbg_print(WIFI_APPS,"%s:%d Disabling CSI data collection\n", __func__, __LINE__);
    count = queue_count(csi_queue);
    for (i = 0; i<count; i++) {
        csi = queue_peek(csi_queue, i);
        if (csi == NULL){
            continue;
        }
        if (csi->enable && csi->subscribed) {
            for (j =0; j<csi->no_of_mac; j++) {
                csi_app->data.u.csi.csi_fns.csi_stop_fn(csi_app, csi->ap_index[j], csi->mac_list[j], wifi_app_inst_motion);
            }
        }
    }
    return 0;
}

int process_csi_start_motion(wifi_app_t *app)
{
    csi_session_t *csi = NULL;
    int count = 0, i = 0, j=0;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    queue_t *csi_queue = get_csi_session_queue();

    wifi_app_t *csi_app = app->data.u.motion.csi_app;
    if (csi_app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    count = queue_count(csi_queue);
    wifi_util_dbg_print(WIFI_APPS,"%s:%d Enabling CSI data collection\n", __func__, __LINE__);
    for (i = 0; i<count; i++) {
        csi = queue_peek(csi_queue, i);
        if (csi == NULL){
            continue;
        }
        if (csi->enable && csi->subscribed) {
            for (j =0; j<csi->no_of_mac; j++) {
                if ((csi->ap_index[j] != -1) && (csi->mac_is_connected[j] == TRUE)) {
                    csi_app->data.u.csi.csi_fns.csi_start_fn((void *)csi_app, csi->ap_index[j], csi->mac_list[j], wifi_app_inst_motion);
                }
            }
        }
    }
    if (app->data.u.motion.sched_handler_id > 0) {
        scheduler_cancel_timer_task(ctrl->sched, app->data.u.motion.sched_handler_id);
        app->data.u.motion.sched_handler_id = 0;
    }
    return 0;
}

int motion_event_csi(wifi_app_t *app, wifi_event_subtype_t sub_type, wifi_csi_dev_t *csi)
{
    switch (sub_type) {
        case wifi_event_type_csi_data:
            process_csi_data(app, csi);
        break;
        default:
            break;
    }
    return RETURN_OK;
}

int process_speed_test_timeout_motion()
{
    wifi_app_t *app =  NULL;
    wifi_apps_mgr_t *apps_mgr;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    app = get_app_by_inst(apps_mgr, wifi_app_inst_motion);
    if (app == NULL) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }
    write_to_file(wifi_log,  "IMP_WiFi_SubscriberUnPauseTimeOut\n");
    get_stubs_descriptor()->t2_event_d_fn("IMP_WiFi_SubscriberUnPauseTimeOut", 1);
    if (app->data.u.motion.paused) {
        wifi_util_info_print(WIFI_APPS, "%s:%d Start motion on timeout\n", __func__, __LINE__);
        process_csi_start_motion(app);
    }
    app->data.u.motion.paused = false;
    return 0;
}

int motion_event_speed_test(wifi_app_t *app, wifi_event_subtype_t sub_type, void *data)
{
    speed_test_data_t *speed_test_data = (speed_test_data_t *)data;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_dbg_print(WIFI_APPS, "%s:%d NULL Pointer \n", __func__, __LINE__);
        return -1;
    }

    wifi_util_info_print(WIFI_APPS, "%s:%d Speed test event: %d\n", __func__, __LINE__,
        speed_test_data->speed_test_running);

    if (speed_test_data->speed_test_running == 1) {
        app->data.u.motion.paused = true;
        process_csi_stop_motion(app);

        if (app->data.u.motion.sched_handler_id == 0) {
            app->data.u.motion.speed_test_timeout  = speed_test_data->speed_test_timeout;
            scheduler_add_timer_task(ctrl->sched, FALSE, &(app->data.u.motion.sched_handler_id),
                    process_speed_test_timeout_motion, NULL, (app->data.u.motion.speed_test_timeout)*1000, 1, FALSE);
        } else if ((app->data.u.motion.speed_test_timeout != speed_test_data->speed_test_timeout) && (app->data.u.motion.sched_handler_id > 0)) {
            app->data.u.motion.speed_test_timeout = speed_test_data->speed_test_timeout;
            scheduler_update_timer_task_interval(ctrl->sched, app->data.u.motion.sched_handler_id, (app->data.u.motion.speed_test_timeout)*1000);
        }
    } else if (speed_test_data->speed_test_running == 5) {
        if (app->data.u.motion.paused == true) {
            app->data.u.motion.paused = false;
            process_csi_start_motion(app);
        }
    }
    return 0;
}

#ifdef ONEWIFI_MOTION_APP_SUPPORT
int motion_event(wifi_app_t *app, wifi_event_t *event)
{

    pthread_mutex_lock(&app->data.u.motion.lock);
    switch (event->event_type) {
        case wifi_event_type_hal_ind:
            hal_event_motion(app, event->sub_type, event->u.core_data.msg);
            break;
        case wifi_event_type_webconfig:
            webconfig_event_motion(app, event->sub_type, event->u.webconfig_data);
            break;
        case wifi_event_type_csi:
            motion_event_csi(app, event->sub_type, event->u.csi);
            break;
        case wifi_event_type_speed_test:
            motion_event_speed_test(app, event->sub_type, event->u.core_data.msg);
            break;
        default:
        break;
    }
    pthread_mutex_unlock(&app->data.u.motion.lock);

    return RETURN_OK;
}
#endif

int motion_start_fn(void* wifi_app, unsigned int ap_index, mac_addr_t mac_addr, int sounding_app)
{
    return 0;
}

int motion_stop_fn(void* wifi_app, unsigned int ap_index, mac_addr_t mac_addr, int sounding_app)
{
    return 0;
}

#ifdef ONEWIFI_MOTION_APP_SUPPORT
static void pipeSignalHandler(int sig)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d Caught SIGPIPE\n", __func__, __LINE__);
    int count = 0;
    int itr = 0;
    char fifo_path[64] = {0};
    csi_session_t *csi = NULL;

    queue_t *csi_queue = get_csi_session_queue();
    if (csi_queue == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: NULL Pointer Unable to delete session\n", __func__, __LINE__);
        return;
    }
    count = queue_count(csi_queue);
    for(itr=0; itr<count; itr++) {
        csi = queue_peek(csi_queue, itr);
        if (csi ==  NULL) {
            continue;
        }
        snprintf(fifo_path, sizeof(fifo_path), "/tmp/csi_motion_pipe%d", csi->csi_sess_number);
        if (csi->csi_fd > 0) {
            close(csi->csi_fd);
            csi->csi_fd = -1;
            unlink(fifo_path);
        }
    }

}

int motion_init(wifi_app_t *app, unsigned int create_flag)
{
    int rc = RBUS_ERROR_SUCCESS;
    char *component_name = "WifiAppsMotion";
    rbusDataElement_t dataElements[] = {
        { WIFI_CSI_TABLE, RBUS_ELEMENT_TYPE_TABLE,
            { NULL, NULL, csi_table_addrowhandler, csi_table_removerowhandler, NULL, NULL}},
        { WIFI_CSI_DATA, RBUS_ELEMENT_TYPE_EVENT,
            { NULL, NULL, NULL, NULL, eventHandler, NULL}},
        { WIFI_CSI_CLIENTMACLIST, RBUS_ELEMENT_TYPE_PROPERTY,
            { csi_get_handler, csi_set_handler, NULL, NULL, NULL, NULL}},
        { WIFI_CSI_ENABLE, RBUS_ELEMENT_TYPE_PROPERTY,
            { csi_get_handler, csi_set_handler, NULL, NULL, NULL, NULL}},
        { WIFI_CSI_NUMBEROFENTRIES, RBUS_ELEMENT_TYPE_PROPERTY,
            { csi_get_handler, NULL, NULL, NULL, NULL, NULL}},

    };

    //Creating named Pipe.
    struct sigaction new_action;
    memset(&new_action, 0, sizeof(struct sigaction));
    new_action.sa_handler = pipeSignalHandler;
    sigaction(SIGPIPE, &new_action, NULL);

    wifi_app_t *csi_app = NULL;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_apps_mgr_t *apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL Pointer \n", __func__, __LINE__);
        return RETURN_ERR;
    }

    csi_app = get_app_by_inst(apps_mgr, wifi_app_inst_csi);
    if (csi_app == NULL) {
        wifi_util_error_print(WIFI_APPS,"%s:%d NULL CSI app instance\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    app->data.u.motion.csi_app = csi_app;
    app->data.u.motion.csi_fns.csi_start_fn = motion_start_fn;
    app->data.u.motion.csi_fns.csi_stop_fn = motion_stop_fn;
    pthread_mutex_init(&app->data.u.motion.lock, NULL);
    app->data.u.motion.csi_data_queue = queue_create();
    if (app->data.u.motion.csi_data_queue == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: NULL queue Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    app->data.u.motion.csi_session_queue = queue_create();
    if (app->data.u.motion.csi_session_queue == NULL) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: NULL queue Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    app->data.u.motion.paused = false;

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: Init Motion\n", __func__, __LINE__);


    rc = rbus_open(&(app->data.u.motion.rbus_handle), component_name);
    if (rc != RBUS_ERROR_SUCCESS) {
        return RETURN_ERR;
    }

    rc = rbus_regDataElements(app->data.u.motion.rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_APPS,"%s:%d rbus_regDataElements failed\n", __func__, __LINE__);
        rbus_unregDataElements(app->data.u.motion.rbus_handle, sizeof(dataElements)/sizeof(rbusDataElement_t), dataElements);
        rbus_close(app->rbus_handle);
        return RETURN_ERR;
    } else {
        wifi_util_info_print(WIFI_APPS,"%s:%d Apps rbus_regDataElement success\n", __func__, __LINE__);
    }

    return RETURN_OK;
}
#endif

