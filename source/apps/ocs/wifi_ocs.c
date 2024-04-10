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
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include "collection.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_events.h"
#include <time.h>
#include <sys/un.h>
#include <sched.h>
#include "scheduler.h"
#include "wifi_apps_mgr.h"

#if defined (FEATURE_OFF_CHANNEL_SCAN_5G)

#define OCS_NEIGBOUR_SCAN_PROVIDER_DELAY_SEC 5
#define OFFCHAN_DEFAULT_NSCAN_IN_SEC 10800
#define SEC_TO_MILLISEC 1000
static int off_chan_scan_init (unsigned int radio_index);
void off_chan_print_neighbour_data (wifi_provider_response_t *provider_response);
static bool is_monitor_done = false;
#define DFS_START 52
#define DFS_END 144
#define ocs_app_event_type_chan_stats       1
#define ocs_app_event_type_neighbor_stats   2

off_channel_param_t *get_wifi_ocs(unsigned int radioIndex)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_apps_mgr_t *apps_mgr;
    wifi_app_t *wifi_app =  NULL;

    apps_mgr = &ctrl->apps_mgr;
    if (apps_mgr == NULL){
        return NULL;
    }

    wifi_app = get_app_by_inst(apps_mgr, wifi_app_inst_ocs);
    if (wifi_app == NULL) {
        return NULL;
    }

    return &wifi_app->data.u.ocs[radioIndex];
}

int print_ocs_state (void *arg) {
    wifi_mgr_t *mgr = get_wifimgr_obj();

    for (UINT radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {
        if(is_radio_band_5G(mgr->radio_config[radioIndex].oper.band)) {
            CcspTraceInfo(("Off_channel_scan feature is disabled returning Radio index = %u RFC = %d; TScan = %lu; NScan = %lu; Tidle = %lu\n", radioIndex, mgr->rfc_dml_parameters.wifioffchannelscan_rfc, mgr->radio_config[radioIndex].feature.OffChanTscanInMsec, ((mgr->radio_config[radioIndex].feature.OffChanNscanInSec != 0)?((24*3600)/mgr->radio_config[radioIndex].feature.OffChanNscanInSec):mgr->radio_config[radioIndex].feature.OffChanNscanInSec), mgr->radio_config[radioIndex].feature.OffChanTidleInSec));
        }
    }
    return TIMER_TASK_COMPLETE;
}


static void ocs_route(wifi_event_route_t *route)
{
    memset(route, 0, sizeof(wifi_event_route_t));
    route->dst = wifi_sub_component_mon;
    route->u.inst_bit_map = wifi_app_inst_ocs;
}

static void config_ocs_neighbour_scan(wifi_monitor_data_t *data, unsigned int radioIndex)
{
    off_channel_param_t *ocs_cfg = get_wifi_ocs(radioIndex);
    wifi_event_route_t route;
    ocs_route(&route);

    /* Request to collect other channel stats */
    data->u.mon_stats_config.data_type = mon_stats_type_neighbor_stats;
    data->u.mon_stats_config.args.app_info = ocs_app_event_type_neighbor_stats;
    data->u.mon_stats_config.args.dwell_time = ocs_cfg->TscanMsec;

    wifi_util_dbg_print(WIFI_OCS, "%s:%d Pushing the event for app %d \n", __func__, __LINE__, route.u.inst_bit_map);
    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
}

void config_ocs_chan_util(wifi_monitor_data_t *data, unsigned int radioIndex) {

    wifi_event_route_t route;
    wifi_util_dbg_print(WIFI_OCS, "%s:%d Entering \n", __func__, __LINE__);
    ocs_route(&route);

    /* Request to collect other channel stats */
    data->u.mon_stats_config.data_type = mon_stats_type_radio_channel_stats;
    data->u.mon_stats_config.args.app_info = ocs_app_event_type_chan_stats;

    wifi_util_dbg_print(WIFI_OCS, "%s:%d Pushing the event for app %d \n", __func__, __LINE__, route.u.inst_bit_map);

    push_event_to_monitor_queue(data, wifi_event_monitor_data_collection_config, &route);
}

int push_ocs_config_event_to_monitor_queue(wifi_mon_stats_request_state_t state, unsigned int radioIndex)
{
    // Send appropriate configs to monitor queue(stats, neighbour scan)
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    off_channel_param_t *ocs_cfg = get_wifi_ocs(radioIndex);
    wifi_monitor_data_t *data;
    wifi_util_dbg_print(WIFI_OCS, "%s:%d Entering \n", __func__, __LINE__);

    if (wifi_mgr == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d Mgr object is NULL \r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    data = (wifi_monitor_data_t *)malloc(sizeof(wifi_monitor_data_t));
    if (data == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d data allocation failed\r\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(data,0,sizeof(wifi_monitor_data_t));
    bool dfs_enable = wifi_mgr->rfc_dml_parameters.dfs_rfc;
    bool dfs_boot = wifi_mgr->rfc_dml_parameters.dfsatbootup_rfc;
    bool dfs = (dfs_enable | dfs_boot); /* checking if dfs is enabled in run time or boot up */

    if (ocs_cfg == NULL) {
        wifi_util_error_print(WIFI_OCS, "%s:%d ocs_cfg is null \n", __func__, __LINE__);
        if (NULL != data) {
            free(data);
            data = NULL;
        }
        return RETURN_ERR;
    }

    wifi_radio_capabilities_t *wifiCapPtr = NULL;
    wifiCapPtr = getRadioCapability(radioIndex);
    if (wifiCapPtr == NULL) {
        wifi_util_error_print(WIFI_OCS, "%s:%d radioOperation or wifiCapPtr is null \n", __func__, __LINE__);
        if (NULL != data) {
            free(data);
            data = NULL;
        }
        return RETURN_ERR;
    }

    int valid_chan_count = 0;
    for (int num = 0; num < wifiCapPtr->channel_list[0].num_channels; num++) {
        if (!dfs && (wifiCapPtr->channel_list[0].channels_list[num] >= DFS_START && wifiCapPtr->channel_list[0].channels_list[num] <= DFS_END)) { //Skip DFS channels if DFS disabled
            CcspTraceDebug(("Off_channel_scan Skipping DFS Channel\n"));
            continue;
        }
        data->u.mon_stats_config.args.channel_list.channels_list[valid_chan_count] = wifiCapPtr->channel_list[0].channels_list[num];
        ocs_cfg->chan_list[valid_chan_count] = wifiCapPtr->channel_list[0].channels_list[num];
        valid_chan_count++;
        wifi_util_dbg_print(WIFI_OCS,"%s:%d off_channel_scan chan number:%u\n", __func__, __LINE__, wifiCapPtr->channel_list[0].channels_list[num]);
    }
    //add nscan, tidlesec and convert into milli seconds and assign it to the time interval 
    data->u.mon_stats_config.args.radio_index = wifi_mgr->radio_config[radioIndex].vaps.radio_index;
    data->u.mon_stats_config.interval_ms = (((int) ocs_cfg->NscanSec + ocs_cfg->TidleSec) * SEC_TO_MILLISEC);
    data->u.mon_stats_config.args.channel_list.num_channels = valid_chan_count;
    data->u.mon_stats_config.args.scan_mode = WIFI_RADIO_SCAN_MODE_OFFCHAN;
    data->u.mon_stats_config.inst = wifi_app_inst_ocs;
    data->u.mon_stats_config.req_state = state;
    data->u.mon_stats_config.start_immediately = false;
    data->u.mon_stats_config.delay_provider_sec = OCS_NEIGBOUR_SCAN_PROVIDER_DELAY_SEC;

    config_ocs_chan_util(data, radioIndex);
    config_ocs_neighbour_scan(data, radioIndex);

    if (NULL != data) {
        free(data);
        data = NULL;
    }

    //update ocs_cfg->Nchannel with number of channels scanned
    wifi_mgr->radio_config[radioIndex].feature.Nchannel = valid_chan_count - 1;
    wifi_util_dbg_print(WIFI_OCS,"%s:%d off_channel_scan Nchannel:%lu\n", __func__, __LINE__, wifi_mgr->radio_config[radioIndex].feature.Nchannel);
    return RETURN_OK;
}

/**************************************************************************************************************************/
/*                                                                                                                        */
/* FUNCTION NAME : SetOffChanTscan                                                                                       */
/*                                                                                                                        */
/* DESCRIPTION   : This function sets Tscan param of Off Channel Scan                                                     */
/*                                                                                                                        */
/* INPUT         : R_Index - Radio Index                                                                                  */
/*                 Tscan - Time that a single channel is scanned (msec)                                                   */
/*                                                                                                                        */
/*                                                                                                                        */
/* OUTPUT        : NONE                                                                                                   */
/*                                                                                                                        */
/* RETURN VALUE  : Whether set is success                                                                                 */
/*                                                                                                                        */
/**************************************************************************************************************************/
int SetOffChanTscan(unsigned int radioIndex, ULONG Tscan)
{
    off_channel_param_t *ocs_cfg = get_wifi_ocs(radioIndex);
    if (ocs_cfg == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d: ocs_cfg is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if (radioIndex >= getNumberRadios()){
        wifi_util_error_print(WIFI_OCS,"%s:%d:invalid radioIndex %u\n", __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (ocs_cfg->TscanMsec == Tscan) {
        return RETURN_OK;
    }
    wifi_util_dbg_print(WIFI_OCS,"%s:%d RADIO_INDEX:%u New value: %lu\n",__func__,__LINE__,radioIndex,Tscan);
    ocs_cfg->TscanMsec = Tscan;
    return RETURN_OK;
}

/**************************************************************************************************************************/
/*                                                                                                                        */
/* FUNCTION NAME : SetOffChanNscan                                                                                       */
/*                                                                                                                        */
/* DESCRIPTION   : This function sets Nscan param of Off Channel Scan                                                     */
/*                                                                                                                        */
/* INPUT         : R_Index - Radio Index                                                                                  */
/*                 Nscan - number of times a single channel must be scanned within a day, converted to seconds and stored */
/*                                                                                                                        */
/*                                                                                                                        */
/* OUTPUT        : NONE                                                                                                   */
/*                                                                                                                        */
/* RETURN VALUE  : Whether set is success                                                                                 */
/*                                                                                                                        */
/**************************************************************************************************************************/
int SetOffChanNscan(unsigned int radioIndex, ULONG Nscan)
{
    off_channel_param_t *ocs_cfg = get_wifi_ocs(radioIndex);
    if (ocs_cfg == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d: ocs_cfg is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if (radioIndex >= getNumberRadios()){
        wifi_util_error_print(WIFI_OCS,"%s:%d:invalid radioIndex %u\n", __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (ocs_cfg->NscanSec == Nscan) {
        return RETURN_OK;
    }
    wifi_util_dbg_print(WIFI_OCS,"%s:%d RADIO_INDEX:%u New value: %lu\n",__func__,__LINE__, radioIndex, Nscan);
    ocs_cfg->NscanSec = Nscan;
    return RETURN_OK;
}

/**************************************************************************************************************************/
/*                                                                                                                        */
/* FUNCTION NAME : SetOffChanTidle                                                                                        */
/*                                                                                                                        */
/* DESCRIPTION   : This function sets Tidle param of Off Channel Scan                                                     */
/*                                                                                                                        */
/* INPUT         : R_Index - Radio Index                                                                                  */
/*                 Tidle - time to account for network idleness (sec)                                                     */
/*                                                                                                                        */
/*                                                                                                                        */
/* OUTPUT        : NONE                                                                                                   */
/*                                                                                                                        */
/* RETURN VALUE  : Whether set is success                                                                                 */
/*                                                                                                                        */
/**************************************************************************************************************************/
int SetOffChanTidle(unsigned int radioIndex, ULONG Tidle)
{
    off_channel_param_t *ocs_cfg = get_wifi_ocs(radioIndex);
    if (ocs_cfg == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d: ocs_cfg is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if (radioIndex >= getNumberRadios()){
        wifi_util_error_print(WIFI_OCS,"%s:%d:invalid radioIndex %u\n", __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    if (ocs_cfg->TidleSec == Tidle) {
        return RETURN_OK;
    }
    wifi_util_dbg_print(WIFI_OCS,"%s:%d RADIO_INDEX:%u New value: %lu\n",__func__,__LINE__,radioIndex,Tidle);
    ocs_cfg->TidleSec = Tidle;
    return RETURN_OK;
}

/**************************************************************************************************************************/
/*                                                                                                                        */
/* FUNCTION NAME : SetOffChanParams                                                                                       */
/*                 Wrapper for setting params                                                                             */
/* DESCRIPTION   : This function sets Off Channel Scan Params                                                             */
/*                                                                                                                        */
/* INPUT         : R_Index - Radio Index                                                                                  */
/*                 Tscan - Time that a single channel is scanned (msec)                                                   */
/*                 Nscan - number of times a single channel must be scanned within a day, converted to seconds and stored */
/*                 Tidle - time to account for network idleness (sec)                                                     */
/* OUTPUT        : NONE                                                                                                   */
/*                                                                                                                        */
/* RETURN VALUE  : Whether set is success                                                                                 */
/*                                                                                                                        */
/**************************************************************************************************************************/
int SetOffChanParams(unsigned int radioIndex, ULONG Tscan, ULONG Nscan, ULONG Tidle)
{

    int ret = 0;

    if (radioIndex >= getNumberRadios()){
        wifi_util_error_print(WIFI_OCS,"%s:%d:invalid radioIndex %u\n", __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    ret |= SetOffChanTscan(radioIndex, Tscan);
    ret |= SetOffChanNscan(radioIndex, Nscan);
    ret |= SetOffChanTidle(radioIndex, Tidle);

    if(ret != 0)
    {
        wifi_util_error_print(WIFI_OCS,"%s:%d:Error in assignment for %u\n", __func__, __LINE__, radioIndex);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

/**************************************************************************************************************************/
/*                                                                                                                        */
/* FUNCTION NAME : off_chan_print_neighbour_data                                                                               */
/*                                                                                                                        */
/* DESCRIPTION   : This function prints the required information for 5G off channel scan feature into WiFiLog.txt         */
/*                                                                                                                        */
/* INPUT         : Neighbor report array and its size                                                                     */
/*                                                                                                                        */
/* OUTPUT        : Logs into WiFiLog.txt                                                                                 */
/*                                                                                                                        */
/* RETURN VALUE  : NONE                                                                                                   */
/*                                                                                                                        */
/***************************************************************************************************************************/

void off_chan_print_neighbour_data(wifi_provider_response_t *provider_response)
{
    wifi_neighbor_ap2_t *off_chan_scan_data = NULL;
    off_chan_scan_data = (wifi_neighbor_ap2_t *) provider_response->stat_pointer;
    unsigned int i,j;
    wifi_mgr_t *wifi_mgr = get_wifimgr_obj();
    off_channel_param_t *ocs_cfg = get_wifi_ocs(provider_response->args.radio_index);

    if (ocs_cfg == NULL || wifi_mgr == NULL || off_chan_scan_data == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d: ocs_cfg or wifi_mgr or off_chan_scan_data is NULL\n", __func__, __LINE__);
        return;
    }

    unsigned int radio_index = provider_response->args.radio_index;
    wifi_util_dbg_print(WIFI_OCS,"%s:%d radio_index : %d stats_array_size : %d\r\n",__func__, __LINE__, radio_index, provider_response->stat_array_size);
    CcspTraceDebug(("Off_channel_scan Total channels: %lu \n", wifi_mgr->radio_config[provider_response->args.radio_index].feature.Nchannel));

    if (provider_response->stat_array_size <= 0){
        wifi_util_error_print(WIFI_OCS,"%s:%d: provider_response is NULL\n", __func__, __LINE__);
        return;
    }

    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio_index);
    if (radioOperation == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d: radioOperation is NULL\n", __func__, __LINE__);
        return;
    }

    UINT prim_chan = radioOperation->channel;

    for (i = 0; i < wifi_mgr->radio_config[provider_response->args.radio_index].feature.Nchannel + 1; i++) {
        int count = 0;

        if (ocs_cfg->chan_list[i] == prim_chan) {
            continue;
        }

        for (j = 0, off_chan_scan_data = (wifi_neighbor_ap2_t *) provider_response->stat_pointer; j < provider_response->stat_array_size; j++, off_chan_scan_data++) {
            if (off_chan_scan_data->ap_Channel > ocs_cfg->chan_list[i]) {
                break;
            } else if (off_chan_scan_data->ap_Channel < ocs_cfg->chan_list[i]) {
                continue;
            }
            count++;
        }
        CcspTraceInfo(("Off_channel_scan Total Scan Results:%d for channel %d \n", count, ocs_cfg->chan_list[i]));
        wifi_util_dbg_print(WIFI_OCS,"%s:%d Off_channel_scan Total Scan Results:%d for channel %d\r\n",__func__, __LINE__, count, ocs_cfg->chan_list[i]);
        int neighbor = 0;
        if (count > 0) {
            for (j = 0, off_chan_scan_data = (wifi_neighbor_ap2_t *) provider_response->stat_pointer; j < provider_response->stat_array_size; j++, off_chan_scan_data++)
            {
                if (off_chan_scan_data->ap_Channel > ocs_cfg->chan_list[i]) {
                    break;
                } else if (off_chan_scan_data->ap_Channel < ocs_cfg->chan_list[i]) {
                    continue;
                }
                neighbor++;
                CcspTraceInfo(("Off_channel_scan Neighbor:%d ap_BSSID:%s ap_SignalStrength: %d\n", neighbor, off_chan_scan_data->ap_BSSID, off_chan_scan_data->ap_SignalStrength));
                wifi_util_dbg_print(WIFI_OCS,"%s:%d Off_channel_scan Neighbor:%d ap_BSSID:%s ap_SignalStrength: %d\n",__func__, __LINE__, neighbor, off_chan_scan_data->ap_BSSID, off_chan_scan_data->ap_SignalStrength);
            }
        }
    }
}

void off_chan_print_chan_stats_data(wifi_provider_response_t *provider_response)
{
    radio_chan_data_t *off_chan_scan_data = NULL;
    off_chan_scan_data = (radio_chan_data_t *) provider_response->stat_pointer;
    if (off_chan_scan_data == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d: off_chan_scan_data is NULL\n", __func__, __LINE__);
        return;
    }
    unsigned int radio_index = provider_response->args.radio_index;
    wifi_util_dbg_print(WIFI_OCS,"%s:%d radio_index : %d stats_array_size : %d\r\n",__func__, __LINE__, radio_index, provider_response->stat_array_size);

    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio_index);
    if (radioOperation == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d: radioOperation is NULL\n", __func__, __LINE__);
        return;
    }

    UINT prim_chan = radioOperation->channel;

    if (provider_response->stat_array_size <= 0){
        wifi_util_error_print(WIFI_OCS,"%s:%d: provider response is NULL\n", __func__, __LINE__);
        return;
    }

    for (unsigned int count = 0; count < provider_response->stat_array_size; count++) {
        if (off_chan_scan_data[count].ch_number == (int) prim_chan) {
            continue;
        }
        CcspTraceInfo(("Off_channel_scan Channel number:%d Channel Utilization:%d \n",off_chan_scan_data[count].ch_number, off_chan_scan_data[count].ch_utilization));
         wifi_util_dbg_print(WIFI_OCS,"%s:%d: radio_index : %d channel_num : %d ch_utilization : %d ch_utilization_total:%lld\r\n",
                             __func__, __LINE__, radio_index, off_chan_scan_data[count].ch_number, off_chan_scan_data[count].ch_utilization, off_chan_scan_data[count].ch_utilization_total);
    }
}

void config_ocs()
{
    unsigned int radioIndex = 0;
    wifi_mgr_t *mgr = get_wifimgr_obj();
    unsigned int total_radios = getNumberRadios();

    wifi_util_dbg_print(WIFI_OCS,"%s:%d: Entered in config os\n", __func__, __LINE__);

    for (radioIndex = 0; radioIndex < total_radios; radioIndex++)
    {
        off_channel_param_t *ocs_cfg = get_wifi_ocs(radioIndex);
        ocs_cfg->radio_index = radioIndex;
        if(!(is_radio_band_5G(mgr->radio_config[radioIndex].oper.band))) {
            if(SetOffChanParams(radioIndex,0,0,0) != RETURN_OK) {
                wifi_util_error_print(WIFI_OCS,"%s:%d: Unable to set Offchannel Params\n", __func__, __LINE__);
            }
            continue;
        }
        wifi_util_dbg_print(WIFI_OCS,"%s:%d: Value of NSCAN is %lu Tscan is %lu Tidle is %lu and radio is %u \n", __func__, __LINE__, ((mgr->radio_config[radioIndex].feature.OffChanNscanInSec != 0)? ((24*3600)/mgr->radio_config[radioIndex].feature.OffChanNscanInSec):mgr->radio_config[radioIndex].feature.OffChanNscanInSec),
                                    mgr->radio_config[radioIndex].feature.OffChanTscanInMsec, mgr->radio_config[radioIndex].feature.OffChanTidleInSec, radioIndex);
        if(SetOffChanParams(radioIndex,mgr->radio_config[radioIndex].feature.OffChanTscanInMsec,mgr->radio_config[radioIndex].feature.OffChanNscanInSec,mgr->radio_config[radioIndex].feature.OffChanTidleInSec) != RETURN_OK) {
            wifi_util_error_print(WIFI_OCS,"%s:%d: Unable to set Offchannel Params\n", __func__, __LINE__);
        }
        off_chan_scan_init(radioIndex);
    }
}

void handle_ocs_command_event(wifi_app_t *app, wifi_event_t *event)
{
    switch(event->sub_type) {
        case wifi_event_type_notify_monitor_done:
            wifi_util_dbg_print(WIFI_OCS,"%s:%d calling config_ocs for monitor_done\n", __func__, __LINE__);
            config_ocs();
            is_monitor_done = TRUE;
            break;
        case wifi_event_type_wifi_offchannelscan_rfc:
            wifi_util_dbg_print(WIFI_OCS,"%s:%d calling config_ocs for change in off_chan rfc \n", __func__, __LINE__);
            if (is_monitor_done) {
                config_ocs();
            }
            break;
        default:
            break;
    }
}


void handle_monitor_ocs_event(wifi_app_t *app, wifi_event_t *event)
{
    wifi_provider_response_t    *provider_response;
    provider_response = (wifi_provider_response_t *)event->u.provider_response;

    switch(provider_response->args.app_info) {
        case ocs_app_event_type_neighbor_stats:
            wifi_util_dbg_print(WIFI_OCS,"%s:%d: Received neighbor stats\n", __func__, __LINE__);
            off_chan_print_neighbour_data(provider_response);
            break;
        case ocs_app_event_type_chan_stats:
            wifi_util_dbg_print(WIFI_OCS,"%s:%d: Received channel stats\n", __func__, __LINE__);
            off_chan_print_chan_stats_data(provider_response);
            break;
        default:
            break;
    }
}

int validate_ocs()
{
    wifi_mgr_t *mgr = get_wifimgr_obj();
    if (mgr == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d: mgr is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    for (UINT radioIndex = 0; radioIndex < getNumberRadios(); radioIndex++) {

        if ((is_radio_band_5G(mgr->radio_config[radioIndex].oper.band))) {
            off_channel_param_t *ocs_cfg = get_wifi_ocs(radioIndex);

            CcspTraceInfo(("Off_channel_scan feature newly configured values RFC = %d; TScan = %lu; NScan = %lu; Tidle = %lu\n", mgr->rfc_dml_parameters.wifioffchannelscan_rfc, mgr->radio_config[radioIndex].feature.OffChanTscanInMsec, ((mgr->radio_config[radioIndex].feature.OffChanNscanInSec != 0)? ((24*3600)/mgr->radio_config[radioIndex].feature.OffChanNscanInSec):mgr->radio_config[radioIndex].feature.OffChanNscanInSec), mgr->radio_config[radioIndex].feature.OffChanTidleInSec));
            if (ocs_cfg->NscanSec == mgr->radio_config[radioIndex].feature.OffChanNscanInSec &&
                ocs_cfg->TscanMsec == mgr->radio_config[radioIndex].feature.OffChanTscanInMsec &&
                ocs_cfg->TidleSec == mgr->radio_config[radioIndex].feature.OffChanTidleInSec) {
                wifi_util_info_print(WIFI_OCS,"%s:%d: No change in Offchannel Params\n", __func__, __LINE__);
                continue;
            }
            if (SetOffChanParams(radioIndex, mgr->radio_config[radioIndex].feature.OffChanTscanInMsec, mgr->radio_config[radioIndex].feature.OffChanNscanInSec, mgr->radio_config[radioIndex].feature.OffChanTidleInSec) != RETURN_OK) {
                wifi_util_error_print(WIFI_OCS,"%s:%d: Unable to set Offchannel Params\n", __func__, __LINE__);
                return RETURN_ERR;
            }
            if (mgr->rfc_dml_parameters.wifioffchannelscan_rfc) {
                off_chan_scan_init(radioIndex);
            }
        }
    }
    return RETURN_OK;
}

void handle_ocs_webconfig_event(wifi_app_t *app, wifi_event_t *event)
{
    switch(event->u.webconfig_data->type) {
        case webconfig_subdoc_type_radio:
            validate_ocs();
            break;
        default:
            break;
    }
}

int ocs_event(wifi_app_t *app, wifi_event_t *event)
{
    switch(event->event_type) {
        case wifi_event_type_webconfig:
            handle_ocs_webconfig_event(app, event);
        break;
        case wifi_event_type_monitor:
            handle_monitor_ocs_event(app, event);
        break;
        case wifi_event_type_command:
            handle_ocs_command_event(app,event);
        break;
        default:
        break;
    }
    return RETURN_OK;
}

int ocs_init(wifi_app_t *app, unsigned int create_flag)
{
    wifi_util_dbg_print(WIFI_OCS, "Entering %s\n", __func__);
    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    return RETURN_OK;
}

int ocs_deinit(wifi_app_t *app)
{
    for(unsigned int radio_index = 0; radio_index < MAX_NUM_RADIOS; radio_index++) {
        push_ocs_config_event_to_monitor_queue(mon_stats_request_state_stop, radio_index);
    }

    return RETURN_OK;
}

/**************************************************************************************************************************/
/*                                                                                                                        */
/* FUNCTION NAME : off_chan_scan_init                                                                                     */
/*                                                                                                                        */
/* DESCRIPTION   : This function prints the required information for 5G off channel scan feature into WiFiLog.txt         */
/*                                                                                                                        */
/* INPUT         : radio index                                                                                            */
/*                                                                                                                        */
/* OUTPUT        :  Status of 5G Off channel scan feature, DFS Feature, value of Parameters related to Off channel scan.  */
/*                  If scanned, No of BSS heard on each channel into WiFiLog.txt                                          */
/*                                                                                                                        */
/* RETURN VALUE  : INT                                                                                                    */
/*                                                                                                                        */
/**************************************************************************************************************************/
static int off_chan_scan_init (unsigned int radio_index)
{
    wifi_util_info_print(WIFI_OCS,"%s:%d: Running Off_channel_scan for %u\n", __func__, __LINE__, radio_index);
    wifi_mgr_t *g_wifi_mgr = get_wifimgr_obj();
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    off_channel_param_t *ocs_cfg = get_wifi_ocs(radio_index);
    ULONG Tscan = 0, Nscan = 0, Tidle = 0;

    bool dfs_enable = g_wifi_mgr->rfc_dml_parameters.dfs_rfc;
    bool dfs_boot = g_wifi_mgr->rfc_dml_parameters.dfsatbootup_rfc;
    bool dfs = (dfs_enable | dfs_boot); /* checking if dfs is enabled in run time or boot up */
    ocs_cfg->off_scan_rfc = g_wifi_mgr->rfc_dml_parameters.wifioffchannelscan_rfc;
    Tscan = ocs_cfg->TscanMsec;
    Nscan = ocs_cfg->NscanSec;
    Tidle = ocs_cfg->TidleSec;

    CcspTraceDebug(("Off_channel_scan feature RFC = %d; TScan = %lu; NScan = %lu; Tidle = %lu; DFS:%d\n", ocs_cfg->off_scan_rfc, Tscan, ((Nscan != 0)?((24*3600)/Nscan):Nscan), Tidle, dfs));

    if (!(is_radio_band_5G(g_wifi_mgr->radio_config[radio_index].oper.band))) {
        CcspTraceError(("Off_channel_scan Cannot run for radio index: %d as feature for the same is not developed yet\n",radio_index + 1));
        return RETURN_OK;
    }

    if (ctrl == NULL) {
        wifi_util_error_print(WIFI_OCS,"%s:%d: ctrl is NULL\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    /*Checking if rfc is disabled or if any one of the params are 0; if yes, scan is aborted*/
    if (!ocs_cfg->off_scan_rfc || Tscan == 0 || Nscan == 0 || Tidle == 0) {
        CcspTraceInfo(("Off_channel_scan feature is disabled returning RFC = %d; TScan = %lu; NScan = %lu; Tidle = %lu\n", ocs_cfg->off_scan_rfc, Tscan, ((Nscan != 0)? ((24*3600)/Nscan):Nscan), Tidle));
        if ((ocs_cfg->curr_off_channel_scan_period != (int) Nscan) && (Nscan != 0)) {
            ocs_cfg->curr_off_channel_scan_period = Nscan;
        }
        else {
            ocs_cfg->curr_off_channel_scan_period = OFFCHAN_DEFAULT_NSCAN_IN_SEC;
        }

        if (ocs_cfg->ocs_scheduler_id == 0) {
            UINT ocs_scheduler_interval = (((int) ocs_cfg->curr_off_channel_scan_period) * SEC_TO_MILLISEC);

            scheduler_add_timer_task(ctrl->sched, FALSE, &ocs_cfg->ocs_scheduler_id, print_ocs_state, NULL, ocs_scheduler_interval, 0, 0);
            ocs_cfg->ocs_scheduler_id++;
            push_ocs_config_event_to_monitor_queue(mon_stats_request_state_stop, radio_index);
        }
        return RETURN_OK;
    }

    //Getting primary channel and country code
    wifi_radio_operationParam_t* radioOperation = getRadioOperationParam(radio_index);
    UINT prim_chan = radioOperation->channel;
    char countryStr[64] = {0};
    snprintf(countryStr, sizeof(wifiCountryMapMembers[radioOperation->countryCode].countryStr),"%s", wifiCountryMapMembers[radioOperation->countryCode].countryStr);
    wifi_util_dbg_print(WIFI_OCS,"%s:%d Off_channel_scan Country Code:%s prim_chan:%u\n", __func__, __LINE__, countryStr, prim_chan);

    //If DFS enabled and country code is not US, CA or GB; the scan should not run for 5GHz radio. Possible updates might be required for GW using two 5G radios
    if (dfs && !(strncmp(countryStr, "US", 2) || strncmp(countryStr, "CA", 2) || strncmp(countryStr, "GB", 2))) {
        CcspTraceError(("Getting country code %s; skipping the scan!\n", countryStr));

        if ((ocs_cfg->curr_off_channel_scan_period != (int) Nscan) && (Nscan != 0)) {
            ocs_cfg->curr_off_channel_scan_period = Nscan;
        }
        else {
            ocs_cfg->curr_off_channel_scan_period = OFFCHAN_DEFAULT_NSCAN_IN_SEC;
        }

        if (ocs_cfg->ocs_scheduler_id == 0) {
            UINT ocs_scheduler_interval = (((int) ocs_cfg->curr_off_channel_scan_period) * SEC_TO_MILLISEC);
            scheduler_add_timer_task(ctrl->sched, FALSE, &ocs_cfg->ocs_scheduler_id, print_ocs_state, NULL, ocs_scheduler_interval, 0, 0);
            ocs_cfg->ocs_scheduler_id++;
            push_ocs_config_event_to_monitor_queue(mon_stats_request_state_stop, radio_index);
        }
        return RETURN_OK;
    }
    CcspTraceInfo(("Off_channel_scan DFS:%d and country code is %s\n", dfs, countryStr));

    if (push_ocs_config_event_to_monitor_queue(mon_stats_request_state_start, radio_index) != RETURN_OK) {
        CcspTraceError(("Off_channel_scan failed to push the event\n"));
        wifi_util_error_print(WIFI_OCS, "Off_channel_scan failed to push the event\n");
        return RETURN_ERR;
    }
    if (ocs_cfg->ocs_scheduler_id != 0){
        scheduler_cancel_timer_task(ctrl->sched, ocs_cfg->ocs_scheduler_id);
        ocs_cfg->ocs_scheduler_id = 0;
    }

    return RETURN_OK;
}

#endif //(FEATURE_OFF_CHANNEL_SCAN_5G)
