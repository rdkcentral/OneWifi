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

#include <rbus.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#ifdef CCSP_COMMON
#include "ansc_platform.h"
#include "ccsp_WifiLog_wrapper.h"
#endif
#include "wifi_events.h"
#include "wifi_mgr.h"
#include "wifi_util.h"

void free_cloned_event(wifi_event_t *clone)
{
    if (clone->event_type != wifi_event_type_monitor) {
        free(clone->u.core_data.msg);
    }

    free(clone);
}

int clone_wifi_event(wifi_event_t *event, wifi_event_t **clone)
{
    wifi_event_t *cloned;

    cloned = (wifi_event_t *)malloc(sizeof(wifi_event_t));
    if (cloned == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d data malloc null\n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    memcpy(cloned, event, sizeof(wifi_event_t));
    if (event->event_type == wifi_event_type_monitor) {
        memcpy(cloned->u.mon_data, event->u.mon_data, sizeof(wifi_monitor_data_t));
    } else {
        cloned->u.core_data.len = event->u.core_data.len;
        cloned->u.core_data.msg = malloc(event->u.core_data.len);
        memcpy(cloned->u.core_data.msg, event->u.core_data.msg, event->u.core_data.len);
    }

    *clone = cloned;

    return RETURN_OK;
}

wifi_event_t *create_wifi_event(unsigned int msg_len, wifi_event_type_t type, wifi_event_subtype_t sub_type)
{
    wifi_event_t *event;
    if (type >= wifi_event_type_max) {
        wifi_util_error_print(WIFI_CTRL,"%s %d Invalid event\n",__FUNCTION__, __LINE__);
        return NULL;
    }

    event = (wifi_event_t *)calloc(1, sizeof(wifi_event_t));
    if (event == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d data malloc null\n",__FUNCTION__, __LINE__);
        return NULL;
    }

    switch(type) {
        case wifi_event_type_exec:
        case wifi_event_type_webconfig:
        case wifi_event_type_hal_ind:
        case wifi_event_type_command:
        case wifi_event_type_net:
        case wifi_event_type_wifiapi:
        case wifi_event_type_speed_test:
            if (msg_len != 0) {
                event->u.core_data.msg = calloc(1, (msg_len + 1));
                if (event->u.core_data.msg == NULL) {
                    wifi_util_error_print(WIFI_CTRL,"%s %d data message malloc null\n",__FUNCTION__, __LINE__);
                    free(event);
                    event = NULL;
                    return NULL;
                }
                event->u.core_data.len = msg_len;
            } else {
                event->u.core_data.len = 0;
            }
        break;
        case wifi_event_type_monitor:
            if (sub_type == wifi_event_monitor_data_collection_response) {
                event->u.dca_response = calloc(1, (msg_len));
                if (event->u.dca_response == NULL) {
                    wifi_util_error_print(WIFI_CTRL,"%s %d data message malloc null\n",__FUNCTION__, __LINE__);
                    free(event);
                    event = NULL;
                    return NULL;
                }
            } else {
                event->u.mon_data = calloc(1, (msg_len));
                if (event->u.mon_data == NULL) {
                    wifi_util_error_print(WIFI_CTRL,"%s %d data message malloc null\n",__FUNCTION__, __LINE__);
                    free(event);
                    event = NULL;
                    return NULL;
                }

            }
        break;
        case wifi_event_type_csi:
            if (sub_type == wifi_event_type_csi_data) {
                event->u.csi = calloc(1, (msg_len));
                if (event->u.csi == NULL) {
                    wifi_util_error_print(WIFI_CTRL,"%s %d data message malloc null\n",__FUNCTION__, __LINE__);
                    free(event);
                    event = NULL;
                    return NULL;
                }
            }
        break;
        case wifi_event_type_analytic:
            break;
        default:
            wifi_util_error_print(WIFI_CTRL,"%s %d Invalid event type : %d\n",__FUNCTION__, __LINE__, type);
            free(event);
            event = NULL;
            return NULL;
    }

    event->event_type = type;
    event->sub_type = sub_type;

    return event;
}

void destroy_wifi_event(wifi_event_t *event)
{
    if (event == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d input args are NULL\n",__FUNCTION__, __LINE__);
        return;
    }

    switch(event->event_type) {
        case wifi_event_type_analytic:
            break;
        case wifi_event_type_exec:
        case wifi_event_type_webconfig:
        case wifi_event_type_hal_ind:
        case wifi_event_type_command:
        case wifi_event_type_net:
        case wifi_event_type_wifiapi:
            if(event->u.core_data.msg != NULL) {
                free(event->u.core_data.msg);
            }
        break;
        case wifi_event_type_monitor:
            if (event->sub_type == wifi_event_monitor_data_collection_response) {
                if (event->u.dca_response != NULL) {
                    free(event->u.dca_response);
                }
            } else {
                if (event->u.mon_data != NULL) {
                    free(event->u.mon_data);
                }

            }
        break;
        case wifi_event_type_csi:
            if (event->sub_type == wifi_event_type_csi_data) {
                free(event->u.csi);
            }
        break;
        default:
        break;
    }

    if (event != NULL) {
        free(event);
        event = NULL;
    }

    return;
}

int push_monitor_event_to_ctrl_queue(const void *msg, unsigned int len, wifi_event_type_t type, wifi_event_subtype_t sub_type, wifi_event_route_t *rt)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_event_t *event;

    if(msg == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d  msg is null\n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    event = create_wifi_event(len, type, sub_type);
    if(event == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d data malloc null\n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    if (rt != NULL) {
        event->route = *rt;
    }

    if (msg != NULL) {
        memcpy(event->u.dca_response, msg, len);
    }

    pthread_mutex_lock(&ctrl->lock);
    queue_push(ctrl->queue, event);
    pthread_cond_signal(&ctrl->cond);
    pthread_mutex_unlock(&ctrl->lock);

    return RETURN_OK;
}

int push_event_to_ctrl_queue(const void *msg, unsigned int len, wifi_event_type_t type, wifi_event_subtype_t sub_type, wifi_event_route_t *rt)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_event_t *event;

    if(msg == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d  msg is null\n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    event = create_wifi_event(len, type, sub_type);
    if(event == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d data malloc null\n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }
    if (rt != NULL) {
        event->route = *rt;
    }

    if (msg != NULL) {
        /* copy msg to data */
        memcpy(event->u.core_data.msg, msg, len);
        event->u.core_data.len = len;
    } else {
        event->u.core_data.msg = NULL;
        event->u.core_data.len = 0;
    }

    pthread_mutex_lock(&ctrl->lock);
    queue_push(ctrl->queue, event);
    pthread_cond_signal(&ctrl->cond);
    pthread_mutex_unlock(&ctrl->lock);

    return RETURN_OK;
}

int push_event_to_monitor_queue(wifi_monitor_data_t *mon_data, wifi_event_subtype_t sub_type, wifi_event_route_t *rt)
{
    wifi_monitor_t *monitor_param = (wifi_monitor_t *)get_wifi_monitor();
    wifi_event_t *event;

    if(mon_data == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d: input monitor data is null\n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    event = create_wifi_event(sizeof(wifi_monitor_data_t), wifi_event_type_monitor, sub_type);
    if(event == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d data malloc null\n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    if (rt != NULL) {
        event->route = *rt;
    }

    memcpy(event->u.mon_data, mon_data, sizeof(wifi_monitor_data_t));

    pthread_mutex_lock(&monitor_param->queue_lock);
    queue_push(monitor_param->queue, event);
    pthread_cond_signal(&monitor_param->cond);
    pthread_mutex_unlock(&monitor_param->queue_lock);

    return RETURN_OK;
}

int push_unicast_event_to_ctrl_queue(const void *msg, unsigned int len, wifi_event_type_t type, wifi_event_subtype_t sub_type, wifi_event_route_t *rt)
{
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
    wifi_event_t *event;

    if(msg == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d  msg is null\n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    event = (wifi_event_t *)malloc(sizeof(wifi_event_t));
    if(event == NULL) {
        wifi_util_error_print(WIFI_CTRL,"%s %d data malloc null\n",__FUNCTION__, __LINE__);
        return RETURN_ERR;
    }

    memset(event, 0, sizeof(wifi_event_t));
    event->event_type = type;
    event->sub_type = sub_type;

    if (rt != NULL) {
        event->route = *rt;
    }

    if (msg != NULL) {
        event->u.core_data.msg = malloc(len + 1);
        if(event->u.core_data.msg == NULL) {
            wifi_util_error_print(WIFI_CTRL,"%s %d data message malloc null\n",__FUNCTION__, __LINE__);
            free(event);
            return RETURN_ERR;
        }
        /* copy msg to data */
        memcpy(event->u.core_data.msg, msg, len);
        event->u.core_data.len = len;
    } else {
        event->u.core_data.msg = NULL;
        event->u.core_data.len = 0;
    }

    pthread_mutex_lock(&ctrl->lock);
    queue_push(ctrl->queue, event);
    pthread_cond_signal(&ctrl->cond);
    pthread_mutex_unlock(&ctrl->lock);

    return RETURN_OK;
}

#ifdef CCSP_COMMON
void events_update_clientdiagdata(unsigned int num_devs, int vap_idx, wifi_associated_dev3_t *dev_array)
{

    unsigned int i =0;
    unsigned int pos = 0;
    unsigned int t_pos = 0;
    unsigned int vap_array_index;
    wifi_ctrl_t *ctrl = (wifi_ctrl_t *)get_wifictrl_obj();

    getVAPArrayIndexFromVAPIndex((unsigned int) vap_idx, &vap_array_index);

    pthread_mutex_lock(&ctrl->events_rbus_data.events_rbus_lock);
    if(ctrl->events_rbus_data.diag_events_json_buffer[vap_array_index] != NULL)
    {

        pos = snprintf(ctrl->events_rbus_data.diag_events_json_buffer[vap_array_index],
                CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS,
                "{"
                "\"Version\":\"1.0\","
                "\"AssociatedClientsDiagnostics\":["
                "{"
                "\"VapIndex\":\"%d\","
                "\"AssociatedClientDiagnostics\":[",
                vap_idx + 1);
        t_pos = pos + 1;
        if(dev_array != NULL) {
            for(i=0; i<num_devs; i++) {
                pos += snprintf(&ctrl->events_rbus_data.diag_events_json_buffer[vap_array_index][pos],
                        (CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS)-pos, "{"
                        "\"MAC\":\"%02x%02x%02x%02x%02x%02x\","
                        "\"DownlinkDataRate\":\"%d\","
                        "\"UplinkDataRate\":\"%d\","
                        "\"BytesSent\":\"%lu\","
                        "\"BytesReceived\":\"%lu\","
                        "\"PacketsSent\":\"%lu\","
                        "\"PacketsRecieved\":\"%lu\","
                        "\"Errors\":\"%lu\","
                        "\"RetransCount\":\"%lu\","
                        "\"Acknowledgements\":\"%lu\","
                        "\"SignalStrength\":\"%d\","
                        "\"SNR\":\"%d\","
                        "\"OperatingStandard\":\"%s\","
                        "\"OperatingChannelBandwidth\":\"%s\","
                        "\"AuthenticationFailures\":\"%d\","
                        "\"AuthenticationState\":\"%d\","
                        "\"Active\":\"%d\","
                        "\"InterferenceSources\":\"%s\","
                        "\"DataFramesSentNoAck\":\"%lu\","
                        "\"RSSI\":\"%d\","
                        "\"MinRSSI\":\"%d\","
                        "\"MaxRSSI\":\"%d\","
                        "\"Disassociations\":\"%u\","
                        "\"Retransmissions\":\"%u\""
                        "},",
                  dev_array->cli_MACAddress[0],
                  dev_array->cli_MACAddress[1],
                  dev_array->cli_MACAddress[2],
                  dev_array->cli_MACAddress[3],
                  dev_array->cli_MACAddress[4],
                  dev_array->cli_MACAddress[5],
                  dev_array->cli_MaxDownlinkRate,
                  dev_array->cli_MaxUplinkRate,
                  dev_array->cli_BytesSent,
                  dev_array->cli_BytesReceived,
                  dev_array->cli_PacketsSent,
                  dev_array->cli_PacketsReceived,
                  dev_array->cli_ErrorsSent,
                  dev_array->cli_RetransCount,
                  dev_array->cli_DataFramesSentAck,
                  dev_array->cli_SignalStrength,
                  dev_array->cli_SNR,
                  dev_array->cli_OperatingStandard,
                  dev_array->cli_OperatingChannelBandwidth,
                  dev_array->cli_AuthenticationFailures,
                  dev_array->cli_AuthenticationState,
                  dev_array->cli_Active,
                  dev_array->cli_InterferenceSources,
                  dev_array->cli_DataFramesSentNoAck,
                  dev_array->cli_RSSI,
                  dev_array->cli_MinRSSI,
                  dev_array->cli_MaxRSSI,
                  dev_array->cli_Disassociations,
                  dev_array->cli_Retransmissions);
                  dev_array++;
            }
            t_pos = pos;
        }
        snprintf(&ctrl->events_rbus_data.diag_events_json_buffer[vap_array_index][t_pos-1], (
                    CLIENTDIAG_JSON_BUFFER_SIZE*(sizeof(char))*MAX_ASSOCIATED_WIFI_DEVS)-t_pos-1,"]"
                "}"
                "]"
                "}");
    }
    pthread_mutex_unlock(&ctrl->events_rbus_data.events_rbus_lock);
}

#endif
