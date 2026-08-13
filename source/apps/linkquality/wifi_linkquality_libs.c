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
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include "wifi_hal.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"
#include "wifi_linkquality_libs.h"
#include "wifi_linkquality.h"
#include "run_qmgr.h"
#include "lq_ipc_sender.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#define MAX_EM_BUFF_SZ  1024
#define QMGR_FILE "/tmp/qmgr_ready"

/* CAFFINITY_EVENT (msg_type 4) – HAL/DHCP events for caffinity scoring */
static int periodic_caffinity_stats_update_impl(stats_arg_t *stats, int len)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d vap_index =%d\n",__func__,__LINE__,
    stats->vap_index);
    int rc = lq_ipc_send(LQ_IPC_MSG_CAFFINITY_EVENT, stats,
                         (uint32_t)len, sizeof(stats_arg_t));
    return rc;
}

/* REGISTER_STA (msg_type 7) – Ignite RF-down station registration */
static void register_station_mac_impl(const char *str)
{

    size_t slen = strlen(str) + 1;
    int rc = lq_ipc_send(LQ_IPC_MSG_REGISTER_STA, str, 1, slen);
    wifi_util_info_print(WIFI_APPS,"%s:%d [IPC->UNREGISTER_STA] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);

}
/* UNREGISTER_STA (msg_type 8) – Ignite RF-down station unregistration */
static void unregister_station_mac_impl(const char *str)
{

    size_t slen = strlen(str) + 1;
    int rc = lq_ipc_send(LQ_IPC_MSG_UNREGISTER_STA, str, 1, slen);
    wifi_util_info_print(WIFI_APPS,"%s:%d [IPC->UNREGISTER_STA] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
}


/* RAPID_DISCONNECT (msg_type 3) – rapid connect/disconnect detection */
static int disconnect_link_stats_impl(stats_arg_t *stats)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d vap_index =%d\n",__func__,__LINE__,
    stats->vap_index);
    int rc = lq_ipc_send(LQ_IPC_MSG_RAPID_DISCONNECT, stats, 1,
                         sizeof(stats_arg_t));
    wifi_util_info_print(WIFI_APPS,"%s:%d [IPC->RAPID_DISCONNECT] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
    return rc;
}

/* REINIT_METRICS (msg_type 9) – webconfig/EM param update */
static int reinit_link_metrics_impl(server_arg_t *arg)
{

    int rc = lq_ipc_send(LQ_IPC_MSG_REINIT_METRICS, arg, 1,sizeof(server_arg_t));
    wifi_util_info_print(WIFI_APPS,"%s:%d [IPC->REINIT_METRICS] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
    return rc;
}

/* DISCONNECT (msg_type 2) – client permanently left sta_map */
static int remove_link_stats_impl(stats_arg_t *stats)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d vap_index =%d\n",__func__,__LINE__,
    stats->vap_index);

    int rc = lq_ipc_send(LQ_IPC_MSG_DISCONNECT, stats, 1,sizeof(stats_arg_t));
    wifi_util_info_print(WIFI_APPS,"%s:%d [IPC->DISCONNECT] lq_ipc_send rc=%d\n",
        __func__, __LINE__, rc);
    return rc;
}

/* PERIODIC_STATS (msg_type 1) – periodic monitor poll batch */
static int process_lq_stats_impl(stats_arg_t *stats, int len)
{
    /* Maximum clients per IPC datagram.  Keeps individual datagrams small
     * (~19 KB) so the kernel socket buffer can hold multiple in-flight
     * without hitting EAGAIN when 50+ clients are connected. */
#define LQ_IPC_BATCH_SIZE 16

    for (int i = 0; i < len; i++) {
        wifi_util_info_print(WIFI_APPS,
            "%s:%d  [%d] MAC=%s snr=%d vap=%u status_code=%u "
            "conn_time=%llds disconn_time=%llds\n",
            __func__, __LINE__, i,
            stats[i].mac_str, stats[i].dev.cli_SNR, stats[i].vap_index,
            stats[i].status_code,
            (long long)stats[i].total_connected_time.tv_sec,
            (long long)stats[i].total_disconnected_time.tv_sec);
    }

    int rc = 0;
    int offset = 0;
    while (offset < len) {
        int chunk = (len - offset > LQ_IPC_BATCH_SIZE) ? LQ_IPC_BATCH_SIZE : (len - offset);
        int ret = lq_ipc_send(LQ_IPC_MSG_PERIODIC_STATS, &stats[offset],
                              (uint32_t)chunk, sizeof(stats_arg_t));
        if (ret < 0) {
            rc = ret;
        }
        offset += chunk;
    }
    wifi_util_info_print(WIFI_APPS,"%s:%d [IPC->PERIODIC_STATS] total=%d batches=%d rc=%d\n",
        __func__, __LINE__, len, (len + LQ_IPC_BATCH_SIZE - 1) / LQ_IPC_BATCH_SIZE, rc);
    return rc;
}

/* get_link_metrics – local only, no IPC equivalent */
static char* get_link_metrics_impl()
{
    wifi_util_dbg_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    return NULL;
}

/* set_quality_flags – local only, no IPC equivalent */
static int set_quality_flags_impl(quality_flags_t *flag)
{
    wifi_util_dbg_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    (void)flag;
    return 0;
}

/* get_quality_flags – local only, no IPC equivalent */
static int get_quality_flags_impl(quality_flags_t *flag)
{
    wifi_util_dbg_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    (void)flag;
    return 0;
}

/* -------------------------------------------------------------------------
 * get_lq_descriptor – singleton; wires up unified functions (no separate
 * _ext/_gw split; mode is checked inside each function).
 * ------------------------------------------------------------------------- */
wifi_lq_descriptor_t* get_lq_descriptor()
{
    static bool initialized = false;
    static wifi_lq_descriptor_t desc;

    if (!initialized) {
#ifdef ONEWIFI_RDKB_APP_SUPPORT
        desc.periodic_caffinity_stats_update_fn = periodic_caffinity_stats_update_impl;
        desc.register_station_mac_fn            = register_station_mac_impl;
        desc.unregister_station_mac_fn          = unregister_station_mac_impl;
        desc.disconnect_link_stats_fn           = disconnect_link_stats_impl;
        desc.reinit_link_metrics_fn             = reinit_link_metrics_impl;
        desc.remove_link_stats_fn               = remove_link_stats_impl;
        desc.get_link_metrics_fn                = get_link_metrics_impl;
        desc.set_quality_flags_fn               = set_quality_flags_impl;
        desc.get_quality_flags_fn               = get_quality_flags_impl;
        desc.process_lq_stats_fn                = process_lq_stats_impl;
#else 
        desc.register_station_mac_fn            = register_station_mac;
        desc.unregister_station_mac_fn          = unregister_station_mac;
        desc.start_link_metrics_fn              = start_link_metrics;
        desc.stop_link_metrics_fn               = stop_link_metrics;
        desc.disconnect_link_stats_fn           = disconnect_link_stats;
        desc.reinit_link_metrics_fn             = reinit_link_metrics;
        desc.remove_link_stats_fn               = remove_link_stats;
        desc.get_link_metrics_fn                = get_link_metrics;
        desc.set_quality_flags_fn               = set_quality_flags;
        desc.get_quality_flags_fn               = get_quality_flags;
#endif
        initialized = true;
    }

    return &desc;
}

