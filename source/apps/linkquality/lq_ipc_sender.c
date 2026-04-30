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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "lq_ipc_sender.h"
#include "wifi_util.h"
#include "run_qmgr.h"

static int lq_ipc_fd = -1;

static const char *lq_msg_type_str(uint32_t type)
{
    switch (type) {
    case LQ_IPC_MSG_PERIODIC_STATS:   return "PERIODIC_STATS";
    case LQ_IPC_MSG_DISCONNECT:       return "DISCONNECT";
    case LQ_IPC_MSG_RAPID_DISCONNECT: return "RAPID_DISCONNECT";
    case LQ_IPC_MSG_CAFFINITY_EVENT:  return "CAFFINITY_EVENT";
    case LQ_IPC_MSG_START_METRICS:    return "START_METRICS";
    case LQ_IPC_MSG_STOP_METRICS:     return "STOP_METRICS";
    case LQ_IPC_MSG_REGISTER_STA:     return "REGISTER_STA";
    case LQ_IPC_MSG_UNREGISTER_STA:   return "UNREGISTER_STA";
    case LQ_IPC_MSG_REINIT_METRICS:   return "REINIT_METRICS";
    case LQ_IPC_MSG_SET_MAX_SNR:      return "SET_MAX_SNR";
    default:                          return "UNKNOWN";
    }
}

static void lq_ipc_log_stats_entries(uint32_t msg_type, const void *entries,
                                     uint32_t count, size_t entry_size)
{
    /* Log per-entry detail for stats_arg_t-bearing messages */
    if (entry_size != sizeof(stats_arg_t) || count == 0 || !entries) {
        return;
    }

    const stats_arg_t *s = (const stats_arg_t *)entries;
    for (uint32_t i = 0; i < count; i++) {
        wifi_util_info_print(WIFI_APPS,
            "%s [IPC-SEND] %s [%u/%u] MAC=%s status_code=%u event=%d "
            "conn_time=%llds disconn_time=%llds snr=%d vap=%u radio=%u\n",
            __func__, lq_msg_type_str(msg_type), i + 1, count,
            s[i].mac_str, s[i].status_code, s[i].event,
            (long long)s[i].total_connected_time.tv_sec,
            (long long)s[i].total_disconnected_time.tv_sec,
            s[i].dev.cli_SNR, s[i].vap_index, s[i].radio_index);
    }
}

int lq_ipc_send(uint32_t msg_type, const void *entries,
                uint32_t count, size_t entry_size)
{
    wifi_util_info_print(WIFI_APPS,
        "%s:%d [IPC-SEND] msg_type=%s(%u) count=%u entry_size=%zu\n",
        __func__, __LINE__, lq_msg_type_str(msg_type), msg_type,
        count, entry_size);

    /* Log per-entry details for stats_arg_t messages */
    lq_ipc_log_stats_entries(msg_type, entries, count, entry_size);

    if (count != 0 && entries == NULL) {
        return -1;
    }

    if (lq_ipc_fd < 0) {
        lq_ipc_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (lq_ipc_fd < 0) {
            wifi_util_error_print(WIFI_MON,
                "%s:%d socket() failed: %s\n", __func__, __LINE__, strerror(errno));
            return -1;
        }
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LQ_STATS_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    size_t data_sz = count * entry_size;
    size_t payload_sz = sizeof(lq_ipc_header_t) + data_sz;
    uint8_t *buf = malloc(payload_sz);
    if (!buf) {
        wifi_util_error_print(WIFI_MON,
            "%s:%d malloc(%zu) failed\n", __func__, __LINE__, payload_sz);
        return -1;
    }

    lq_ipc_header_t *hdr = (lq_ipc_header_t *)buf;
    hdr->msg_type    = msg_type;
    hdr->num_entries = count;

    memcpy(buf + sizeof(lq_ipc_header_t), entries, data_sz);

    ssize_t ret = sendto(lq_ipc_fd, buf, payload_sz, MSG_DONTWAIT,
                         (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        wifi_util_dbg_print(WIFI_MON,
            "%s:%d sendto(%s) failed: %s (non-fatal)\n",
            __func__, __LINE__, LQ_STATS_SOCKET_PATH, strerror(errno));
    } else {
        wifi_util_info_print(WIFI_APPS,
            "%s:%d [IPC-SEND] %s sent %zd bytes OK\n",
            __func__, __LINE__, lq_msg_type_str(msg_type), ret);
    }

    free(buf);
    return (ret < 0) ? -1 : 0;
}
