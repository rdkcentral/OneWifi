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

#ifndef LQ_IPC_SENDER_H
#define LQ_IPC_SENDER_H

#include <stdint.h>
#include <stddef.h>

/*
 * AF_UNIX datagram socket path shared between OneWifi (sender) and
 * linkquality-stats daemon (receiver).
 */
#define LQ_STATS_SOCKET_PATH "/tmp/linkquality_stats.sock"

/*
 * IPC message types — each maps to a qmgr function in linkquality-stats.
 *
 * PERIODIC_STATS   → add_stats_metrics() + periodic_caffinity_stats_update()
 * DISCONNECT       → remove_link_stats()
 * RAPID_DISCONNECT → disconnect_link_stats()
 * CAFFINITY_EVENT  → periodic_caffinity_stats_update() [single entry, HAL/DHCP]
 * START_METRICS    → start_link_metrics() + set_max_snr_radios()
 * STOP_METRICS     → stop_link_metrics()
 * REGISTER_STA     → register_station_mac() [ignite]
 * UNREGISTER_STA   → unregister_station_mac() [ignite]
 * REINIT_METRICS   → reinit_link_metrics() [server_arg_t payload]
 * SET_MAX_SNR      → set_max_snr_radios() [radio_max_snr_t payload]
 */
#define LQ_IPC_MSG_PERIODIC_STATS    1
#define LQ_IPC_MSG_DISCONNECT        2
#define LQ_IPC_MSG_RAPID_DISCONNECT  3
#define LQ_IPC_MSG_CAFFINITY_EVENT   4
#define LQ_IPC_MSG_START_METRICS     5
#define LQ_IPC_MSG_STOP_METRICS      6
#define LQ_IPC_MSG_REGISTER_STA      7
#define LQ_IPC_MSG_UNREGISTER_STA    8
#define LQ_IPC_MSG_REINIT_METRICS    9
#define LQ_IPC_MSG_SET_MAX_SNR      10

/*
 * Fixed-size header prepended to every datagram.
 * Followed by num_entries × stats_arg_t (or equivalent).
 */
typedef struct {
    uint32_t msg_type;       /* LQ_IPC_MSG_* */
    uint32_t num_entries;    /* number of entries that follow */
} lq_ipc_header_t;

/*
 * Send a link-quality event over the AF_UNIX datagram socket.
 *
 *   msg_type   – LQ_IPC_MSG_*
 *   entries    – pointer to count × entry_size bytes (stats_arg_t array)
 *   count      – number of entries
 *   entry_size – sizeof one entry (sizeof(stats_arg_t))
 *
 * Returns 0 on success, -1 on error (non-fatal — logged and ignored).
 */
int lq_ipc_send(uint32_t msg_type, const void *entries,
                uint32_t count, size_t entry_size);

#endif /* LQ_IPC_SENDER_H */
