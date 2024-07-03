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

#ifndef WIFI_CAC_H
#define WIFI_CAC_H

#ifdef __cplusplus
extern "C" {
#endif

#define EXP_WEIGHT 0.05
#define MAX_NUM_FRAME_TO_WAIT 3
#define DBM_DEVIATION 3

#define CAC_STATUS_OK 0
#define CAC_STATUS_DENY 1

#define NL_OK 0
#define NL_SKIP 1
#define WLAN_STATUS_SUCCESS 0
#define WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA 17
#define WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS 34
#define WLAN_FC_STYPE_ASSOC_REQ		0
#define WLAN_FC_STYPE_ASSOC_RESP	1
#define WLAN_FC_STYPE_REASSOC_REQ	2
#define WLAN_FC_STYPE_REASSOC_RESP	3
#define WLAN_FC_STYPE_PROBE_REQ		4
#define WLAN_FC_STYPE_PROBE_RESP	5
#define WLAN_FC_STYPE_BEACON		8
#define WLAN_FC_STYPE_ATIM		9
#define WLAN_FC_STYPE_DISASSOC		10
#define WLAN_FC_STYPE_AUTH		11
#define WLAN_FC_STYPE_DEAUTH		12
#define WLAN_FC_STYPE_ACTION		13
#define WLAN_FC_STYPE_ACTION_NO_ACK	14

typedef enum {
    status_ok,
    status_wait,
    status_deny
} cac_status_t;

typedef struct {
    unsigned int    ap_index;
    mac_addr_str_t  mac_addr;
    int             num_frames;
    int             rssi_avg;
    int             snr_avg;
    int             uplink_rate_avg;
    int             seconds_alive;
} cac_sta_info_t;

typedef struct {
    unsigned int    ap_index;
    mac_address_t   sta_mac;
    int             rssi_avg;
    int             snr_avg;
    int             uplink_rate_avg;
    int             sampling_count;
    int             sampling_interval;
} cac_associated_devices_t;

typedef struct {
    hash_map_t      *assoc_req_map;
    hash_map_t      *sta_map;
} cac_data_t;

#ifdef __cplusplus
}
#endif

#endif // WIFI_CAC_H
